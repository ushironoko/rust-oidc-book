use std::collections::HashMap;

use axum::extract::{Form, Query, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{Html, IntoResponse, Redirect, Response};
use serde::Deserialize;
use url::Url;

use crate::{
    CODE_TTL_SECS, CodeGrant, ISSUER, MAX_CODES, MAX_PENDING, PendingRequest, Shared, constant_time_eq,
    find_client, insert_bounded, now, random_token,
};

const PENDING_TTL_SECS: u64 = 600;
const BINDING_COOKIE: &str = "mini_op_login";

fn single_valued(pairs: Vec<(String, String)>) -> Option<HashMap<String, String>> {
    let mut map = HashMap::new();
    for (k, v) in pairs {
        if map.insert(k, v).is_some() {
            return None;
        }
    }
    Some(map)
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

fn page(status: StatusCode, body: String) -> Response {
    (
        status,
        [
            (header::CACHE_CONTROL, "no-store"),
            (header::X_FRAME_OPTIONS, "DENY"),
            (header::CONTENT_SECURITY_POLICY, "frame-ancestors 'none'"),
        ],
        Html(format!(
            "<!doctype html><html lang=\"ja\"><meta charset=\"utf-8\"><title>mini-op</title>{body}</html>"
        )),
    )
        .into_response()
}

fn error_page(message: &str) -> Response {
    page(StatusCode::BAD_REQUEST, format!("<h1>認可リクエストのエラー</h1><p>{}</p>", html_escape(message)))
}

fn cookie_value<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(';'))
        .filter_map(|pair| pair.trim().split_once('='))
        .find(|(k, _)| *k == name)
        .map(|(_, v)| v)
}

fn redirect_with(redirect_uri: &str, params: &[(&str, &str)]) -> Response {
    let mut url = Url::parse(redirect_uri).expect("登録済みの redirect_uri は URL として正しい");
    url.query_pairs_mut().extend_pairs(params);
    Redirect::to(url.as_str()).into_response()
}

fn login_form(request_id: &str, client_id: &str, scope: &str, message: &str) -> Response {
    page(
        StatusCode::OK,
        format!(
            "<h1>mini-op にログイン</h1><p>{client}が次の範囲へのアクセスを求めています: {scope}</p>\
             <p>{message}</p>\
             <form method=\"post\" action=\"/authorize\">\
             <input type=\"hidden\" name=\"request_id\" value=\"{rid}\">\
             <label>ユーザー名 <input name=\"username\"></label>\
             <label>パスワード <input type=\"password\" name=\"password\"></label>\
             <button>ログインして許可する</button></form>",
            client = html_escape(client_id),
            scope = html_escape(scope),
            message = html_escape(message),
            rid = html_escape(request_id),
        ),
    )
}

pub async fn show_login(
    State(state): State<Shared>,
    Query(pairs): Query<Vec<(String, String)>>,
) -> Response {
    let Some(params) = single_valued(pairs) else {
        return error_page("同じパラメータが複数回含まれています");
    };
    let get = |k: &str| params.get(k).map(String::as_str).unwrap_or("");

    // 1. client_id と redirect_uri を確かめるまでは、エラーでもリダイレクトしない
    let Some(client) = find_client(&state, get("client_id")) else {
        return error_page("client_id が不正です");
    };
    let redirect_uri = get("redirect_uri");
    if !client.redirect_uris.contains(&redirect_uri) {
        return error_page("redirect_uri が登録値と一致しません");
    }

    // 2. ここから先のエラーは redirect_uri へ返してよい
    let st = get("state");
    let fail = |error: &str, description: &str| {
        redirect_with(
            redirect_uri,
            &[("error", error), ("error_description", description), ("state", st), ("iss", ISSUER)]
                .into_iter()
                .filter(|(_, v)| !v.is_empty())
                .collect::<Vec<_>>(),
        )
    };
    // mini-op はリクエストオブジェクトに対応しないので、外側のパラメータだけで処理せずに拒否する(Core 6.1、6.2)
    if params.contains_key("request") {
        return fail("request_not_supported", "request parameter is not supported");
    }
    if params.contains_key("request_uri") {
        return fail("request_uri_not_supported", "request_uri parameter is not supported");
    }
    if get("response_type") != "code" {
        return fail("unsupported_response_type", "response_type=code only");
    }
    let scope = get("scope");
    if !scope.split(' ').any(|s| s == "openid") {
        return fail("invalid_scope", "openid scope is required");
    }
    if get("code_challenge").is_empty() || get("code_challenge_method") != "S256" {
        return fail("invalid_request", "PKCE with S256 is required");
    }
    if get("nonce").is_empty() {
        return fail("invalid_request", "nonce is required");
    }
    // mini-op は OP 側のログインセッションを持たないので、画面を出さずに認証することはできない
    if get("prompt").split(' ').any(|p| p == "none") {
        return fail("login_required", "mini-op has no login session");
    }

    // request_id を、このブラウザだけが持つ Cookie の値に結びつける(ログインフォームの CSRF 対策)
    let request_id = random_token(&state.rng);
    let browser_binding = random_token(&state.rng);
    let stored = insert_bounded(
        &state.pending,
        request_id.clone(),
        PendingRequest {
            client_id: client.client_id.to_string(),
            redirect_uri: redirect_uri.to_string(),
            scope: scope.to_string(),
            state: st.to_string(),
            nonce: get("nonce").to_string(),
            code_challenge: get("code_challenge").to_string(),
            browser_binding: browser_binding.clone(),
            expires_at: now() + PENDING_TTL_SECS,
        },
        MAX_PENDING,
        |p| p.expires_at,
    );
    if !stored {
        return fail("temporarily_unavailable", "too many pending requests");
    }
    let mut res = login_form(&request_id, client.client_id, scope, "");
    let cookie = format!(
        "{BINDING_COOKIE}={browser_binding}; HttpOnly; SameSite=Strict; Path=/authorize; Max-Age={PENDING_TTL_SECS}"
    );
    res.headers_mut().insert(header::SET_COOKIE, HeaderValue::from_str(&cookie).expect("Base64url と固定の文字だけ"));
    res
}

#[derive(Deserialize)]
pub struct LoginForm {
    request_id: String,
    username: String,
    password: String,
}

pub async fn submit_login(
    State(state): State<Shared>,
    headers: HeaderMap,
    Form(form): Form<LoginForm>,
) -> Response {
    let Some(req) = state.pending.lock().unwrap().remove(&form.request_id) else {
        return error_page("認可リクエストが見つかりません");
    };
    if req.expires_at < now() {
        return error_page("認可リクエストの期限が切れました");
    }
    let bound = cookie_value(&headers, BINDING_COOKIE)
        .is_some_and(|v| constant_time_eq(v.as_bytes(), req.browser_binding.as_bytes()));
    if !bound {
        println!("[mini-op] POST /authorize -> 400 (request_id が別のブラウザに発行されている)");
        return error_page("このブラウザで開始した認可リクエストではありません");
    }
    let user = state
        .users
        .iter()
        .find(|u| u.username == form.username && u.password == form.password);
    let Some(user) = user else {
        let (client_id, scope) = (req.client_id.clone(), req.scope.clone());
        if !insert_bounded(&state.pending, form.request_id.clone(), req, MAX_PENDING, |p| p.expires_at) {
            return error_page("認可リクエストを保存できません");
        }
        return login_form(&form.request_id, &client_id, &scope, "ユーザー名かパスワードが違います");
    };

    // 3. 認可コードを、クライアント・redirect_uri・PKCE・nonce に束縛して保存する
    let code = random_token(&state.rng);
    let auth_time = now();
    let stored = insert_bounded(
        &state.codes,
        code.clone(),
        CodeGrant {
            client_id: req.client_id,
            redirect_uri: req.redirect_uri.clone(),
            code_challenge: req.code_challenge,
            nonce: req.nonce,
            scope: req.scope,
            sub: user.sub.to_string(),
            auth_time,
            expires_at: auth_time + CODE_TTL_SECS,
        },
        MAX_CODES,
        |g| g.expires_at,
    );
    if !stored {
        return error_page("認可コードを発行できません。時間をおいてやり直してください");
    }
    println!("[mini-op] 認可コードを発行 sub={} code={}...", user.sub, &code[..8]);
    let mut url = Url::parse(&req.redirect_uri).expect("登録済みの redirect_uri は URL として正しい");
    url.query_pairs_mut().append_pair("code", &code);
    if !req.state.is_empty() {
        url.query_pairs_mut().append_pair("state", &req.state);
    }
    url.query_pairs_mut().append_pair("iss", ISSUER);
    Redirect::to(url.as_str()).into_response()
}
