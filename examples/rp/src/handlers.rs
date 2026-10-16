use std::time::{Duration, Instant};

use axum::extract::{Query, State};
use axum::response::{Html, IntoResponse, Redirect, Response};
use openidconnect::core::{CoreAuthenticationFlow, CoreUserInfoClaims};
use openidconnect::{
    AccessTokenHash, AuthorizationCode, CsrfToken, Nonce, OAuth2TokenResponse, PkceCodeChallenge,
    PkceCodeVerifier, RequestTokenError, Scope, TokenResponse, UserInfoError,
};
use serde::{Deserialize, Serialize};
use tower_sessions::Session;

use crate::error::{AppError, escape};
use crate::{API_URL, AppState, ISSUER, Shared};

const PENDING_KEY: &str = "pending_login";
const USER_KEY: &str = "user";
const PENDING_TTL: Duration = Duration::from_secs(600);
const MAX_PENDING: usize = 1000;

pub struct PendingLogin {
    nonce: String,
    pkce_verifier: String,
    created_at: Instant,
}

fn store_pending(app: &AppState, state: String, login: PendingLogin) -> bool {
    let mut pending = app.pending.lock().unwrap();
    pending.retain(|_, p| p.created_at.elapsed() < PENDING_TTL);
    if pending.len() >= MAX_PENDING {
        return false;
    }
    pending.insert(state, login);
    true
}

fn take_pending(app: &AppState, state: &str) -> Option<PendingLogin> {
    let login = app.pending.lock().unwrap().remove(state)?;
    (login.created_at.elapsed() < PENDING_TTL).then_some(login)
}

// 応答の本文はトークンを含みうるので、エラーの種類だけを文字列にする
fn describe_token_error<RE, T>(e: &RequestTokenError<RE, T>) -> String
where
    RE: std::error::Error + 'static,
    T: openidconnect::ErrorResponse + std::fmt::Display + 'static,
{
    match e {
        RequestTokenError::ServerResponse(r) => format!("OP のエラー応答 {r}"),
        RequestTokenError::Request(_) => "通信に失敗しました".to_string(),
        RequestTokenError::Parse(_, _) => "応答を解析できません".to_string(),
        RequestTokenError::Other(_) => "予期しない応答です".to_string(),
    }
}

fn describe_userinfo_error<RE: std::error::Error + 'static>(e: &UserInfoError<RE>) -> String {
    match e {
        UserInfoError::ClaimsVerification(v) => v.to_string(),
        UserInfoError::Request(_) => "通信に失敗しました".to_string(),
        UserInfoError::Response(status, _, _) => format!("予期しない応答です(status={status})"),
        UserInfoError::Parse(_) => "応答を解析できません".to_string(),
        _ => "予期しない応答です".to_string(),
    }
}

#[derive(Serialize, Deserialize)]
struct LoggedInUser {
    iss: String,
    sub: String,
    name: Option<String>,
    email: Option<String>,
    access_token: String,
}

pub async fn login(State(app): State<Shared>, session: Session) -> Result<Redirect, AppError> {
    let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();
    let (auth_url, csrf_state, nonce) = app
        .oidc
        .authorize_url(CoreAuthenticationFlow::AuthorizationCode, CsrfToken::new_random, Nonce::new_random)
        .add_scope(Scope::new("profile".to_string()))
        .add_scope(Scope::new("email".to_string()))
        .add_scope(Scope::new("api.read".to_string()))
        .set_pkce_challenge(pkce_challenge)
        .url();
    // nonce と code_verifier はサーバ側のストアに、state をキーにして保存する。セッションには state だけを置く
    let login = PendingLogin {
        nonce: nonce.secret().clone(),
        pkce_verifier: pkce_verifier.secret().clone(),
        created_at: Instant::now(),
    };
    if !store_pending(&app, csrf_state.secret().clone(), login) {
        return Err(AppError::TooManyPendingLogins);
    }
    session.insert(PENDING_KEY, csrf_state.secret()).await?;
    Ok(Redirect::to(auth_url.as_str()))
}

#[derive(Deserialize)]
pub struct CallbackParams {
    code: Option<String>,
    state: Option<String>,
    iss: Option<String>,
    error: Option<String>,
    error_description: Option<String>,
}

pub async fn callback(
    State(app): State<Shared>,
    session: Session,
    Query(params): Query<CallbackParams>,
) -> Result<Redirect, AppError> {
    // 1. このブラウザの state でストアから取り出す。取り出しと削除は Mutex の中の1つの操作
    let expected_state: String = session.remove(PENDING_KEY).await?.ok_or(AppError::NoPendingLogin)?;
    let pending = take_pending(&app, &expected_state).ok_or(AppError::NoPendingLogin)?;
    if params.state.as_deref() != Some(expected_state.as_str()) {
        return Err(AppError::StateMismatch);
    }
    if params.iss.as_deref().is_some_and(|iss| iss != ISSUER) {
        return Err(AppError::IssuerMismatch);
    }
    if let Some(error) = params.error {
        let description = params.error_description.unwrap_or_default();
        return Err(AppError::AuthorizationDenied(format!("{error} {description}")));
    }
    let code = params.code.ok_or(AppError::MissingCode)?;

    // 2. 認可コードをトークンに交換する(client_secret_basic + PKCE)
    let token_response = app
        .oidc
        .exchange_code(AuthorizationCode::new(code))
        .map_err(|e| AppError::TokenExchange(e.to_string()))?
        .set_pkce_verifier(PkceCodeVerifier::new(pending.pkce_verifier))
        .request_async(&app.http)
        .await
        .map_err(|e| AppError::TokenExchange(describe_token_error(&e)))?;

    // 3. IDトークンを検証する(署名、iss、aud、exp、nonce)
    let id_token = token_response
        .id_token()
        .ok_or_else(|| AppError::IdToken("id_token がありません".to_string()))?;
    let verifier = app.oidc.id_token_verifier();
    let nonce = Nonce::new(pending.nonce);
    let claims = id_token
        .claims(&verifier, &nonce)
        .map_err(|e| AppError::IdToken(e.to_string()))?;
    if let Some(expected) = claims.access_token_hash() {
        let alg = id_token.signing_alg().map_err(|e| AppError::IdToken(e.to_string()))?;
        let key = id_token.signing_key(&verifier).map_err(|e| AppError::IdToken(e.to_string()))?;
        let actual = AccessTokenHash::from_token(token_response.access_token(), alg, key)
            .map_err(|e| AppError::IdToken(e.to_string()))?;
        if actual != *expected {
            return Err(AppError::IdToken("at_hash が一致しません".to_string()));
        }
    }

    // 4. UserInfo を取得する。sub が IDトークンと一致しなければエラーになる
    let userinfo: CoreUserInfoClaims = app
        .oidc
        .user_info(token_response.access_token().clone(), Some(claims.subject().clone()))
        .map_err(|e| AppError::UserInfo(e.to_string()))?
        .request_async(&app.http)
        .await
        .map_err(|e| AppError::UserInfo(describe_userinfo_error(&e)))?;

    // 5. セッション ID を再発行してからログイン状態を保存する(セッション固定攻撃への対策)
    session.cycle_id().await?;
    session
        .insert(
            USER_KEY,
            LoggedInUser {
                iss: claims.issuer().to_string(),
                sub: claims.subject().to_string(),
                name: userinfo.name().and_then(|n| n.get(None)).map(|n| n.to_string()),
                email: userinfo.email().map(|e| e.to_string()),
                access_token: token_response.access_token().secret().clone(),
            },
        )
        .await?;
    println!("[rp] ログイン成功 iss={} sub={}", claims.issuer().as_str(), claims.subject().as_str());
    Ok(Redirect::to("/"))
}

pub async fn index(session: Session) -> Result<Html<String>, AppError> {
    let user: Option<LoggedInUser> = session.get(USER_KEY).await?;
    let body = match user {
        Some(u) => format!(
            "<p>ログイン中: iss={} sub={} name={} email={}</p>\
             <p><a href=\"/api-call\">API を呼ぶ</a> <a href=\"/logout\">ログアウト</a></p>",
            escape(&u.iss),
            escape(&u.sub),
            escape(&u.name.unwrap_or_default()),
            escape(&u.email.unwrap_or_default())
        ),
        None => "<p>未ログイン</p><p><a href=\"/login\">ログイン</a></p>".to_string(),
    };
    Ok(Html(format!("<!doctype html><meta charset=\"utf-8\"><h1>rp</h1>{body}")))
}

pub async fn api_call(State(app): State<Shared>, session: Session) -> Result<Response, AppError> {
    let user: LoggedInUser = session.get(USER_KEY).await?.ok_or(AppError::NotLoggedIn)?;
    let res = app.http.get(API_URL).bearer_auth(&user.access_token).send().await?;
    let status = res.status();
    let body = res.text().await?;
    Ok(Html(format!(
        "<!doctype html><meta charset=\"utf-8\"><h1>API の応答</h1><p>status={status}</p><pre>{}</pre>",
        escape(&body)
    ))
    .into_response())
}

pub async fn logout(session: Session) -> Result<Redirect, AppError> {
    session.flush().await?;
    Ok(Redirect::to("/"))
}
