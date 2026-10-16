use std::collections::HashMap;

use axum::extract::{Form, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::Json;
use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use percent_encoding::percent_decode_str;
use serde_json::json;
use sha2::{Digest, Sha256};

use crate::{
    Client, ISSUER, RESOURCE_ID, Shared, TOKEN_TTL_SECS, constant_time_eq, find_client, jwt, now,
    random_token,
};

fn token_error(status: StatusCode, error: &str, description: &str) -> Response {
    let mut res = (
        status,
        [(header::CACHE_CONTROL, "no-store")],
        Json(json!({ "error": error, "error_description": description })),
    )
        .into_response();
    if status == StatusCode::UNAUTHORIZED {
        res.headers_mut().insert(
            header::WWW_AUTHENTICATE,
            "Basic realm=\"mini-op\"".parse().expect("固定値"),
        );
    }
    res
}

fn form_decode(raw: &str) -> Option<String> {
    // 1つの値として復号する。& や = を区切りとして扱うと、その後ろの文字が失われる
    let plus_as_space = raw.replace('+', " ");
    percent_decode_str(&plus_as_space).decode_utf8().ok().map(|s| s.into_owned())
}

fn authenticate_client<'a>(state: &'a Shared, headers: &HeaderMap) -> Option<&'a Client> {
    let value = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    let encoded = value.strip_prefix("Basic ")?;
    let decoded = String::from_utf8(STANDARD.decode(encoded).ok()?).ok()?;
    let (raw_id, raw_secret) = decoded.split_once(':')?;
    // RFC 6749 2.3.1: Base64 の前に form-urlencode されているので戻す
    let (client_id, secret) = (form_decode(raw_id)?, form_decode(raw_secret)?);
    let client = find_client(state, &client_id)?;
    constant_time_eq(client.client_secret.as_bytes(), secret.as_bytes()).then_some(client)
}

fn pkce_s256(code_verifier: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(code_verifier.as_bytes()))
}

fn valid_verifier_syntax(v: &str) -> bool {
    (43..=128).contains(&v.len())
        && v.bytes().all(|b| b.is_ascii_alphanumeric() || b"-._~".contains(&b))
}

pub async fn token(
    State(state): State<Shared>,
    headers: HeaderMap,
    Form(pairs): Form<Vec<(String, String)>>,
) -> Response {
    let mut params = HashMap::new();
    for (k, v) in pairs {
        if params.insert(k, v).is_some() {
            return token_error(StatusCode::BAD_REQUEST, "invalid_request", "duplicate parameter");
        }
    }
    let get = |k: &str| params.get(k).map(String::as_str).unwrap_or("");

    // 1. クライアント認証(client_secret_basic)
    let Some(client) = authenticate_client(&state, &headers) else {
        println!("[mini-op] POST /token -> 401 invalid_client");
        return token_error(StatusCode::UNAUTHORIZED, "invalid_client", "client authentication failed");
    };
    if get("grant_type") != "authorization_code" {
        return token_error(StatusCode::BAD_REQUEST, "unsupported_grant_type", "authorization_code only");
    }

    // 2. 認可コードを取り出して即座に消す(2回目以降は見つからない)
    let code = get("code");
    let Some(grant) = state.codes.lock().unwrap().remove(code) else {
        println!("[mini-op] POST /token client_id={} -> 400 invalid_grant (unknown or used code)", client.client_id);
        return token_error(StatusCode::BAD_REQUEST, "invalid_grant", "unknown or already used code");
    };

    // 3. コードに束縛した値と照合する
    if now() >= grant.expires_at {
        return token_error(StatusCode::BAD_REQUEST, "invalid_grant", "code expired");
    }
    if grant.client_id != client.client_id {
        return token_error(StatusCode::BAD_REQUEST, "invalid_grant", "code was issued to another client");
    }
    if grant.redirect_uri != get("redirect_uri") {
        return token_error(StatusCode::BAD_REQUEST, "invalid_grant", "redirect_uri mismatch");
    }
    let verifier = get("code_verifier");
    if !valid_verifier_syntax(verifier) {
        return token_error(StatusCode::BAD_REQUEST, "invalid_request", "code_verifier is missing or malformed");
    }
    if !constant_time_eq(pkce_s256(verifier).as_bytes(), grant.code_challenge.as_bytes()) {
        println!("[mini-op] POST /token client_id={} -> 400 invalid_grant (PKCE)", client.client_id);
        return token_error(StatusCode::BAD_REQUEST, "invalid_grant", "PKCE verification failed");
    }

    // 4. アクセストークン(RFC 9068)と IDトークンを発行する
    let iat = now();
    let exp = iat + TOKEN_TTL_SECS;
    let access_claims = json!({
        "iss": ISSUER, "sub": grant.sub, "aud": RESOURCE_ID, "client_id": client.client_id,
        "scope": grant.scope, "iat": iat, "exp": exp, "jti": random_token(&state.rng),
    });
    let Ok(access_token) = jwt::sign(&state.signer, "at+jwt", &access_claims) else {
        return token_error(StatusCode::INTERNAL_SERVER_ERROR, "server_error", "signing failed");
    };
    let id_claims = json!({
        "iss": ISSUER, "sub": grant.sub, "aud": client.client_id, "iat": iat, "exp": exp,
        "auth_time": grant.auth_time, "nonce": grant.nonce,
        "at_hash": jwt::at_hash(&access_token),
    });
    let Ok(id_token) = jwt::sign(&state.signer, "JWT", &id_claims) else {
        return token_error(StatusCode::INTERNAL_SERVER_ERROR, "server_error", "signing failed");
    };
    println!("[mini-op] POST /token client_id={} sub={} -> 200", client.client_id, grant.sub);
    (
        [(header::CACHE_CONTROL, "no-store"), (header::PRAGMA, "no-cache")],
        Json(json!({
            "access_token": access_token,
            "token_type": "Bearer",
            "expires_in": TOKEN_TTL_SECS,
            "scope": grant.scope,
            "id_token": id_token,
        })),
    )
        .into_response()
}
