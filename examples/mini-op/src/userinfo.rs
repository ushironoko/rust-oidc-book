use axum::Json;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use serde_json::{Map, Value, json};

use crate::{ISSUER, Shared, jwt, now};

fn invalid_token() -> Response {
    (
        StatusCode::UNAUTHORIZED,
        [(header::WWW_AUTHENTICATE, "Bearer error=\"invalid_token\"")],
    )
        .into_response()
}

pub async fn userinfo(State(state): State<Shared>, headers: HeaderMap) -> Response {
    let token = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "));
    let Some(claims) = token.and_then(|t| jwt::verify_own(&state.signer, t, "at+jwt")) else {
        return invalid_token();
    };
    let exp = claims["exp"].as_u64().unwrap_or(0);
    let scopes: Vec<&str> = claims["scope"].as_str().unwrap_or("").split(' ').collect();
    if claims["iss"] != ISSUER || exp < now() || !scopes.contains(&"openid") {
        return invalid_token();
    }
    let sub = claims["sub"].as_str().unwrap_or("");
    let Some(user) = state.users.iter().find(|u| u.sub == sub) else {
        return invalid_token();
    };
    let mut body = Map::new();
    body.insert("sub".into(), json!(user.sub));
    if scopes.contains(&"profile") {
        body.insert("name".into(), json!(user.name));
    }
    if scopes.contains(&"email") {
        body.insert("email".into(), json!(user.email));
        body.insert("email_verified".into(), json!(true));
    }
    ([(header::CACHE_CONTROL, "no-store")], Json(Value::Object(body))).into_response()
}
