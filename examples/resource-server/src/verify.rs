use std::time::{SystemTime, UNIX_EPOCH};

use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ring::signature::{ECDSA_P256_SHA256_FIXED, UnparsedPublicKey};
use serde::Deserialize;
use serde_json::Value;

use crate::{ISSUER, REQUIRED_SCOPE, RESOURCE_ID, Shared};

const LEEWAY_SECS: u64 = 30;

#[derive(Debug, thiserror::Error)]
pub enum AuthError {
    #[error("no access token")]
    Missing,
    #[error("{0}")]
    InvalidToken(&'static str),
    #[error("insufficient scope")]
    InsufficientScope,
}

impl IntoResponse for AuthError {
    fn into_response(self) -> Response {
        let (status, challenge) = match &self {
            AuthError::Missing => (StatusCode::UNAUTHORIZED, r#"Bearer realm="resource-server""#.to_string()),
            AuthError::InvalidToken(desc) => (
                StatusCode::UNAUTHORIZED,
                format!(r#"Bearer realm="resource-server", error="invalid_token", error_description="{desc}""#),
            ),
            AuthError::InsufficientScope => (
                StatusCode::FORBIDDEN,
                format!(r#"Bearer realm="resource-server", error="insufficient_scope", scope="{REQUIRED_SCOPE}""#),
            ),
        };
        println!("[resource-server] {status} {self}");
        let mut res = status.into_response();
        if let Ok(v) = HeaderValue::from_str(&challenge) {
            res.headers_mut().insert(header::WWW_AUTHENTICATE, v);
        }
        res
    }
}

#[derive(Deserialize)]
struct Header {
    alg: String,
    typ: Option<String>,
    kid: Option<String>,
    crit: Option<Value>,
}

#[derive(Deserialize)]
pub struct Claims {
    iss: String,
    aud: Value,
    exp: u64,
    iat: u64,
    nbf: Option<u64>,
    jti: String,
    pub sub: String,
    pub client_id: String,
    #[serde(default)]
    pub scope: String,
}

fn decode_json<T: for<'de> Deserialize<'de>>(part: &str) -> Result<T, AuthError> {
    let bytes = URL_SAFE_NO_PAD.decode(part).map_err(|_| AuthError::InvalidToken("bad base64url"))?;
    serde_json::from_slice(&bytes).map_err(|_| AuthError::InvalidToken("bad json"))
}

fn audience_contains(aud: &Value, me: &str) -> bool {
    match aud {
        Value::String(s) => s == me,
        Value::Array(items) => items.iter().any(|v| v == me),
        _ => false,
    }
}

pub async fn authorize(state: &Shared, headers: &HeaderMap) -> Result<Claims, AuthError> {
    let token = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .ok_or(AuthError::Missing)?;
    let parts: Vec<&str> = token.split('.').collect();
    let [h, p, s] = parts[..] else {
        return Err(AuthError::InvalidToken("not a JWS compact serialization"));
    };

    // 1. ヘッダ: alg は ES256 に固定し、typ で JWT アクセストークンだけを受け入れる
    let header: Header = decode_json(h)?;
    if header.alg != "ES256" {
        return Err(AuthError::InvalidToken("unexpected alg"));
    }
    let typ = header.typ.unwrap_or_default().to_ascii_lowercase();
    if typ != "at+jwt" && typ != "application/at+jwt" {
        return Err(AuthError::InvalidToken("typ must be at+jwt"));
    }
    // RFC 7515 4.1.11: crit に挙げられた拡張を理解できなければ無効。対応している拡張はない
    if header.crit.is_some() {
        return Err(AuthError::InvalidToken("unsupported crit"));
    }

    // 2. 署名: kid で鍵を選び、未知なら JWKS を取り直す
    let kid = header.kid.ok_or(AuthError::InvalidToken("kid is required"))?;
    let key = state
        .jwks
        .key_for(&state.http, &kid)
        .await
        .ok_or(AuthError::InvalidToken("unknown kid"))?;
    let sig = URL_SAFE_NO_PAD.decode(s).map_err(|_| AuthError::InvalidToken("bad signature encoding"))?;
    UnparsedPublicKey::new(&ECDSA_P256_SHA256_FIXED, &key)
        .verify(format!("{h}.{p}").as_bytes(), &sig)
        .map_err(|_| AuthError::InvalidToken("signature verification failed"))?;

    // 3. クレーム: 署名検証の後で初めてペイロードを読む。RFC 9068 2.2 の必須クレームが欠けていれば解析で失敗する
    let claims: Claims =
        decode_json(p).map_err(|_| AuthError::InvalidToken("missing or malformed claims"))?;
    if claims.iss != ISSUER {
        return Err(AuthError::InvalidToken("unexpected iss"));
    }
    if !audience_contains(&claims.aud, RESOURCE_ID) {
        return Err(AuthError::InvalidToken("aud does not contain this resource server"));
    }
    let now = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(u64::MAX);
    if claims.exp.saturating_add(LEEWAY_SECS) <= now {
        return Err(AuthError::InvalidToken("token expired"));
    }
    let latest_accepted = now.saturating_add(LEEWAY_SECS);
    if claims.nbf.is_some_and(|nbf| nbf > latest_accepted) {
        return Err(AuthError::InvalidToken("token not yet valid"));
    }
    if claims.iat > latest_accepted {
        return Err(AuthError::InvalidToken("iat is in the future"));
    }
    if claims.jti.is_empty() {
        return Err(AuthError::InvalidToken("jti is empty"));
    }

    // 4. スコープ: 有効なトークンでも権限が足りなければ 403
    if !claims.scope.split(' ').any(|sc| sc == REQUIRED_SCOPE) {
        return Err(AuthError::InsufficientScope);
    }
    Ok(claims)
}
