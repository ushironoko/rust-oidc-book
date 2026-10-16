mod authorize;
mod jwt;
mod token;
mod userinfo;

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use axum::extract::State;
use axum::routing::get;
use axum::{Json, Router};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ring::rand::{SecureRandom, SystemRandom};
use serde_json::{Value, json};

pub const ISSUER: &str = "http://127.0.0.1:9000";
pub const RESOURCE_ID: &str = "http://127.0.0.1:4000";
pub const CODE_TTL_SECS: u64 = 60;
pub const TOKEN_TTL_SECS: u64 = 300;
pub const MAX_PENDING: usize = 1000;
pub const MAX_CODES: usize = 1000;

pub struct Client {
    pub client_id: &'static str,
    pub client_secret: &'static str,
    pub redirect_uris: &'static [&'static str],
}

pub struct User {
    pub username: &'static str,
    pub password: &'static str,
    pub sub: &'static str,
    pub name: &'static str,
    pub email: &'static str,
}

pub struct PendingRequest {
    pub client_id: String,
    pub redirect_uri: String,
    pub scope: String,
    pub state: String,
    pub nonce: String,
    pub code_challenge: String,
    pub browser_binding: String,
    pub expires_at: u64,
}

pub struct CodeGrant {
    pub client_id: String,
    pub redirect_uri: String,
    pub code_challenge: String,
    pub nonce: String,
    pub scope: String,
    pub sub: String,
    pub auth_time: u64,
    pub expires_at: u64,
}

pub struct AppState {
    pub signer: jwt::Signer,
    pub rng: SystemRandom,
    pub clients: Vec<Client>,
    pub users: Vec<User>,
    pub pending: Mutex<HashMap<String, PendingRequest>>,
    pub codes: Mutex<HashMap<String, CodeGrant>>,
}

pub type Shared = Arc<AppState>;

pub fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

pub fn random_token(rng: &SystemRandom) -> String {
    let mut buf = [0u8; 32];
    rng.fill(&mut buf).expect("OS の乱数生成器が使えない");
    URL_SAFE_NO_PAD.encode(buf)
}

pub fn find_client<'a>(state: &'a AppState, client_id: &str) -> Option<&'a Client> {
    state.clients.iter().find(|c| c.client_id == client_id)
}

pub fn insert_bounded<V>(
    store: &Mutex<HashMap<String, V>>,
    key: String,
    value: V,
    limit: usize,
    expires_at: fn(&V) -> u64,
) -> bool {
    let mut map = store.lock().unwrap();
    let t = now();
    map.retain(|_, v| expires_at(v) > t);
    if map.len() >= limit {
        return false;
    }
    map.insert(key, value);
    true
}

pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

async fn discovery() -> Json<Value> {
    Json(json!({
        "issuer": ISSUER,
        "authorization_endpoint": format!("{ISSUER}/authorize"),
        "token_endpoint": format!("{ISSUER}/token"),
        "userinfo_endpoint": format!("{ISSUER}/userinfo"),
        "jwks_uri": format!("{ISSUER}/jwks"),
        "scopes_supported": ["openid", "profile", "email", "api.read"],
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["ES256"],
        "token_endpoint_auth_methods_supported": ["client_secret_basic"],
        "code_challenge_methods_supported": ["S256"],
        "authorization_response_iss_parameter_supported": true,
        "request_parameter_supported": false,
        "request_uri_parameter_supported": false,
        "claims_supported": ["sub", "iss", "aud", "exp", "iat", "auth_time", "nonce",
                             "at_hash", "name", "email", "email_verified"]
    }))
}

async fn jwks(State(state): State<Shared>) -> Json<Value> {
    Json(json!({ "keys": [jwt::public_jwk(&state.signer)] }))
}

fn demo_state() -> anyhow::Result<AppState> {
    let rng = SystemRandom::new();
    Ok(AppState {
        signer: jwt::generate_signer(&rng)?,
        rng,
        clients: vec![Client {
            client_id: "demo-rp",
            client_secret: "demo-rp-secret-not-for-production",
            redirect_uris: &["http://127.0.0.1:3000/callback"],
        }],
        users: vec![User {
            username: "demo",
            password: "demo-password",
            sub: "user-0001",
            name: "Demo User",
            email: "demo@example.com",
        }],
        pending: Mutex::new(HashMap::new()),
        codes: Mutex::new(HashMap::new()),
    })
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let state: Shared = Arc::new(demo_state()?);
    println!("[mini-op] 署名鍵 kid={}", state.signer.kid);
    let app = Router::new()
        .route("/.well-known/openid-configuration", get(discovery))
        .route("/jwks", get(jwks))
        .route("/authorize", get(authorize::show_login).post(authorize::submit_login))
        .route("/token", axum::routing::post(token::token))
        .route("/userinfo", get(userinfo::userinfo).post(userinfo::userinfo))
        .with_state(state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:9000").await?;
    println!("[mini-op] listening on {ISSUER}");
    axum::serve(listener, app).await?;
    Ok(())
}
