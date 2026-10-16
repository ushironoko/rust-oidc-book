mod jwks;
mod verify;

use std::sync::Arc;
use std::time::Duration;

use axum::Json;
use axum::Router;
use axum::extract::State;
use axum::http::HeaderMap;
use axum::routing::get;
use serde_json::{Value, json};

pub const ISSUER: &str = "http://127.0.0.1:9000";
pub const RESOURCE_ID: &str = "http://127.0.0.1:4000";
pub const REQUIRED_SCOPE: &str = "api.read";

pub struct AppState {
    pub http: reqwest::Client,
    pub jwks: jwks::JwksCache,
}

pub type Shared = Arc<AppState>;

async fn me(State(state): State<Shared>, headers: HeaderMap) -> Result<Json<Value>, verify::AuthError> {
    let claims = verify::authorize(&state, &headers).await?;
    Ok(Json(json!({
        "message": "保護されたリソースにアクセスしました",
        "sub": claims.sub,
        "client_id": claims.client_id,
        "scope": claims.scope,
    })))
}

async fn discover_with_retry(http: &reqwest::Client) -> anyhow::Result<String> {
    let mut last_err = None;
    for _ in 0..20 {
        match jwks::discover_jwks_uri(http, ISSUER).await {
            Ok(uri) => return Ok(uri),
            Err(e) => last_err = Some(e),
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    Err(last_err.unwrap_or_else(|| anyhow::anyhow!("discovery failed")))
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let http = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(5))
        .build()?;
    let jwks_uri = discover_with_retry(&http).await?;
    println!("[resource-server] jwks_uri={jwks_uri}");
    let state: Shared = Arc::new(AppState { jwks: jwks::JwksCache::new(jwks_uri), http });
    let app = Router::new().route("/api/me", get(me)).with_state(state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:4000").await?;
    println!("[resource-server] listening on {RESOURCE_ID}");
    axum::serve(listener, app).await?;
    Ok(())
}
