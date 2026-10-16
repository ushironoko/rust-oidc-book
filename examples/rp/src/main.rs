mod error;
mod handlers;

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::Router;
use axum::routing::get;
use openidconnect::core::{CoreClient, CoreProviderMetadata};
use openidconnect::{
    ClientId, ClientSecret, EndpointMaybeSet, EndpointNotSet, EndpointSet, IssuerUrl, RedirectUrl,
};
use tower_sessions::cookie::SameSite;
use tower_sessions::cookie::time::Duration as CookieDuration;
use tower_sessions::{Expiry, MemoryStore, SessionManagerLayer};

pub const ISSUER: &str = "http://127.0.0.1:9000";
pub const CLIENT_ID: &str = "demo-rp";
pub const CLIENT_SECRET: &str = "demo-rp-secret-not-for-production";
pub const REDIRECT_URI: &str = "http://127.0.0.1:3000/callback";
pub const API_URL: &str = "http://127.0.0.1:4000/api/me";

// 型引数は順に 認可/デバイス認可/イントロスペクション/失効/トークン/UserInfo の各エンドポイントの設定状態
pub type OidcClient = CoreClient<
    EndpointSet,
    EndpointNotSet,
    EndpointNotSet,
    EndpointNotSet,
    EndpointMaybeSet,
    EndpointMaybeSet,
>;

pub struct AppState {
    pub oidc: OidcClient,
    pub http: reqwest::Client,
    pub pending: Mutex<HashMap<String, handlers::PendingLogin>>,
}

pub type Shared = Arc<AppState>;

async fn discover(http: &reqwest::Client) -> anyhow::Result<CoreProviderMetadata> {
    let issuer = IssuerUrl::new(ISSUER.to_string())?;
    let mut last_err = None;
    for _ in 0..20 {
        match CoreProviderMetadata::discover_async(issuer.clone(), http).await {
            Ok(meta) => return Ok(meta),
            Err(e) => last_err = Some(e),
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    Err(anyhow::anyhow!("discovery failed: {:?}", last_err))
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // リダイレクトを追跡すると SSRF の経路になるため、OP との通信では追跡しない
    let http = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(5))
        .build()?;
    let metadata = discover(&http).await?;
    let oidc = CoreClient::from_provider_metadata(
        metadata,
        ClientId::new(CLIENT_ID.to_string()),
        Some(ClientSecret::new(CLIENT_SECRET.to_string())),
    )
    .set_redirect_uri(RedirectUrl::new(REDIRECT_URI.to_string())?);
    let state: Shared = Arc::new(AppState { oidc, http, pending: Mutex::new(HashMap::new()) });

    let sessions = SessionManagerLayer::new(MemoryStore::default())
        .with_name("rp_session")
        .with_http_only(true)
        .with_same_site(SameSite::Lax)
        .with_secure(false)
        .with_expiry(Expiry::OnInactivity(CookieDuration::minutes(30)));

    let app = Router::new()
        .route("/", get(handlers::index))
        .route("/login", get(handlers::login))
        .route("/callback", get(handlers::callback))
        .route("/api-call", get(handlers::api_call))
        .route("/logout", get(handlers::logout))
        .layer(sessions)
        .with_state(state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:3000").await?;
    println!("[rp] listening on http://127.0.0.1:3000");
    axum::serve(listener, app).await?;
    Ok(())
}
