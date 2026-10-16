use std::collections::HashMap;
use std::time::{Duration, Instant};

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::Deserialize;
use tokio::sync::{Mutex, RwLock};

const MIN_REFRESH_INTERVAL: Duration = Duration::from_secs(10);

#[derive(Deserialize)]
struct Metadata {
    issuer: String,
    jwks_uri: String,
}

#[derive(Deserialize)]
struct Jwk {
    kty: String,
    crv: Option<String>,
    x: Option<String>,
    y: Option<String>,
    kid: Option<String>,
    #[serde(rename = "use")]
    use_: Option<String>,
    alg: Option<String>,
}

#[derive(Deserialize)]
struct JwkSet {
    keys: Vec<Jwk>,
}

pub struct JwksCache {
    jwks_uri: String,
    keys: RwLock<HashMap<String, Vec<u8>>>,
    last_attempt: Mutex<Option<Instant>>,
}

pub async fn discover_jwks_uri(http: &reqwest::Client, issuer: &str) -> anyhow::Result<String> {
    let url = format!("{issuer}/.well-known/openid-configuration");
    let meta: Metadata = http.get(url).send().await?.error_for_status()?.json().await?;
    // OIDC Discovery 4.3: 取得した issuer は問い合わせに使った issuer と完全一致しなければならない
    anyhow::ensure!(meta.issuer == issuer, "issuer mismatch: {}", meta.issuer);
    Ok(meta.jwks_uri)
}

fn es256_public_key(jwk: &Jwk) -> Option<(String, Vec<u8>)> {
    let usable = jwk.kty == "EC"
        && jwk.crv.as_deref() == Some("P-256")
        && jwk.use_.as_deref().is_none_or(|u| u == "sig")
        && jwk.alg.as_deref().is_none_or(|a| a == "ES256");
    if !usable {
        return None;
    }
    let x = URL_SAFE_NO_PAD.decode(jwk.x.as_ref()?).ok()?;
    let y = URL_SAFE_NO_PAD.decode(jwk.y.as_ref()?).ok()?;
    if x.len() != 32 || y.len() != 32 {
        return None;
    }
    let point = [&[0x04u8][..], &x, &y].concat();
    Some((jwk.kid.clone()?, point))
}

impl JwksCache {
    pub fn new(jwks_uri: String) -> Self {
        Self { jwks_uri, keys: RwLock::new(HashMap::new()), last_attempt: Mutex::new(None) }
    }

    async fn refresh(&self, http: &reqwest::Client) -> anyhow::Result<()> {
        let mut last_attempt = self.last_attempt.lock().await;
        // 未知の kid を送りつけて JWKS を取得させ続ける攻撃を防ぐため、取得の試行の間隔に下限を置く
        if last_attempt.is_some_and(|t| t.elapsed() < MIN_REFRESH_INTERVAL) {
            return Ok(());
        }
        // 失敗した試行も間隔の計算に含めるため、通信の前に時刻を記録する
        *last_attempt = Some(Instant::now());
        let set: JwkSet = http.get(&self.jwks_uri).send().await?.error_for_status()?.json().await?;
        let fresh: HashMap<String, Vec<u8>> = set.keys.iter().filter_map(es256_public_key).collect();
        println!("[resource-server] JWKS を取得: kid={:?}", fresh.keys().collect::<Vec<_>>());
        *self.keys.write().await = fresh;
        Ok(())
    }

    pub async fn key_for(&self, http: &reqwest::Client, kid: &str) -> Option<Vec<u8>> {
        if let Some(key) = self.keys.read().await.get(kid) {
            return Some(key.clone());
        }
        self.refresh(http).await.ok()?;
        self.keys.read().await.get(kid).cloned()
    }
}
