use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ring::rand::SystemRandom;
use ring::signature::{
    ECDSA_P256_SHA256_FIXED, ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, KeyPair,
    UnparsedPublicKey,
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

pub struct Signer {
    pub key: EcdsaKeyPair,
    pub kid: String,
    rng: SystemRandom,
}

fn coordinates(key: &EcdsaKeyPair) -> (String, String) {
    // 公開鍵は 0x04 || x(32バイト) || y(32バイト) の非圧縮形式
    let point = key.public_key().as_ref();
    (
        URL_SAFE_NO_PAD.encode(&point[1..33]),
        URL_SAFE_NO_PAD.encode(&point[33..65]),
    )
}

fn thumbprint(x: &str, y: &str) -> String {
    // RFC 7638: 必須メンバーだけを辞書順に並べた JSON の SHA-256
    let canonical = format!(r#"{{"crv":"P-256","kty":"EC","x":"{x}","y":"{y}"}}"#);
    URL_SAFE_NO_PAD.encode(Sha256::digest(canonical.as_bytes()))
}

pub fn generate_signer(rng: &SystemRandom) -> anyhow::Result<Signer> {
    let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, rng)
        .map_err(|_| anyhow::anyhow!("鍵ペアを生成できない"))?;
    let key = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8.as_ref(), rng)
        .map_err(|_| anyhow::anyhow!("PKCS#8 を読めない"))?;
    let (x, y) = coordinates(&key);
    let kid = thumbprint(&x, &y);
    Ok(Signer { key, kid, rng: rng.clone() })
}

pub fn public_jwk(signer: &Signer) -> Value {
    let (x, y) = coordinates(&signer.key);
    json!({
        "kty": "EC", "crv": "P-256", "x": x, "y": y,
        "kid": signer.kid, "use": "sig", "alg": "ES256"
    })
}

pub fn sign(signer: &Signer, typ: &str, claims: &Value) -> anyhow::Result<String> {
    let header = json!({ "alg": "ES256", "typ": typ, "kid": signer.kid });
    let signing_input = format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header)?),
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(claims)?)
    );
    let sig = signer
        .key
        .sign(&signer.rng, signing_input.as_bytes())
        .map_err(|_| anyhow::anyhow!("署名に失敗"))?;
    Ok(format!("{signing_input}.{}", URL_SAFE_NO_PAD.encode(sig.as_ref())))
}

pub fn at_hash(access_token: &str) -> String {
    // ES256 は SHA-256 なので、ダイジェストの左半分(16バイト)を使う
    let digest = Sha256::digest(access_token.as_bytes());
    URL_SAFE_NO_PAD.encode(&digest[..16])
}

pub fn verify_own(signer: &Signer, token: &str, expected_typ: &str) -> Option<Value> {
    let mut parts = token.split('.');
    let (h, p, s) = (parts.next()?, parts.next()?, parts.next()?);
    if parts.next().is_some() {
        return None;
    }
    let header: Value = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(h).ok()?).ok()?;
    if header["alg"] != "ES256" || header["typ"] != expected_typ || header["kid"] != signer.kid.as_str() {
        return None;
    }
    let public = UnparsedPublicKey::new(&ECDSA_P256_SHA256_FIXED, signer.key.public_key().as_ref());
    let sig = URL_SAFE_NO_PAD.decode(s).ok()?;
    public.verify(format!("{h}.{p}").as_bytes(), &sig).ok()?;
    serde_json::from_slice(&URL_SAFE_NO_PAD.decode(p).ok()?).ok()
}
