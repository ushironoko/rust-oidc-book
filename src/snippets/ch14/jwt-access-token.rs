use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ring::rand::SystemRandom;
use ring::signature::{
    ECDSA_P256_SHA256_FIXED, ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, KeyPair,
    UnparsedPublicKey,
};
use serde_json::{Value, json};
use std::collections::HashMap;

const ISSUER: &str = "https://as.example.com";
const RS_ID: &str = "https://api.example.com/orders";
// 実験を再現可能にするための固定の現在時刻
const NOW: i64 = 1_760_000_000;
const LEEWAY: i64 = 60;

fn b64(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

fn sign(key: &EcdsaKeyPair, header: &Value, claims: &Value) -> String {
    let input = format!("{}.{}", b64(header.to_string().as_bytes()), b64(claims.to_string().as_bytes()));
    let sig = key.sign(&SystemRandom::new(), input.as_bytes()).unwrap();
    format!("{input}.{}", b64(sig.as_ref()))
}

// 検査の失敗。HTTP の応答に対応づける
enum Reject {
    InvalidToken(String),
    InsufficientScope(String),
}

fn decode_json(part: &str) -> Result<Value, Reject> {
    let bytes = URL_SAFE_NO_PAD
        .decode(part)
        .map_err(|_| Reject::InvalidToken("Base64url として不正".into()))?;
    serde_json::from_slice(&bytes).map_err(|_| Reject::InvalidToken("JSON として不正".into()))
}

// RFC 9068 4節の検証。jwks は kid から公開鍵への対応
fn validate(token: &str, jwks: &HashMap<String, Vec<u8>>, required_scope: &str) -> Result<Value, Reject> {
    let bad = |m: &str| Reject::InvalidToken(m.to_string());
    let parts: Vec<&str> = token.split('.').collect();
    let [h, p, s] = parts[..] else {
        return Err(bad("JWS コンパクト形式ではない"));
    };
    let header = decode_json(h)?;
    let typ = header["typ"].as_str().unwrap_or("");
    if typ != "at+jwt" && typ != "application/at+jwt" {
        return Err(bad(&format!("typ が at+jwt ではない ({typ:?})")));
    }
    if header["alg"] != "ES256" {
        return Err(bad(&format!("許可していない alg ({})", header["alg"])));
    }
    let kid = header["kid"].as_str().unwrap_or("");
    let key = jwks.get(kid).ok_or_else(|| bad(&format!("未知の kid ({kid})")))?;
    let sig = URL_SAFE_NO_PAD.decode(s).map_err(|_| bad("署名が Base64url ではない"))?;
    UnparsedPublicKey::new(&ECDSA_P256_SHA256_FIXED, key)
        .verify(format!("{h}.{p}").as_bytes(), &sig)
        .map_err(|_| bad("署名検証に失敗"))?;
    // 署名を確かめた後でのみペイロードを読む
    let c = decode_json(p)?;
    if c["iss"] != ISSUER {
        return Err(bad("iss が一致しない"));
    }
    let aud_ok = match &c["aud"] {
        Value::String(a) => a == RS_ID,
        Value::Array(v) => v.iter().any(|a| a == RS_ID),
        _ => false,
    };
    if !aud_ok {
        return Err(bad(&format!("aud にこのリソースサーバが含まれない ({})", c["aud"])));
    }
    let exp = c["exp"].as_i64().ok_or_else(|| bad("exp がない"))?;
    if NOW >= exp + LEEWAY {
        return Err(bad("有効期限切れ"));
    }
    let scopes = c["scope"].as_str().unwrap_or("");
    if !scopes.split(' ').any(|x| x == required_scope) {
        return Err(Reject::InsufficientScope(required_scope.to_string()));
    }
    Ok(c)
}

fn respond(label: &str, token: &str, jwks: &HashMap<String, Vec<u8>>, scope: &str) {
    println!("{label}");
    match validate(token, jwks, scope) {
        Ok(c) => println!("  HTTP/1.1 200 OK (sub={}, client_id={})", c["sub"], c["client_id"]),
        Err(Reject::InvalidToken(why)) => {
            println!("  HTTP/1.1 401 Unauthorized");
            println!("  WWW-Authenticate: Bearer error=\"invalid_token\"");
            println!("  (ログにだけ残す理由: {why})");
        }
        Err(Reject::InsufficientScope(s)) => {
            println!("  HTTP/1.1 403 Forbidden");
            println!("  WWW-Authenticate: Bearer error=\"insufficient_scope\", scope=\"{s}\"");
        }
    }
}

fn main() {
    let rng = SystemRandom::new();
    let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng).unwrap();
    let as_key = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8.as_ref(), &rng).unwrap();
    // リソースサーバが jwks_uri から取得してキャッシュした鍵
    let jwks = HashMap::from([("as-key-1".to_string(), as_key.public_key().as_ref().to_vec())]);

    let at_header = json!({"typ": "at+jwt", "alg": "ES256", "kid": "as-key-1"});
    let at_claims = |aud: &str, exp: i64| {
        json!({
            "iss": ISSUER, "sub": "user-5821", "aud": aud, "client_id": "s6BhdRkqt3",
            "iat": NOW - 10, "exp": exp, "jti": "at-0001", "scope": "orders:read"
        })
    };

    let good = sign(&as_key, &at_header, &at_claims(RS_ID, NOW + 300));
    println!("JWT アクセストークンのペイロード:");
    println!("  {}\n", String::from_utf8(URL_SAFE_NO_PAD.decode(good.split('.').nth(1).unwrap()).unwrap()).unwrap());

    respond("[1] 正しいトークンで GET /orders", &good, &jwks, "orders:read");
    respond("[2] 同じトークンで POST /orders", &good, &jwks, "orders:write");

    let id_token = sign(
        &as_key,
        &json!({"typ": "JWT", "alg": "ES256", "kid": "as-key-1"}),
        &json!({"iss": ISSUER, "sub": "user-5821", "aud": "s6BhdRkqt3", "iat": NOW - 10, "exp": NOW + 300, "nonce": "n-0S6"}),
    );
    respond("[3] ID トークンを送る", &id_token, &jwks, "orders:read");

    let other = sign(&as_key, &at_header, &at_claims("https://api.example.com/payments", NOW + 300));
    respond("[4] 別のリソースサーバ宛てのトークン", &other, &jwks, "orders:read");

    let expired = sign(&as_key, &at_header, &at_claims(RS_ID, NOW - 600));
    respond("[5] 期限切れのトークン", &expired, &jwks, "orders:read");

    let none_header = b64(json!({"typ": "at+jwt", "alg": "none"}).to_string().as_bytes());
    let none_payload = b64(at_claims(RS_ID, NOW + 300).to_string().as_bytes());
    respond("[6] alg=none で署名なし", &format!("{none_header}.{none_payload}."), &jwks, "orders:read");

    let rotated = sign(&as_key, &json!({"typ": "at+jwt", "alg": "ES256", "kid": "as-key-2"}), &at_claims(RS_ID, NOW + 300));
    respond("[7] キャッシュにない kid", &rotated, &jwks, "orders:read");
}
