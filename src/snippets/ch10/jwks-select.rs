use std::collections::HashMap;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use ring::rand::SystemRandom;
use ring::signature::{
    ECDSA_P256_SHA256_FIXED, ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, KeyPair,
    UnparsedPublicKey,
};
use serde_json::{Value, json};

const MIN_REFETCH_INTERVAL: u64 = 60;
const CACHE_MAX_AGE: u64 = 3600;

fn new_key(rng: &SystemRandom) -> EcdsaKeyPair {
    let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, rng).unwrap();
    EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8.as_ref(), rng).unwrap()
}

fn jwk(kid: &str, key: &EcdsaKeyPair) -> Value {
    let p = key.public_key().as_ref();
    json!({"kty": "EC", "crv": "P-256", "x": B64.encode(&p[1..33]), "y": B64.encode(&p[33..65]),
           "kid": kid, "use": "sig", "alg": "ES256"})
}

fn sign(rng: &SystemRandom, kid: &str, alg: &str, key: &EcdsaKeyPair) -> String {
    let header = B64.encode(json!({"alg": alg, "typ": "JWT", "kid": kid}).to_string());
    let payload = B64.encode(json!({"iss": "https://op.example.com", "sub": "user-0001"}).to_string());
    let input = format!("{header}.{payload}");
    let sig = key.sign(rng, input.as_bytes()).unwrap();
    format!("{input}.{}", B64.encode(sig.as_ref()))
}

// RP 側のキャッシュ: kid から公開鍵(非圧縮形式の点)を引く
struct Cache {
    keys: HashMap<String, Vec<u8>>,
    fetched_at: Option<u64>,
    fetch_count: u32,
}

// kid/kty/crv/use/alg がすべて条件を満たす鍵だけを使う
fn usable_es256_key(k: &Value) -> Option<(String, Vec<u8>)> {
    let ok = k["kty"] == "EC" && k["crv"] == "P-256"
        && (k["use"].is_null() || k["use"] == "sig")
        && (k["alg"].is_null() || k["alg"] == "ES256");
    if !ok {
        return None;
    }
    let x = B64.decode(k["x"].as_str()?).ok()?;
    let y = B64.decode(k["y"].as_str()?).ok()?;
    Some((k["kid"].as_str()?.to_string(), [&[4u8][..], &x, &y].concat()))
}

fn fetch(cache: &mut Cache, jwks: &Value, now: u64) {
    cache.keys = jwks["keys"].as_array().unwrap().iter().filter_map(usable_es256_key).collect();
    cache.fetched_at = Some(now);
    cache.fetch_count += 1;
    let mut kids: Vec<_> = cache.keys.keys().cloned().collect();
    kids.sort();
    println!("    (JWKS を取得: {} 回目、使える鍵 {:?})", cache.fetch_count, kids);
}

fn verify(cache: &mut Cache, jwks_now: &Value, token: &str, now: u64) -> Result<(), String> {
    let parts: Vec<&str> = token.split('.').collect();
    let header: Value = serde_json::from_slice(&B64.decode(parts[0]).unwrap()).unwrap();
    // 1. alg は許可リストで先に判定する。鍵を探すのはその後
    if header["alg"] != "ES256" {
        return Err(format!("alg={} は許可していない", header["alg"]));
    }
    let kid = header["kid"].as_str().ok_or("kid がない")?;
    // 2. キャッシュが古ければ取り直す
    if cache.fetched_at.is_none_or(|t| now - t >= CACHE_MAX_AGE) {
        fetch(cache, jwks_now, now);
    }
    // 3. 未知の kid なら1回だけ取り直す。ただし直前に取得していれば取り直さない
    if !cache.keys.contains_key(kid) {
        if cache.fetched_at.is_some_and(|t| now - t < MIN_REFETCH_INTERVAL) {
            return Err(format!("kid={kid} は {MIN_REFETCH_INTERVAL} 秒以内に取得した JWKS にない(再取得しない)"));
        }
        fetch(cache, jwks_now, now);
    }
    let key = cache.keys.get(kid).ok_or(format!("kid={kid} は取り直した JWKS の使える鍵にもない"))?;
    let sig = B64.decode(parts[2]).unwrap();
    UnparsedPublicKey::new(&ECDSA_P256_SHA256_FIXED, key)
        .verify(format!("{}.{}", parts[0], parts[1]).as_bytes(), &sig)
        .map_err(|_| "署名が一致しない".to_string())
}

fn main() {
    let rng = SystemRandom::new();
    let old = new_key(&rng);
    let new = new_key(&rng);
    let enc_key = json!({"kty": "RSA", "kid": "enc-1", "use": "enc", "n": "AQAB", "e": "AQAB"});

    let jwks_v1 = json!({"keys": [jwk("key-2026-09", &old), enc_key]});
    let jwks_v2 = json!({"keys": [jwk("key-2026-09", &old), jwk("key-2026-10", &new), enc_key]});
    let jwks_v3 = json!({"keys": [jwk("key-2026-10", &new), enc_key]});

    let token_old = sign(&rng, "key-2026-09", "ES256", &old);
    let token_new = sign(&rng, "key-2026-10", "ES256", &new);
    let token_unknown = sign(&rng, "attacker-0001", "ES256", &new);
    let token_hs256 = sign(&rng, "key-2026-09", "HS256", &old);
    let token_enc = sign(&rng, "enc-1", "ES256", &old);

    let mut cache = Cache { keys: HashMap::new(), fetched_at: None, fetch_count: 0 };
    let steps: [(u64, &str, &Value, &str); 8] = [
        (0, "旧鍵で署名(公開: v1)", &jwks_v1, &token_old),
        (10, "旧鍵で署名(2回目)", &jwks_v1, &token_old),
        (100, "新鍵で署名(OP が v2 を公開して切り替え)", &jwks_v2, &token_new),
        (110, "未知の kid", &jwks_v2, &token_unknown),
        (120, "alg=HS256 を名乗るトークン", &jwks_v2, &token_hs256),
        (200, "暗号化用の鍵の kid を指す", &jwks_v2, &token_enc),
        (300, "旧鍵で署名(まだ v2 を公開中)", &jwks_v2, &token_old),
        (4000, "旧鍵で署名(OP が v3 で旧鍵を退役)", &jwks_v3, &token_old),
    ];
    for (now, label, jwks, token) in steps {
        println!("t={now:>4}s {label}");
        match verify(&mut cache, jwks, token, now) {
            Ok(()) => println!("    → 検証成功"),
            Err(e) => println!("    → 拒否: {e}"),
        }
    }
}
