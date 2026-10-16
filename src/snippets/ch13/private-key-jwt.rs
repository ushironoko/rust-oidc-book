use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ring::rand::SystemRandom;
use ring::signature::{
    ECDSA_P256_SHA256_FIXED, ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, KeyPair,
    UnparsedPublicKey,
};
use serde_json::{Value, json};
use std::collections::{HashMap, HashSet};

const CLIENT_ID: &str = "s6BhdRkqt3";
const OTHER_CLIENT_ID: &str = "other-client";
const AS_ISSUER: &str = "https://as.example.com";
const TOKEN_ENDPOINT: &str = "https://as.example.com/token";
// 実験を再現可能にするための固定の現在時刻
const NOW: i64 = 1_760_000_000;

fn b64(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

// クライアント側: 秘密鍵でクライアントアサーションを作る
fn make_assertion(key: &EcdsaKeyPair, claims: &Value) -> String {
    let header = json!({"alg": "ES256", "kid": "client-key-1"});
    let signing_input = format!(
        "{}.{}",
        b64(header.to_string().as_bytes()),
        b64(claims.to_string().as_bytes())
    );
    let sig = key
        .sign(&SystemRandom::new(), signing_input.as_bytes())
        .unwrap();
    format!("{signing_input}.{}", b64(sig.as_ref()))
}

// 認可サーバ側の状態: client_id ごとの登録済み公開鍵と、使用済みの jti
struct AuthServer {
    registered_keys: HashMap<String, Vec<u8>>,
    seen_jti: HashSet<String>,
}

impl AuthServer {
    // RFC 7523 3節の検査を、署名検証を先にして順に行う
    fn authenticate(&mut self, client_id: &str, assertion_type: &str, assertion: &str) -> Result<(), String> {
        if assertion_type != "urn:ietf:params:oauth:client-assertion-type:jwt-bearer" {
            return Err("client_assertion_type が不正".into());
        }
        let parts: Vec<&str> = assertion.split('.').collect();
        let [h, p, s] = parts[..] else {
            return Err("JWS の形式ではない".into());
        };
        let header: Value = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(h).map_err(|e| e.to_string())?)
            .map_err(|e| e.to_string())?;
        if header["alg"] != "ES256" {
            return Err(format!("許可していない alg: {}", header["alg"]));
        }
        // 要求された client_id に登録された鍵だけで検証する
        let public_key = self.registered_keys.get(client_id).ok_or("未登録の client_id")?;
        let sig = URL_SAFE_NO_PAD.decode(s).map_err(|e| e.to_string())?;
        UnparsedPublicKey::new(&ECDSA_P256_SHA256_FIXED, public_key)
            .verify(format!("{h}.{p}").as_bytes(), &sig)
            .map_err(|_| "署名検証に失敗".to_string())?;
        let c: Value = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(p).map_err(|e| e.to_string())?)
            .map_err(|e| e.to_string())?;
        if c["iss"] != client_id || c["sub"] != client_id {
            return Err("iss と sub が client_id と一致しない".into());
        }
        let aud_ok = match &c["aud"] {
            Value::String(a) => a == AS_ISSUER || a == TOKEN_ENDPOINT,
            Value::Array(list) => list.iter().any(|a| a == AS_ISSUER || a == TOKEN_ENDPOINT),
            _ => false,
        };
        if !aud_ok {
            return Err(format!("aud に自分が含まれない: {}", c["aud"]));
        }
        let exp = c["exp"].as_i64().ok_or("exp がない")?;
        if NOW >= exp + 30 {
            return Err("exp を過ぎている".into());
        }
        if !c["nbf"].is_null() {
            let nbf = c["nbf"].as_i64().ok_or("nbf が整数ではない")?;
            if NOW + 30 < nbf {
                return Err("nbf より前に使われた".into());
            }
        }
        let jti = c["jti"].as_str().ok_or("jti がない")?.to_string();
        if !self.seen_jti.insert(jti) {
            return Err("jti が再利用された".into());
        }
        Ok(())
    }
}

fn claims(aud: &str, exp: i64) -> Value {
    json!({
        "iss": CLIENT_ID,
        "sub": CLIENT_ID,
        "aud": aud,
        "jti": uuid::Uuid::new_v4().to_string(),
        "iat": NOW,
        "exp": exp,
    })
}

fn main() {
    let rng = SystemRandom::new();
    let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng).unwrap();
    let client_key =
        EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8.as_ref(), &rng).unwrap();

    let other_pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng).unwrap();
    let other_key =
        EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, other_pkcs8.as_ref(), &rng).unwrap();

    // 登録時に渡すのは公開鍵だけ。鍵は client_id と対で保存する
    let mut server = AuthServer {
        registered_keys: HashMap::from([
            (CLIENT_ID.to_string(), client_key.public_key().as_ref().to_vec()),
            (OTHER_CLIENT_ID.to_string(), other_key.public_key().as_ref().to_vec()),
        ]),
        seen_jti: HashSet::new(),
    };

    let assertion = make_assertion(&client_key, &claims(AS_ISSUER, NOW + 60));
    let payload = assertion.split('.').nth(1).unwrap();
    println!("[1] クライアントアサーションのペイロード");
    println!("  {}", String::from_utf8(URL_SAFE_NO_PAD.decode(payload).unwrap()).unwrap());
    println!("  トークンリクエストの本文:");
    let body = form_urlencoded::Serializer::new(String::new())
        .append_pair("grant_type", "authorization_code")
        .append_pair("code", "dummy-code")
        .append_pair("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
        .append_pair("client_assertion", &assertion)
        .finish();
    println!("  {}...", &body[..140]);

    let jwt_bearer = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";
    let report = |label: &str, r: Result<(), String>| match r {
        Ok(()) => println!("{label}: 認証成功"),
        Err(e) => println!("{label}: invalid_client ({e})"),
    };

    println!();
    report("[2] 正しいアサーション", server.authenticate(CLIENT_ID, jwt_bearer, &assertion));
    report("[3] 同じアサーションの再送", server.authenticate(CLIENT_ID, jwt_bearer, &assertion));

    let other_as = make_assertion(&client_key, &claims("https://other-as.example.net", NOW + 60));
    report("[4] 別の認可サーバ宛て", server.authenticate(CLIENT_ID, jwt_bearer, &other_as));

    let expired = make_assertion(&client_key, &claims(AS_ISSUER, NOW - 120));
    report("[5] 期限切れ", server.authenticate(CLIENT_ID, jwt_bearer, &expired));

    let fresh = make_assertion(&client_key, &claims(AS_ISSUER, NOW + 60));
    let mut parts: Vec<String> = fresh.split('.').map(String::from).collect();
    let mut c: Value = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(&parts[1]).unwrap()).unwrap();
    c["sub"] = json!(OTHER_CLIENT_ID);
    c["iss"] = json!(OTHER_CLIENT_ID);
    parts[1] = b64(c.to_string().as_bytes());
    report("[6] ペイロードを書き換え", server.authenticate(OTHER_CLIENT_ID, jwt_bearer, &parts.join(".")));

    let attacker_pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng).unwrap();
    let attacker_key =
        EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, attacker_pkcs8.as_ref(), &rng).unwrap();
    let forged = make_assertion(&attacker_key, &claims(AS_ISSUER, NOW + 60));
    report("[7] 別の鍵で署名", server.authenticate(CLIENT_ID, jwt_bearer, &forged));

    // 登録済みの別クライアントが、自分の鍵で s6BhdRkqt3 を名乗る
    let impersonation = make_assertion(&other_key, &claims(AS_ISSUER, NOW + 60));
    report("[8] 別クライアントの登録鍵で署名", server.authenticate(CLIENT_ID, jwt_bearer, &impersonation));

    let mut early = claims(AS_ISSUER, NOW + 600);
    early["nbf"] = json!(NOW + 300);
    let not_yet = make_assertion(&client_key, &early);
    report("[9] nbf が5分後", server.authenticate(CLIENT_ID, jwt_bearer, &not_yet));
}
