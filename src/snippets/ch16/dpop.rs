use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ring::rand::SystemRandom;
use ring::signature::{
    ECDSA_P256_SHA256_FIXED, ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, KeyPair,
    UnparsedPublicKey,
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::HashSet;

// 実験を再現可能にするための固定の現在時刻
const NOW: i64 = 1_760_000_000;
const WINDOW: i64 = 60;
const TOKEN_URL: &str = "https://as.example.com/token";
const ORDERS_URL: &str = "https://api.example.com/orders";

fn b64(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

fn new_key() -> EcdsaKeyPair {
    let rng = SystemRandom::new();
    let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng).unwrap();
    EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8.as_ref(), &rng).unwrap()
}

// 非圧縮形式の公開鍵 (0x04 || x || y) を JWK にする
fn public_jwk(key: &EcdsaKeyPair) -> Value {
    let point = key.public_key().as_ref();
    json!({"kty": "EC", "crv": "P-256", "x": b64(&point[1..33]), "y": b64(&point[33..65])})
}

fn jwk_thumbprint(jwk: &Value) -> String {
    let canonical = format!(
        r#"{{"crv":"{}","kty":"{}","x":"{}","y":"{}"}}"#,
        jwk["crv"].as_str().unwrap_or(""),
        jwk["kty"].as_str().unwrap_or(""),
        jwk["x"].as_str().unwrap_or(""),
        jwk["y"].as_str().unwrap_or("")
    );
    b64(&Sha256::digest(canonical.as_bytes()))
}

fn sign_jwt(key: &EcdsaKeyPair, header: &Value, claims: &Value) -> String {
    let input = format!("{}.{}", b64(header.to_string().as_bytes()), b64(claims.to_string().as_bytes()));
    let sig = key.sign(&SystemRandom::new(), input.as_bytes()).unwrap();
    format!("{input}.{}", b64(sig.as_ref()))
}

// クライアント: 1回のリクエストごとに DPoP 証明を作る
fn make_proof(key: &EcdsaKeyPair, typ: &str, htm: &str, htu: &str, iat: i64, access_token: Option<&str>) -> String {
    let header = json!({"typ": typ, "alg": "ES256", "jwk": public_jwk(key)});
    let mut claims = json!({"jti": uuid::Uuid::new_v4().to_string(), "htm": htm, "htu": htu, "iat": iat});
    if let Some(at) = access_token {
        claims["ath"] = json!(b64(&Sha256::digest(at.as_bytes())));
    }
    sign_jwt(key, &header, &claims)
}

fn decode_json(part: &str) -> Result<Value, String> {
    let bytes = URL_SAFE_NO_PAD.decode(part).map_err(|_| "Base64url として不正".to_string())?;
    serde_json::from_slice(&bytes).map_err(|_| "JSON として不正".to_string())
}

fn strip_query(u: &str) -> &str {
    u.split(['?', '#']).next().unwrap_or(u)
}

// RFC 9449 4.3節の検査。成功すれば証明の公開鍵の jkt を返す
fn check_proof(
    dpop_headers: &[&str],
    method: &str,
    url: &str,
    access_token: Option<&str>,
    seen_jti: &mut HashSet<String>,
) -> Result<String, String> {
    let [proof] = dpop_headers else {
        return Err("(1) DPoP ヘッダが1つではない".into());
    };
    let parts: Vec<&str> = proof.split('.').collect();
    let [h, p, s] = parts[..] else {
        return Err("(2) JWT の形式ではない".into());
    };
    let header = decode_json(h)?;
    let claims = decode_json(p)?;
    for c in ["jti", "htm", "htu", "iat"] {
        if claims.get(c).is_none() {
            return Err(format!("(3) {c} がない"));
        }
    }
    if header["typ"] != "dpop+jwt" {
        return Err(format!("(4) typ が dpop+jwt ではない ({})", header["typ"]));
    }
    if header["alg"] != "ES256" {
        return Err(format!("(5) 許可していない alg ({})", header["alg"]));
    }
    let jwk = &header["jwk"];
    if jwk.get("d").is_some() {
        return Err("(7) jwk に秘密鍵が含まれる".into());
    }
    // ES256 の鍵は P-256 の EC 鍵で、座標は32バイト (RFC 7518 3.4節/6.2.1節)
    if jwk["kty"] != "EC" || jwk["crv"] != "P-256" {
        return Err(format!("(6) jwk が P-256 の EC 鍵ではない (kty={}, crv={})", jwk["kty"], jwk["crv"]));
    }
    let coord = |name: &str| -> Result<Vec<u8>, String> {
        let bytes = URL_SAFE_NO_PAD
            .decode(jwk[name].as_str().unwrap_or(""))
            .map_err(|_| format!("(6) jwk の {name} が Base64url ではない"))?;
        if bytes.len() != 32 {
            return Err(format!("(6) jwk の {name} が32バイトではない ({} バイト)", bytes.len()));
        }
        Ok(bytes)
    };
    let mut point = vec![0x04];
    point.extend(coord("x")?);
    point.extend(coord("y")?);
    let sig = URL_SAFE_NO_PAD.decode(s).map_err(|e| e.to_string())?;
    UnparsedPublicKey::new(&ECDSA_P256_SHA256_FIXED, &point)
        .verify(format!("{h}.{p}").as_bytes(), &sig)
        .map_err(|_| "(6) jwk の公開鍵で署名を検証できない".to_string())?;
    if claims["htm"] != method {
        return Err(format!("(8) htm が {method} ではない ({})", claims["htm"]));
    }
    if claims["htu"].as_str().map(strip_query) != Some(strip_query(url)) {
        return Err(format!("(9) htu が一致しない ({})", claims["htu"]));
    }
    let iat = claims["iat"].as_i64().ok_or("(3) iat が数値ではない")?;
    // iat は送信者が決める値なので、i128 で差を取り桁あふれを防ぐ
    let diff = i128::from(iat) - i128::from(NOW);
    if diff.abs() > i128::from(WINDOW) {
        return Err(format!("(11) iat が許容範囲外 (現在との差 {diff} 秒)"));
    }
    if let Some(at) = access_token {
        let expected = b64(&Sha256::digest(at.as_bytes()));
        if claims["ath"] != expected.as_str() {
            return Err("(12) ath がアクセストークンのハッシュと一致しない".into());
        }
    }
    // 同じ jti の証明は2度受け付けない (11.1節)
    if !seen_jti.insert(claims["jti"].as_str().unwrap_or("").to_string()) {
        return Err("(11.1節) jti が再利用された".into());
    }
    Ok(jwk_thumbprint(jwk))
}

// 認可サーバのトークンエンドポイント: 証明の鍵の jkt を cnf に入れて発行する
fn token_endpoint(as_key: &EcdsaKeyPair, dpop: &[&str], seen: &mut HashSet<String>) -> Result<Value, String> {
    let jkt = check_proof(dpop, "POST", TOKEN_URL, None, seen).map_err(|e| format!("invalid_dpop_proof {e}"))?;
    let at = sign_jwt(
        as_key,
        &json!({"typ": "at+jwt", "alg": "ES256", "kid": "as-key-1"}),
        &json!({"iss": "https://as.example.com", "sub": "user-5821", "aud": "https://api.example.com/orders",
                "client_id": "spa-client", "exp": NOW + 300, "iat": NOW, "jti": "at-0001",
                "scope": "orders:read orders:write", "cnf": {"jkt": jkt}}),
    );
    Ok(json!({"access_token": at, "token_type": "DPoP", "expires_in": 300}))
}

// 14章と同じ RFC 9068 の検証: typ、署名、iss、aud、exp
fn validate_access_token(as_pub: &[u8], token: &str) -> Result<Value, String> {
    let parts: Vec<&str> = token.split('.').collect();
    let [h, p, s] = parts[..] else { return Err("アクセストークンが JWT ではない".into()) };
    let header = decode_json(h)?;
    if header["typ"] != "at+jwt" || header["alg"] != "ES256" {
        return Err("アクセストークンの typ または alg が不正".into());
    }
    let sig = URL_SAFE_NO_PAD.decode(s).unwrap_or_default();
    UnparsedPublicKey::new(&ECDSA_P256_SHA256_FIXED, as_pub)
        .verify(format!("{h}.{p}").as_bytes(), &sig)
        .map_err(|_| "アクセストークンの署名が不正".to_string())?;
    let claims = decode_json(p)?;
    if claims["iss"] != "https://as.example.com" {
        return Err("iss が一致しない".into());
    }
    if claims["aud"] != ORDERS_URL {
        return Err("aud にこのリソースサーバが含まれない".into());
    }
    let exp = claims["exp"].as_i64().ok_or("exp がない")?;
    if NOW >= exp + WINDOW {
        return Err("アクセストークンの有効期限切れ".into());
    }
    Ok(claims)
}

// リソースサーバ: アクセストークンを検証してから DPoP ヘッダを検査し、最後にスコープを確認する
fn resource(as_pub: &[u8], authz: &str, dpop: &[&str], method: &str, url: &str, seen: &mut HashSet<String>) -> String {
    let fail = |e: &str| format!("401 WWW-Authenticate: DPoP error=\"invalid_token\" (理由: {e})");
    let (scheme, token) = authz.split_once(' ').unwrap_or(("", ""));
    let claims = match validate_access_token(as_pub, token) {
        Ok(c) => c,
        Err(e) => return fail(&e),
    };
    let bound_jkt = claims["cnf"]["jkt"].as_str();
    match (scheme, bound_jkt) {
        ("Bearer", Some(_)) => return fail("DPoP に束縛されたトークンが Bearer で送られた (7.2節)"),
        ("DPoP", Some(jkt)) => match check_proof(dpop, method, url, Some(token), seen) {
            Ok(proof_jkt) if proof_jkt == jkt => {}
            Ok(_) => return fail("証明の鍵が cnf.jkt と一致しない"),
            Err(e) => return format!("401 WWW-Authenticate: DPoP error=\"invalid_dpop_proof\" (理由: {e})"),
        },
        _ => return fail("想定外のスキーム"),
    }
    let required = if method == "GET" { "orders:read" } else { "orders:write" };
    if !claims["scope"].as_str().unwrap_or("").split(' ').any(|s| s == required) {
        return format!("403 WWW-Authenticate: DPoP error=\"insufficient_scope\" (必要なスコープ: {required})");
    }
    format!("200 OK (sub={})", claims["sub"])
}

fn main() {
    let as_key = new_key();
    let as_pub = as_key.public_key().as_ref().to_vec();
    let client_key = new_key();
    let mut as_seen = HashSet::new();
    let mut rs_seen = HashSet::new();

    println!("[1] トークンリクエスト (DPoP ヘッダ付き)");
    let proof = make_proof(&client_key, "dpop+jwt", "POST", TOKEN_URL, NOW, None);
    let resp = token_endpoint(&as_key, &[&proof], &mut as_seen).unwrap();
    let at = resp["access_token"].as_str().unwrap().to_string();
    println!("  token_type = {}", resp["token_type"]);
    let at_claims = decode_json(at.split('.').nth(1).unwrap()).unwrap();
    println!("  アクセストークンの cnf = {}", at_claims["cnf"]);
    println!("  クライアント公開鍵の jkt = {}", jwk_thumbprint(&public_jwk(&client_key)));
    println!("  同じ証明でもう1度リクエスト -> {}", token_endpoint(&as_key, &[&proof], &mut as_seen).unwrap_err());

    let authz = format!("DPoP {at}");
    let ok_proof = make_proof(&client_key, "dpop+jwt", "GET", ORDERS_URL, NOW, Some(&at));
    println!("\n[2] 正規クライアントが GET {ORDERS_URL}");
    println!("  -> {}", resource(&as_pub, &authz, &[&ok_proof], "GET", ORDERS_URL, &mut rs_seen));

    println!("\n[3] 盗聴者が同じリクエストをそのまま再送");
    println!("  -> {}", resource(&as_pub, &authz, &[&ok_proof], "GET", ORDERS_URL, &mut rs_seen));

    println!("\n[4] 盗んだアクセストークンを、攻撃者自身の鍵の証明と送る");
    let attacker = new_key();
    let p = make_proof(&attacker, "dpop+jwt", "GET", ORDERS_URL, NOW, Some(&at));
    println!("  -> {}", resource(&as_pub, &authz, &[&p], "GET", ORDERS_URL, &mut rs_seen));

    println!("\n[5] 盗んだトークンと未使用の証明を、別のメソッドで使う");
    let p = make_proof(&client_key, "dpop+jwt", "GET", ORDERS_URL, NOW, Some(&at));
    println!("  -> {}", resource(&as_pub, &authz, &[&p], "DELETE", ORDERS_URL, &mut rs_seen));

    println!("\n[6] 盗んだトークンを Bearer として送る");
    println!("  -> {}", resource(&as_pub, &format!("Bearer {at}"), &[], "GET", ORDERS_URL, &mut rs_seen));

    println!("\n[7] typ が JWT の証明");
    let p = make_proof(&client_key, "JWT", "GET", ORDERS_URL, NOW, Some(&at));
    println!("  -> {}", resource(&as_pub, &authz, &[&p], "GET", ORDERS_URL, &mut rs_seen));

    println!("\n[8] 1時間後の iat で事前に作った証明");
    let p = make_proof(&client_key, "dpop+jwt", "GET", ORDERS_URL, NOW + 3600, Some(&at));
    println!("  -> {}", resource(&as_pub, &authz, &[&p], "GET", ORDERS_URL, &mut rs_seen));

    println!("\n[9] ath を含まない証明 (トークンとの結びつきがない)");
    let p = make_proof(&client_key, "dpop+jwt", "GET", ORDERS_URL, NOW, None);
    println!("  -> {}", resource(&as_pub, &authz, &[&p], "GET", ORDERS_URL, &mut rs_seen));

    println!("\n[10] DPoP ヘッダを2つ付ける");
    let p1 = make_proof(&client_key, "dpop+jwt", "GET", ORDERS_URL, NOW, Some(&at));
    let p2 = make_proof(&client_key, "dpop+jwt", "GET", ORDERS_URL, NOW, Some(&at));
    println!("  -> {}", resource(&as_pub, &authz, &[&p1, &p2], "GET", ORDERS_URL, &mut rs_seen));

    println!("\n[11] 同じ鍵に束縛された期限切れのアクセストークンと、正しい証明");
    let expired = sign_jwt(
        &as_key,
        &json!({"typ": "at+jwt", "alg": "ES256", "kid": "as-key-1"}),
        &json!({"iss": "https://as.example.com", "sub": "user-5821", "aud": ORDERS_URL,
                "client_id": "spa-client", "exp": NOW - 3600, "iat": NOW - 3900, "jti": "at-0000",
                "scope": "orders:read orders:write", "cnf": {"jkt": jwk_thumbprint(&public_jwk(&client_key))}}),
    );
    let p = make_proof(&client_key, "dpop+jwt", "GET", ORDERS_URL, NOW, Some(&expired));
    println!("  -> {}", resource(&as_pub, &format!("DPoP {expired}"), &[&p], "GET", ORDERS_URL, &mut rs_seen));

    println!("\n[12] jwk の crv を P-384 と偽った証明");
    let mut header = json!({"typ": "dpop+jwt", "alg": "ES256", "jwk": public_jwk(&client_key)});
    header["jwk"]["crv"] = json!("P-384");
    let claims = json!({"jti": uuid::Uuid::new_v4().to_string(), "htm": "GET", "htu": ORDERS_URL, "iat": NOW,
                        "ath": b64(&Sha256::digest(at.as_bytes()))});
    let p = sign_jwt(&client_key, &header, &claims);
    println!("  -> {}", resource(&as_pub, &authz, &[&p], "GET", ORDERS_URL, &mut rs_seen));

    println!("\n[13] iat に i64 の最小値を入れた証明");
    let claims = json!({"jti": uuid::Uuid::new_v4().to_string(), "htm": "GET", "htu": ORDERS_URL, "iat": i64::MIN,
                        "ath": b64(&Sha256::digest(at.as_bytes()))});
    let header = json!({"typ": "dpop+jwt", "alg": "ES256", "jwk": public_jwk(&client_key)});
    let p = sign_jwt(&client_key, &header, &claims);
    println!("  -> {}", resource(&as_pub, &authz, &[&p], "GET", ORDERS_URL, &mut rs_seen));
}
