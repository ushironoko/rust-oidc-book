// 本書の要素を1つのプロセスに統合した OP・RP・リソースサーバの簡易実装
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use ring::rand::{SecureRandom, SystemRandom};
use ring::signature::{self, EcdsaKeyPair, KeyPair};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use subtle::ConstantTimeEq;

const ISSUER: &str = "https://op.example";
const RS_ID: &str = "https://api.example";
const CLIENT_ID: &str = "demo-rp";
const CLIENT_SECRET: &str = "dummy-secret";
const REDIRECT_URI: &str = "https://rp.example/callback";

fn random_b64(rng: &SystemRandom, n: usize) -> String {
    let mut buf = vec![0u8; n];
    rng.fill(&mut buf).unwrap();
    B64.encode(buf)
}

fn s256(v: &str) -> String {
    B64.encode(Sha256::digest(v.as_bytes()))
}

fn sign_jws(key: &EcdsaKeyPair, rng: &SystemRandom, header: &Value, payload: &Value) -> String {
    let input = format!(
        "{}.{}",
        B64.encode(header.to_string()),
        B64.encode(payload.to_string())
    );
    let sig = key.sign(rng, input.as_bytes()).unwrap();
    format!("{input}.{}", B64.encode(sig.as_ref()))
}

// 署名を検証してからヘッダとペイロードを返す。alg は ES256 に固定する
fn verify_jws(jwt: &str, jwks: &Value, typ: &str) -> Result<Value, String> {
    let parts: Vec<&str> = jwt.split('.').collect();
    if parts.len() != 3 {
        return Err("JWS の形式が不正".into());
    }
    let header: Value = serde_json::from_slice(&B64.decode(parts[0]).map_err(|_| "ヘッダの復号に失敗")?)
        .map_err(|_| "ヘッダが JSON でない")?;
    if header["alg"] != "ES256" {
        return Err(format!("許可していない alg: {}", header["alg"]));
    }
    if header["typ"] != typ {
        return Err(format!("typ が {typ} でない: {}", header["typ"]));
    }
    let jwk = jwks["keys"]
        .as_array()
        .unwrap()
        .iter()
        .find(|k| k["kid"] == header["kid"])
        .ok_or("JWKS に kid がない")?;
    let mut point = vec![0x04];
    point.extend(B64.decode(jwk["x"].as_str().unwrap()).unwrap());
    point.extend(B64.decode(jwk["y"].as_str().unwrap()).unwrap());
    let sig = B64.decode(parts[2]).map_err(|_| "署名の復号に失敗")?;
    signature::UnparsedPublicKey::new(&signature::ECDSA_P256_SHA256_FIXED, &point)
        .verify(format!("{}.{}", parts[0], parts[1]).as_bytes(), &sig)
        .map_err(|_| "署名の検証に失敗")?;
    serde_json::from_slice(&B64.decode(parts[1]).unwrap()).map_err(|_| "ペイロードが JSON でない".into())
}

struct CodeRecord {
    client_id: String,
    redirect_uri: String,
    code_challenge: String,
    nonce: String,
    expires_at: u64,
}

struct Op {
    rng: SystemRandom,
    key: EcdsaKeyPair,
    kid: String,
    codes: HashMap<String, CodeRecord>,
}

impl Op {
    fn new() -> Op {
        let rng = SystemRandom::new();
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(&signature::ECDSA_P256_SHA256_FIXED_SIGNING, &rng).unwrap();
        let key = EcdsaKeyPair::from_pkcs8(&signature::ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8.as_ref(), &rng).unwrap();
        Op { rng, key, kid: "k1".into(), codes: HashMap::new() }
    }

    fn jwks(&self) -> Value {
        let p = self.key.public_key().as_ref();
        json!({"keys": [{"kty": "EC", "crv": "P-256", "kid": self.kid, "use": "sig", "alg": "ES256",
            "x": B64.encode(&p[1..33]), "y": B64.encode(&p[33..65])}]})
    }

    // 認可エンドポイント: client_id と redirect_uri の照合に失敗したらリダイレクトしない
    fn authorize(&mut self, q: &HashMap<String, String>, now: u64) -> Result<String, String> {
        if q.get("client_id").map(String::as_str) != Some(CLIENT_ID)
            || q.get("redirect_uri").map(String::as_str) != Some(REDIRECT_URI)
        {
            return Err("エラー画面を表示(リダイレクトしない)".into());
        }
        let state = q.get("state").cloned().unwrap_or_default();
        // 値はクエリとして符号化して付ける(state に & が入っていても別のパラメータにならない)
        let respond = |pairs: &[(&str, &str)]| {
            let mut url = url::Url::parse(REDIRECT_URI).unwrap();
            url.query_pairs_mut().extend_pairs(pairs).append_pair("state", &state).append_pair("iss", ISSUER);
            url.to_string()
        };
        let fail = |e: &str| Ok(respond(&[("error", e)]));
        if q.get("response_type").map(String::as_str) != Some("code") {
            return fail("unsupported_response_type");
        }
        if !q.get("scope").is_some_and(|s| s.split(' ').any(|t| t == "openid")) {
            return fail("invalid_scope");
        }
        if q.get("code_challenge_method").map(String::as_str) != Some("S256") || !q.contains_key("code_challenge") {
            return fail("invalid_request");
        }
        let code = random_b64(&self.rng, 32);
        self.codes.insert(code.clone(), CodeRecord {
            client_id: CLIENT_ID.into(),
            redirect_uri: REDIRECT_URI.into(),
            code_challenge: q["code_challenge"].clone(),
            nonce: q.get("nonce").cloned().unwrap_or_default(),
            expires_at: now + 60,
        });
        Ok(respond(&[("code", &code)]))
    }

    // トークンエンドポイント: クライアント認証 → コードの取り出し(1回限り) → 束縛の照合 → PKCE
    fn token(&mut self, client_id: &str, secret: &str, form: &HashMap<&str, &str>, now: u64) -> Result<Value, String> {
        let secret_ok: bool = secret.as_bytes().ct_eq(CLIENT_SECRET.as_bytes()).into();
        if client_id != CLIENT_ID || !secret_ok {
            return Err("401 invalid_client".into());
        }
        match form.get("grant_type") {
            None => return Err("400 invalid_request (grant_type がない)".into()),
            Some(&"authorization_code") => {}
            Some(_) => return Err("400 unsupported_grant_type".into()),
        }
        let rec = self.codes.remove(form["code"]).ok_or("400 invalid_grant (未知または使用済みのコード)")?;
        if rec.expires_at <= now || rec.client_id != client_id || rec.redirect_uri != form["redirect_uri"] {
            return Err("400 invalid_grant (期限切れまたは束縛の不一致)".into());
        }
        if s256(form.get("code_verifier").unwrap_or(&"")) != rec.code_challenge {
            return Err("400 invalid_grant (PKCE の検証に失敗)".into());
        }
        let at = sign_jws(&self.key, &self.rng, &json!({"alg": "ES256", "typ": "at+jwt", "kid": self.kid}),
            &json!({"iss": ISSUER, "sub": "user-0001", "aud": RS_ID, "client_id": CLIENT_ID,
                "scope": "openid api.read", "iat": now, "exp": now + 300, "jti": random_b64(&self.rng, 16)}));
        let at_hash = B64.encode(&Sha256::digest(at.as_bytes())[..16]);
        let id = sign_jws(&self.key, &self.rng, &json!({"alg": "ES256", "typ": "JWT", "kid": self.kid}),
            &json!({"iss": ISSUER, "sub": "user-0001", "aud": CLIENT_ID, "iat": now, "exp": now + 300,
                "nonce": rec.nonce, "at_hash": at_hash}));
        Ok(json!({"access_token": at, "token_type": "Bearer", "expires_in": 300, "id_token": id}))
    }
}

struct Rp {
    // 照合したら取り出して消す(同じ認可レスポンスの再送を拒否するため)
    state: Option<String>,
    nonce: String,
    verifier: String,
}

impl Rp {
    fn login(rng: &SystemRandom) -> (Rp, HashMap<String, String>) {
        let rp = Rp { state: Some(random_b64(rng, 16)), nonce: random_b64(rng, 16), verifier: random_b64(rng, 32) };
        let q = [
            ("response_type", "code"), ("client_id", CLIENT_ID), ("redirect_uri", REDIRECT_URI),
            ("scope", "openid api.read"), ("state", rp.state.as_deref().unwrap()), ("nonce", &rp.nonce),
            ("code_challenge", &s256(&rp.verifier)), ("code_challenge_method", "S256"),
        ]
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
        (rp, q)
    }

    fn parse_callback(&mut self, location: &str) -> Result<String, String> {
        let url = url::Url::parse(location).map_err(|_| "URL が不正")?;
        let p: HashMap<_, _> = url.query_pairs().into_owned().collect();
        let Some(expected) = self.state.take() else {
            return Err("処理中のログインがない(再送の疑い)".into());
        };
        if p.get("state") != Some(&expected) {
            return Err("state が一致しない(CSRF の疑い)".into());
        }
        if p.get("iss").map(String::as_str) != Some(ISSUER) {
            return Err("iss が一致しない(ミックスアップの疑い)".into());
        }
        match (p.get("code"), p.get("error")) {
            (Some(code), None) => Ok(code.clone()),
            (None, Some(e)) => Err(format!("エラー応答: {e}")),
            _ => Err("code と error の組み合わせが不正".into()),
        }
    }

    fn validate_id_token(&self, res: &Value, jwks: &Value, now: u64) -> Result<String, String> {
        let c = verify_jws(res["id_token"].as_str().unwrap(), jwks, "JWT")?;
        let checks = [
            (c["iss"] == ISSUER, "iss"),
            (c["aud"] == CLIENT_ID, "aud"),
            (c["exp"].as_u64().unwrap_or(0) > now, "exp"),
            (c["nonce"] == self.nonce.as_str(), "nonce"),
        ];
        if let Some((_, name)) = checks.iter().find(|(ok, _)| !ok) {
            return Err(format!("ID トークンの {name} が不正"));
        }
        let at = res["access_token"].as_str().unwrap();
        if c["at_hash"] != B64.encode(&Sha256::digest(at.as_bytes())[..16]).as_str() {
            return Err("at_hash が一致しない".into());
        }
        Ok(c["sub"].as_str().unwrap().into())
    }
}

// リソースサーバ: typ=at+jwt、署名、iss、aud、exp、scope の順に検査する
fn resource_server(authz: &str, jwks: &Value, now: u64) -> String {
    let Some(token) = authz.strip_prefix("Bearer ") else {
        return "401 (Bearer トークンがない)".into();
    };
    match verify_jws(token, jwks, "at+jwt") {
        Err(e) => format!("401 invalid_token ({e})"),
        Ok(c) if c["iss"] != ISSUER || c["aud"] != RS_ID => "401 invalid_token (iss または aud が不正)".into(),
        Ok(c) if c["exp"].as_u64().unwrap_or(0) <= now => "401 invalid_token (期限切れ)".into(),
        Ok(c) if !c["scope"].as_str().unwrap_or("").split(' ').any(|s| s == "api.read") => "403 insufficient_scope".into(),
        Ok(c) => format!("200 OK (sub={})", c["sub"].as_str().unwrap()),
    }
}

fn main() {
    let mut op = Op::new();
    let jwks = op.jwks();
    let now = 1_800_000_000;

    println!("[1] 正常なログインと API 呼び出し");
    let (mut rp, q) = Rp::login(&op.rng);
    let loc = op.authorize(&q, now).unwrap();
    let code = rp.parse_callback(&loc).unwrap();
    let form = HashMap::from([("grant_type", "authorization_code"), ("code", code.as_str()),
        ("redirect_uri", REDIRECT_URI), ("code_verifier", rp.verifier.as_str())]);
    let res = op.token(CLIENT_ID, CLIENT_SECRET, &form, now).unwrap();
    println!("  ID トークンの検証: {:?}", rp.validate_id_token(&res, &jwks, now));
    let at = res["access_token"].as_str().unwrap();
    println!("  API: {}", resource_server(&format!("Bearer {at}"), &jwks, now + 10));

    println!("[2] 同じ認可コードの再利用と、同じ認可レスポンスの再送");
    println!("  OP: {:?}", op.token(CLIENT_ID, CLIENT_SECRET, &form, now + 5).map(|_| "発行"));
    println!("  RP: {:?}", rp.parse_callback(&loc));

    println!("[3] 横取りしたコードを推測した code_verifier で交換する");
    let (mut rp3, q3) = Rp::login(&op.rng);
    let code3 = rp3.parse_callback(&op.authorize(&q3, now).unwrap()).unwrap();
    let stolen = HashMap::from([("grant_type", "authorization_code"), ("code", code3.as_str()),
        ("redirect_uri", REDIRECT_URI), ("code_verifier", "guess")]);
    println!("  {:?}", op.token(CLIENT_ID, CLIENT_SECRET, &stolen, now).map(|_| "発行"));

    println!("[4] 攻撃者が自分の認可レスポンスを被害者の RP に送る");
    let (_attacker, qa) = Rp::login(&op.rng);
    let (mut victim, _) = Rp::login(&op.rng);
    println!("  {:?}", victim.parse_callback(&op.authorize(&qa, now).unwrap()));

    println!("[5] 登録されていない redirect_uri");
    let mut q5 = q.clone();
    q5.insert("redirect_uri".into(), "https://attacker.example/cb".into());
    println!("  {:?}", op.authorize(&q5, now));

    println!("[6] ID トークンをリソースサーバに送る");
    println!("  {}", resource_server(&format!("Bearer {}", res["id_token"].as_str().unwrap()), &jwks, now));

    println!("[7] アクセストークンのペイロードを書き換える");
    let parts: Vec<&str> = at.split('.').collect();
    let forged = B64.encode(String::from_utf8(B64.decode(parts[1]).unwrap()).unwrap().replace("user-0001", "user-0002"));
    println!("  {}", resource_server(&format!("Bearer {}.{forged}.{}", parts[0], parts[2]), &jwks, now));

    println!("[8] 有効期限の後に API を呼ぶ");
    println!("  {}", resource_server(&format!("Bearer {at}"), &jwks, now + 301));
}
