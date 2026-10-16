use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use ring::rand::SystemRandom;
use ring::signature::{
    ECDSA_P256_SHA256_FIXED, ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, KeyPair, UnparsedPublicKey,
};
use serde_json::{Value, json};
use std::collections::{HashMap, HashSet};

const ISS: &str = "https://server.example.com";
const CLIENT_ID: &str = "s6BhdRkqt3";
const EVENT: &str = "http://schemas.openid.net/event/backchannel-logout";
const NOW: i64 = 1_800_000_000;
const LEEWAY: i64 = 60;
// このRPが信頼する audience。自分の client_id 以外を含むトークンは拒否する
const TRUSTED_AUD: &[&str] = &[CLIENT_ID];
// このRPが理解できる crit の拡張。1つもない
const SUPPORTED_CRIT: &[&str] = &[];

fn sign(key: &EcdsaKeyPair, rng: &SystemRandom, header: &Value, claims: &Value) -> String {
    let input = format!("{}.{}", B64.encode(header.to_string()), B64.encode(claims.to_string()));
    let sig = key.sign(rng, input.as_bytes()).unwrap();
    format!("{input}.{}", B64.encode(sig.as_ref()))
}

struct Rp {
    op_public_key: Vec<u8>,
    // RPのセッションストア: セッションCookieの値 -> (iss, sub, sid)
    sessions: HashMap<&'static str, (&'static str, &'static str, &'static str)>,
    seen_jti: HashSet<String>,
}

impl Rp {
    // Back-Channel Logout 1.0 2.6節の検証手順
    fn validate(&mut self, token: &str) -> Result<Value, String> {
        let parts: Vec<&str> = token.split('.').collect();
        if parts.len() != 3 {
            return Err("JWSの形式ではない".into());
        }
        let header: Value = serde_json::from_slice(&B64.decode(parts[0]).map_err(|e| e.to_string())?)
            .map_err(|e| e.to_string())?;
        // 手順3: alg は許可リストで固定。none は不可
        if header["alg"] != "ES256" {
            return Err(format!("手順3: alg={} は受け付けない", header["alg"]));
        }
        if header.get("typ").is_some_and(|t| t != "logout+jwt") {
            return Err(format!("typ={} はログアウトトークンではない", header["typ"]));
        }
        // 手順2: 理解できない crit の拡張を含む JWS は無効(RFC 7515 4.1.11節)
        if let Some(crit) = header.get("crit") {
            let ok = crit.as_array().is_some_and(|a| {
                !a.is_empty() && a.iter().all(|n| n.as_str().is_some_and(|n| SUPPORTED_CRIT.contains(&n)))
            });
            if !ok {
                return Err(format!("手順2: crit={crit} の拡張に対応していない"));
            }
        }
        // 手順2: 署名検証。ここを通るまでペイロードを信用しない
        let input = format!("{}.{}", parts[0], parts[1]);
        let sig = B64.decode(parts[2]).map_err(|e| e.to_string())?;
        UnparsedPublicKey::new(&ECDSA_P256_SHA256_FIXED, &self.op_public_key)
            .verify(input.as_bytes(), &sig)
            .map_err(|_| "手順2: 署名が一致しない".to_string())?;
        let c: Value = serde_json::from_slice(&B64.decode(parts[1]).map_err(|e| e.to_string())?)
            .map_err(|e| e.to_string())?;
        // 手順4: iss / aud / iat / exp はIDトークンと同じ方法で検証
        if c["iss"] != ISS {
            return Err("手順4: iss が一致しない".into());
        }
        // aud は文字列か文字列の配列。自分の client_id を含み、ほかの要素もすべて信頼できる値であること
        let auds: Vec<&str> = match &c["aud"] {
            Value::String(s) => vec![s.as_str()],
            Value::Array(a) => a.iter().map(Value::as_str).collect::<Option<_>>().ok_or("手順4: aud に文字列以外の要素がある")?,
            _ => return Err("手順4: aud が文字列でも配列でもない".into()),
        };
        if !auds.contains(&CLIENT_ID) {
            return Err("手順4: aud に自分の client_id がない".into());
        }
        if let Some(a) = auds.iter().find(|a| !TRUSTED_AUD.contains(a)) {
            return Err(format!("手順4: 信頼できない audience {a} を含む"));
        }
        let exp = c["exp"].as_i64().ok_or("手順4: exp がない")?;
        let iat = c["iat"].as_i64().ok_or("手順4: iat がない")?;
        if NOW >= exp + LEEWAY {
            return Err("手順4: exp を過ぎている".into());
        }
        if iat > NOW + LEEWAY {
            return Err("手順4: iat が未来".into());
        }
        // 手順5: sub と sid の少なくとも一方。あれば空でない文字列であること
        for name in ["sub", "sid"] {
            if c.get(name).is_some_and(|v| v.as_str().is_none_or(str::is_empty)) {
                return Err(format!("手順5: {name}={} は不正な値(空でない文字列であること)", c[name]));
            }
        }
        if c.get("sub").is_none() && c.get("sid").is_none() {
            return Err("手順5: sub も sid もない".into());
        }
        // 手順6: events にバックチャネルログアウトのイベント
        if !c["events"].get(EVENT).is_some_and(Value::is_object) {
            return Err("手順6: events にログアウトイベントがない".into());
        }
        // 手順7: nonce があってはならない
        if c.get("nonce").is_some() {
            return Err("手順7: nonce がある".into());
        }
        // 手順8: 同じ jti を最近受け取っていないか
        let jti = c["jti"].as_str().ok_or("jti がない")?.to_string();
        if !self.seen_jti.insert(jti) {
            return Err("手順8: jti が再利用された".into());
        }
        Ok(c)
    }

    // 2.7節: sid があればそのセッション、なければ iss+sub の全セッションを消す
    fn handle(&mut self, token: &str) -> String {
        match self.validate(token) {
            Err(e) => format!("HTTP/1.1 400 Bad Request  {{\"error\":\"invalid_request\"}}  理由: {e}"),
            Ok(c) => {
                let before = self.sessions.len();
                self.sessions.retain(|_, (iss, sub, sid)| {
                    let hit = match c.get("sid") {
                        Some(s) => s == *sid && c["iss"] == *iss,
                        None => c["iss"] == *iss && c["sub"] == *sub,
                    };
                    !hit
                });
                format!("HTTP/1.1 200 OK  ({}個のセッションを削除)", before - self.sessions.len())
            }
        }
    }
}

fn main() {
    let rng = SystemRandom::new();
    let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng).unwrap();
    let op_key = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8.as_ref(), &rng).unwrap();
    let attacker_pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng).unwrap();
    let attacker_key =
        EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, attacker_pkcs8.as_ref(), &rng).unwrap();

    let mut rp = Rp {
        op_public_key: op_key.public_key().as_ref().to_vec(),
        sessions: HashMap::from([
            ("cookie-1", (ISS, "248289761001", "08a5019c-17e1-4977-8f42-65a12843ea02")),
            ("cookie-2", (ISS, "248289761001", "5d3a1f20-0000-4000-8000-000000000002")),
            ("cookie-3", (ISS, "999000111222", "77c1d2e3-0000-4000-8000-000000000003")),
        ]),
        seen_jti: HashSet::new(),
    };

    let header = json!({"alg": "ES256", "typ": "logout+jwt", "kid": "op-key-1"});
    let base = json!({
        "iss": ISS, "sub": "248289761001", "aud": CLIENT_ID,
        "iat": NOW - 5, "exp": NOW + 115, "jti": "bWJq",
        "sid": "08a5019c-17e1-4977-8f42-65a12843ea02",
        "events": { EVENT: {} }
    });
    let with = |f: &dyn Fn(&mut Value)| {
        let mut c = base.clone();
        f(&mut c);
        c
    };

    let valid = sign(&op_key, &rng, &header, &base);
    println!("ログアウトトークン(署名は実行ごとに変わる):\n{}...\n", &valid[..90]);

    let id_token_header = json!({"alg": "ES256", "kid": "op-key-1"});
    let id_token = json!({"iss": ISS, "sub": "248289761001", "aud": CLIENT_ID,
        "iat": NOW - 5, "exp": NOW + 600, "nonce": "n-0S6_WzA2Mj", "jti": "id-1"});
    let mut tampered: Vec<String> = valid.split('.').map(String::from).collect();
    tampered[1] = B64.encode(with(&|c| c["sub"] = json!("999000111222")).to_string());

    let cases: Vec<(&str, String)> = vec![
        ("正しいトークン(sid 指定)", valid.clone()),
        ("同じトークンの再送", valid.clone()),
        ("IDトークンをログアウトトークンとして送る", sign(&op_key, &rng, &id_token_header, &id_token)),
        ("events と nonce を両方持つトークン",
            sign(&op_key, &rng, &header, &with(&|c| { c["nonce"] = json!("x"); c["jti"] = json!("j2"); }))),
        ("期限切れ", sign(&op_key, &rng, &header, &with(&|c| { c["exp"] = json!(NOW - 120); c["jti"] = json!("j3"); }))),
        ("別のRP宛て", sign(&op_key, &rng, &header, &with(&|c| { c["aud"] = json!("other-rp"); c["jti"] = json!("j4"); }))),
        ("信頼できない audience を追加", sign(&op_key, &rng, &header,
            &with(&|c| { c["aud"] = json!([CLIENT_ID, "unknown-rp"]); c["jti"] = json!("j8"); }))),
        ("未知の crit 拡張", sign(&op_key, &rng,
            &json!({"alg": "ES256", "typ": "logout+jwt", "kid": "op-key-1", "crit": ["exp-ext"], "exp-ext": 1}),
            &with(&|c| c["jti"] = json!("j9")))),
        ("alg=none", format!("{}.{}.", B64.encode(r#"{"alg":"none"}"#), B64.encode(base.to_string()))),
        ("ペイロードの改ざん", tampered.join(".")),
        ("攻撃者の鍵で署名", sign(&attacker_key, &rng, &header, &with(&|c| c["jti"] = json!("j5")))),
        ("sub も sid もない", sign(&op_key, &rng, &header, &with(&|c| {
            c.as_object_mut().unwrap().remove("sub");
            c.as_object_mut().unwrap().remove("sid");
            c["jti"] = json!("j6");
        }))),
        ("sub が null", sign(&op_key, &rng, &header, &with(&|c| { c["sub"] = Value::Null; c["jti"] = json!("j10"); }))),
        ("sid が数値", sign(&op_key, &rng, &header, &with(&|c| { c["sid"] = json!(123); c["jti"] = json!("j11"); }))),
        ("sid なし(この利用者の全セッション)", sign(&op_key, &rng, &header, &with(&|c| {
            c.as_object_mut().unwrap().remove("sid");
            c["jti"] = json!("j7");
        }))),
    ];
    for (name, token) in cases {
        println!("{name}\n  -> {}", rp.handle(&token));
    }
    let mut left: Vec<_> = rp.sessions.keys().collect();
    left.sort();
    println!("\n残ったセッション: {left:?}");
}
