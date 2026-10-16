use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ring::rand::SystemRandom;
use ring::signature::{
    self, ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, KeyPair, RsaPublicKeyComponents,
    UnparsedPublicKey,
};
use serde_json::{Value, json};
use subtle::ConstantTimeEq;

// 検証に使う公開鍵。1つの鍵は1つの alg にだけ使う
enum KeyMaterial {
    EcP256 { point: Vec<u8> },
    Rsa { n: Vec<u8>, e: Vec<u8> },
}

struct Jwk {
    kid: String,
    alg: &'static str,
    key: KeyMaterial,
}

// RP が事前に持っている値(Discovery と登録で得る)
struct RpConfig {
    issuer: &'static str,
    client_id: &'static str,
    allowed_algs: &'static [&'static str],
    trusted_extra_audiences: &'static [&'static str],
    leeway: i64,
    max_iat_age: i64,
}

// この認証リクエストに固有の値(セッションに保存しておく)
struct Expected<'a> {
    nonce: &'a str,
}

#[derive(Debug)]
struct IdClaims {
    sub: String,
    exp: i64,
}

fn b64d(s: &str) -> Result<Vec<u8>, String> {
    URL_SAFE_NO_PAD
        .decode(s)
        .map_err(|_| "Base64url として不正".to_string())
}

// NumericDate は小数も許される(RFC 7519 2節)。小数部は切り捨て、i64 に収まらない値は拒否する
fn numeric_date(claims: &Value, name: &str) -> Result<i64, String> {
    let n = claims[name].as_number().ok_or(format!("{name} がないか数値ではない"))?;
    if let Some(i) = n.as_i64() {
        return Ok(i);
    }
    match n.as_f64() {
        Some(f) if f.is_finite() && f >= i64::MIN as f64 && f < i64::MAX as f64 => {
            Ok(f.floor() as i64)
        }
        _ => Err(format!("{name} が扱える範囲の数値ではない")),
    }
}

// 手順の順序: 形式 → alg → 鍵 → 署名 → (ここで初めてペイロードを読む) → クレーム
fn validate(
    token: &str,
    cfg: &RpConfig,
    jwks: &[Jwk],
    expected: &Expected,
    now: i64,
) -> Result<IdClaims, String> {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() == 5 {
        return Err("暗号化された ID トークン(JWE)は受け付けない設定".into());
    }
    let [h64, p64, s64] = parts[..] else {
        return Err("JWS コンパクトシリアライゼーションではない".into());
    };

    let header: Value = serde_json::from_slice(&b64d(h64)?).map_err(|_| "ヘッダが JSON ではない")?;
    if header.get("crit").is_some() {
        return Err("crit の拡張には対応していない".into());
    }
    let alg = header["alg"].as_str().ok_or("alg がない")?;
    if !cfg.allowed_algs.contains(&alg) {
        return Err(format!("alg={alg} は許可リスト {:?} にない", cfg.allowed_algs));
    }

    let kid = header["kid"].as_str().ok_or("kid がない")?;
    let jwk = jwks
        .iter()
        .find(|k| k.kid == kid)
        .ok_or(format!("kid={kid} の鍵を持っていない"))?;
    if jwk.alg != alg {
        return Err(format!("kid={kid} の鍵は {} 用で、alg={alg} には使えない", jwk.alg));
    }

    let signing_input = format!("{h64}.{p64}");
    let sig = b64d(s64)?;
    let verified = match &jwk.key {
        KeyMaterial::EcP256 { point } => {
            UnparsedPublicKey::new(&signature::ECDSA_P256_SHA256_FIXED, point)
                .verify(signing_input.as_bytes(), &sig)
        }
        KeyMaterial::Rsa { n, e } => RsaPublicKeyComponents { n, e }.verify(
            &signature::RSA_PKCS1_2048_8192_SHA256,
            signing_input.as_bytes(),
            &sig,
        ),
    };
    verified.map_err(|_| "署名が一致しない")?;

    let claims: Value =
        serde_json::from_slice(&b64d(p64)?).map_err(|_| "ペイロードが JSON ではない")?;

    let iss = claims["iss"].as_str().ok_or("iss がない")?;
    if iss != cfg.issuer {
        return Err(format!("iss={iss} は期待する {} と完全一致しない", cfg.issuer));
    }

    let auds: Vec<&str> = match &claims["aud"] {
        Value::String(s) => vec![s.as_str()],
        Value::Array(a) => a
            .iter()
            .map(|v| v.as_str().ok_or("aud の配列に文字列以外の要素がある"))
            .collect::<Result<_, _>>()?,
        _ => return Err("aud がないか、文字列でも配列でもない".into()),
    };
    if !auds.contains(&cfg.client_id) {
        return Err(format!("aud={auds:?} に自分の client_id がない"));
    }
    if let Some(other) = auds
        .iter()
        .find(|a| **a != cfg.client_id && !cfg.trusted_extra_audiences.contains(a))
    {
        return Err(format!("aud に信頼しない宛先 {other} が含まれる"));
    }

    match claims.get("azp") {
        None => {}
        Some(Value::String(azp)) if azp == cfg.client_id => {}
        Some(Value::String(azp)) => return Err(format!("azp={azp} が自分の client_id ではない")),
        Some(_) => return Err("azp が文字列ではない".into()),
    }

    // now と設定値の側で加減算し、攻撃者が書ける exp と iat の側では桁あふれを起こさない
    let exp = numeric_date(&claims, "exp")?;
    if now - cfg.leeway >= exp {
        return Err(format!("期限切れ (exp から {} 秒経過)", now.saturating_sub(exp)));
    }

    let iat = numeric_date(&claims, "iat")?;
    if iat > now + cfg.leeway {
        return Err("iat が未来の時刻".into());
    }
    if iat < now - cfg.max_iat_age {
        return Err(format!("発行から {} 秒経っていて古すぎる", now.saturating_sub(iat)));
    }

    let nonce = claims["nonce"].as_str().ok_or("nonce がない")?;
    if !bool::from(nonce.as_bytes().ct_eq(expected.nonce.as_bytes())) {
        return Err("nonce が認証リクエストで送った値と一致しない".into());
    }

    let sub = claims["sub"].as_str().ok_or("sub がない")?;
    if !sub.is_ascii() || sub.len() > 255 {
        return Err("sub が255文字以下の ASCII 文字列ではない".into());
    }
    Ok(IdClaims { sub: sub.to_string(), exp })
}

fn b64(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

// テスト用の OP: ES256 で ID トークンに署名する
struct TestOp {
    key_pair: EcdsaKeyPair,
    rng: SystemRandom,
}

impl TestOp {
    fn sign(&self, header: &Value, claims: &Value) -> String {
        let input = format!(
            "{}.{}",
            b64(header.to_string().as_bytes()),
            b64(claims.to_string().as_bytes())
        );
        let sig = self.key_pair.sign(&self.rng, input.as_bytes()).unwrap();
        format!("{input}.{}", b64(sig.as_ref()))
    }
}

const NOW: i64 = 1_800_000_000;
const ISSUER: &str = "https://op.example.com";
const CLIENT_ID: &str = "rp-demo";
const NONCE: &str = "n-Wq3vZ8kF1tQx";

fn good_claims() -> Value {
    json!({
        "iss": ISSUER, "sub": "248289761001", "aud": CLIENT_ID,
        "nonce": NONCE, "iat": NOW - 5, "exp": NOW + 300,
    })
}

fn with(mut v: Value, key: &str, value: Value) -> Value {
    v[key] = value;
    v
}

fn without(mut v: Value, key: &str) -> Value {
    v.as_object_mut().unwrap().remove(key);
    v
}

// OpenID Connect Core 1.0 A.3節の ID トークン(RS256)と A.7節の公開鍵
const CORE_A3_TOKEN: &str = concat!(
    "eyJraWQiOiIxZTlnZGs3IiwiYWxnIjoiUlMyNTYifQ.",
    "ewogImlzcyI6ICJodHRwczovL3NlcnZlci5leGFtcGxlLmNvbSIsCiAic3ViIjog",
    "IjI0ODI4OTc2MTAwMSIsCiAiYXVkIjogInM2QmhkUmtxdDMiLAogIm5vbmNlIjog",
    "Im4tMFM2X1d6QTJNaiIsCiAiZXhwIjogMTMxMTI4MTk3MCwKICJpYXQiOiAxMzEx",
    "MjgwOTcwLAogImF0X2hhc2giOiAiNzdRbVVQdGpQZnpXdEYyQW5wSzlSUSIKfQ.",
    "kdqTmftlaXg5WBYBr1wkxhkqCGZPc0k8vTiV5g2jj67jQ7XkrDamYx2bOkZLdZrp",
    "MPIzkdYB1nZI_G8vQGQuamRhJcEIt21kblGPZ-yhEhdkAiZIZLu38rChalDS2Mh0",
    "glE_rke5XXRhmqqoEFFdziFdnO3p61-7y51co84OEAZvARSINQaOWIzvioRfs4zw",
    "IFOaT33Vpxfqr8HDyh31zo9eBW2dSQuCa071z0ENWChWoPliK1JCo_Bk9eDg2uwo",
    "2ZwhsvHzj6TMQ0lYOTzufSlSmXIKfjlOsb3nftQeR697_hA-nMZyAdL8_NRfaC37",
    "XnAbW8WB9wCfECp7cuNuOg",
);
const CORE_3133_TOKEN: &str = concat!(
    "eyJhbGciOiJSUzI1NiIsImtpZCI6IjFlOWdkazcifQ.ewogImlzc",
    "yI6ICJodHRwOi8vc2VydmVyLmV4YW1wbGUuY29tIiwKICJzdWIiOiAiMjQ4Mjg5",
    "NzYxMDAxIiwKICJhdWQiOiAiczZCaGRSa3F0MyIsCiAibm9uY2UiOiAibi0wUzZ",
    "fV3pBMk1qIiwKICJleHAiOiAxMzExMjgxOTcwLAogImlhdCI6IDEzMTEyODA5Nz",
    "AKfQ.ggW8hZ1EuVLuxNuuIJKX_V8a_OMXzR0EHR9R6jgdqrOOF4daGU96Sr_P6q",
    "Jp6IcmD3HP99Obi1PRs-cwh3LO-p146waJ8IhehcwL7F09JdijmBqkvPeB2T9CJ",
    "NqeGpe-gccMg4vfKjkM8FcGvnzZUN4_KSP0aAp1tOJ1zZwgjxqGByKHiOtX7Tpd",
    "QyHE5lcMiKPXfEIQILVq0pc_E2DzL7emopWoaoZTF_m0_N0YzFC6g6EJbOEoRoS",
    "K5hoDalrcvRYLSrQAZZKflyuVCyixEoV9GfNQC3_osjzw2PAithfubEEBLuVVk4",
    "XUVrWOLrLl0nx7RkKU8NXNHq-rvKMzqg",
);
const CORE_A7_N: &str = concat!(
    "w7Zdfmece8iaB0kiTY8pCtiBtzbptJmP28nSWwtdjRu0f2GFpajvWE4VhfJA",
    "jEsOcwYzay7XGN0b-X84BfC8hmCTOj2b2eHT7NsZegFPKRUQzJ9wW8ipn_aD",
    "JWMGDuB1XyqT1E7DYqjUCEOD1b4FLpy_xPn6oV_TYOfQ9fZdbE5HGxJUzeku",
    "GcOKqOQ8M7wfYHhHHLxGpQVgL0apWuP2gDDOdTtpuld4D2LK1MZK99s9gaSj",
    "RHE8JDb1Z4IGhEcEyzkxswVdPndUWzfvWBBWXWxtSUvQGBRkuy1BHOa4sP6F",
    "KjWEeeF7gm7UMs2Nm2QUgNZw6xvEDGaLk4KASdIxRQ",
);

fn report(label: &str, result: Result<IdClaims, String>) {
    match result {
        Ok(c) => println!("[受理] {label}: sub={} exp={}", c.sub, c.exp),
        Err(e) => println!("[拒否] {label}: {e}"),
    }
}

fn main() {
    let rng = SystemRandom::new();
    let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng).unwrap();
    let key_pair =
        EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8.as_ref(), &rng).unwrap();
    let point = key_pair.public_key().as_ref().to_vec();
    let op = TestOp { key_pair, rng };

    let jwks = vec![
        Jwk { kid: "ec-2026".into(), alg: "ES256", key: KeyMaterial::EcP256 { point } },
        Jwk {
            kid: "1e9gdk7".into(),
            alg: "RS256",
            key: KeyMaterial::Rsa {
                n: b64d(CORE_A7_N).unwrap(),
                e: b64d("AQAB").unwrap(),
            },
        },
    ];
    let cfg = RpConfig {
        issuer: ISSUER,
        client_id: CLIENT_ID,
        allowed_algs: &["ES256", "RS256"],
        trusted_extra_audiences: &[],
        leeway: 60,
        max_iat_age: 600,
    };
    let expected = Expected { nonce: NONCE };
    let es256 = json!({ "alg": "ES256", "kid": "ec-2026", "typ": "JWT" });
    let check = |label: &str, token: &str| report(label, validate(token, &cfg, &jwks, &expected, NOW));

    println!("== 署名とヘッダの検査 ==");
    check("正しい ID トークン", &op.sign(&es256, &good_claims()));

    let none_token = format!(
        "{}.{}.",
        b64(br#"{"alg":"none"}"#),
        b64(good_claims().to_string().as_bytes())
    );
    check("alg=none で署名なし", &none_token);
    check("alg=HS256", &op.sign(&json!({ "alg": "HS256", "kid": "ec-2026" }), &good_claims()));
    check("知らない kid", &op.sign(&json!({ "alg": "ES256", "kid": "ec-1999" }), &good_claims()));
    check("RSA 鍵の kid に alg=ES256", &op.sign(&json!({ "alg": "ES256", "kid": "1e9gdk7" }), &good_claims()));
    let crit = json!({ "alg": "ES256", "kid": "ec-2026", "crit": ["exp"], "exp": NOW });
    check("知らない crit の拡張", &op.sign(&crit, &good_claims()));

    let token = op.sign(&es256, &good_claims());
    let parts: Vec<&str> = token.split('.').collect();
    let forged_payload = b64(with(good_claims(), "sub", json!("999999999999")).to_string().as_bytes());
    check("署名後に sub を書き換え", &format!("{}.{}.{}", parts[0], forged_payload, parts[2]));

    println!("\n== クレームの検査 (署名は正しい) ==");
    let signed = |claims: Value| op.sign(&es256, &claims);
    check("iss の末尾に /", &signed(with(good_claims(), "iss", json!("https://op.example.com/"))));
    check("別のクライアント宛て", &signed(with(good_claims(), "aud", json!("other-rp"))));
    check("aud に知らない宛先も含む", &signed(with(good_claims(), "aud", json!([CLIENT_ID, "unknown-api"]))));
    check("aud の配列に数値", &signed(with(good_claims(), "aud", json!([CLIENT_ID, 123]))));
    check("azp が別のクライアント", &signed(with(good_claims(), "azp", json!("other-rp"))));
    check("azp が数値", &signed(with(good_claims(), "azp", json!(123))));
    check("exp を30秒過ぎた", &signed(with(good_claims(), "exp", json!(NOW - 30))));
    check("exp を120秒過ぎた", &signed(with(good_claims(), "exp", json!(NOW - 120))));
    check("exp が小数", &signed(with(good_claims(), "exp", json!(NOW as f64 + 300.5))));
    check("exp が i64 の最大値", &signed(with(good_claims(), "exp", json!(i64::MAX))));
    check("iat が i64 の最小値", &signed(with(good_claims(), "iat", json!(i64::MIN))));
    let old = with(with(good_claims(), "iat", json!(NOW - 3600)), "exp", json!(NOW + 3600));
    check("1時間前に発行された", &signed(old));
    check("nonce が違う", &signed(with(good_claims(), "nonce", json!("n-attacker"))));
    check("nonce がない", &signed(without(good_claims(), "nonce")));
    check("sub が256文字", &signed(with(good_claims(), "sub", json!("a".repeat(256)))));
    check("sub に ASCII 以外", &signed(with(good_claims(), "sub", json!("ユーザー1"))));

    println!("\n== OpenID Connect Core 1.0 の例 (RS256) ==");
    let core_cfg = RpConfig { issuer: "https://server.example.com", client_id: "s6BhdRkqt3", ..cfg };
    let core_expected = Expected { nonce: "n-0S6_WzA2Mj" };
    let core_now = 1_311_281_000;
    report("A.3節の ID トークン", validate(CORE_A3_TOKEN, &core_cfg, &jwks, &core_expected, core_now));
    report("3.1.3.3節の ID トークン", validate(CORE_3133_TOKEN, &core_cfg, &jwks, &core_expected, core_now));
    report("A.3節を NOW で検証", validate(CORE_A3_TOKEN, &core_cfg, &jwks, &core_expected, NOW));
}
