use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use ring::rand::SystemRandom;
use ring::signature::{
    ECDSA_P256_SHA256_FIXED, ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, KeyPair,
    UnparsedPublicKey,
};
use serde_json::{Value, json};

const ISS: &str = "https://op.example";
// 本文の例ではクライアントIDとAPIの識別子が同じ URL になっている
const APP: &str = "https://app.example";
const NOW: i64 = 1_790_000_000;

fn sign(kp: &EcdsaKeyPair, rng: &SystemRandom, header: Value, claims: Value) -> String {
    let input = format!("{}.{}", B64.encode(header.to_string()), B64.encode(claims.to_string()));
    let sig = kp.sign(rng, input.as_bytes()).unwrap();
    format!("{input}.{}", B64.encode(sig.as_ref()))
}

struct Checked {
    header: Value,
    claims: Value,
}

// 署名・iss・exp だけを確かめる共通部分(alg は ES256 に固定)
fn verify_common(token: &str, public: &[u8]) -> Result<Checked, String> {
    let (input, sig) = token.rsplit_once('.').ok_or("形式が不正")?;
    let (h, p) = input.split_once('.').ok_or("形式が不正")?;
    let header: Value = serde_json::from_slice(&B64.decode(h).map_err(|e| e.to_string())?)
        .map_err(|e| e.to_string())?;
    if header["alg"] != "ES256" {
        return Err("alg が ES256 ではない".into());
    }
    UnparsedPublicKey::new(&ECDSA_P256_SHA256_FIXED, public)
        .verify(input.as_bytes(), &B64.decode(sig).map_err(|e| e.to_string())?)
        .map_err(|_| "署名が一致しない")?;
    let claims: Value = serde_json::from_slice(&B64.decode(p).unwrap()).unwrap();
    if claims["iss"] != ISS {
        return Err("iss が一致しない".into());
    }
    if claims["exp"].as_i64().unwrap_or(0) <= NOW {
        return Err("期限切れ".into());
    }
    Ok(Checked { header, claims })
}

// RFC 7515 4.1.9: "/" を含まない typ は "application/" を前置して比べる。メディアタイプは大小文字を区別しない
fn media_type(typ: &str) -> String {
    let t = typ.to_ascii_lowercase();
    if t.contains('/') { t } else { format!("application/{t}") }
}

fn rs_naive(token: &str, public: &[u8]) -> Result<(), String> {
    verify_common(token, public).map(|_| ())
}

fn rs_with_aud(token: &str, public: &[u8]) -> Result<(), String> {
    let c = verify_common(token, public)?;
    if c.claims["aud"] != APP {
        return Err("aud が一致しない".into());
    }
    Ok(())
}

// RFC 9068 4節: typ が at+jwt か application/at+jwt でなければ拒否
fn rs_with_typ(token: &str, public: &[u8]) -> Result<(), String> {
    let c = verify_common(token, public)?;
    let typ = c.header["typ"].as_str().unwrap_or("");
    if media_type(typ) != "application/at+jwt" {
        return Err(format!("typ={typ:?} はアクセストークンではない"));
    }
    if c.claims["aud"] != APP {
        return Err("aud が一致しない".into());
    }
    Ok(())
}

fn main() {
    let rng = SystemRandom::new();
    let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng).unwrap();
    let kp = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8.as_ref(), &rng).unwrap();
    let public = kp.public_key().as_ref().to_vec();

    // OP が同じ鍵で発行した2種類の JWT
    let access_token = sign(&kp, &rng,
        json!({"alg": "ES256", "typ": "at+jwt", "kid": "op-2026"}),
        json!({"iss": ISS, "sub": "248289761001", "aud": APP, "client_id": APP,
               "scope": "orders:read", "iat": NOW - 60, "exp": NOW + 300, "jti": "at-1"}));
    let id_token = sign(&kp, &rng,
        json!({"alg": "ES256", "typ": "JWT", "kid": "op-2026"}),
        json!({"iss": ISS, "sub": "248289761001", "aud": APP, "nonce": "n-0S6_WzA2Mj",
               "iat": NOW - 60, "exp": NOW + 300}));
    let other_rp_id_token = sign(&kp, &rng,
        json!({"alg": "ES256", "kid": "op-2026"}),
        json!({"iss": ISS, "sub": "248289761001", "aud": "https://other-rp.example",
               "iat": NOW - 60, "exp": NOW + 300}));

    let cases = [
        ("アクセストークン(typ=at+jwt)", &access_token),
        ("同じアプリ宛の ID トークン(typ=JWT)", &id_token),
        ("別 RP 宛の ID トークン(typ なし)", &other_rp_id_token),
    ];
    for (label, t) in cases {
        println!("[{label}]");
        for (name, f) in [
            ("署名+iss+exp", rs_naive as fn(&str, &[u8]) -> Result<(), String>),
            ("+aud        ", rs_with_aud),
            ("+aud+typ    ", rs_with_typ),
        ] {
            match f(t, &public) {
                Ok(()) => println!("  {name}: 受理"),
                Err(e) => println!("  {name}: 拒否 ({e})"),
            }
        }
    }
    println!();
    for t in ["at+jwt", "application/at+jwt", "AT+JWT", "JWT", "jwt"] {
        println!("typ={t:<20} => {}", media_type(t));
    }
}
