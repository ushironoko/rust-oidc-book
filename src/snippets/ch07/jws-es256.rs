use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ring::rand::SystemRandom;
use ring::signature::{
    ECDSA_P256_SHA256_FIXED, ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, KeyPair,
    UnparsedPublicKey,
};
use sha2::{Digest, Sha256};

fn b64(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

// 公開鍵 0x04 || x || y (65バイト) を JWK の x と y に分ける
fn public_jwk(public_key: &[u8]) -> serde_json::Value {
    assert_eq!(public_key.len(), 65);
    assert_eq!(public_key[0], 0x04);
    serde_json::json!({
        "kty": "EC",
        "crv": "P-256",
        "x": b64(&public_key[1..33]),
        "y": b64(&public_key[33..65]),
    })
}

// RFC 7638: EC 鍵の必須メンバー crv, kty, x, y を辞書順・空白なしで並べてハッシュする
fn jwk_thumbprint(jwk: &serde_json::Value) -> String {
    let canonical = format!(
        r#"{{"crv":"{}","kty":"{}","x":"{}","y":"{}"}}"#,
        jwk["crv"].as_str().unwrap(),
        jwk["kty"].as_str().unwrap(),
        jwk["x"].as_str().unwrap(),
        jwk["y"].as_str().unwrap(),
    );
    b64(&Sha256::digest(canonical.as_bytes()))
}

// コンパクト形式の JWS を3つに分け、ヘッダの alg が ES256 であることを確かめてから、
// JWK の x と y から組み立てた公開鍵で署名を検証する
fn verify(jwk: &serde_json::Value, jws: &str) -> Result<(), &'static str> {
    let parts: Vec<&str> = jws.split('.').collect();
    let [header_b64, payload_b64, sig_b64] = parts[..] else {
        return Err("'.' で区切った部分が3つではない");
    };
    let header_bytes = URL_SAFE_NO_PAD
        .decode(header_b64)
        .map_err(|_| "ヘッダの Base64url が不正")?;
    let header: serde_json::Value =
        serde_json::from_slice(&header_bytes).map_err(|_| "ヘッダが JSON ではない")?;
    if header["alg"].as_str() != Some("ES256") {
        return Err("ヘッダの alg が ES256 ではない");
    }
    let sig = URL_SAFE_NO_PAD.decode(sig_b64).map_err(|_| "署名の Base64url が不正")?;
    if sig.len() != 64 {
        return Err("ES256 の署名は64バイトでなければならない");
    }
    let x = URL_SAFE_NO_PAD.decode(jwk["x"].as_str().unwrap()).unwrap();
    let y = URL_SAFE_NO_PAD.decode(jwk["y"].as_str().unwrap()).unwrap();
    let point = [&[0x04u8][..], &x, &y].concat();
    let signing_input = format!("{header_b64}.{payload_b64}");
    UnparsedPublicKey::new(&ECDSA_P256_SHA256_FIXED, point)
        .verify(signing_input.as_bytes(), &sig)
        .map_err(|_| "署名が一致しない")
}

fn main() {
    let rng = SystemRandom::new();
    let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng).unwrap();
    let key_pair =
        EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8.as_ref(), &rng).unwrap();

    let jwk = public_jwk(key_pair.public_key().as_ref());
    let kid = jwk_thumbprint(&jwk);
    println!("公開鍵の JWK: {jwk}");
    println!("kid (JWK Thumbprint): {kid}");

    let header = serde_json::json!({ "alg": "ES256", "typ": "JWT", "kid": kid });
    let claims = serde_json::json!({
        "iss": "https://op.example.com",
        "sub": "248289761001",
        "aud": "s6BhdRkqt3",
        "iat": 1_800_000_000,
        "exp": 1_800_000_600,
    });
    let signing_input = format!(
        "{}.{}",
        b64(header.to_string().as_bytes()),
        b64(claims.to_string().as_bytes())
    );
    let sig = key_pair.sign(&rng, signing_input.as_bytes()).unwrap();
    let jws = format!("{signing_input}.{}", b64(sig.as_ref()));

    let parts: Vec<&str> = jws.split('.').collect();
    println!(
        "\nJWS の各部分の文字数: ヘッダ {} / ペイロード {} / 署名 {}",
        parts[0].len(),
        parts[1].len(),
        parts[2].len()
    );
    println!("署名の長さ: {} バイト (r と s が32バイトずつ)", sig.as_ref().len());

    println!("\n正しい JWS の検証: {:?}", verify(&jwk, &jws));

    // ペイロードの sub を書き換え、署名はそのまま付け直す
    let forged_claims = claims.to_string().replace("248289761001", "999999999999");
    let forged = format!("{}.{}.{}", parts[0], b64(forged_claims.as_bytes()), parts[2]);
    println!("sub を書き換えた JWS の検証: {:?}", verify(&jwk, &forged));

    // 別の鍵ペアの公開鍵では検証できない
    let other_pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng).unwrap();
    let other =
        EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, other_pkcs8.as_ref(), &rng)
            .unwrap();
    let other_jwk = public_jwk(other.public_key().as_ref());
    println!("別の公開鍵での検証: {:?}", verify(&other_jwk, &jws));

    // ヘッダの alg を書き換えた JWS と、部分が4つある JWS
    let none_header = b64(br#"{"alg":"none","typ":"JWT"}"#);
    let alg_none = format!("{none_header}.{}.{}", parts[1], parts[2]);
    println!("alg を none に書き換えた JWS の検証: {:?}", verify(&jwk, &alg_none));
    println!("部分が4つある JWS の検証: {:?}", verify(&jwk, &format!("{jws}.x")));

    // ECDSA は署名のたびに乱数を使うため、同じ入力でも署名の値は毎回変わる
    let sig2 = key_pair.sign(&rng, signing_input.as_bytes()).unwrap();
    println!("\n同じ入力にもう一度署名した値が1回目と同じ: {}", sig.as_ref() == sig2.as_ref());
    let jws2 = format!("{signing_input}.{}", b64(sig2.as_ref()));
    println!("2回目の署名の検証: {:?}", verify(&jwk, &jws2));
}
