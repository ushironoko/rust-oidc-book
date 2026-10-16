use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use hmac::{Hmac, KeyInit, Mac};
use ring::signature::{RSA_PKCS1_2048_8192_SHA256, UnparsedPublicKey};
use sha2::Sha256;

// RFC 7515 付録A.2 の RSA 公開鍵(n, e)と RS256 の JWS
const N: &str = "ofgWCuLjybRlzo0tZWJjNiuSfb4p4fAkd_wWJcyQoTbji9k0l8W26mPddxHmfHQp-Vaw-4qPCJrcS2mJPMEzP1Pt0Bm4d4QlL-yRT-SFd2lZS-pCgNMsD1W_YpRPEwOWvG6b32690r2jZ47soMZo9wGzjb_7OMg0LOL-bSf63kpaSHSXndS5z5rexMdbBYUsLA9e-KXBdQOS-UTo7WTBEMa2R2CapHg665xsmtdVMTBQY4uDZlxvb3qCo5ZwKh9kG4LT6_I5IhlJH7aGhyxXFvUK-DWNmoudF8NAco9_h9iaGNj8q2ethFkMLs91kzk2PAcDTW9gb54h4FRWyuXpoQ";
const E: &str = "AQAB";
const RFC7515_A2: &str = "eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.cC4hiUPoj9Eetdgtv3hF80EGrhuB__dzERat0XF9g2VtQgr9PJbu3XOiZj5RZmh7AAuHIm4Bh-0Qc_lF5YKt_O8W2Fp5jujGbds9uJdbF9CUAr7t1dnZcAcQjbKBYNX4BAynRFdiuB--f_nZLgrnbyTyWzO75vRK5h6xBArLIARNPvkSjtQBMHlb1L07Qe7K0GarZRmB_eSN9383LcOLn6_dO--xi12jzDwusC-eOkHWEsqtFZESc6BfI7noOPqvhJ1phCnvWh6IeYI2w9QOYEUipUTI8np6LbgGY9Fs98rqVt5AXLIhWkWywlVmtVrBp0igcN_IoypGlUPQGe77Rw";

// DER の長さ部
fn der_len(len: usize) -> Vec<u8> {
    match len {
        0..=127 => vec![len as u8],
        128..=255 => vec![0x81, len as u8],
        _ => vec![0x82, (len >> 8) as u8, len as u8],
    }
}

// INTEGER: 先頭ビットが1なら 0x00 を前置して正の数にする
fn der_int(bytes: &[u8]) -> Vec<u8> {
    let mut v = bytes.to_vec();
    if v[0] & 0x80 != 0 {
        v.insert(0, 0);
    }
    [vec![0x02], der_len(v.len()), v].concat()
}

// RSAPublicKey ::= SEQUENCE { modulus INTEGER, publicExponent INTEGER }
fn rsa_public_key_der(n: &[u8], e: &[u8]) -> Vec<u8> {
    let body = [der_int(n), der_int(e)].concat();
    [vec![0x30], der_len(body.len()), body].concat()
}

fn split(token: &str) -> Option<(&str, &str, Vec<u8>)> {
    let (signing_input, sig) = token.rsplit_once('.')?;
    let (_, payload) = signing_input.split_once('.')?;
    Some((signing_input, payload, B64.decode(sig).ok()?))
}

fn header_alg(token: &str) -> Option<String> {
    let h = B64.decode(token.split('.').next()?).ok()?;
    let v: serde_json::Value = serde_json::from_slice(&h).ok()?;
    Some(v["alg"].as_str()?.to_string())
}

fn hs256(key: &[u8], msg: &[u8]) -> Vec<u8> {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).unwrap();
    mac.update(msg);
    mac.finalize().into_bytes().to_vec()
}

fn verify_with(alg: &str, key: &[u8], signing_input: &str, sig: &[u8]) -> Result<(), String> {
    match alg {
        "RS256" => UnparsedPublicKey::new(&RSA_PKCS1_2048_8192_SHA256, key)
            .verify(signing_input.as_bytes(), sig)
            .map_err(|_| "RS256 署名が一致しない".to_string()),
        "HS256" => {
            let mut mac = Hmac::<Sha256>::new_from_slice(key).unwrap();
            mac.update(signing_input.as_bytes());
            mac.verify_slice(sig).map_err(|_| "HS256 の MAC が一致しない".to_string())
        }
        other => Err(format!("未対応の alg: {other}")),
    }
}

// 脆弱な検証器: ヘッダの alg を信用し、同じ鍵バイト列をそのアルゴリズムに渡す
fn vulnerable_verify(token: &str, key: &[u8]) -> Result<String, String> {
    let alg = header_alg(token).ok_or("ヘッダを解析できない")?;
    let (input, payload, sig) = split(token).ok_or("形式が不正")?;
    verify_with(&alg, key, input, &sig)?;
    Ok(String::from_utf8(B64.decode(payload).unwrap()).unwrap())
}

// 安全な検証器: 鍵ごとに alg を固定し、ヘッダの alg は一致確認にだけ使う
struct PinnedKey {
    alg: &'static str,
    key: Vec<u8>,
}

fn safe_verify(token: &str, k: &PinnedKey) -> Result<String, String> {
    let alg = header_alg(token).ok_or("ヘッダを解析できない")?;
    if alg != k.alg {
        return Err(format!("ヘッダの alg={alg} は鍵に固定した {} と異なる", k.alg));
    }
    let (input, payload, sig) = split(token).ok_or("形式が不正")?;
    verify_with(k.alg, &k.key, input, &sig)?;
    Ok(String::from_utf8(B64.decode(payload).unwrap()).unwrap())
}

fn show(label: &str, r: Result<String, String>) {
    match r {
        Ok(p) => println!("  {label}: 受理  payload={}", p.replace("\r\n", "")),
        Err(e) => println!("  {label}: 拒否  ({e})"),
    }
}

fn main() {
    let n = B64.decode(N).unwrap();
    let e = B64.decode(E).unwrap();
    let public_der = rsa_public_key_der(&n, &e);
    println!("公開鍵(RSAPublicKey の DER): {} バイト、先頭 {:02x?}", public_der.len(), &public_der[..8]);
    let pinned = PinnedKey { alg: "RS256", key: public_der.clone() };

    println!();
    println!("[1] RFC 7515 A.2 の正規トークン (alg=RS256)");
    show("脆弱な検証器", vulnerable_verify(RFC7515_A2, &public_der));
    show("安全な検証器", safe_verify(RFC7515_A2, &pinned));

    // 攻撃者は jwks_uri から n, e を取得し、同じ DER を組み立てて HMAC 鍵にする
    let attacker_key = rsa_public_key_der(&n, &e);
    let header = B64.encode(br#"{"alg":"HS256"}"#);
    let payload = B64.encode(br#"{"iss":"joe","exp":1300819380,"http://example.com/is_root":true,"sub":"admin"}"#);
    let input = format!("{header}.{payload}");
    let forged = format!("{input}.{}", B64.encode(hs256(&attacker_key, input.as_bytes())));

    println!();
    println!("[2] 偽造トークン (alg=HS256、公開鍵の DER を HMAC 鍵に使用)");
    show("脆弱な検証器", vulnerable_verify(&forged, &public_der));
    show("安全な検証器", safe_verify(&forged, &pinned));
}
