use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;

// RFC 7515 付録A.1 の値。ヘッダとペイロードは行の区切りに CRLF と空白1つを含む
const HEADER_JSON: &str = "{\"typ\":\"JWT\",\r\n \"alg\":\"HS256\"}";
const PAYLOAD_JSON: &str =
    "{\"iss\":\"joe\",\r\n \"exp\":1300819380,\r\n \"http://example.com/is_root\":true}";
const HEADER_OCTETS: [u8; 30] = [
    123, 34, 116, 121, 112, 34, 58, 34, 74, 87, 84, 34, 44, 13, 10, 32, 34, 97, 108, 103, 34,
    58, 34, 72, 83, 50, 53, 54, 34, 125,
];
const KEY_K: &str =
    "AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow";
const EXPECTED_SIGNATURE: [u8; 32] = [
    116, 24, 223, 180, 151, 153, 224, 37, 79, 250, 96, 125, 216, 173, 187, 186, 22, 212, 37,
    77, 105, 214, 191, 240, 91, 88, 5, 88, 83, 132, 141, 121,
];
const EXPECTED_B64: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";

// 署名入力 ASCII(BASE64URL(UTF8(ヘッダ)) || '.' || BASE64URL(ペイロード)) を作る
fn signing_input(header: &str, payload: &str) -> String {
    format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(header.as_bytes()),
        URL_SAFE_NO_PAD.encode(payload.as_bytes())
    )
}

fn hs256(key: &[u8], input: &str) -> Vec<u8> {
    let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(key).expect("HMAC は任意長の鍵を受け付ける");
    mac.update(input.as_bytes());
    mac.finalize().into_bytes().to_vec()
}

fn main() {
    println!("ヘッダのバイト列が RFC の配列と一致: {}", HEADER_JSON.as_bytes() == HEADER_OCTETS);

    let key = URL_SAFE_NO_PAD.decode(KEY_K).expect("鍵の Base64url");
    println!("鍵の長さ: {} バイト", key.len());

    let input = signing_input(HEADER_JSON, PAYLOAD_JSON);
    println!("\n署名入力:\n{input}");

    let sig = hs256(&key, &input);
    let sig_b64 = URL_SAFE_NO_PAD.encode(&sig);
    println!("\n計算した署名: {sig_b64}");
    println!("RFC 記載の署名: {EXPECTED_B64}");
    println!("バイト列が一致: {} / 文字列が一致: {}", sig == EXPECTED_SIGNATURE, sig_b64 == EXPECTED_B64);

    println!("\nJWS コンパクトシリアライゼーション:\n{input}.{sig_b64}");

    // 受信側の検証: verify_slice は定数時間で比較する
    let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(&key).unwrap();
    mac.update(input.as_bytes());
    println!("\n受信側の検証(verify_slice): {:?}", mac.verify_slice(&EXPECTED_SIGNATURE).is_ok());

    // 同じ意味の JSON を空白なしで書き直すと、署名入力も署名も変わる
    let compact_header = "{\"typ\":\"JWT\",\"alg\":\"HS256\"}";
    let compact_payload = "{\"iss\":\"joe\",\"exp\":1300819380,\"http://example.com/is_root\":true}";
    let a: serde_json::Value = serde_json::from_str(HEADER_JSON).unwrap();
    let b: serde_json::Value = serde_json::from_str(compact_header).unwrap();
    println!("\n空白を除いたヘッダは JSON として同じ値: {}", a == b);
    let sig2 = URL_SAFE_NO_PAD.encode(hs256(&key, &signing_input(compact_header, compact_payload)));
    println!("空白を除いて計算した署名: {sig2}");
    println!("RFC の署名と一致: {}", sig2 == EXPECTED_B64);
}
