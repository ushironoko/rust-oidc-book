use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use sha2::{Digest, Sha256};

// RFC 7638 3.1節の例の RSA 公開鍵(n は表示用の改行を除いて連結したもの)
const N: &str = concat!(
    "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAt",
    "VT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn6",
    "4tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FD",
    "W2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n9",
    "1CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINH",
    "aQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
);
const E: &str = "AQAB";
const EXPECTED_DIGEST: [u8; 32] = [
    55, 54, 203, 177, 120, 124, 184, 48, 156, 119, 238, 140, 55, 5, 197, 225, 111, 251, 158,
    133, 151, 21, 144, 31, 30, 76, 89, 177, 17, 130, 245, 123,
];
const EXPECTED_B64: &str = "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs";

fn thumbprint(canonical_json: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(canonical_json.as_bytes()))
}

fn main() {
    // 必須メンバー e, kty, n だけを名前の辞書順に並べ、空白を入れずに書く
    let canonical = format!(r#"{{"e":"{E}","kty":"RSA","n":"{N}"}}"#);
    println!("ハッシュ入力: {} バイト", canonical.len());
    println!("先頭: {}...", &canonical[..40]);

    let digest = Sha256::digest(canonical.as_bytes());
    println!("\nSHA-256 が RFC の配列と一致: {}", digest[..] == EXPECTED_DIGEST);
    let tp = thumbprint(&canonical);
    println!("計算した JWK Thumbprint: {tp}");
    println!("RFC 記載の値:            {EXPECTED_B64}");
    println!("一致: {}", tp == EXPECTED_B64);

    // n をバイト列に戻すと鍵の大きさがわかる
    let n_bytes = URL_SAFE_NO_PAD.decode(N).unwrap();
    println!("\nn は {} バイト ({} ビットの RSA 鍵)", n_bytes.len(), n_bytes.len() * 8);

    // 規則を外した入力では別の値になる
    let with_optional = format!(
        r#"{{"alg":"RS256","e":"{E}","kid":"2011-04-29","kty":"RSA","n":"{N}"}}"#
    );
    let wrong_order = format!(r#"{{"kty":"RSA","n":"{N}","e":"{E}"}}"#);
    let with_spaces = format!(r#"{{"e": "{E}", "kty": "RSA", "n": "{N}"}}"#);
    println!("\nalg と kid も含めた場合: {}", thumbprint(&with_optional));
    println!("メンバーの順序を変えた場合: {}", thumbprint(&wrong_order));
    println!("空白を入れた場合:         {}", thumbprint(&with_spaces));

    // serde_json の Map は既定で名前の順に並び、to_string は空白を入れない
    let v = serde_json::json!({ "n": N, "kty": "RSA", "e": E });
    let via_serde = serde_json::to_string(&v).unwrap();
    println!("\nserde_json で組み立てた入力が手書きと同じ: {}", via_serde == canonical);
}
