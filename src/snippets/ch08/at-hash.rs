use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use sha2::{Digest, Sha256, Sha384, Sha512};

// alg の末尾の数字がハッシュ関数を決める(RS256/ES256/PS256 → SHA-256)
fn hash_for_alg(alg: &str, data: &[u8]) -> Option<Vec<u8>> {
    match &alg[alg.len().saturating_sub(3)..] {
        "256" => Some(Sha256::digest(data).to_vec()),
        "384" => Some(Sha384::digest(data).to_vec()),
        "512" => Some(Sha512::digest(data).to_vec()),
        _ => None,
    }
}

// at_hash = BASE64URL(ハッシュの左半分)
fn at_hash(alg: &str, access_token: &str) -> Option<String> {
    let digest = hash_for_alg(alg, access_token.as_bytes())?;
    Some(URL_SAFE_NO_PAD.encode(&digest[..digest.len() / 2]))
}

fn main() {
    // OpenID Connect Core 1.0 A.3節の例(ID トークンの alg は RS256)
    let access_token = "jHkWEdUXMU1BwAsC4vtUsZwnNvTIxEl0z9K3vx5KF0Y";
    let claimed = "77QmUPtjPfzWtF2AnpK9RQ";

    let digest = Sha256::digest(access_token.as_bytes());
    println!("SHA-256(access_token) = {} バイト", digest.len());
    println!("左半分 = {} バイト", digest.len() / 2);

    let computed = at_hash("RS256", access_token).unwrap();
    println!("\n計算した at_hash: {computed}");
    println!("ID トークンの at_hash: {claimed}");
    println!("一致: {}", computed == claimed);

    // 攻撃者が別のアクセストークンに差し替えた場合
    let swapped = "SlAV32hkKG";
    let computed = at_hash("RS256", swapped).unwrap();
    println!("\n差し替えたトークン {swapped} の at_hash: {computed}");
    println!("一致: {}", computed == claimed);

    // alg ごとの長さ
    println!();
    for alg in ["ES256", "RS384", "ES512"] {
        let v = at_hash(alg, access_token).unwrap();
        println!("alg={alg}: at_hash は {} 文字 ({v})", v.len());
    }
}
