use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use sha2::{Digest, Sha256, Sha384, Sha512};

// alg のハッシュ関数で値をハッシュし、左半分を base64url にする
fn left_half_hash(alg: &str, value: &str) -> String {
    let digest: Vec<u8> = match &alg[2..] {
        "256" => Sha256::digest(value.as_bytes()).to_vec(),
        "384" => Sha384::digest(value.as_bytes()).to_vec(),
        "512" => Sha512::digest(value.as_bytes()).to_vec(),
        _ => panic!("未対応の alg: {alg}"),
    };
    URL_SAFE_NO_PAD.encode(&digest[..digest.len() / 2])
}

fn main() {
    // OIDC Core 付録A.6 の認可応答(response_type=code id_token token)
    let code = "Qcb0Orv1zh30vL1MPRsbm-diHiMwcLyZvn1arpZv-Jxf_11jnpEX3Tgfvk";
    let access_token = "jHkWEdUXMU1BwAsC4vtUsZwnNvTIxEl0z9K3vx5KF0Y";
    let payload_b64 = concat!(
        "ewogImlzcyI6ICJodHRwczovL3NlcnZlci5leGFtcGxlLmNvbSIsCiAic3ViIjog",
        "IjI0ODI4OTc2MTAwMSIsCiAiYXVkIjogInM2QmhkUmtxdDMiLAogIm5vbmNlIjog",
        "Im4tMFM2X1d6QTJNaiIsCiAiZXhwIjogMTMxMTI4MTk3MCwKICJpYXQiOiAxMzEx",
        "MjgwOTcwLAogImF0X2hhc2giOiAiNzdRbVVQdGpQZnpXdEYyQW5wSzlSUSIsCiAi",
        "Y19oYXNoIjogIkxEa3RLZG9RYWszUGswY25YeENsdEEiCn0",
    );
    let payload = URL_SAFE_NO_PAD.decode(payload_b64).unwrap();
    let claims: serde_json::Value = serde_json::from_slice(&payload).unwrap();
    println!("IDトークンのペイロード: {claims}");

    let alg = "RS256";
    let c_hash = left_half_hash(alg, code);
    let at_hash = left_half_hash(alg, access_token);
    println!("\n計算した c_hash  = {c_hash}  一致: {}", claims["c_hash"] == c_hash.as_str());
    println!("計算した at_hash = {at_hash}  一致: {}", claims["at_hash"] == at_hash.as_str());

    // 攻撃者が認可応答の code だけを自分のコードに差し替えた場合
    let injected = "SplxlOBeZQQYbYS6WxSbIA";
    let ok = claims["c_hash"] == left_half_hash(alg, injected).as_str();
    println!("\ncode を {injected} に差し替えた応答: c_hash 一致={ok} -> {}",
        if ok { "受理" } else { "拒否(コードの差し替えを検出)" });

    println!("\nalg ごとの左半分の長さ:");
    for alg in ["ES256", "ES384", "HS512"] {
        let h = left_half_hash(alg, code);
        println!("  {alg}: {} バイト -> {h}", URL_SAFE_NO_PAD.decode(&h).unwrap().len());
    }
}
