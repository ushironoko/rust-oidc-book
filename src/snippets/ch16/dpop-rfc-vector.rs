use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ring::signature::{ECDSA_P256_SHA256_FIXED, UnparsedPublicKey};
use serde_json::Value;
use sha2::{Digest, Sha256};

// RFC 9449 Figure 2 (トークンリクエスト用の DPoP 証明)
const PROOF_TOKEN_REQ: &str = "eyJ0eXAiOiJkcG9wK2p3dCIsImFsZyI6IkVTMjU2IiwiandrIjp7Imt0eSI6IkVDIiwieCI6Imw4dEZyaHgtMzR0VjNoUklDUkRZOXpDa0RscEJoRjQyVVFVZldWQVdCRnMiLCJ5IjoiOVZFNGpmX09rX282NHpiVFRsY3VOSmFqSG10NnY5VERWclUwQ2R2R1JEQSIsImNydiI6IlAtMjU2In19.eyJqdGkiOiItQndDM0VTYzZhY2MybFRjIiwiaHRtIjoiUE9TVCIsImh0dSI6Imh0dHBzOi8vc2VydmVyLmV4YW1wbGUuY29tL3Rva2VuIiwiaWF0IjoxNTYyMjYyNjE2fQ.2-GxA6T8lP4vfrg8v-FdWP0A0zdrj8igiMLvqRMUvwnQg4PtFLbdLXiOSsX0x7NVY-FNyJK70nfbV37xRZT3Lg";

// RFC 9449 Figure 13 (リソースアクセス用の DPoP 証明。ath を含む)
const PROOF_RESOURCE: &str = "eyJ0eXAiOiJkcG9wK2p3dCIsImFsZyI6IkVTMjU2IiwiandrIjp7Imt0eSI6IkVDIiwieCI6Imw4dEZyaHgtMzR0VjNoUklDUkRZOXpDa0RscEJoRjQyVVFVZldWQVdCRnMiLCJ5IjoiOVZFNGpmX09rX282NHpiVFRsY3VOSmFqSG10NnY5VERWclUwQ2R2R1JEQSIsImNydiI6IlAtMjU2In19.eyJqdGkiOiJlMWozVl9iS2ljOC1MQUVCIiwiaHRtIjoiR0VUIiwiaHR1IjoiaHR0cHM6Ly9yZXNvdXJjZS5leGFtcGxlLm9yZy9wcm90ZWN0ZWRyZXNvdXJjZSIsImlhdCI6MTU2MjI2MjYxOCwiYXRoIjoiZlVIeU8ycjJaM0RaNTNFc05yV0JiMHhXWG9hTnk1OUlpS0NBcWtzbVFFbyJ9.2oW9RP35yRqzhrtNP86L-Ey71EOptxRimPPToA1plemAgR6pxHF8y6-yqyVnmcw6Fy1dqd-jfxSYoMxhAJpLjA";

// RFC 9449 Figure 6 のアクセストークンと、Figure 9 の cnf.jkt
const ACCESS_TOKEN: &str = "Kz~8mXK1EalYznwH-LC-1fBAo.4Ljp~zsPE_NeO.gxU";
const EXPECTED_JKT: &str = "0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I";

fn decode(part: &str) -> Value {
    serde_json::from_slice(&URL_SAFE_NO_PAD.decode(part).unwrap()).unwrap()
}

// RFC 7638: 必須メンバーだけを辞書順に並べ、空白なしの JSON にしてハッシュする
fn jwk_thumbprint(jwk: &Value) -> String {
    let canonical = format!(
        r#"{{"crv":"{}","kty":"{}","x":"{}","y":"{}"}}"#,
        jwk["crv"].as_str().unwrap(),
        jwk["kty"].as_str().unwrap(),
        jwk["x"].as_str().unwrap(),
        jwk["y"].as_str().unwrap()
    );
    URL_SAFE_NO_PAD.encode(Sha256::digest(canonical.as_bytes()))
}

// jwk ヘッダの x と y から、非圧縮形式の公開鍵 (0x04 || x || y) を作る
fn ec_public_key(jwk: &Value) -> Vec<u8> {
    let mut point = vec![0x04];
    point.extend(URL_SAFE_NO_PAD.decode(jwk["x"].as_str().unwrap()).unwrap());
    point.extend(URL_SAFE_NO_PAD.decode(jwk["y"].as_str().unwrap()).unwrap());
    point
}

fn verify(proof: &str) -> (Value, Value, bool) {
    let parts: Vec<&str> = proof.split('.').collect();
    let header = decode(parts[0]);
    let payload = decode(parts[1]);
    let sig = URL_SAFE_NO_PAD.decode(parts[2]).unwrap();
    let key = ec_public_key(&header["jwk"]);
    let ok = UnparsedPublicKey::new(&ECDSA_P256_SHA256_FIXED, &key)
        .verify(format!("{}.{}", parts[0], parts[1]).as_bytes(), &sig)
        .is_ok();
    (header, payload, ok)
}

fn main() {
    for (label, proof) in [("Figure 2", PROOF_TOKEN_REQ), ("Figure 13", PROOF_RESOURCE)] {
        let (header, payload, ok) = verify(proof);
        println!("[{label}]");
        println!("  header : {header}");
        println!("  payload: {payload}");
        println!("  jwk ヘッダの公開鍵で署名を検証: {}", if ok { "成功" } else { "失敗" });
    }

    let (header, payload, _) = verify(PROOF_RESOURCE);
    let ath = URL_SAFE_NO_PAD.encode(Sha256::digest(ACCESS_TOKEN.as_bytes()));
    println!("\n[ath] アクセストークンの SHA-256 を Base64url にした値");
    println!("  計算値 : {ath}");
    println!("  証明の値: {}", payload["ath"].as_str().unwrap());
    println!("  一致: {}", payload["ath"] == ath.as_str());

    let jkt = jwk_thumbprint(&header["jwk"]);
    println!("\n[jkt] jwk ヘッダの公開鍵の JWK Thumbprint");
    println!("  計算値      : {jkt}");
    println!("  cnf.jkt の値: {EXPECTED_JKT}");
    println!("  一致: {}", jkt == EXPECTED_JKT);
}
