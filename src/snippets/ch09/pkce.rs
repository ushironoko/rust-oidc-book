use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

// RFC 7636 付録B の値
const RANDOM_OCTETS: [u8; 32] = [
    116, 24, 223, 180, 151, 153, 224, 37, 79, 250, 96, 125, 216, 173, 187, 186, 22, 212, 37,
    77, 105, 214, 191, 240, 91, 88, 5, 88, 83, 132, 141, 121,
];
const EXPECTED_VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
const EXPECTED_HASH: [u8; 32] = [
    19, 211, 30, 150, 26, 26, 216, 236, 47, 22, 177, 12, 76, 152, 46, 8, 118, 168, 120, 173,
    109, 241, 68, 86, 110, 225, 137, 74, 203, 112, 249, 195,
];
const EXPECTED_CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

// S256: BASE64URL-ENCODE(SHA256(ASCII(code_verifier)))
fn s256(code_verifier: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(code_verifier.as_bytes()))
}

// RFC 7636 4.1節の ABNF: code-verifier = 43*128unreserved
fn is_valid_verifier(v: &str) -> bool {
    (43..=128).contains(&v.len())
        && v.bytes()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'-' | b'.' | b'_' | b'~'))
}

// トークンエンドポイントでの照合(4.6節)
fn server_verifies(method: &str, stored_challenge: &str, code_verifier: &str) -> bool {
    let computed = match method {
        "S256" => s256(code_verifier),
        "plain" => code_verifier.to_string(),
        _ => return false,
    };
    computed.as_bytes().ct_eq(stored_challenge.as_bytes()).into()
}

fn main() {
    println!("== RFC 7636 付録B ==");
    let verifier = URL_SAFE_NO_PAD.encode(RANDOM_OCTETS);
    println!("code_verifier  = {verifier}");
    println!("  付録B と一致: {}", verifier == EXPECTED_VERIFIER);

    let hash = Sha256::digest(verifier.as_bytes());
    println!("SHA-256 の32バイトが付録B の配列と一致: {}", hash[..] == EXPECTED_HASH);

    let challenge = s256(&verifier);
    println!("code_challenge = {challenge}");
    println!("  付録B と一致: {}", challenge == EXPECTED_CHALLENGE);

    println!("\n認可リクエストに付ける値:");
    println!("  code_challenge={challenge}&code_challenge_method=S256");
    println!("トークンリクエストに付ける値:");
    println!("  code_verifier={verifier}");

    println!("\n== トークンエンドポイントでの照合 ==");
    println!("正しい code_verifier: {}", server_verifies("S256", &challenge, &verifier));
    let wrong = "attacker-guess-0000000000000000000000000000000";
    println!("別の code_verifier: {}", server_verifies("S256", &challenge, wrong));
    println!("code_challenge をそのまま送る: {}", server_verifies("S256", &challenge, &challenge));

    println!("\n== 新しい code_verifier の生成 (実行ごとに変わる) ==");
    let mut octets = [0u8; 32];
    rand::fill(&mut octets);
    let fresh = URL_SAFE_NO_PAD.encode(octets);
    println!("code_verifier  = {fresh}");
    println!("code_challenge = {}", s256(&fresh));
    println!("長さ {} 文字、ABNF を満たす: {}", fresh.len(), is_valid_verifier(&fresh));
    println!("42文字の値は ABNF を満たす: {}", is_valid_verifier(&fresh[..42]));
}
