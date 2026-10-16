use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;

// OpenID Connect Core 1.0 3.1.3.3節のトークンレスポンス例に含まれる id_token
const ID_TOKEN: &str = concat!(
    "eyJhbGciOiJSUzI1NiIsImtpZCI6IjFlOWdkazcifQ",
    ".",
    "ewogImlzcyI6ICJodHRwOi8vc2VydmVyLmV4YW1wbGUuY29tIiwKICJzdWIiOiAi",
    "MjQ4Mjg5NzYxMDAxIiwKICJhdWQiOiAiczZCaGRSa3F0MyIsCiAibm9uY2UiOiAi",
    "bi0wUzZfV3pBMk1qIiwKICJleHAiOiAxMzExMjgxOTcwLAogImlhdCI6IDEzMTEy",
    "ODA5NzAKfQ",
    ".",
    "ggW8hZ1EuVLuxNuuIJKX_V8a_OMXzR0EHR9R6jgdqrOOF4daGU96Sr_P6qJp6Icm",
    "D3HP99Obi1PRs-cwh3LO-p146waJ8IhehcwL7F09JdijmBqkvPeB2T9CJNqeGpe-",
    "gccMg4vfKjkM8FcGvnzZUN4_KSP0aAp1tOJ1zZwgjxqGByKHiOtX7TpdQyHE5lcM",
    "iKPXfEIQILVq0pc_E2DzL7emopWoaoZTF_m0_N0YzFC6g6EJbOEoRoSK5hoDalrc",
    "vRYLSrQAZZKflyuVCyixEoV9GfNQC3_osjzw2PAithfubEEBLuVVk4XUVrWOLrLl",
    "0nx7RkKU8NXNHq-rvKMzqg",
);

fn main() {
    let parts: Vec<&str> = ID_TOKEN.split('.').collect();
    println!("ID トークンの長さ: {} 文字、'.' で区切った部分の数: {}", ID_TOKEN.len(), parts.len());

    let header = URL_SAFE_NO_PAD.decode(parts[0]).expect("ヘッダの Base64url");
    let payload = URL_SAFE_NO_PAD.decode(parts[1]).expect("ペイロードの Base64url");
    let signature = URL_SAFE_NO_PAD.decode(parts[2]).expect("署名の Base64url");

    println!("\n[1つ目] ヘッダ:");
    println!("{}", String::from_utf8_lossy(&header));
    println!("\n[2つ目] ペイロード(クレームの集合):");
    println!("{}", String::from_utf8_lossy(&payload));
    println!("\n[3つ目] 署名: {} バイトのバイナリ", signature.len());

    // JSON として読み、RP が使う値を取り出す。ここでは署名を検証していない
    let claims: serde_json::Value = serde_json::from_slice(&payload).expect("JSON");
    println!("\nクレームを取り出した結果(未検証):");
    for name in ["iss", "sub", "aud", "nonce", "exp", "iat"] {
        println!("  {name:5} = {}", claims[name]);
    }
}
