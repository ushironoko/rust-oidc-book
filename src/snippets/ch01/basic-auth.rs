use base64::Engine;
use base64::engine::general_purpose::STANDARD;

// クライアント側: user-id と password から Authorization ヘッダの値を作る
fn basic_header(user_id: &str, password: &str) -> String {
    let user_pass = format!("{user_id}:{password}");
    format!("Basic {}", STANDARD.encode(user_pass.as_bytes()))
}

// サーバ側: Authorization ヘッダの値から user-id と password を取り出す
fn parse_basic(header: &str) -> Result<(String, String), String> {
    let (scheme, credentials) = header
        .split_once(' ')
        .ok_or("スキームと資格情報の区切りがない")?;
    if !scheme.eq_ignore_ascii_case("basic") {
        return Err(format!("Basic 以外のスキーム: {scheme}"));
    }
    let bytes = STANDARD
        .decode(credentials.trim())
        .map_err(|e| format!("Base64 として不正: {e}"))?;
    let user_pass = String::from_utf8(bytes).map_err(|_| "UTF-8 として不正")?;
    // 最初のコロンで分ける。2つ目以降のコロンはパスワードの一部
    let (user_id, password) = user_pass
        .split_once(':')
        .ok_or("コロンがない")?;
    Ok((user_id.to_string(), password.to_string()))
}

fn main() {
    println!("[1] RFC 7617 2節の例");
    let h = basic_header("Aladdin", "open sesame");
    println!("  Authorization: {h}");
    println!("  RFC の値と一致: {}", h == "Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==");

    println!("\n[2] RFC 7617 2.1節の例 (パスワードに U+00A3 を含む)");
    let h = basic_header("test", "123\u{00A3}");
    println!("  Authorization: {h}");
    println!("  RFC の値と一致: {}", h == "Basic dGVzdDoxMjPCow==");

    println!("\n[3] 受け取った側は誰でも復号できる");
    let (user, pass) = parse_basic("Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==").unwrap();
    println!("  user-id = {user:?}, password = {pass:?}");

    println!("\n[4] user-id にコロンを含めると、境界がずれる");
    let h = basic_header("team:alice", "s3cret");
    let (user, pass) = parse_basic(&h).unwrap();
    println!("  送ったつもり: user-id = \"team:alice\", password = \"s3cret\"");
    println!("  サーバの解釈: user-id = {user:?}, password = {pass:?}");

    println!("\n[5] パスワードのコロンは問題にならない");
    let h = basic_header("alice", "a:b:c");
    let (user, pass) = parse_basic(&h).unwrap();
    println!("  user-id = {user:?}, password = {pass:?}");

    println!("\n[6] 不正なヘッダ");
    for bad in ["Bearer abc", "Basic %%%", "Basic YWxpY2U="] {
        println!("  {bad:<16} => {:?}", parse_basic(bad));
    }
}
