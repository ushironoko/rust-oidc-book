use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use percent_encoding::{AsciiSet, CONTROLS, percent_decode_str, utf8_percent_encode};

// RFC 6749 付録B の application/x-www-form-urlencoded 符号化
fn form_encode(s: &str) -> String {
    form_urlencoded::byte_serialize(s.as_bytes()).collect()
}

// 符号化の逆変換。'+' を空白に戻してからパーセント復号
fn form_decode(s: &str) -> Option<String> {
    let replaced = s.replace('+', " ");
    percent_decode_str(&replaced)
        .decode_utf8()
        .ok()
        .map(|c| c.into_owned())
}

// コロンとパーセントだけを符号化する、部分的な実装
const ONLY_COLON_AND_PERCENT: &AsciiSet = &CONTROLS.add(b':').add(b'%');

type ClientImpl = (&'static str, fn(&str, &str) -> String);
type ServerImpl = (&'static str, fn(&str) -> Option<(String, String)>);

// クライアント実装A: RFC 6749 2.3.1節どおり、符号化してから Basic にする
fn client_spec(id: &str, secret: &str) -> String {
    let user_pass = format!("{}:{}", form_encode(id), form_encode(secret));
    format!("Basic {}", STANDARD.encode(user_pass))
}

// クライアント実装B: 符号化を省き、RFC 7617 の Basic 認証として送る
fn client_raw(id: &str, secret: &str) -> String {
    format!("Basic {}", STANDARD.encode(format!("{id}:{secret}")))
}

// クライアント実装C: 一部の文字だけを符号化する
fn client_partial(id: &str, secret: &str) -> String {
    let id = utf8_percent_encode(id, ONLY_COLON_AND_PERCENT).to_string();
    let secret = utf8_percent_encode(secret, ONLY_COLON_AND_PERCENT).to_string();
    format!("Basic {}", STANDARD.encode(format!("{id}:{secret}")))
}

fn split_basic(header: &str) -> Option<(String, String)> {
    let b64 = header.strip_prefix("Basic ")?;
    let bytes = STANDARD.decode(b64).ok()?;
    let user_pass = String::from_utf8(bytes).ok()?;
    let (u, p) = user_pass.split_once(':')?;
    Some((u.to_string(), p.to_string()))
}

// サーバ実装S1: Base64 を復号し、コロンで分け、それぞれを form 復号する
fn server_spec(header: &str) -> Option<(String, String)> {
    let (u, p) = split_basic(header)?;
    Some((form_decode(&u)?, form_decode(&p)?))
}

// サーバ実装S2: Base64 を復号し、コロンで分けるだけ
fn server_raw(header: &str) -> Option<(String, String)> {
    split_basic(header)
}

fn main() {
    println!("[1] RFC 6749 2.3.1節の例を復号する");
    let (id, secret) = split_basic("Basic czZCaGRSa3F0Mzo3RmpmcDBaQnIxS3REUmJuZlZkbUl3").unwrap();
    println!("  client_id = {id}, client_secret = {secret}");
    println!(
        "  英数字だけなら符号化の前後で同じヘッダになるか: {}",
        client_spec(&id, &secret) == client_raw(&id, &secret)
    );

    let clients: [ClientImpl; 3] = [
        ("A 仕様どおり", client_spec),
        ("B 符号化なし", client_raw),
        ("C 一部だけ", client_partial),
    ];
    let servers: [ServerImpl; 2] = [("S1 仕様どおり", server_spec), ("S2 復号なし", server_raw)];

    let cases = [
        ("s6BhdRkqt3", "7Fjfp0ZBr1KtDRbnfVdmIw"),
        ("s6BhdRkqt3", "dummy+secret/=="),
        ("s6BhdRkqt3", "dummy%41:secret"),
        ("urn:example:client", "dummy-secret"),
    ];
    for (n, (id, secret)) in cases.iter().enumerate() {
        println!("\n[{}] client_id = {id:?}, client_secret = {secret:?}", n + 2);
        for (cname, client) in &clients {
            let header = client(id, secret);
            let decoded = STANDARD.decode(header.strip_prefix("Basic ").unwrap()).unwrap();
            println!("  {cname}: user-pass = {}", String::from_utf8(decoded).unwrap());
            for (sname, server) in &servers {
                let verdict = match server(&header) {
                    Some((i, s)) if i == *id && s == *secret => "認証成功".to_string(),
                    Some((i, s)) => format!("認証失敗 (解釈: {i:?} / {s:?})"),
                    None => "形式エラー".to_string(),
                };
                println!("    -> {sname}: {verdict}");
            }
        }
    }
}
