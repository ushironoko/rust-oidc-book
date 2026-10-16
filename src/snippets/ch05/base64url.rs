use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE, URL_SAFE_NO_PAD};

// RFC 7515 付録C の手順: 標準の Base64 から '=' を除き、'+' と '/' を置き換える
fn base64url_by_hand(bytes: &[u8]) -> String {
    STANDARD
        .encode(bytes)
        .trim_end_matches('=')
        .replace('+', "-")
        .replace('/', "_")
}

fn main() {
    println!("[1] RFC 7515 付録C の例");
    let bytes = [3u8, 236, 255, 224, 193];
    println!("  入力: {bytes:?}");
    println!("  Base64            : {}", STANDARD.encode(bytes));
    println!("  Base64url (パディングあり): {}", URL_SAFE.encode(bytes));
    println!("  Base64url (パディングなし): {}", URL_SAFE_NO_PAD.encode(bytes));
    println!("  付録C の手順      : {}", base64url_by_hand(&bytes));
    println!("  RFC の値と一致    : {}", URL_SAFE_NO_PAD.encode(bytes) == "A-z_4ME");

    println!("\n[2] 入力の長さとパディング");
    for n in 1..=6 {
        let data = &b"abcdef"[..n];
        let padded = STANDARD.encode(data);
        let unpadded = URL_SAFE_NO_PAD.encode(data);
        println!("  {n} バイト: {padded:<8} → {unpadded:<8} (長さ mod 4 = {})", unpadded.len() % 4);
    }

    println!("\n[3] URL のクエリに入れたとき");
    let q = format!("token={}", STANDARD.encode(bytes));
    let parsed: Vec<(String, String)> = form_urlencoded::parse(q.as_bytes()).into_owned().collect();
    println!("  標準 Base64 をそのまま入れる: {q}");
    println!("  クエリとして解析した値      : {:?} ('+' が空白になる)", parsed[0].1);

    println!("\n[4] 復号の検査");
    let cases = ["A-z_4ME", "A-z_4ME=", "A+z/4ME", "A-z_4M", "A-z_4MEA", "A-z_4MEAB"];
    for s in cases {
        let r = URL_SAFE_NO_PAD.decode(s);
        let shown = match &r {
            Ok(v) => format!("{v:?}"),
            Err(e) => format!("エラー: {e}"),
        };
        println!("  {s:<10} (長さ mod 4 = {}) → {shown}", s.len() % 4);
    }
}
