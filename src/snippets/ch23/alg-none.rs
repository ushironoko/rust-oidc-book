use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;

// 明らかにダミーとわかる HS256 の共有鍵(32バイト)
const KEY: &[u8; 32] = b"dummy-hs256-key-for-book-000000!";

fn parts(token: &str) -> Option<(String, String, Vec<u8>)> {
    let mut it = token.split('.');
    let (h, p, s) = (it.next()?, it.next()?, it.next()?);
    if it.next().is_some() {
        return None;
    }
    let header: serde_json::Value = serde_json::from_slice(&B64.decode(h).ok()?).ok()?;
    let alg = header["alg"].as_str()?.to_string();
    Some((alg, format!("{h}.{p}"), B64.decode(s).ok()?))
}

fn hmac_ok(input: &str, sig: &[u8]) -> bool {
    let mut mac = Hmac::<Sha256>::new_from_slice(KEY).unwrap();
    mac.update(input.as_bytes());
    mac.verify_slice(sig).is_ok()
}

// A: ヘッダの alg をそのまま信用する
fn trust_header(token: &str) -> Result<(), String> {
    let (alg, input, sig) = parts(token).ok_or("形式が不正")?;
    match alg.as_str() {
        "none" => Ok(()),
        "HS256" if hmac_ok(&input, &sig) => Ok(()),
        _ => Err(format!("alg={alg} の検証に失敗")),
    }
}

// B: "none" を拒否リストで拒否するが、alg を大文字小文字を区別せずに解釈する
fn blocklist(token: &str) -> Result<(), String> {
    let (alg, input, sig) = parts(token).ok_or("形式が不正")?;
    if alg == "none" {
        return Err("拒否リストの none".into());
    }
    match alg.to_ascii_lowercase().as_str() {
        "none" => Ok(()),
        "hs256" if hmac_ok(&input, &sig) => Ok(()),
        _ => Err(format!("alg={alg} の検証に失敗")),
    }
}

// C: 許可リスト。この鍵には HS256 だけを使う
fn allowlist(token: &str) -> Result<(), String> {
    let (alg, input, sig) = parts(token).ok_or("形式が不正")?;
    if alg != "HS256" {
        return Err(format!("alg={alg} は許可リストにない"));
    }
    if hmac_ok(&input, &sig) { Ok(()) } else { Err("MAC が一致しない".into()) }
}

fn unsecured(alg: &str, claims: &str) -> String {
    format!("{}.{}.", B64.encode(format!(r#"{{"alg":"{alg}"}}"#)), B64.encode(claims))
}

fn main() {
    let claims = r#"{"iss":"https://op.example","sub":"admin","aud":"api"}"#;
    let input = format!("{}.{}", B64.encode(r#"{"alg":"HS256"}"#), B64.encode(claims));
    let mut mac = Hmac::<Sha256>::new_from_slice(KEY).unwrap();
    mac.update(input.as_bytes());
    let legit = format!("{input}.{}", B64.encode(mac.finalize().into_bytes()));

    let tokens = [
        ("正規 HS256", legit),
        ("alg=none", unsecured("none", claims)),
        ("alg=noNE", unsecured("noNE", claims)),
        ("alg=None", unsecured("None", claims)),
    ];
    println!("alg=none のトークン: {}", tokens[1].1);
    println!();
    for (label, t) in &tokens {
        println!("[{label}]");
        for (name, f) in [
            ("A ヘッダを信用", trust_header as fn(&str) -> Result<(), String>),
            ("B 拒否リスト  ", blocklist),
            ("C 許可リスト  ", allowlist),
        ] {
            match f(t) {
                Ok(()) => println!("  {name}: 受理"),
                Err(e) => println!("  {name}: 拒否 ({e})"),
            }
        }
    }
}
