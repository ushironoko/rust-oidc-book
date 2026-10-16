use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use reqwest::Response;

pub const SECRET_LIKE: [&str; 4] = ["code", "state", "nonce", "code_challenge"];

pub fn step(title: &str) {
    println!("\n== {title}");
}

pub fn short(s: &str) -> String {
    if s.chars().count() > 16 {
        format!("{}...", s.chars().take(16).collect::<String>())
    } else {
        s.to_string()
    }
}

fn shorten_header(name: &str, value: &str) -> String {
    match name {
        "location" => value
            .split('&')
            .map(|kv| match kv.split_once('=') {
                Some((k, v)) if SECRET_LIKE.iter().any(|s| k.ends_with(s)) => format!("{k}={}", short(v)),
                _ => kv.to_string(),
            })
            .collect::<Vec<_>>()
            .join("&"),
        "set-cookie" => match value.split_once(';') {
            Some((pair, attrs)) => match pair.split_once('=') {
                Some((k, v)) => format!("{k}={};{attrs}", short(v)),
                None => value.to_string(),
            },
            None => value.to_string(),
        },
        _ => value.to_string(),
    }
}

pub fn print_response(res: &Response, headers: &[&str]) {
    println!("  HTTP/1.1 {}", res.status());
    for name in headers {
        for value in res.headers().get_all(*name).iter() {
            println!("  {name}: {}", shorten_header(name, value.to_str().unwrap_or("?")));
        }
    }
}

pub fn text_of(html: &str) -> String {
    let mut out = String::new();
    let mut in_tag = false;
    for c in html.chars() {
        match c {
            '<' => {
                in_tag = true;
                out.push(' ');
            }
            '>' => in_tag = false,
            _ if !in_tag => out.push(c),
            _ => {}
        }
    }
    out.split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .replace("&quot;", "\"")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&amp;", "&")
}

pub fn decode_jwt_part(part: &str) -> anyhow::Result<String> {
    let value: serde_json::Value = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(part)?)?;
    let mut obj = value;
    for key in ["jti", "at_hash", "kid"] {
        if let Some(v) = obj.get_mut(key).and_then(|v| v.as_str().map(short)) {
            obj[key] = serde_json::Value::String(v);
        }
    }
    Ok(obj.to_string())
}
