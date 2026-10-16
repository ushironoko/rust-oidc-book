use std::collections::HashMap;

// 同じリクエスト群を、RFC 6749 のままの制限の少ない認可サーバと
// OAuth 2.1(draft-ietf-oauth-v2-1-16)に従う認可サーバに送って比べる

#[derive(Clone, Copy, PartialEq)]
enum Mode {
    OAuth20,
    OAuth21,
}

const REGISTERED: &str = "https://client.example/cb";

fn params(q: &str) -> HashMap<String, String> {
    form_urlencoded::parse(q.as_bytes()).into_owned().collect()
}

// 認可エンドポイント(パブリッククライアントからのリクエストを想定)
fn authorize(mode: Mode, query: &str) -> Result<(), String> {
    let p = params(query);
    let rt = p.get("response_type").map(String::as_str).unwrap_or("");
    match (mode, rt) {
        (_, "code") => {}
        (Mode::OAuth20, "token") => {}
        (Mode::OAuth21, "token") => return Err("response_type=token は定義されていない".into()),
        _ => return Err("unsupported_response_type".into()),
    }
    let ru = p.get("redirect_uri").map(String::as_str).unwrap_or(REGISTERED);
    let redirect_ok = match mode {
        Mode::OAuth20 => ru.starts_with(REGISTERED),
        Mode::OAuth21 => ru == REGISTERED,
    };
    if !redirect_ok {
        return Err("redirect_uri が登録値と一致しない".into());
    }
    if mode == Mode::OAuth21 && rt == "code" {
        if !p.contains_key("code_challenge") {
            return Err("パブリッククライアントの code_challenge がない".into());
        }
        if p.get("code_challenge_method").map(String::as_str) != Some("S256") {
            return Err("code_challenge_method は S256 のみ(plain は禁止)".into());
        }
    }
    Ok(())
}

// トークンエンドポイント
fn token(mode: Mode, body: &str) -> Result<(), String> {
    let p = params(body);
    match (mode, p.get("grant_type").map(String::as_str)) {
        (_, Some("authorization_code" | "refresh_token" | "client_credentials")) => Ok(()),
        (Mode::OAuth20, Some("password")) => Ok(()),
        (Mode::OAuth21, Some("password")) => Err("ROPC グラントは定義されていない".into()),
        _ => Err("unsupported_grant_type".into()),
    }
}

// リソースサーバ: アクセストークンの受け取り方
fn resource(mode: Mode, target: &str, authorization: Option<&str>) -> Result<(), String> {
    let in_query = target.split_once('?').is_some_and(|(_, q)| params(q).contains_key("access_token"));
    if in_query && mode == Mode::OAuth21 {
        return Err("クエリ文字列のトークンは受け付けない".into());
    }
    if in_query || authorization.is_some_and(|a| a.starts_with("Bearer ")) {
        Ok(())
    } else {
        Err("トークンがない".into())
    }
}

fn mark(r: Result<(), String>) -> String {
    match r {
        Ok(()) => "受理".into(),
        Err(e) => format!("拒否 ({e})"),
    }
}

fn main() {
    let az = [
        ("インプリシット", "response_type=token&client_id=spa&redirect_uri=https%3A%2F%2Fclient.example%2Fcb"),
        ("PKCE なし", "response_type=code&client_id=spa&redirect_uri=https%3A%2F%2Fclient.example%2Fcb"),
        ("PKCE plain", "response_type=code&client_id=spa&code_challenge=abc123&code_challenge_method=plain"),
        ("redirect_uri にクエリ追加", "response_type=code&client_id=spa&redirect_uri=https%3A%2F%2Fclient.example%2Fcb%3Fnext%3D%2Fadmin&code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM&code_challenge_method=S256"),
        ("PKCE S256", "response_type=code&client_id=spa&redirect_uri=https%3A%2F%2Fclient.example%2Fcb&code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM&code_challenge_method=S256"),
    ];
    for (label, q) in az {
        println!("[認可] {label}");
        println!("  OAuth 2.0: {}", mark(authorize(Mode::OAuth20, q)));
        println!("  OAuth 2.1: {}", mark(authorize(Mode::OAuth21, q)));
    }
    let tk = [("ROPC", "grant_type=password&username=alice&password=dummy-password-123")];
    for (label, b) in tk {
        println!("[トークン] {label}");
        println!("  OAuth 2.0: {}", mark(token(Mode::OAuth20, b)));
        println!("  OAuth 2.1: {}", mark(token(Mode::OAuth21, b)));
    }
    let rs = [
        ("クエリで送る", "/orders?access_token=mF_9.B5f-4.1JqM", None),
        ("Authorization ヘッダで送る", "/orders", Some("Bearer mF_9.B5f-4.1JqM")),
    ];
    for (label, t, h) in rs {
        println!("[リソース] {label}");
        println!("  OAuth 2.0: {}", mark(resource(Mode::OAuth20, t, h)));
        println!("  OAuth 2.1: {}", mark(resource(Mode::OAuth21, t, h)));
    }
}
