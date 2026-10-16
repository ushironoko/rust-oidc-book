use std::collections::HashMap;

// リソースサーバが保持するトークンの情報 (検証方法そのものは14章で扱う)
struct TokenInfo {
    scopes: Vec<&'static str>,
    expires_at: u64,
}

struct Request<'a> {
    method: &'a str,
    path: &'a str,
    authorization: Option<&'a str>,
    query_token: Option<&'a str>,
}

// b64token = 1*( ALPHA / DIGIT / "-" / "." / "_" / "~" / "+" / "/" ) *"="
fn is_b64token(s: &str) -> bool {
    let body = s.trim_end_matches('=');
    !body.is_empty()
        && body
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-._~+/".contains(&b))
}

enum Credential<'a> {
    None,
    Bearer(&'a str),
    Malformed,
}

// Authorization: Bearer <b64token> を解析する。スキーム名は大文字小文字を区別しない
fn parse_authorization(value: Option<&str>) -> Credential<'_> {
    let Some(value) = value else { return Credential::None };
    let Some((scheme, rest)) = value.split_once(' ') else { return Credential::None };
    if !scheme.eq_ignore_ascii_case("Bearer") {
        // Bearer 以外のスキームは、Bearer の資格情報がないものとして扱う
        return Credential::None;
    }
    let token = rest.trim_start_matches(' ');
    if is_b64token(token) { Credential::Bearer(token) } else { Credential::Malformed }
}

fn challenge(params: &[(&str, &str)]) -> String {
    let mut parts = vec![r#"Bearer realm="example""#.to_string()];
    parts.extend(params.iter().map(|(k, v)| format!(r#"{k}="{v}""#)));
    parts.join(", ")
}

fn required_scope(method: &str, path: &str) -> &'static str {
    match (method, path.starts_with("/photos")) {
        ("GET", true) => "photos:read",
        ("DELETE", true) => "photos:delete",
        _ => "admin",
    }
}

fn handle(req: &Request, tokens: &HashMap<&str, TokenInfo>, now: u64) -> String {
    let cred = parse_authorization(req.authorization);
    // 1つのリクエストで複数の送信方法を使うのは invalid_request
    if req.query_token.is_some() && !matches!(cred, Credential::None) {
        return format!(
            "HTTP/1.1 400 Bad Request\nWWW-Authenticate: {}",
            challenge(&[("error", "invalid_request")])
        );
    }
    let token = match cred {
        Credential::Bearer(t) => t,
        Credential::Malformed => {
            return format!(
                "HTTP/1.1 401 Unauthorized\nWWW-Authenticate: {}",
                challenge(&[("error", "invalid_token"), ("error_description", "malformed")])
            );
        }
        // 認証情報がないときは error を付けない
        Credential::None => {
            return format!("HTTP/1.1 401 Unauthorized\nWWW-Authenticate: {}", challenge(&[]));
        }
    };
    let Some(info) = tokens.get(token) else {
        return format!(
            "HTTP/1.1 401 Unauthorized\nWWW-Authenticate: {}",
            challenge(&[("error", "invalid_token")])
        );
    };
    if info.expires_at <= now {
        return format!(
            "HTTP/1.1 401 Unauthorized\nWWW-Authenticate: {}",
            challenge(&[("error", "invalid_token"), ("error_description", "The access token expired")])
        );
    }
    let need = required_scope(req.method, req.path);
    if !info.scopes.contains(&need) {
        return format!(
            "HTTP/1.1 403 Forbidden\nWWW-Authenticate: {}",
            challenge(&[("error", "insufficient_scope"), ("scope", need)])
        );
    }
    format!("HTTP/1.1 200 OK\n\n({} {} の結果)", req.method, req.path)
}

fn main() {
    let now = 1_000_000;
    let mut tokens = HashMap::new();
    tokens.insert("mF_9.B5f-4.1JqM", TokenInfo { scopes: vec!["photos:read"], expires_at: now + 3600 });
    tokens.insert("dummy-expired-token", TokenInfo { scopes: vec!["photos:read"], expires_at: now - 1 });

    let cases = [
        ("Authorization なし", Request { method: "GET", path: "/photos", authorization: None, query_token: None }),
        ("有効なトークン", Request { method: "GET", path: "/photos", authorization: Some("Bearer mF_9.B5f-4.1JqM"), query_token: None }),
        ("スキーム名が小文字", Request { method: "GET", path: "/photos", authorization: Some("bearer mF_9.B5f-4.1JqM"), query_token: None }),
        ("b64token に使えない文字", Request { method: "GET", path: "/photos", authorization: Some("Bearer mF_9 B5f@4"), query_token: None }),
        ("未知のトークン", Request { method: "GET", path: "/photos", authorization: Some("Bearer dummy-unknown"), query_token: None }),
        ("期限切れのトークン", Request { method: "GET", path: "/photos", authorization: Some("Bearer dummy-expired-token"), query_token: None }),
        ("スコープ不足", Request { method: "DELETE", path: "/photos/1", authorization: Some("Bearer mF_9.B5f-4.1JqM"), query_token: None }),
        ("ヘッダとクエリの両方", Request { method: "GET", path: "/photos", authorization: Some("Bearer mF_9.B5f-4.1JqM"), query_token: Some("mF_9.B5f-4.1JqM") }),
        ("Basic 認証を試みた", Request { method: "GET", path: "/photos", authorization: Some("Basic YWxpY2U6eA=="), query_token: None }),
    ];
    for (i, (title, req)) in cases.iter().enumerate() {
        println!("[{}] {title}", i + 1);
        let mut line = format!("{} {}", req.method, req.path);
        if let Some(t) = req.query_token {
            line += &format!("?access_token={t}");
        }
        println!("  > {line} HTTP/1.1");
        if let Some(a) = req.authorization {
            println!("  > Authorization: {a}");
        }
        for l in handle(req, &tokens, now).lines().filter(|l| !l.is_empty()) {
            println!("  < {l}");
        }
        println!();
    }
}
