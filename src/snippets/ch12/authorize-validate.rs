use std::collections::HashMap;

struct RegisteredClient {
    client_id: &'static str,
    redirect_uris: &'static [&'static str],
}

enum Outcome {
    // ユーザーにエラー画面を見せる。リダイレクトしない
    ErrorPage(&'static str),
    // redirect_uri へ error を付けて返す
    RedirectError { location: String },
    ShowLogin,
}

const CLIENTS: &[RegisteredClient] = &[RegisteredClient {
    client_id: "demo-rp",
    redirect_uris: &["https://rp.example.com/callback"],
}];

fn validate(query: &str) -> Outcome {
    let mut params = HashMap::new();
    for (k, v) in url::form_urlencoded::parse(query.as_bytes()).into_owned() {
        if params.insert(k, v).is_some() {
            return Outcome::ErrorPage("同じパラメータが2回以上ある");
        }
    }
    let get = |k: &str| params.get(k).map(String::as_str);

    // 1. client_id と redirect_uri: ここで失敗したらリダイレクトしない
    let Some(client) = CLIENTS.iter().find(|c| Some(c.client_id) == get("client_id")) else {
        return Outcome::ErrorPage("client_id が未登録");
    };
    let Some(redirect_uri) = get("redirect_uri") else {
        return Outcome::ErrorPage("redirect_uri がない");
    };
    if !client.redirect_uris.contains(&redirect_uri) {
        return Outcome::ErrorPage("redirect_uri が登録値と完全一致しない");
    }

    // 2. ここから先は redirect_uri を信頼できるので、エラーをクライアントへ返す
    let fail = |error: &str| {
        let mut url = url::Url::parse(redirect_uri).unwrap();
        url.query_pairs_mut().append_pair("error", error);
        if let Some(state) = get("state") {
            url.query_pairs_mut().append_pair("state", state);
        }
        Outcome::RedirectError { location: url.to_string() }
    };
    if get("response_type") != Some("code") {
        return fail("unsupported_response_type");
    }
    if !get("scope").unwrap_or("").split(' ').any(|s| s == "openid") {
        return fail("invalid_scope");
    }
    if get("code_challenge").is_none() || get("code_challenge_method") != Some("S256") {
        return fail("invalid_request");
    }
    if get("nonce").is_none() {
        return fail("invalid_request");
    }
    Outcome::ShowLogin
}

fn main() {
    let ok = "client_id=demo-rp&redirect_uri=https%3A%2F%2Frp.example.com%2Fcallback\
              &response_type=code&scope=openid&state=s1&nonce=n1\
              &code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM&code_challenge_method=S256";
    let cases = [
        ("正しいリクエスト", ok.to_string()),
        ("未登録の client_id と攻撃者の redirect_uri",
         ok.replace("client_id=demo-rp", "client_id=unknown")
           .replace("rp.example.com", "evil.example")),
        ("redirect_uri の後ろに文字を足す",
         ok.replace("%2Fcallback", "%2Fcallback%2F..%2F..%2Fopen-redirect")),
        ("redirect_uri を省く", ok.replace("&redirect_uri=https%3A%2F%2Frp.example.com%2Fcallback", "")),
        ("response_type=token", ok.replace("response_type=code", "response_type=token")),
        ("openid スコープがない", ok.replace("scope=openid", "scope=profile")),
        ("PKCE が plain", ok.replace("code_challenge_method=S256", "code_challenge_method=plain")),
        ("state が2つある", format!("{ok}&state=s2")),
    ];
    for (label, query) in cases {
        let shown = match validate(&query) {
            Outcome::ErrorPage(reason) => format!("エラー画面を表示: {reason}"),
            Outcome::RedirectError { location } => format!("303 Location: {location}"),
            Outcome::ShowLogin => "ログイン画面を表示".to_string(),
        };
        println!("{label}\n    → {shown}");
    }
}
