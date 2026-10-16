use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde_json::json;
use std::collections::HashMap;

type Params = Vec<(String, String)>;

struct Pushed {
    client_id: String,
    params: Params,
    expires_at: u64,
    used: bool,
}

struct Client {
    secret: &'static str,
    redirect_uri: &'static str,
    scopes: &'static [&'static str],
}

struct AuthServer {
    clients: HashMap<&'static str, Client>,
    pushed: HashMap<String, Pushed>,
}

fn parse(s: &str) -> Params {
    form_urlencoded::parse(s.as_bytes()).into_owned().collect()
}

fn get<'a>(p: &'a Params, k: &str) -> Option<&'a str> {
    p.iter().find(|(key, _)| key == k).map(|(_, v)| v.as_str())
}

fn encode(pairs: &[(&str, &str)]) -> String {
    let mut s = form_urlencoded::Serializer::new(String::new());
    for (k, v) in pairs {
        s.append_pair(k, v);
    }
    s.finish()
}

fn error(status: u16, code: &str, description: &str) -> (u16, String) {
    (status, json!({"error": code, "error_description": description}).to_string())
}

// RFC 9126 2.1節: クライアント認証 → request_uri の拒否 → 認可リクエストとしての検証
fn par_endpoint(asv: &mut AuthServer, body: &str, now: u64) -> (u16, String) {
    let p = parse(body);
    // 登録とシークレットを明示的に取り出し、どちらかが欠ければ拒否する
    let authenticated = get(&p, "client_id")
        .and_then(|id| asv.clients.get_key_value(id))
        .filter(|(_, c)| get(&p, "client_secret") == Some(c.secret));
    let Some((&client_id, client)) = authenticated else {
        return (401, json!({"error": "invalid_client"}).to_string());
    };
    if get(&p, "request_uri").is_some() {
        return error(400, "invalid_request", "request_uri is not allowed");
    }
    match get(&p, "response_type") {
        None => return error(400, "invalid_request", "response_type is required"),
        Some("code") => {}
        Some(_) => return error(400, "unsupported_response_type", "only code is supported"),
    }
    if get(&p, "redirect_uri") != Some(client.redirect_uri) {
        return error(400, "invalid_request", "redirect_uri is missing or not registered");
    }
    let scope = get(&p, "scope").unwrap_or("");
    if scope.split(' ').filter(|s| !s.is_empty()).any(|s| !client.scopes.contains(&s)) {
        return error(400, "invalid_scope", "scope is not allowed for this client");
    }
    let mut random = [0u8; 24];
    rand::fill(&mut random);
    let request_uri = format!("urn:ietf:params:oauth:request_uri:{}", URL_SAFE_NO_PAD.encode(random));
    // クライアント認証の値は認可リクエストの一部として保存しない
    let params = p.into_iter().filter(|(k, _)| k != "client_secret").collect();
    asv.pushed.insert(request_uri.clone(), Pushed {
        client_id: client_id.to_string(), params, expires_at: now + 60, used: false,
    });
    (201, json!({"request_uri": request_uri, "expires_in": 60}).to_string())
}

// RFC 9126 4節: request_uri を解決し、PAR で受け取ったパラメータだけを使う
fn authorize(asv: &mut AuthServer, query: &str, now: u64) -> Result<Params, String> {
    let q = parse(query);
    let client_id = get(&q, "client_id").ok_or("client_id がない")?;
    let uri = get(&q, "request_uri").ok_or("このサーバは PAR 以外を受け付けない")?;
    let pushed = asv.pushed.get_mut(uri).ok_or("invalid_request_uri (未知)")?;
    if pushed.client_id != client_id {
        return Err("invalid_request_uri (別のクライアントの request_uri)".into());
    }
    if now >= pushed.expires_at {
        return Err("invalid_request_uri (期限切れ)".into());
    }
    if pushed.used {
        return Err("invalid_request_uri (使用済み)".into());
    }
    pushed.used = true;
    Ok(pushed.params.clone())
}

fn main() {
    let authorization_details = r#"[{"type":"account_information","actions":["list_accounts","read_balances","read_transactions"],"locations":["https://example.com/accounts"]},{"type":"payment_initiation","actions":["initiate","status","cancel"],"locations":["https://example.com/payments"],"instructedAmount":{"currency":"EUR","amount":"123.50"},"creditorName":"Merchant A","creditorAccount":{"iban":"DE02100100109307118603"},"remittanceInformationUnstructured":"Ref Number Merchant"}]"#;
    let request = [
        ("response_type", "code"),
        ("client_id", "s6BhdRkqt3"),
        ("redirect_uri", "https://client.example.org/cb"),
        ("state", "af0ifjsldkj"),
        ("code_challenge", "K2-ltc83acc4h0c9w6ESC_rEMTJ3bww-uCHaoeK1t8U"),
        ("code_challenge_method", "S256"),
        ("authorization_details", authorization_details),
    ];

    let front = format!("https://as.example.com/authorize?{}", encode(&request));
    println!("[1] フロントチャネルで送る場合の URL: {} 文字", front.len());
    println!("  {}...", &front[..120]);

    let mut asv = AuthServer {
        clients: HashMap::from([
            ("s6BhdRkqt3", Client {
                secret: "dummy-secret", redirect_uri: "https://client.example.org/cb", scopes: &["openid", "accounts"],
            }),
            ("other-client", Client {
                secret: "dummy-secret-2", redirect_uri: "https://other.example.net/cb", scopes: &["openid"],
            }),
        ]),
        pushed: HashMap::new(),
    };

    let mut body_pairs = request.to_vec();
    body_pairs.push(("client_secret", "dummy-secret"));
    let (status, resp) = par_endpoint(&mut asv, &encode(&body_pairs), 0);
    println!("\n[2] POST /as/par -> HTTP {status}");
    println!("  {resp}");
    let request_uri = serde_json::from_str::<serde_json::Value>(&resp).unwrap()["request_uri"]
        .as_str().unwrap().to_string();

    let back = format!("https://as.example.com/authorize?{}", encode(&[("client_id", "s6BhdRkqt3"), ("request_uri", &request_uri)]));
    println!("\n[3] PAR 後の認可リクエスト URL: {} 文字", back.len());
    println!("  {back}");

    println!("\n[4] 攻撃者がクエリに scope と redirect_uri を書き足す");
    let tampered = format!("{}&scope=admin&redirect_uri=https%3A%2F%2Fattacker.example%2Fcb", back.split_once('?').unwrap().1);
    match authorize(&mut asv, &tampered, 5) {
        Ok(p) => println!("  使われた redirect_uri = {}, scope = {:?}", get(&p, "redirect_uri").unwrap(), get(&p, "scope")),
        Err(e) => println!("  {e}"),
    }

    println!("\n[5] 同じ request_uri を再利用する");
    println!("  {}", authorize(&mut asv, back.split_once('?').unwrap().1, 6).unwrap_err());

    let mut fresh = request.to_vec();
    fresh.push(("client_secret", "dummy-secret"));
    let (_, resp) = par_endpoint(&mut asv, &encode(&fresh), 10);
    let uri2 = serde_json::from_str::<serde_json::Value>(&resp).unwrap()["request_uri"].as_str().unwrap().to_string();
    println!("\n[6] 別のクライアントが他人の request_uri を使う");
    println!("  {}", authorize(&mut asv, &encode(&[("client_id", "other-client"), ("request_uri", &uri2)]), 11).unwrap_err());
    println!("\n[7] 期限 (60秒) を過ぎてから使う");
    println!("  {}", authorize(&mut asv, &encode(&[("client_id", "s6BhdRkqt3"), ("request_uri", &uri2)]), 75).unwrap_err());

    println!("\n[8] 未登録の redirect_uri を PAR で送る (ユーザーの操作より前に拒否される)");
    let mut bad = request.to_vec();
    bad[2] = ("redirect_uri", "https://attacker.example/cb");
    bad.push(("client_secret", "dummy-secret"));
    let (status, resp) = par_endpoint(&mut asv, &encode(&bad), 20);
    println!("  HTTP {status} {resp}");

    println!("\n[9] クライアント認証に失敗する");
    let mut wrong = request.to_vec();
    wrong.push(("client_secret", "wrong-secret"));
    let (status, resp) = par_endpoint(&mut asv, &encode(&wrong), 20);
    println!("  HTTP {status} {resp}");

    println!("\n[10] 未登録の client_id で、client_secret と redirect_uri を省く");
    let (status, resp) = par_endpoint(&mut asv, &encode(&[("client_id", "unknown-client"), ("response_type", "code")]), 20);
    println!("  HTTP {status} {resp}");

    println!("\n[11] response_type を省く");
    let no_type: Vec<_> = body_pairs.iter().copied().filter(|(k, _)| *k != "response_type").collect();
    let (status, resp) = par_endpoint(&mut asv, &encode(&no_type), 20);
    println!("  HTTP {status} {resp}");

    println!("\n[12] 許可されていない scope=admin を要求する");
    let mut admin = body_pairs.clone();
    admin.push(("scope", "openid admin"));
    let (status, resp) = par_endpoint(&mut asv, &encode(&admin), 20);
    println!("  HTTP {status} {resp}");
}
