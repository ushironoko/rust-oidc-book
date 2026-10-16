use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use std::collections::HashMap;
use std::time::{Duration, Instant};
use url::Url;

// HTTP メッセージを文字列として扱うための最小限の型
struct Request {
    method: &'static str,
    url: Url,
    headers: Vec<(String, String)>,
    body: String,
}

struct Response {
    status: &'static str,
    headers: Vec<(String, String)>,
    body: String,
}

fn request_text(r: &Request) -> String {
    let target = match r.url.query() {
        Some(q) => format!("{}?{q}", r.url.path()),
        None => r.url.path().to_string(),
    };
    let mut s = format!("{} {target} HTTP/1.1\nHost: {}", r.method, r.url.host_str().unwrap());
    for (k, v) in &r.headers {
        s += &format!("\n{k}: {v}");
    }
    if !r.body.is_empty() {
        s += &format!("\n\n{}", r.body);
    }
    s
}

fn response_text(r: &Response) -> String {
    let mut s = format!("HTTP/1.1 {}", r.status);
    for (k, v) in &r.headers {
        s += &format!("\n{k}: {v}");
    }
    if !r.body.is_empty() {
        s += &format!("\n\n{}", r.body);
    }
    s
}

fn header<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.as_str())
}

fn h(k: &str, v: impl Into<String>) -> (String, String) {
    (k.to_string(), v.into())
}

fn random_value() -> String {
    let mut bytes = [0u8; 16];
    rand::fill(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

fn form_encode(pairs: &[(&str, &str)]) -> String {
    let mut s = form_urlencoded::Serializer::new(String::new());
    for (k, v) in pairs {
        s.append_pair(k, v);
    }
    s.finish()
}

// 同じ名前が2回以上現れたら None を返す (RFC 6749 3.1節、3.2節)
fn form_decode(s: &str) -> Option<HashMap<String, String>> {
    form_urlencoded::parse(s.as_bytes())
        .into_owned()
        .try_fold(HashMap::new(), |mut map, (k, v)| map.insert(k, v).is_none().then_some(map))
}

// RFC 6749 2.3.1節: client_id と client_secret は、それぞれ付録Bの規則で符号化してから連結する
fn form_component_encode(s: &str) -> String {
    form_urlencoded::byte_serialize(s.as_bytes()).collect()
}

fn form_component_decode(s: &str) -> Option<String> {
    let plus_as_space = s.replace('+', " ");
    percent_encoding::percent_decode_str(&plus_as_space)
        .decode_utf8()
        .ok()
        .map(|c| c.into_owned())
}

fn bad_request(body: &str) -> Response {
    Response { status: "400 Bad Request", headers: vec![], body: body.to_string() }
}

// やり取りを表示する。経路がフロントチャネルかバックチャネルかも示す
fn show_request(no: u32, route: &str, req: &Request) {
    println!("==> [{no}] {route}");
    println!("{}\n", request_text(req));
}

fn show_response(no: u32, res: &Response) {
    println!("<== [{no}]");
    println!("{}\n", response_text(res));
}

// ---------------- 認可サーバ (server.example.com) ----------------

struct Grant {
    client_id: String,
    redirect_uri: String,
    user: String,
    scope: String,
    issued_at: Instant,
}

struct AuthServer {
    // client_id → (クライアントシークレット, 登録済みリダイレクトURI)
    clients: HashMap<String, (String, String)>,
    codes: HashMap<String, Grant>,
}

impl AuthServer {
    fn handle(&mut self, req: &Request) -> Response {
        match (req.method, req.url.path()) {
            ("GET", "/authorize") => self.authorize_get(req),
            ("POST", "/authorize") => self.authorize_post(req),
            ("POST", "/token") => self.token(req),
            _ => Response { status: "404 Not Found", headers: vec![], body: String::new() },
        }
    }

    // 認可リクエストを検証し、ログインと同意の画面を返す
    fn authorize_get(&self, req: &Request) -> Response {
        // 重複したパラメータは信頼できないので、リダイレクトせずに利用者へ表示する
        let Some(q) = form_decode(req.url.query().unwrap_or_default()) else {
            return bad_request("invalid_request: パラメータが重複しています");
        };
        let client_id = q.get("client_id").cloned().unwrap_or_default();
        let redirect_uri = q.get("redirect_uri").cloned().unwrap_or_default();
        match self.clients.get(&client_id) {
            Some((_, registered)) if *registered == redirect_uri => {}
            _ => {
                // client_id や redirect_uri が不正なら、リダイレクトせずに利用者へ表示する
                return bad_request("不正なクライアントです");
            }
        }
        let hidden = form_encode(&[
            ("response_type", &q["response_type"]),
            ("client_id", &client_id),
            ("redirect_uri", &redirect_uri),
            ("scope", &q["scope"]),
            ("state", &q["state"]),
        ]);
        Response {
            status: "200 OK",
            headers: vec![h("Content-Type", "text/html; charset=utf-8")],
            body: format!(
                "<p>{client_id} が「{}」へのアクセスを求めています</p>\n\
                 <form method=\"post\" action=\"/authorize\"> ID・パスワード欄、許可ボタン、\
                 隠しフィールド: {hidden} </form>",
                q["scope"]
            ),
        }
    }

    // ログインと同意の結果を受け取り、認可コードを付けてクライアントへリダイレクトする
    fn authorize_post(&mut self, req: &Request) -> Response {
        let Some(f) = form_decode(&req.body) else {
            return bad_request("invalid_request: パラメータが重複しています");
        };
        let user_ok = f["username"] == "alice" && f["password"] == "dummy-password";
        let client_ok = self
            .clients
            .get(&f["client_id"])
            .is_some_and(|(_, uri)| *uri == f["redirect_uri"]);
        if !user_ok || !client_ok {
            return bad_request("ログインに失敗しました");
        }
        let code = random_value();
        self.codes.insert(
            code.clone(),
            Grant {
                client_id: f["client_id"].clone(),
                redirect_uri: f["redirect_uri"].clone(),
                user: f["username"].clone(),
                scope: f["scope"].clone(),
                issued_at: Instant::now(),
            },
        );
        let mut location = Url::parse(&f["redirect_uri"]).unwrap();
        location
            .query_pairs_mut()
            .append_pair("code", &code)
            .append_pair("state", &f["state"]);
        Response {
            status: "302 Found",
            headers: vec![h("Location", location.as_str())],
            body: String::new(),
        }
    }

    // トークンエンドポイント: クライアント認証、コードの検証、トークンの発行
    fn token(&mut self, req: &Request) -> Response {
        let error = |status, code: &str| Response {
            status,
            headers: vec![
                h("Content-Type", "application/json"),
                h("Cache-Control", "no-store"),
                h("Pragma", "no-cache"),
            ],
            body: format!("{{\"error\":\"{code}\"}}"),
        };
        // スキーム名は大文字小文字を区別せずに照合する (RFC 9110 11.1節)
        let authenticated = header(&req.headers, "Authorization")
            .and_then(|v| v.split_once(' '))
            .filter(|(scheme, _)| scheme.eq_ignore_ascii_case("Basic"))
            .and_then(|(_, b64)| STANDARD.decode(b64.trim()).ok())
            .and_then(|bytes| String::from_utf8(bytes).ok())
            .and_then(|s| {
                let (id, secret) = s.split_once(':')?;
                let (id, secret) = (form_component_decode(id)?, form_component_decode(secret)?);
                let (registered_secret, _) = self.clients.get(&id)?;
                (*registered_secret == secret).then_some(id)
            });
        let Some(client_id) = authenticated else {
            let mut res = error("401 Unauthorized", "invalid_client");
            res.headers.push(h("WWW-Authenticate", "Basic realm=\"token\""));
            return res;
        };
        let Some(f) = form_decode(&req.body) else {
            return error("400 Bad Request", "invalid_request");
        };
        // 必須パラメータの欠落は invalid_request、未対応の値は unsupported_grant_type (5.2節)
        match f.get("grant_type").map(String::as_str) {
            None | Some("") => return error("400 Bad Request", "invalid_request"),
            Some("authorization_code") => {}
            Some(_) => return error("400 Bad Request", "unsupported_grant_type"),
        }
        // remove で取り出すので、同じコードは2度使えない
        let Some(grant) = f.get("code").and_then(|c| self.codes.remove(c)) else {
            return error("400 Bad Request", "invalid_grant");
        };
        let expired = grant.issued_at.elapsed() > Duration::from_secs(600);
        if expired || grant.client_id != client_id || Some(&grant.redirect_uri) != f.get("redirect_uri") {
            return error("400 Bad Request", "invalid_grant");
        }
        let body = serde_json::json!({
            "access_token": random_value(),
            "token_type": "Bearer",
            "expires_in": 3600,
            "scope": grant.scope,
        });
        println!("(認可サーバ内部: {} が {} に許可した範囲 {} でトークンを発行)\n",
            grant.user, client_id, grant.scope);
        Response {
            status: "200 OK",
            headers: vec![
                h("Content-Type", "application/json"),
                h("Cache-Control", "no-store"),
                h("Pragma", "no-cache"),
            ],
            body: serde_json::to_string_pretty(&body).unwrap(),
        }
    }
}

// ---------------- クライアント (client.example.com) ----------------

struct Client {
    client_id: String,
    client_secret: String,
    redirect_uri: String,
    // クライアントのセッションID → 認可リクエストに付けた state
    pending: HashMap<String, String>,
    // クライアントのセッションID → 取得したアクセストークン
    tokens: HashMap<String, String>,
}

impl Client {
    fn handle(&mut self, req: &Request, server: &mut AuthServer, log_no: &mut u32) -> Response {
        match req.url.path() {
            "/login" => self.start(),
            "/cb" => self.callback(req, server, log_no),
            _ => Response { status: "404 Not Found", headers: vec![], body: String::new() },
        }
    }

    // ログイン開始: state を作ってセッションに保存し、認可エンドポイントへリダイレクトする
    fn start(&mut self) -> Response {
        let sid = random_value();
        let state = random_value();
        self.pending.insert(sid.clone(), state.clone());
        let mut url = Url::parse("https://server.example.com/authorize").unwrap();
        url.query_pairs_mut()
            .append_pair("response_type", "code")
            .append_pair("client_id", &self.client_id)
            .append_pair("redirect_uri", &self.redirect_uri)
            .append_pair("scope", "photos:read")
            .append_pair("state", &state);
        Response {
            status: "302 Found",
            headers: vec![
                h("Location", url.as_str()),
                h("Set-Cookie", format!("client_sid={sid}; Path=/; Secure; HttpOnly; SameSite=Lax")),
            ],
            body: String::new(),
        }
    }

    // リダイレクトエンドポイント: state を照合し、バックチャネルでコードをトークンに交換する
    fn callback(&mut self, req: &Request, server: &mut AuthServer, log_no: &mut u32) -> Response {
        let Some(q) = form_decode(req.url.query().unwrap_or_default()) else {
            return bad_request("パラメータが重複しています");
        };
        let sid = header(&req.headers, "Cookie")
            .and_then(|c| c.strip_prefix("client_sid="))
            .unwrap_or_default()
            .to_string();
        let expected = self.pending.remove(&sid);
        if expected.is_none() || expected.as_ref() != q.get("state") {
            return bad_request("state 不一致");
        }
        let credentials = STANDARD.encode(format!(
            "{}:{}",
            form_component_encode(&self.client_id),
            form_component_encode(&self.client_secret)
        ));
        let token_req = Request {
            method: "POST",
            url: Url::parse("https://server.example.com/token").unwrap(),
            headers: vec![
                h("Authorization", format!("Basic {credentials}")),
                h("Content-Type", "application/x-www-form-urlencoded"),
            ],
            body: form_encode(&[
                ("grant_type", "authorization_code"),
                ("code", &q["code"]),
                ("redirect_uri", &self.redirect_uri),
            ]),
        };
        *log_no += 1;
        let no = *log_no;
        show_request(no, "クライアント → 認可サーバ (バックチャネル)", &token_req);
        let token_res = server.handle(&token_req);
        show_response(no, &token_res);
        let json: serde_json::Value = serde_json::from_str(&token_res.body).unwrap();
        self.tokens.insert(sid, json["access_token"].as_str().unwrap().to_string());
        Response {
            status: "302 Found",
            headers: vec![h("Location", "https://client.example.com/photos")],
            body: String::new(),
        }
    }
}

// ---------------- ブラウザ ----------------

fn main() {
    let mut server = AuthServer { clients: HashMap::new(), codes: HashMap::new() };
    server.clients.insert(
        "s6BhdRkqt3".to_string(),
        ("gX1fBat3bV".to_string(), "https://client.example.com/cb".to_string()),
    );
    let mut client = Client {
        client_id: "s6BhdRkqt3".to_string(),
        client_secret: "gX1fBat3bV".to_string(),
        redirect_uri: "https://client.example.com/cb".to_string(),
        pending: HashMap::new(),
        tokens: HashMap::new(),
    };

    let mut log_no = 0;
    let mut history: Vec<String> = vec![];
    let mut client_cookie = String::new();

    // ブラウザの1回の遷移: Host の値で宛先を決めて送り、Set-Cookie を保存する
    let mut browse = |req: Request, client: &mut Client, server: &mut AuthServer, log_no: &mut u32| {
        history.push(req.url.to_string());
        let host = req.url.host_str().unwrap().to_string();
        *log_no += 1;
        let no = *log_no;
        show_request(no, &format!("ブラウザ → {host} (フロントチャネル)"), &req);
        let res = if host == "client.example.com" {
            let res = client.handle(&req, server, log_no);
            if let Some(c) = header(&res.headers, "Set-Cookie") {
                client_cookie = c.split(';').next().unwrap().to_string();
            }
            res
        } else {
            server.handle(&req)
        };
        show_response(no, &res);
        (res, client_cookie.clone())
    };

    // 1. 利用者がクライアントの「ログイン」を押す
    let (res, cookie) = browse(
        Request { method: "GET", url: Url::parse("https://client.example.com/login").unwrap(), headers: vec![], body: String::new() },
        &mut client, &mut server, &mut log_no,
    );
    // 2. ブラウザが Location に従い、認可エンドポイントを開く
    let authz_url = Url::parse(header(&res.headers, "Location").unwrap()).unwrap();
    let q: HashMap<String, String> = authz_url.query_pairs().into_owned().collect();
    browse(
        Request { method: "GET", url: authz_url, headers: vec![], body: String::new() },
        &mut client, &mut server, &mut log_no,
    );
    // 3. 利用者がログインして許可する (フォームの送信)
    let (res, _) = browse(
        Request {
            method: "POST",
            url: Url::parse("https://server.example.com/authorize").unwrap(),
            headers: vec![h("Content-Type", "application/x-www-form-urlencoded")],
            body: form_encode(&[
                ("username", "alice"),
                ("password", "dummy-password"),
                ("response_type", &q["response_type"]),
                ("client_id", &q["client_id"]),
                ("redirect_uri", &q["redirect_uri"]),
                ("scope", &q["scope"]),
                ("state", &q["state"]),
            ]),
        },
        &mut client, &mut server, &mut log_no,
    );
    // 4. ブラウザがリダイレクトエンドポイントへ戻る (Cookie を付ける)
    let cb_url = Url::parse(header(&res.headers, "Location").unwrap()).unwrap();
    browse(
        Request { method: "GET", url: cb_url, headers: vec![h("Cookie", cookie)], body: String::new() },
        &mut client, &mut server, &mut log_no,
    );

    println!("ブラウザが開いた URL:");
    for (i, u) in history.iter().enumerate() {
        println!("  {}. {u}", i + 1);
    }
    let token = client.tokens.values().next().unwrap();
    let leaked = history.iter().any(|u| u.contains(token.as_str()));
    println!("\nアクセストークンがブラウザの URL に現れたか: {leaked}");
    println!("クライアントが保持するアクセストークン: {token}");
}
