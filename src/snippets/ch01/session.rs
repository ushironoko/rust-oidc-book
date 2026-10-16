use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use std::collections::HashMap;

// サーバ側のセッションストア: セッションID → ログイン中のユーザー
type SessionStore = HashMap<String, String>;

// 128ビットの乱数から推測不能なセッションIDを作る
fn new_session_id() -> String {
    let mut bytes = [0u8; 16];
    rand::fill(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

// パスワードの照合。実際の保存と照合の方法は5章で扱う
fn check_password(user: &str, password: &str) -> bool {
    user == "alice" && password == "dummy-password"
}

// Cookie ヘッダから指定した名前の値を取り出す
fn cookie_value<'a>(cookie_header: &'a str, name: &str) -> Option<&'a str> {
    cookie_header
        .split(';')
        .filter_map(|pair| pair.trim().split_once('='))
        .find(|(k, _)| *k == name)
        .map(|(_, v)| v)
}

fn login(store: &mut SessionStore, user: &str, password: &str) -> String {
    if !check_password(user, password) {
        return "HTTP/1.1 303 See Other\nLocation: /login?error=1".to_string();
    }
    let sid = new_session_id();
    store.insert(sid.clone(), user.to_string());
    format!(
        "HTTP/1.1 303 See Other\nLocation: /me\n\
         Set-Cookie: sid={sid}; Path=/; Secure; HttpOnly; SameSite=Lax"
    )
}

fn me(store: &SessionStore, cookie_header: Option<&str>) -> String {
    let user = cookie_header
        .and_then(|h| cookie_value(h, "sid"))
        .and_then(|sid| store.get(sid));
    match user {
        Some(u) => format!("HTTP/1.1 200 OK\n\nこんにちは、{u} さん"),
        None => "HTTP/1.1 303 See Other\nLocation: /login".to_string(),
    }
}

fn logout(store: &mut SessionStore, cookie_header: &str) -> String {
    if let Some(sid) = cookie_value(cookie_header, "sid") {
        store.remove(sid);
    }
    "HTTP/1.1 303 See Other\nLocation: /login\n\
     Set-Cookie: sid=; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=0"
        .to_string()
}

fn show(title: &str, request: &str, response: &str) {
    println!("--- {title}");
    println!("{request}\n");
    println!("{response}\n");
}

fn main() {
    let mut store = SessionStore::new();

    let req = "POST /login HTTP/1.1\nContent-Type: application/x-www-form-urlencoded\n\n\
               user=alice&password=dummy-password";
    let res = login(&mut store, "alice", "dummy-password");
    show("1. ログイン", req, &res);

    // ブラウザは Set-Cookie の値を保存し、以後のリクエストに付ける
    let set_cookie = res.lines().find(|l| l.starts_with("Set-Cookie:")).unwrap();
    let sid = cookie_value(set_cookie.trim_start_matches("Set-Cookie:"), "sid").unwrap();
    let cookie = format!("sid={sid}");

    let req = format!("GET /me HTTP/1.1\nCookie: {cookie}");
    show("2. Cookie 付きのリクエスト", &req, &me(&store, Some(&cookie)));

    show("3. Cookie なしのリクエスト", "GET /me HTTP/1.1", &me(&store, None));

    let guess = "sid=AAAAAAAAAAAAAAAAAAAAAA";
    let req = format!("GET /me HTTP/1.1\nCookie: {guess}");
    show("4. 推測したセッションID", &req, &me(&store, Some(guess)));

    println!("サーバ側ストアの中身: {} 件 {:?}\n", store.len(), store);

    let req = format!("POST /logout HTTP/1.1\nCookie: {cookie}");
    show("5. ログアウト", &req, &logout(&mut store, &cookie));

    let req = format!("GET /me HTTP/1.1\nCookie: {cookie}");
    show("6. 古い Cookie を再送する", &req, &me(&store, Some(&cookie)));
    println!("サーバ側ストアの中身: {} 件", store.len());
}
