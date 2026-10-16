// ログインフォームの POST に認可サーバがリダイレクトで応答したとき、
// ブラウザが次のリクエストをどう組み立てるか(RFC 9110 15.4)

struct Request {
    method: &'static str,
    url: String,
    body: Option<String>,
}

// 多くのブラウザの挙動: 302/303 は GET に書き換えて本文を破棄し、307/308 は保持する
fn follow(prev: &Request, status: u16, location: &str) -> Request {
    let keep = matches!(status, 307 | 308);
    if keep {
        Request { method: prev.method, url: location.to_string(), body: prev.body.clone() }
    } else {
        Request { method: "GET", url: location.to_string(), body: None }
    }
}

// クライアントのリダイレクトエンドポイントが受け取った内容を記録する
fn client_receives(req: &Request) {
    println!("    クライアントが受信: {} {}", req.method, req.url);
    match &req.body {
        Some(b) => println!("    本文: {b}  <= パスワードがクライアントに渡った"),
        None => println!("    本文なし"),
    }
}

fn main() {
    let login = Request {
        method: "POST",
        url: "https://as.example/login".into(),
        body: Some("username=alice&password=dummy-password-123".into()),
    };
    let location = "https://client.example/cb?code=SplxlOBeZQQYbYS6WxSbIA&state=xyz";

    println!("{} {}", login.method, login.url);
    println!("本文: {}", login.body.as_deref().unwrap());
    for status in [302u16, 303, 307] {
        println!();
        println!("  認可サーバの応答: {status}  Location: {location}");
        let next = follow(&login, status, location);
        client_receives(&next);
    }
}
