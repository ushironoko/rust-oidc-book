use url::Url;

// ブラウザがサーバへ送るのはパスとクエリだけで、フラグメントは送らない
fn request_line(u: &Url) -> String {
    let q = u.query().map(|q| format!("?{q}")).unwrap_or_default();
    format!("GET {}{q} HTTP/1.1  (Host: {})", u.path(), u.host_str().unwrap())
}

// RFC 9110 10.2.2: Location にフラグメントがなければ元のフラグメントを引き継ぐ
fn follow_redirect(current: &Url, location: &str) -> Url {
    let mut next = current.join(location).unwrap();
    if next.fragment().is_none() {
        next.set_fragment(current.fragment());
    }
    next
}

// 認可サーバのリダイレクトURI検査
fn prefix_match(registered: &str, requested: &str) -> bool {
    requested.starts_with(registered)
}
fn exact_match(registered: &str, requested: &str) -> bool {
    requested == registered
}

// クライアント側のオープンリダイレクタ(/cb?redirect_to=...)
fn client_open_redirector(u: &Url) -> Option<String> {
    u.query_pairs().find(|(k, _)| k == "redirect_to").map(|(_, v)| v.into_owned())
}

fn main() {
    let registered = "https://client.somesite.example/cb";
    let requested = "https://client.somesite.example/cb?redirect_to=https%3A%2F%2Fattacker.example%2F";

    for (name, check) in [("前方一致", prefix_match as fn(&str, &str) -> bool), ("完全一致", exact_match)] {
        println!("== 認可サーバの検査: {name} ==");
        if !check(registered, requested) {
            println!("redirect_uri を拒否。トークンは発行されない\n");
            continue;
        }
        // インプリシットグラントの応答はフラグメントに入る
        let location = format!("{requested}#access_token=2YotnFZFEjr1zCsicMWpAA&token_type=Bearer&state=9ad67f13");
        let mut at = Url::parse(&location).unwrap();
        println!("1. 303 Location: {at}");
        println!("   ブラウザが送る: {}", request_line(&at));

        let next = client_open_redirector(&at).unwrap();
        println!("2. クライアントのリダイレクタが返す Location: {next}");
        at = follow_redirect(&at, &next);
        println!("3. ブラウザが移動する先: {at}");
        println!("   攻撃者のサーバが受け取る: {}", request_line(&at));
        println!("   攻撃者のページのJavaScriptが読む location.hash: #{}\n", at.fragment().unwrap());
    }
}
