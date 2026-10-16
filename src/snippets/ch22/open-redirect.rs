use url::Url;

// 応答: 303 + Location か、200 + 本文
enum Resp {
    SeeOther(String),
    Ok(String),
    BadRequest(String),
}

#[derive(Clone, Copy)]
struct Setup {
    as_exact_match: bool,     // 認可サーバが完全一致で比較するか
    client_open_redirect: bool, // クライアントにオープンリダイレクタがあるか
    client_adds_fragment: bool, // リダイレクタが Location に "#_" を付けるか
}

const REGISTERED: &str = "https://client.somesite.example/cb";

// 認可サーバ: インプリシットグラントで access_token をフラグメントに入れて返す
fn authorization_server(url: &Url, s: Setup) -> Resp {
    let q: std::collections::HashMap<_, _> = url.query_pairs().into_owned().collect();
    let redirect_uri = q.get("redirect_uri").cloned().unwrap_or_default();
    let ok = if s.as_exact_match {
        redirect_uri == REGISTERED
    } else {
        // 登録パターン https://client.somesite.example/cb?* を前方一致で照合
        redirect_uri == REGISTERED || redirect_uri.starts_with("https://client.somesite.example/cb?")
    };
    if !ok {
        return Resp::BadRequest("redirect_uri が登録値と一致しません".into());
    }
    let state = q.get("state").cloned().unwrap_or_default();
    Resp::SeeOther(format!(
        "{redirect_uri}#access_token=2YotnFZFEjr1zCsicMWpAA&token_type=bearer&state={state}"
    ))
}

// クライアント: /cb に redirect_to があれば転送する
fn client(url: &Url, s: Setup) -> Resp {
    let target = url.query_pairs().find(|(k, _)| k == "redirect_to").map(|(_, v)| v.into_owned());
    match target {
        Some(t) if s.client_open_redirect => {
            if s.client_adds_fragment {
                Resp::SeeOther(format!("{t}#_"))
            } else {
                Resp::SeeOther(t)
            }
        }
        Some(_) => Resp::BadRequest("redirect_to は許可リストにありません".into()),
        None => Resp::Ok("コールバックを処理しました".into()),
    }
}

fn attacker(_url: &Url) -> Resp {
    Resp::Ok("攻撃者のページ".into())
}

// ブラウザ: Location にフラグメントがなければ元のフラグメントを付け直す(RFC 9110 10.2.2)
fn browse(start: &str, s: Setup) {
    let mut current = Url::parse(start).unwrap();
    for _ in 0..5 {
        println!("  GET {}", current);
        let resp = match current.host_str() {
            Some("server.somesite.example") => authorization_server(&current, s),
            Some("client.somesite.example") => client(&current, s),
            _ => attacker(&current),
        };
        match resp {
            Resp::SeeOther(loc) => {
                println!("    303 See Other  Location: {loc}");
                let mut next = Url::parse(&loc).unwrap();
                if next.fragment().is_none() {
                    next.set_fragment(current.fragment());
                }
                current = next;
            }
            Resp::Ok(body) => {
                println!("    200 OK  {body}");
                if current.host_str() == Some("attacker.example") {
                    match current.fragment() {
                        Some(f) if f.contains("access_token") => {
                            println!("  => 攻撃者のスクリプトが location.hash を読む: {f}")
                        }
                        _ => println!("  => 攻撃者のページにトークンは届かない"),
                    }
                }
                return;
            }
            Resp::BadRequest(msg) => {
                println!("    400 Bad Request  {msg}");
                println!("  => 攻撃は失敗");
                return;
            }
        }
    }
}

fn main() {
    let mut redirect = Url::parse(REGISTERED).unwrap();
    redirect.query_pairs_mut().append_pair("redirect_to", "https://attacker.example/");
    let mut req = Url::parse("https://server.somesite.example/authorize").unwrap();
    req.query_pairs_mut()
        .append_pair("response_type", "token")
        .append_pair("client_id", "s6BhdRkqt3")
        .append_pair("state", "9ad67f13")
        .append_pair("redirect_uri", redirect.as_str());

    let cases = [
        ("A: パターン照合 + オープンリダイレクタ", Setup { as_exact_match: false, client_open_redirect: true, client_adds_fragment: false }),
        ("B: Aのリダイレクタが \"#_\" を付ける", Setup { as_exact_match: false, client_open_redirect: true, client_adds_fragment: true }),
        ("C: パターン照合 + 転送先を許可リストで検査", Setup { as_exact_match: false, client_open_redirect: false, client_adds_fragment: false }),
        ("D: 完全一致", Setup { as_exact_match: true, client_open_redirect: true, client_adds_fragment: false }),
    ];
    for (label, s) in cases {
        println!("[{label}]");
        browse(req.as_str(), s);
        println!();
    }
}
