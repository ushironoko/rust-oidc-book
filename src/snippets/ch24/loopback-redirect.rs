use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use rand::Rng;
use sha2::{Digest, Sha256};
use std::io::{BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};
use url::Url;

const REGISTERED: [&str; 3] = [
    "http://127.0.0.1/oauth2redirect/example-provider",
    "com.example.app:/oauth2redirect/example-provider",
    "https://app.example.com/oauth2redirect/example-provider",
];

// 認可サーバの登録時検査: プライベートユース URI スキームはピリオドを含むこと
fn registration_check(uri: &str) -> Result<(), &'static str> {
    let u = Url::parse(uri).map_err(|_| "URI として解析できない")?;
    match u.scheme() {
        "https" => Ok(()),
        "http" if matches!(u.host_str(), Some("127.0.0.1") | Some("[::1]")) => Ok(()),
        "http" if u.host_str() == Some("localhost") => Err("localhost ではなくループバック IP リテラルを使う"),
        "http" => Err("http はループバック以外では使えない"),
        s if s.contains('.') => Ok(()),
        _ => Err("ドメイン名に基づかないスキーム(ピリオドを含まない)"),
    }
}

// ループバックIPリテラルなら、URL を正規化せず元の文字列からポート番号だけを取り除く
fn strip_loopback_port(uri: &str) -> Option<String> {
    for base in ["http://127.0.0.1", "http://[::1]"] {
        let Some(rest) = uri.strip_prefix(base) else { continue };
        let rest = match rest.strip_prefix(':') {
            Some(r) => {
                let digits = r.chars().take_while(|c| c.is_ascii_digit()).count();
                if digits == 0 {
                    return None;
                }
                &r[digits..]
            }
            None => rest,
        };
        if !(rest.is_empty() || rest.starts_with(['/', '?', '#'])) {
            return None;
        }
        return Some(format!("{base}{rest}"));
    }
    None
}

// 認可リクエスト時の照合: 完全一致。ただしループバックはポートだけ無視
fn redirect_uri_allowed(requested: &str) -> bool {
    REGISTERED.iter().any(|r| {
        *r == requested
            || matches!(
                (strip_loopback_port(r), strip_loopback_port(requested)),
                (Some(a), Some(b)) if a == b
            )
    })
}

fn random_b64(n: usize) -> String {
    let mut buf = vec![0u8; n];
    rand::rng().fill_bytes(&mut buf);
    B64.encode(buf)
}

fn main() {
    println!("[1] 登録時の検査");
    for uri in [
        REGISTERED[0],
        REGISTERED[1],
        "myapp:/oauth2redirect",
        "http://localhost/oauth2redirect",
        "http://192.168.1.10:8080/oauth2redirect",
    ] {
        match registration_check(uri) {
            Ok(()) => println!("  登録可   {uri}"),
            Err(e) => println!("  登録不可 {uri}: {e}"),
        }
    }

    // アプリ: OS に空いているポートを割り当てさせる(ポート番号は実行ごとに変わる)
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let redirect_uri = format!("http://127.0.0.1:{port}/oauth2redirect/example-provider");
    let state = random_b64(16);
    let verifier = random_b64(32);
    let challenge = B64.encode(Sha256::digest(verifier.as_bytes()));
    let mut auth = Url::parse("https://as.example/authorize").unwrap();
    auth.query_pairs_mut()
        .append_pair("response_type", "code")
        .append_pair("client_id", "native-app-1")
        .append_pair("redirect_uri", &redirect_uri)
        .append_pair("state", &state)
        .append_pair("code_challenge", &challenge)
        .append_pair("code_challenge_method", "S256");
    println!();
    println!("[2] アプリが待ち受けを開始: 127.0.0.1:{port}");
    println!("  外部ブラウザで開く URL: {auth}");

    // 認可サーバ: redirect_uri を照合してから認可コードを返す
    let ok = redirect_uri_allowed(&redirect_uri);
    println!("  認可サーバの照合: {}", if ok { "許可(ポート以外が完全一致)" } else { "拒否" });
    let dot_segment = format!("http://127.0.0.1:{port}/x/../oauth2redirect/example-provider");
    println!(
        "  未登録のパスの照合: {}  {dot_segment}",
        if redirect_uri_allowed(&dot_segment) { "許可" } else { "拒否" }
    );
    let mut cb = Url::parse(&redirect_uri).unwrap();
    cb.query_pairs_mut().append_pair("code", "SplxlOBeZQQYbYS6WxSbIA").append_pair("state", &state);
    println!("  302 Found  Location: {cb}");

    // ブラウザ: Location に従ってループバックの待ち受けへ GET を送る
    let path = format!("{}?{}", cb.path(), cb.query().unwrap());
    let browser = std::thread::spawn(move || {
        let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
        write!(s, "GET {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\n\r\n").unwrap();
        let mut status = String::new();
        BufReader::new(s).read_line(&mut status).unwrap();
        status
    });

    // アプリ: 1回だけ受け取り、state を確かめて待ち受けを閉じる
    let (conn, _) = listener.accept().unwrap();
    let mut line = String::new();
    BufReader::new(&conn).read_line(&mut line).unwrap();
    println!();
    println!("[3] アプリが受信: {}", line.trim_end());
    let target = line.split_whitespace().nth(1).unwrap();
    let got = Url::parse(&format!("http://127.0.0.1:{port}{target}")).unwrap();
    let get = |k: &str| got.query_pairs().find(|(n, _)| n == k).map(|(_, v)| v.into_owned());
    let state_ok = get("state").as_deref() == Some(state.as_str());
    println!("  state の照合: {}", if state_ok { "一致" } else { "不一致" });
    let (status, body) = if state_ok {
        ("200 OK", "認可が完了しました。アプリに戻ってください。")
    } else {
        ("400 Bad Request", "認可レスポンスを受け付けられませんでした。")
    };
    write!(&conn, "HTTP/1.1 {status}\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: {}\r\n\r\n{body}", body.len()).unwrap();
    drop(conn);
    drop(listener);
    println!("  ブラウザが受けた応答: {}", browser.join().unwrap().trim_end());
    if !state_ok {
        println!("  state が一致しないため code を破棄し、フローをエラーで終了した");
        return;
    }
    println!("  code = {}", get("code").unwrap());
    println!("  待ち受けを閉じた。次はトークンリクエストに code_verifier を付けて送る");
}
