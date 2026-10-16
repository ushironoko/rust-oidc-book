use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use sha2::{Digest, Sha256};
use std::collections::HashMap;

fn s256(v: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(v.as_bytes()))
}

fn new_verifier() -> String {
    let mut b = [0u8; 32];
    rand::fill(&mut b);
    URL_SAFE_NO_PAD.encode(b)
}

// 認可リクエストで受け取る PKCE のパラメータ。method が None なら plain として扱う(RFC 7636 4.3節)
struct PkceParams {
    method: Option<&'static str>,
    challenge: String,
}

// 認可サーバが対応する変換方式。未知の方式はこの型に変換できない
enum Method {
    Plain,
    S256,
}

struct Pkce {
    method: Method,
    challenge: String,
}

fn parse_pkce(p: PkceParams) -> Result<Pkce, String> {
    let method = match p.method.unwrap_or("plain") {
        "S256" => Method::S256,
        "plain" => Method::Plain,
        other => return Err(format!("invalid_request (未対応の code_challenge_method={other})")),
    };
    Ok(Pkce { method, challenge: p.challenge })
}

struct CodeRecord {
    user: String,
    client_id: String,
    redirect_uri: String,
    pkce: Option<Pkce>,
    used: bool,
}

struct Client {
    redirect_uri: &'static str,
    secret: Option<&'static str>,
}

// 認可サーバ。認可コードを発行先・リダイレクトURI・PKCE の値に結びつけて保存する
#[derive(Default)]
struct AuthServer {
    clients: HashMap<&'static str, Client>,
    codes: HashMap<String, CodeRecord>,
    next: u32,
}

struct TokenRequest<'a> {
    code: &'a str,
    client_id: &'a str,
    redirect_uri: &'a str,
    client_secret: Option<&'a str>,
    code_verifier: Option<&'a str>,
}

impl AuthServer {
    fn authorize(&mut self, user: &str, client_id: &str, pkce: Option<PkceParams>) -> Result<String, String> {
        let pkce = pkce.map(parse_pkce).transpose()?;
        self.next += 1;
        let code = format!("code-{}", self.next);
        let redirect_uri = self.clients[client_id].redirect_uri.to_string();
        self.codes.insert(
            code.clone(),
            CodeRecord { user: user.into(), client_id: client_id.into(), redirect_uri, pkce, used: false },
        );
        Ok(code)
    }

    fn token(&mut self, req: &TokenRequest) -> Result<String, String> {
        let client = self.clients.get(req.client_id).ok_or("invalid_client")?;
        if client.secret.is_some() && client.secret != req.client_secret {
            return Err("invalid_client (クライアント認証の失敗)".into());
        }
        let rec = self.codes.get_mut(req.code).ok_or("invalid_grant (未知のコード)")?;
        if rec.used {
            return Err("invalid_grant (使用済みのコード)".into());
        }
        if rec.client_id != req.client_id || rec.redirect_uri != req.redirect_uri {
            return Err("invalid_grant (発行先またはリダイレクトURIの不一致)".into());
        }
        match (&rec.pkce, req.code_verifier) {
            (None, Some(_)) => return Err("invalid_grant (PKCE なしのコードに code_verifier)".into()),
            (Some(_), None) => return Err("invalid_grant (code_verifier がない)".into()),
            (Some(p), Some(v)) => {
                let computed = match p.method {
                    Method::S256 => s256(v),
                    Method::Plain => v.to_string(),
                };
                if computed != p.challenge {
                    return Err("invalid_grant (code_verifier が code_challenge に合わない)".into());
                }
            }
            (None, None) => {}
        }
        rec.used = true;
        Ok(format!("{} のアクセストークン", rec.user))
    }
}

fn show(who: &str, r: Result<String, String>) {
    match r {
        Ok(t) => println!("    {who}: 成功 → {t}"),
        Err(e) => println!("    {who}: 失敗 → {e}"),
    }
}

fn server() -> AuthServer {
    let mut s = AuthServer::default();
    s.clients.insert("photo-app", Client { redirect_uri: "com.example.photo:/cb", secret: None });
    s.clients.insert("web-rp", Client { redirect_uri: "https://rp.example.com/cb", secret: Some("dummy-secret") });
    s
}

fn native_req<'a>(code: &'a str, verifier: Option<&'a str>) -> TokenRequest<'a> {
    TokenRequest {
        code,
        client_id: "photo-app",
        redirect_uri: "com.example.photo:/cb",
        client_secret: None,
        code_verifier: verifier,
    }
}

fn main() {
    println!("[A] パブリッククライアント、PKCE なし");
    let mut s = server();
    let code = s.authorize("alice", "photo-app", None).unwrap();
    println!("    OS が {code} を正規アプリではなく悪意のあるアプリに渡します");
    show("悪意のあるアプリ", s.token(&native_req(&code, None)));
    show("正規アプリ", s.token(&native_req(&code, None)));

    println!("\n[B] パブリッククライアント、PKCE (S256)");
    let mut s = server();
    let verifier = new_verifier();
    let pkce = PkceParams { method: Some("S256"), challenge: s256(&verifier) };
    let code = s.authorize("alice", "photo-app", Some(pkce)).unwrap();
    println!("    悪意のあるアプリが {code} を横取りします");
    show("悪意のあるアプリ(verifier なし)", s.token(&native_req(&code, None)));
    let guess = new_verifier();
    show("悪意のあるアプリ(推測した verifier)", s.token(&native_req(&code, Some(&guess))));
    show("正規アプリ", s.token(&native_req(&code, Some(&verifier))));

    println!("\n[C] 攻撃者が認可リクエストも読める場合 (RFC 7636 1節の条件 4b)");
    for method in ["plain", "S256"] {
        let mut s = server();
        let verifier = new_verifier();
        let challenge = if method == "S256" { s256(&verifier) } else { verifier.clone() };
        let params = PkceParams { method: Some(method), challenge: challenge.clone() };
        let code = s.authorize("alice", "photo-app", Some(params)).unwrap();
        let observed = challenge;
        println!("  code_challenge_method={method}");
        show("悪意のあるアプリ(観測した code_challenge を送る)", s.token(&native_req(&code, Some(&observed))));
    }

    println!("\n[D] 機密クライアントへのコードインジェクション");
    for use_pkce in [false, true] {
        let mut s = server();
        let mut sessions: HashMap<&str, Option<String>> = HashMap::new();
        // alice のセッションで認可リクエストを送り、発行されたコードが攻撃者に漏れる
        let alice_verifier = new_verifier();
        sessions.insert("alice", use_pkce.then(|| alice_verifier.clone()));
        let alice_pkce = use_pkce.then(|| PkceParams { method: Some("S256"), challenge: s256(&alice_verifier) });
        let stolen = s.authorize("alice", "web-rp", alice_pkce).unwrap();
        // 攻撃者は自分のブラウザでログインを開始し、コールバックに盗んだコードを入れる
        sessions.insert("attacker", use_pkce.then(new_verifier));
        let attacker_verifier = sessions["attacker"].clone();
        let req = TokenRequest {
            code: &stolen,
            client_id: "web-rp",
            redirect_uri: "https://rp.example.com/cb",
            client_secret: Some("dummy-secret"),
            code_verifier: attacker_verifier.as_deref(),
        };
        println!("  PKCE {}", if use_pkce { "あり" } else { "なし" });
        show("RP が攻撃者のセッションでコードを交換", s.token(&req));
    }

    println!("\n[E] 認可リクエストに未対応の code_challenge_method");
    let mut s = server();
    let params = PkceParams { method: Some("S512"), challenge: s256(&new_verifier()) };
    match s.authorize("alice", "photo-app", Some(params)) {
        Ok(code) => println!("    認可サーバ: {code} を発行"),
        Err(e) => println!("    認可サーバ: 認可エラーレスポンス → {e}"),
    }
}
