use std::collections::HashMap;
use url::Url;

const CLIENT_ID: &str = "s6BhdRkqt3";
const REGISTERED_REDIRECT: &str = "https://client.example.com/cb";

// 認可エンドポイントの結果: リダイレクトするか、利用者に直接エラーを表示するか
enum AuthzResult {
    Redirect(String),
    ShowError(&'static str),
}

struct AuthServer {
    codes: HashMap<String, (String, String)>, // code → (client_id, redirect_uri)
    next: u32,
}

impl AuthServer {
    fn authorize(&mut self, query: &str, user_approves: bool) -> AuthzResult {
        let pairs: Vec<(String, String)> = form_urlencoded::parse(query.as_bytes()).into_owned().collect();
        let count = |k: &str| pairs.iter().filter(|(name, _)| name == k).count();
        let q: HashMap<String, String> = pairs.iter().cloned().collect();
        let get = |k: &str| q.get(k).map(String::as_str).unwrap_or("");
        // 1. client_id と redirect_uri を先に検証する。不正ならリダイレクトしない
        if count("client_id") > 1 || count("redirect_uri") > 1 {
            return AuthzResult::ShowError("client_id または redirect_uri が重複しています");
        }
        if get("client_id") != CLIENT_ID {
            return AuthzResult::ShowError("client_id が不正です");
        }
        // 登録値との完全一致 (単純な文字列比較)
        if get("redirect_uri") != REGISTERED_REDIRECT {
            return AuthzResult::ShowError("redirect_uri が登録値と一致しません");
        }
        // 2. ここから先のエラーはリダイレクトURIへ error として返す
        let redirect = |pairs: &[(&str, &str)]| {
            let mut url = Url::parse(REGISTERED_REDIRECT).unwrap();
            url.query_pairs_mut().extend_pairs(pairs);
            if let Some(state) = q.get("state") {
                url.query_pairs_mut().append_pair("state", state);
            }
            AuthzResult::Redirect(url.to_string())
        };
        // 重複、欠落、空の値は invalid_request。値が空のパラメータは省略として扱う (3.1節)
        if pairs.iter().any(|(k, _)| count(k) > 1) || get("response_type").is_empty() {
            return redirect(&[("error", "invalid_request")]);
        }
        if get("response_type") != "code" {
            return redirect(&[("error", "unsupported_response_type")]);
        }
        if !user_approves {
            return redirect(&[("error", "access_denied")]);
        }
        self.next += 1;
        let code = format!("dummy-code-{}", self.next);
        self.codes.insert(code.clone(), (CLIENT_ID.to_string(), get("redirect_uri").to_string()));
        redirect(&[("code", &code)])
    }

    fn token(&mut self, client_id: &str, code: &str, redirect_uri: &str) -> Result<&'static str, &'static str> {
        // コードは取り出した時点でストアから消える (1回限り)
        let (issued_to, uri) = self.codes.remove(code).ok_or("invalid_grant")?;
        if issued_to != client_id || uri != redirect_uri {
            return Err("invalid_grant");
        }
        Ok("dummy-access-token")
    }
}

// クライアントのリダイレクトエンドポイント: error の確認と state の照合
fn client_callback(location: &str, expected_state: &str) -> Result<String, String> {
    let url = Url::parse(location).unwrap();
    let q: HashMap<String, String> = url.query_pairs().into_owned().collect();
    if q.get("state").map(String::as_str) != Some(expected_state) {
        return Err("state が一致しないため破棄".to_string());
    }
    if let Some(e) = q.get("error") {
        return Err(format!("認可サーバがエラーを返した: {e}"));
    }
    q.get("code").cloned().ok_or_else(|| "code がない".to_string())
}

fn authz_query(response_type: &str, redirect_uri: &str, state: &str) -> String {
    form_urlencoded::Serializer::new(String::new())
        .append_pair("response_type", response_type)
        .append_pair("client_id", CLIENT_ID)
        .append_pair("redirect_uri", redirect_uri)
        .append_pair("state", state)
        .finish()
}

fn show(title: &str, r: &AuthzResult) {
    match r {
        AuthzResult::Redirect(loc) => println!("{title}\n  302 Found\n  Location: {loc}"),
        AuthzResult::ShowError(msg) => println!("{title}\n  400 Bad Request (リダイレクトせず利用者に表示): {msg}"),
    }
}

fn main() {
    let mut server = AuthServer { codes: HashMap::new(), next: 0 };

    let r = server.authorize(&authz_query("code", REGISTERED_REDIRECT, "xyz"), true);
    show("[1] 正常なリクエスト", &r);
    let AuthzResult::Redirect(loc) = &r else { unreachable!() };
    let code = client_callback(loc, "xyz").unwrap();
    println!("  クライアント: code = {code}");

    println!();
    let r = server.authorize(&authz_query("code", "https://attacker.example/cb", "xyz"), true);
    show("[2] 登録されていない redirect_uri", &r);

    println!();
    let r = server.authorize(&authz_query("token", REGISTERED_REDIRECT, "xyz"), true);
    show("[3] サポートしない response_type", &r);
    let AuthzResult::Redirect(loc) = &r else { unreachable!() };
    println!("  クライアント: {:?}", client_callback(loc, "xyz"));
    let r = server.authorize(&authz_query("", REGISTERED_REDIRECT, "xyz"), true);
    show("[3'] response_type が空 (省略と同じ扱い)", &r);

    println!();
    let r = server.authorize(&authz_query("code", REGISTERED_REDIRECT, "xyz"), false);
    show("[4] 利用者が拒否", &r);
    let AuthzResult::Redirect(loc) = &r else { unreachable!() };
    println!("  クライアント: {:?}", client_callback(loc, "xyz"));

    println!();
    println!("[5] 攻撃者が自分のセッションで得た code を、被害者のブラウザで開かせる");
    let forged = "https://client.example.com/cb?code=dummy-code-attacker&state=abc";
    println!("  Location: {forged}");
    println!("  クライアント (被害者のセッションの state は xyz): {:?}", client_callback(forged, "xyz"));

    println!();
    println!("[6] トークンエンドポイントで同じ code を2回使う");
    println!("  1回目: {:?}", server.token(CLIENT_ID, &code, REGISTERED_REDIRECT));
    println!("  2回目: {:?}", server.token(CLIENT_ID, &code, REGISTERED_REDIRECT));

    println!();
    println!("[7] 認可リクエストと異なる redirect_uri でトークンを要求する");
    let r = server.authorize(&authz_query("code", REGISTERED_REDIRECT, "xyz"), true);
    let AuthzResult::Redirect(loc) = &r else { unreachable!() };
    let code = client_callback(loc, "xyz").unwrap();
    println!("  {:?}", server.token(CLIENT_ID, &code, "https://client.example.com/other"));
}
