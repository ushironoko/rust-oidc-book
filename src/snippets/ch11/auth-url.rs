use std::collections::HashMap;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use sha2::{Digest, Sha256};
use url::Url;

// RP がログイン開始時にセッションへ保存する3つの値
struct PendingLogin {
    state: String,
    nonce: String,
    code_verifier: String,
}

fn authorization_url(endpoint: &str, client_id: &str, redirect_uri: &str, p: &PendingLogin) -> Url {
    let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(p.code_verifier.as_bytes()));
    let mut url = Url::parse(endpoint).expect("認可エンドポイントは URL");
    url.query_pairs_mut()
        .append_pair("response_type", "code")
        .append_pair("client_id", client_id)
        .append_pair("redirect_uri", redirect_uri)
        .append_pair("scope", "openid profile email")
        .append_pair("state", &p.state)
        .append_pair("nonce", &p.nonce)
        .append_pair("code_challenge", &challenge)
        .append_pair("code_challenge_method", "S256");
    url
}

// コールバックの処理: セッションから取り出して(同時に消して)から state を比べる
fn callback(sessions: &mut HashMap<String, PendingLogin>, sid: &str, query: &str) -> Result<(String, PendingLogin), String> {
    let pending = sessions.remove(sid).ok_or("ログイン開始の記録がない(使用済みか期限切れ)")?;
    let params: HashMap<String, String> = url::form_urlencoded::parse(query.as_bytes()).into_owned().collect();
    if params.get("state") != Some(&pending.state) {
        return Err(format!("state が一致しない: {:?}", params.get("state")));
    }
    let code = params.get("code").ok_or("code がない")?.clone();
    Ok((code, pending))
}

fn random_b64(len: usize) -> String {
    let bytes: Vec<u8> = (0..len).map(|_| rand::random::<u8>()).collect();
    URL_SAFE_NO_PAD.encode(bytes)
}

// 固定値(code_verifier は RFC 7636 付録B の値)
fn fixed_pending() -> PendingLogin {
    PendingLogin {
        state: "dummy-state-0001".to_string(),
        nonce: "dummy-nonce-0001".to_string(),
        code_verifier: "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk".to_string(),
    }
}

fn main() {
    // 1. 固定値で組み立てる
    let fixed = fixed_pending();
    let url = authorization_url(
        "https://op.example.com/authorize",
        "demo-rp",
        "https://rp.example.com/callback",
        &fixed,
    );
    println!("== 認可リクエストの URL");
    println!("{url}");
    println!("\n== クエリの各パラメータ(デコード後)");
    for (k, v) in url.query_pairs() {
        println!("{k:>22} = {v}");
    }

    // 2. セッションに保存し、コールバックを3通り処理する
    let mut sessions = HashMap::new();
    sessions.insert("sid-browser".to_string(), fixed);
    println!("\n== コールバックの処理");
    let cases = [
        ("攻撃者が別の state で送る", "code=attacker-code&state=attacker-state"),
        ("正しい認可レスポンス", "code=SplxlOBeZQQYbYS6WxSbIA&state=dummy-state-0001"),
        ("同じ認可レスポンスを再送", "code=SplxlOBeZQQYbYS6WxSbIA&state=dummy-state-0001"),
    ];
    for (i, (label, query)) in cases.iter().enumerate() {
        if i == 1 {
            // 1件目の失敗で記録が消えたので、ログインをやり直したことにする
            sessions.insert("sid-browser".to_string(), fixed_pending());
        }
        match callback(&mut sessions, "sid-browser", query) {
            Ok((code, p)) => println!(
                "[成功] {label}: code={code} を交換へ(code_verifier={}、IDトークンの nonce は {} と照合)",
                p.code_verifier, p.nonce
            ),
            Err(e) => println!("[失敗] {label}: {e}"),
        }
    }

    // 3. 実際には乱数で作る(出力は実行ごとに変わる)
    let state = random_b64(16);
    let nonce = random_b64(16);
    let verifier = random_b64(32);
    println!("\n== 乱数で生成した値");
    println!("state         = {state} ({} 文字)", state.len());
    println!("nonce         = {nonce} ({} 文字)", nonce.len());
    println!("code_verifier = {verifier} ({} 文字)", verifier.len());
}
