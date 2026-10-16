mod show;

use anyhow::{Context, Result, ensure};
use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use reqwest::{Client, Response, StatusCode};
use sha2::{Digest, Sha256};
use url::Url;

use show::{decode_jwt_part, print_response, short, step, text_of};

const RP: &str = "http://127.0.0.1:3000";
const OP: &str = "http://127.0.0.1:9000";
const RS: &str = "http://127.0.0.1:4000/api/me";
const CLIENT_ID: &str = "demo-rp";
const CLIENT_SECRET: &str = "demo-rp-secret-not-for-production";
const REDIRECT_URI: &str = "http://127.0.0.1:3000/callback";
const USERNAME: &str = "demo";
const PASSWORD: &str = "demo-password";

fn expect_status(res: &Response, expected: StatusCode) -> Result<()> {
    ensure!(res.status() == expected, "ステータスが {expected} ではなく {}", res.status());
    Ok(())
}

fn header_of(res: &Response, name: &str) -> String {
    res.headers()
        .get_all(name)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .collect::<Vec<_>>()
        .join(", ")
}

fn expect_header(res: &Response, name: &str, needle: &str) -> Result<()> {
    let value = header_of(res, name);
    ensure!(value.contains(needle), "{name} に {needle} がない: {value:?}");
    Ok(())
}

fn expect_error_code(body: &str, code: &str) -> Result<()> {
    let json: serde_json::Value = serde_json::from_str(body).context("エラー応答が JSON ではない")?;
    ensure!(json["error"] == code, "error が {code} ではない: {body}");
    Ok(())
}

fn location(res: &Response) -> Result<String> {
    Ok(res
        .headers()
        .get("location")
        .context("Location ヘッダがない")?
        .to_str()?
        .to_string())
}

fn session_cookie(res: &Response) -> Option<String> {
    res.headers()
        .get_all("set-cookie")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .find(|v| v.starts_with("rp_session="))
        .and_then(|v| v.split(';').next())
        .map(|v| v.trim_start_matches("rp_session=").to_string())
}

fn hidden_request_id(html: &str) -> Result<String> {
    let marker = "name=\"request_id\" value=\"";
    let start = html.find(marker).context("request_id がフォームにない")? + marker.len();
    let end = html[start..].find('"').context("request_id の終端がない")?;
    Ok(html[start..start + end].to_string())
}

fn query_param(url: &str, key: &str) -> Result<String> {
    Url::parse(url)?
        .query_pairs()
        .find(|(k, _)| k == key)
        .map(|(_, v)| v.into_owned())
        .with_context(|| format!("{key} がない"))
}

async fn login_at_op(client: &Client, authorize_url: &str) -> Result<String> {
    let res = client.get(authorize_url).send().await?;
    ensure!(res.status() == StatusCode::OK, "ログインフォームを取得できない: {}", res.status());
    let request_id = hidden_request_id(&res.text().await?)?;
    let res = client
        .post(format!("{OP}/authorize"))
        .form(&[("request_id", request_id.as_str()), ("username", USERNAME), ("password", PASSWORD)])
        .send()
        .await?;
    location(&res)
}

async fn browser_flow() -> Result<()> {
    let browser = Client::builder()
        .cookie_store(true)
        .redirect(reqwest::redirect::Policy::none())
        .build()?;

    step("1. ブラウザ → RP: GET /login");
    let res = browser.get(format!("{RP}/login")).send().await?;
    print_response(&res, &["location", "set-cookie"]);
    expect_status(&res, StatusCode::SEE_OTHER)?;
    let first_session = session_cookie(&res).context("ログイン前のセッションCookieがない")?;
    let authorize_url = location(&res)?;
    ensure!(authorize_url.starts_with(&format!("{OP}/authorize?")), "認可エンドポイントへのリダイレクトではない");
    let sent_state = query_param(&authorize_url, "state")?;
    println!("  認可リクエストのパラメータ:");
    for (k, v) in Url::parse(&authorize_url)?.query_pairs() {
        println!("    {k} = {v}");
    }

    step("2. ブラウザ → OP: GET /authorize (ログインフォームの表示)");
    let res = browser.get(&authorize_url).send().await?;
    print_response(&res, &["content-type", "cache-control", "x-frame-options", "set-cookie"]);
    expect_status(&res, StatusCode::OK)?;
    expect_header(&res, "cache-control", "no-store")?;
    expect_header(&res, "x-frame-options", "DENY")?;
    expect_header(&res, "set-cookie", "mini_op_login=")?;
    let request_id = hidden_request_id(&res.text().await?)?;
    println!("  フォームの hidden: request_id = {}", short(&request_id));

    step("3. ブラウザ → OP: POST /authorize (ユーザー名とパスワード)");
    let res = browser
        .post(format!("{OP}/authorize"))
        .form(&[("request_id", request_id.as_str()), ("username", USERNAME), ("password", PASSWORD)])
        .send()
        .await?;
    print_response(&res, &["location"]);
    expect_status(&res, StatusCode::SEE_OTHER)?;
    let callback_url = location(&res)?;
    ensure!(callback_url.starts_with(&format!("{REDIRECT_URI}?")), "redirect_uri へのリダイレクトではない");
    ensure!(query_param(&callback_url, "state")? == sent_state, "state が段1の値と異なる");
    ensure!(query_param(&callback_url, "iss")? == OP, "iss が mini-op の issuer ではない");
    println!("  認可レスポンスのパラメータ:");
    for (k, v) in Url::parse(&callback_url)?.query_pairs() {
        let shown = if show::SECRET_LIKE.contains(&k.as_ref()) { short(&v) } else { v.into_owned() };
        println!("    {k} = {shown}");
    }

    step("4. ブラウザ → RP: GET /callback (RP の裏で トークン交換・IDトークン検証・UserInfo)");
    let res = browser.get(&callback_url).send().await?;
    print_response(&res, &["location", "set-cookie"]);
    expect_status(&res, StatusCode::SEE_OTHER)?;
    ensure!(location(&res)? == "/", "コールバックの後の遷移先が / ではない");
    let second_session = session_cookie(&res).context("ログイン後のセッションCookieがない")?;
    println!(
        "  セッションIDの再発行: {} → {} (変わった: {})",
        short(&first_session),
        short(&second_session),
        first_session != second_session
    );
    ensure!(first_session != second_session, "セッションIDが再発行されていない");

    step("5. ブラウザ → RP: GET /");
    let res = browser.get(format!("{RP}/")).send().await?;
    print_response(&res, &[]);
    expect_status(&res, StatusCode::OK)?;
    let body = text_of(&res.text().await?);
    println!("  本文: {body}");
    ensure!(body.contains("sub=user-0001"), "ログイン中の表示ではない");

    step("6. ブラウザ → RP: GET /api-call (RP → リソースサーバ)");
    let res = browser.get(format!("{RP}/api-call")).send().await?;
    print_response(&res, &[]);
    expect_status(&res, StatusCode::OK)?;
    let body = res.text().await?;
    println!("  本文: {}", text_of(&body));
    ensure!(body.contains("status=200 OK"), "API 呼び出しが失敗した");

    step("7. 攻撃の再現: 同じ認可レスポンスをもう一度 RP に送る");
    let res = browser.get(&callback_url).send().await?;
    print_response(&res, &[]);
    expect_status(&res, StatusCode::BAD_REQUEST)?;
    let body = text_of(&res.text().await?);
    println!("  本文: {body}");
    ensure!(body.contains("ログイン処理が開始されていないか"), "再送が別の理由で拒否された");
    Ok(())
}

fn pkce_pair() -> (String, String) {
    let verifier = URL_SAFE_NO_PAD.encode(rand::random::<[u8; 32]>());
    let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
    (verifier, challenge)
}

fn authorize_url(challenge: &str) -> Result<String> {
    let mut url = Url::parse(&format!("{OP}/authorize"))?;
    url.query_pairs_mut()
        .append_pair("response_type", "code")
        .append_pair("client_id", CLIENT_ID)
        .append_pair("redirect_uri", REDIRECT_URI)
        .append_pair("scope", "openid profile email api.read")
        .append_pair("state", "flow-test-state")
        .append_pair("nonce", "flow-test-nonce")
        .append_pair("code_challenge", challenge)
        .append_pair("code_challenge_method", "S256");
    Ok(url.into())
}

fn basic_auth(id: &str, secret: &str) -> String {
    let enc = |s: &str| url::form_urlencoded::byte_serialize(s.as_bytes()).collect::<String>();
    format!("Basic {}", STANDARD.encode(format!("{}:{}", enc(id), enc(secret))))
}

async fn token_request(client: &Client, secret: &str, code: &str, verifier: &str) -> Result<Response> {
    Ok(client
        .post(format!("{OP}/token"))
        .header("authorization", basic_auth(CLIENT_ID, secret))
        .form(&[
            ("grant_type", "authorization_code"),
            ("code", code),
            ("redirect_uri", REDIRECT_URI),
            ("code_verifier", verifier),
        ])
        .send()
        .await?)
}

async fn backchannel_flow() -> Result<()> {
    let client = Client::builder()
        .cookie_store(true)
        .redirect(reqwest::redirect::Policy::none())
        .build()?;

    step("8. RP → OP: POST /token (flow-test が RP の役をして直接送る)");
    let (verifier, challenge) = pkce_pair();
    let code = query_param(&login_at_op(&client, &authorize_url(&challenge)?).await?, "code")?;
    let res = token_request(&client, CLIENT_SECRET, &code, &verifier).await?;
    print_response(&res, &["content-type", "cache-control", "pragma"]);
    expect_status(&res, StatusCode::OK)?;
    expect_header(&res, "cache-control", "no-store")?;
    expect_header(&res, "pragma", "no-cache")?;
    let body: serde_json::Value = res.json().await?;
    let access_token = body["access_token"].as_str().context("access_token がない")?.to_string();
    let id_token = body["id_token"].as_str().context("id_token がない")?.to_string();
    println!(
        "  本文: token_type={} expires_in={} scope=\"{}\"",
        body["token_type"], body["expires_in"], body["scope"].as_str().unwrap_or("")
    );
    for (name, token, typ) in [("access_token", &access_token, "at+jwt"), ("id_token", &id_token, "JWT")] {
        let parts: Vec<&str> = token.split('.').collect();
        println!("  {name} のヘッダ:     {}", decode_jwt_part(parts[0])?);
        println!("  {name} のペイロード: {}", decode_jwt_part(parts[1])?);
        let header: serde_json::Value = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[0])?)?;
        ensure!(header["typ"] == typ, "{name} の typ が {typ} ではない");
    }
    let id_claims: serde_json::Value = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(id_token.split('.').nth(1).context("id_token の形式")?)?)?;
    ensure!(id_claims["nonce"] == "flow-test-nonce", "IDトークンの nonce が認可リクエストの値ではない");

    step("9. 攻撃の再現: 同じ認可コードでもう一度 POST /token");
    let res = token_request(&client, CLIENT_SECRET, &code, &verifier).await?;
    print_response(&res, &[]);
    expect_status(&res, StatusCode::BAD_REQUEST)?;
    let body = res.text().await?;
    println!("  本文: {body}");
    expect_error_code(&body, "invalid_grant")?;

    step("10. 攻撃の再現: 誤ったクライアントシークレット、誤った code_verifier");
    let (verifier2, challenge2) = pkce_pair();
    let code2 = query_param(&login_at_op(&client, &authorize_url(&challenge2)?).await?, "code")?;
    let res = token_request(&client, "wrong-secret", &code2, &verifier2).await?;
    print_response(&res, &["www-authenticate"]);
    expect_status(&res, StatusCode::UNAUTHORIZED)?;
    expect_header(&res, "www-authenticate", "Basic")?;
    let body = res.text().await?;
    println!("  本文: {body}");
    expect_error_code(&body, "invalid_client")?;
    let (wrong_verifier, _) = pkce_pair();
    let res = token_request(&client, CLIENT_SECRET, &code2, &wrong_verifier).await?;
    print_response(&res, &[]);
    expect_status(&res, StatusCode::BAD_REQUEST)?;
    let body = res.text().await?;
    println!("  本文: {body}");
    expect_error_code(&body, "invalid_grant")?;

    step("11. RP → リソースサーバ: アクセストークンの有無と種類を変えて GET /api/me");
    let cases = [
        ("トークンなし", None, StatusCode::UNAUTHORIZED, None),
        ("IDトークンを Bearer として送る", Some(id_token.clone()), StatusCode::UNAUTHORIZED, Some("typ must be at+jwt")),
        (
            "ペイロードを1文字改ざんしたアクセストークン",
            Some(tamper(&access_token)),
            StatusCode::UNAUTHORIZED,
            Some("signature verification failed"),
        ),
        ("正しいアクセストークン", Some(access_token.clone()), StatusCode::OK, None),
    ];
    for (label, token, expected, description) in cases {
        println!("  -- {label}");
        let req = client.get(RS);
        let req = match token {
            Some(t) => req.bearer_auth(t),
            None => req,
        };
        let res = req.send().await?;
        print_response(&res, &["www-authenticate"]);
        expect_status(&res, expected)?;
        let challenge = header_of(&res, "www-authenticate");
        match (expected, description) {
            (StatusCode::OK, _) => ensure!(challenge.is_empty(), "成功の応答に WWW-Authenticate がある"),
            (_, None) => ensure!(
                challenge.starts_with("Bearer") && !challenge.contains("error="),
                "トークンなしの応答に error が含まれている: {challenge}"
            ),
            (_, Some(d)) => ensure!(
                challenge.contains("error=\"invalid_token\"") && challenge.contains(d),
                "invalid_token と {d} がない: {challenge}"
            ),
        }
        let text = res.text().await?;
        if !text.is_empty() {
            println!("  本文: {text}");
        }
        if expected == StatusCode::OK {
            ensure!(text.contains("\"sub\":\"user-0001\""), "API の応答に sub がない");
        }
    }

    step("12. 攻撃の再現: 攻撃者のブラウザで発行された request_id を被害者のブラウザから POST /authorize");
    let attacker = Client::builder().cookie_store(true).redirect(reqwest::redirect::Policy::none()).build()?;
    let victim = Client::builder().cookie_store(true).redirect(reqwest::redirect::Policy::none()).build()?;
    let (_, challenge3) = pkce_pair();
    let res = attacker.get(authorize_url(&challenge3)?).send().await?;
    expect_status(&res, StatusCode::OK)?;
    let attacker_request_id = hidden_request_id(&res.text().await?)?;
    let res = victim.get(authorize_url(&challenge3)?).send().await?;
    expect_status(&res, StatusCode::OK)?;
    let res = victim
        .post(format!("{OP}/authorize"))
        .form(&[("request_id", attacker_request_id.as_str()), ("username", USERNAME), ("password", PASSWORD)])
        .send()
        .await?;
    print_response(&res, &["location"]);
    expect_status(&res, StatusCode::BAD_REQUEST)?;
    ensure!(res.headers().get("location").is_none(), "認可コードが発行された");
    let body = text_of(&res.text().await?);
    println!("  本文: {body}");
    ensure!(body.contains("このブラウザで開始した認可リクエストではありません"), "別の理由で拒否された");
    Ok(())
}

fn tamper(token: &str) -> String {
    let parts: Vec<&str> = token.split('.').collect();
    let mut payload = parts[1].to_string();
    let last = payload.pop().unwrap_or('A');
    payload.push(if last == 'A' { 'B' } else { 'A' });
    format!("{}.{}.{}", parts[0], payload, parts[2])
}

#[tokio::main]
async fn main() -> Result<()> {
    browser_flow().await?;
    backchannel_flow().await?;
    println!("\nすべての段が完了しました");
    Ok(())
}
