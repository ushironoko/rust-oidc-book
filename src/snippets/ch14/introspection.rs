use serde_json::{Value, json};
use std::collections::HashMap;

// 認可サーバが保持するトークンの記録。不透明トークンの値そのものには意味がない
struct TokenRecord {
    sub: &'static str,
    client_id: &'static str,
    aud: &'static str,
    scope: &'static str,
    exp: u64,
    revoked: bool,
}

struct AuthServer {
    tokens: HashMap<&'static str, TokenRecord>,
    // イントロスペクションを呼べるリソースサーバの資格情報
    rs_credentials: HashMap<&'static str, &'static str>,
    // 機密クライアントの資格情報
    client_credentials: HashMap<&'static str, &'static str>,
}

// RFC 7662 2.1節/2.2節: 呼び出し元を認証し、active とメタ情報を返す
fn introspect(
    asv: &AuthServer,
    caller: Option<(&str, &str)>,
    token: &str,
    now: u64,
) -> Result<Value, &'static str> {
    let (rs_id, secret) = caller.ok_or("401 Unauthorized (呼び出し元の認証がない)")?;
    if asv.rs_credentials.get(rs_id) != Some(&secret) {
        return Err("401 Unauthorized (呼び出し元の認証に失敗)");
    }
    let inactive = json!({"active": false});
    let Some(t) = asv.tokens.get(token) else {
        return Ok(inactive);
    };
    if t.revoked || now >= t.exp || t.aud != rs_id {
        return Ok(inactive);
    }
    Ok(json!({
        "active": true, "sub": t.sub, "client_id": t.client_id,
        "aud": t.aud, "scope": t.scope, "exp": t.exp,
        "iss": "https://as.example.com/", "token_type": "Bearer"
    }))
}

// RFC 7009 2.1節/2.2節: 資格情報を検証し、要求元に発行したトークンだけを失効させる
fn revoke(asv: &mut AuthServer, client: (&str, &str), token: &str) -> &'static str {
    let (client_id, secret) = client;
    if asv.client_credentials.get(client_id) != Some(&secret) {
        return "401 invalid_client";
    }
    match asv.tokens.get_mut(token) {
        // 存在しないトークンでも 200 を返す
        None => "200 OK",
        Some(t) if t.client_id != client_id => "400 Bad Request (要求元に発行されたトークンではない)",
        Some(t) => {
            t.revoked = true;
            "200 OK"
        }
    }
}

// リソースサーバ: イントロスペクションの結果を ttl 秒だけキャッシュする
struct ResourceServer {
    id: &'static str,
    secret: &'static str,
    ttl: u64,
    // 値はキャッシュの期限。RFC 7662 4節により exp を超えない
    cache: HashMap<String, (Value, u64)>,
}

fn handle_request(rs: &mut ResourceServer, asv: &AuthServer, token: &str, now: u64) -> String {
    let (resp, source) = match rs.cache.get(token) {
        Some((v, until)) if now < *until => (v.clone(), "キャッシュ"),
        _ => match introspect(asv, Some((rs.id, rs.secret)), token, now) {
            Ok(v) => {
                let until = v["exp"].as_u64().map_or(now + rs.ttl, |exp| exp.min(now + rs.ttl));
                rs.cache.insert(token.to_string(), (v.clone(), until));
                (v, "イントロスペクション")
            }
            Err(e) => return format!("500 (認可サーバへの問い合わせ失敗: {e})"),
        },
    };
    if resp["active"] == true {
        format!("200 OK [{source}] sub={}", resp["sub"])
    } else {
        format!("401 invalid_token [{source}]")
    }
}

fn main() {
    let mut asv = AuthServer {
        tokens: HashMap::from([
            ("dummy-opaque-token-A", TokenRecord {
                sub: "user-5821", client_id: "s6BhdRkqt3", aud: "https://api.example.com/orders",
                scope: "orders:read", exp: 3600, revoked: false,
            }),
            ("dummy-opaque-token-B", TokenRecord {
                sub: "user-5821", client_id: "s6BhdRkqt3", aud: "https://api.example.com/payments",
                scope: "payments:read", exp: 3600, revoked: false,
            }),
            ("dummy-opaque-token-C", TokenRecord {
                sub: "user-5821", client_id: "s6BhdRkqt3", aud: "https://api.example.com/orders",
                scope: "orders:read", exp: 30, revoked: false,
            }),
        ]),
        rs_credentials: HashMap::from([("https://api.example.com/orders", "dummy-rs-secret")]),
        client_credentials: HashMap::from([
            ("s6BhdRkqt3", "dummy-client-secret"),
            ("other-client", "dummy-other-secret"),
        ]),
    };
    let client = ("s6BhdRkqt3", "dummy-client-secret");

    println!("[1] イントロスペクション応答の中身");
    let caller = Some(("https://api.example.com/orders", "dummy-rs-secret"));
    println!("  有効なトークン: {}", introspect(&asv, caller, "dummy-opaque-token-A", 0).unwrap());
    println!("  存在しないトークン: {}", introspect(&asv, caller, "no-such-token", 0).unwrap());
    println!("  別の RS 宛てのトークン: {}", introspect(&asv, caller, "dummy-opaque-token-B", 0).unwrap());
    println!("  認証なしの呼び出し: {}", introspect(&asv, None, "dummy-opaque-token-A", 0).unwrap_err());

    println!("\n[2] キャッシュ (ttl=60秒) と失効の時間差");
    let mut rs = ResourceServer {
        id: "https://api.example.com/orders",
        secret: "dummy-rs-secret",
        ttl: 60,
        cache: HashMap::new(),
    };
    println!("  t=0   API 呼び出し -> {}", handle_request(&mut rs, &asv, "dummy-opaque-token-A", 0));
    println!("  t=5   資格情報なしで失効を要求 -> {}", revoke(&mut asv, ("s6BhdRkqt3", ""), "dummy-opaque-token-A"));
    println!(
        "  t=5   別のクライアントが失効を要求 -> {}",
        revoke(&mut asv, ("other-client", "dummy-other-secret"), "dummy-opaque-token-A")
    );
    println!("  t=10  クライアントが失効を要求 -> {}", revoke(&mut asv, client, "dummy-opaque-token-A"));
    println!("  t=20  API 呼び出し -> {}", handle_request(&mut rs, &asv, "dummy-opaque-token-A", 20));
    println!("  t=59  API 呼び出し -> {}", handle_request(&mut rs, &asv, "dummy-opaque-token-A", 59));
    println!("  t=61  API 呼び出し -> {}", handle_request(&mut rs, &asv, "dummy-opaque-token-A", 61));
    println!("  失効要求に不正なトークンを渡す -> {}", revoke(&mut asv, client, "no-such-token"));

    println!("\n[3] exp=30 のトークン (ttl=60秒より先に期限が来る)");
    println!("  t=0   API 呼び出し -> {}", handle_request(&mut rs, &asv, "dummy-opaque-token-C", 0));
    println!("  t=29  API 呼び出し -> {}", handle_request(&mut rs, &asv, "dummy-opaque-token-C", 29));
    println!("  t=30  API 呼び出し -> {}", handle_request(&mut rs, &asv, "dummy-opaque-token-C", 30));
}
