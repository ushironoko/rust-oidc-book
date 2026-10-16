use std::collections::HashMap;

// クライアントが保持する認可サーバの設定 (メタデータから取得した値)
struct AsConfig {
    issuer: &'static str,
    authorization_endpoint: &'static str,
    token_endpoint: &'static str,
    client_id: &'static str,
    iss_supported: bool,
}

// ブラウザのセッションに保存した、認可リクエストごとの記録
struct PendingAuth {
    issuer: &'static str,
    state: &'static str,
}

fn parse(query: &str) -> HashMap<String, String> {
    form_urlencoded::parse(query.as_bytes()).into_owned().collect()
}

// コールバック処理。check_iss が false の実装は RFC 9207 に未対応のクライアント
fn callback(
    servers: &[AsConfig],
    session: &PendingAuth,
    query: &str,
    check_iss: bool,
) -> Result<String, String> {
    let q = parse(query);
    if q.get("state").map(String::as_str) != Some(session.state) {
        return Err("state が一致しない (CSRF の疑い)".into());
    }
    let expected = servers.iter().find(|s| s.issuer == session.issuer).unwrap();
    if check_iss {
        match q.get("iss") {
            // form 復号済みの値を単純な文字列比較で照合する (RFC 9207 2.4節)
            Some(iss) if iss == expected.issuer => {}
            Some(iss) => return Err(format!("iss が一致しない (期待 {}, 受信 {iss})", expected.issuer)),
            None if expected.iss_supported => return Err("iss 対応の認可サーバなのに iss がない".into()),
            None => {}
        }
    }
    let code = q.get("code").ok_or("code がない")?;
    Ok(format!(
        "POST {} に code={code} と client_id={} を送る",
        expected.token_endpoint, expected.client_id
    ))
}

fn main() {
    let servers = [
        AsConfig {
            issuer: "https://honest.as.example",
            authorization_endpoint: "https://honest.as.example/authorize",
            token_endpoint: "https://honest.as.example/token",
            client_id: "7ZGZldHQ",
            iss_supported: true,
        },
        AsConfig {
            issuer: "https://attacker.example",
            authorization_endpoint: "https://attacker.example/authorize",
            token_endpoint: "https://attacker.example/token",
            client_id: "666RVZJTA",
            iss_supported: false,
        },
    ];

    println!("[1] 利用者が A-AS を選び、クライアントはセッションに A-AS を記録する");
    let session = PendingAuth { issuer: "https://attacker.example", state: "ZWVlNDBlYzA1NjdkMDNhYjg3ZjUxZjAyNGQzMTM2NzI" };
    println!("  302 Location: {}?response_type=code&client_id={}&state={}",
        servers[1].authorization_endpoint, servers[1].client_id, session.state);
    println!("  A-AS は client_id を差し替えて H-AS へ転送する");
    println!("  303 Location: {}?response_type=code&client_id={}&state={}",
        servers[0].authorization_endpoint, servers[0].client_id, session.state);

    let response = "code=x1848ZT64p4IirMPT0R-X3141MFPTuBX-VFL_cvaplMH58&state=ZWVlNDBlYzA1NjdkMDNhYjg3ZjUxZjAyNGQzMTM2NzI&iss=https%3A%2F%2Fhonest.as.example";
    println!("\n[2] H-AS の認可レスポンスがクライアントに届く");
    println!("  GET /cb?{response}");

    println!("\n[3] iss を検査しないクライアント");
    match callback(&servers, &session, response, false) {
        Ok(action) => println!("  {action}  <- H-AS の認可コードが攻撃者に渡る"),
        Err(e) => println!("  中止: {e}"),
    }

    println!("\n[4] iss を検査するクライアント");
    match callback(&servers, &session, response, true) {
        Ok(action) => println!("  {action}"),
        Err(e) => println!("  中止: {e}"),
    }

    println!("\n[5] 正常な H-AS とのフロー");
    let honest = PendingAuth { issuer: "https://honest.as.example", state: "N2JjNGJhY2JiZjRhYzA3MGJkMzNmMDE5OWJhZmJhZjA" };
    let ok = "code=dummy-code&state=N2JjNGJhY2JiZjRhYzA3MGJkMzNmMDE5OWJhZmJhZjA&iss=https%3A%2F%2Fhonest.as.example";
    println!("  {}", callback(&servers, &honest, ok, true).unwrap());

    println!("\n[6] iss 対応の H-AS からの応答に iss がない");
    let no_iss = "code=dummy-code&state=N2JjNGJhY2JiZjRhYzA3MGJkMzNmMDE5OWJhZmJhZjA";
    println!("  中止: {}", callback(&servers, &honest, no_iss, true).unwrap_err());

    println!("\n[7] 末尾にスラッシュが付いた iss");
    let slash = "code=dummy-code&state=N2JjNGJhY2JiZjRhYzA3MGJkMzNmMDE5OWJhZmJhZjA&iss=https%3A%2F%2Fhonest.as.example%2F";
    println!("  中止: {}", callback(&servers, &honest, slash, true).unwrap_err());
}
