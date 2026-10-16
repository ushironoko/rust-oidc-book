// BFF のセッション Cookie を組み立て、ブラウザ側の規則(接頭辞と SameSite)を関数で再現して確かめる

#[derive(Debug, Clone, Copy, PartialEq)]
enum SameSite {
    Strict,
    Lax,
    None,
}

struct Cookie {
    name: String,
    secure: bool,
    http_only: bool,
    path: Option<String>,
    domain: Option<String>,
    same_site: SameSite,
}

fn set_cookie_header(c: &Cookie, value: &str) -> String {
    let mut s = format!("Set-Cookie: {}={}", c.name, value);
    if let Some(p) = &c.path {
        s += &format!("; Path={p}");
    }
    if let Some(d) = &c.domain {
        s += &format!("; Domain={d}");
    }
    if c.secure {
        s += "; Secure";
    }
    if c.http_only {
        s += "; HttpOnly";
    }
    s += &format!("; SameSite={:?}", c.same_site);
    s
}

// 接頭辞の規則(Cookie 仕様の改訂版による)。満たさない Cookie はブラウザが保存しない
fn prefix_check(c: &Cookie, secure_origin: bool, set_by_script: bool) -> Result<(), String> {
    let host_rules = |c: &Cookie| -> Result<(), String> {
        if !(c.secure && secure_origin) {
            return Err("Secure 属性と https のオリジンが必要".into());
        }
        if c.domain.is_some() {
            return Err("Domain 属性を付けてはならない".into());
        }
        if c.path.as_deref() != Some("/") {
            return Err("Path=/ が必要".into());
        }
        Ok(())
    };
    if c.name.starts_with("__Host-Http-") {
        host_rules(c)?;
        if !c.http_only || set_by_script {
            return Err("HttpOnly が必要で、スクリプトからは設定できない".into());
        }
    } else if c.name.starts_with("__Host-") {
        host_rules(c)?;
    }
    if c.same_site == SameSite::None && !c.secure {
        return Err("SameSite=None には Secure が必要".into());
    }
    Ok(())
}

// サイト: 登録可能ドメイン(eTLD+1)。このコードでは末尾2ラベルで近似する
fn site(host: &str) -> String {
    let labels: Vec<&str> = host.split('.').collect();
    labels[labels.len().saturating_sub(2)..].join(".")
}

struct Req {
    from: &'static str,
    to: &'static str,
    top_level_nav: bool,
    method: &'static str,
}

fn sends(c: &Cookie, r: &Req) -> bool {
    let same_site = site(r.from) == site(r.to);
    match c.same_site {
        SameSite::Strict => same_site,
        SameSite::Lax => same_site || (r.top_level_nav && r.method == "GET"),
        SameSite::None => true,
    }
}

fn mark(b: bool) -> &'static str {
    if b { "送る    " } else { "送らない" }
}

fn main() {
    let bff = Cookie {
        name: "__Host-Http-session".into(),
        secure: true,
        http_only: true,
        path: Some("/".into()),
        domain: None,
        same_site: SameSite::Strict,
    };
    println!("[1] BFF が返すヘッダ");
    println!("  {}", set_cookie_header(&bff, "Zm9vYmFyLWR1bW15LXNlc3Npb24"));

    println!();
    println!("[2] 接頭辞の規則");
    let mk = |name: &str, secure, http_only, path: Option<&str>, domain: Option<&str>| Cookie {
        name: name.into(),
        secure,
        http_only,
        path: path.map(Into::into),
        domain: domain.map(Into::into),
        same_site: SameSite::Strict,
    };
    let cases = [
        (mk("__Host-Http-session", true, true, Some("/"), None), true, false),
        (mk("__Host-session", true, false, Some("/"), Some("example.com")), true, false),
        (mk("__Host-session", true, true, Some("/app"), None), true, false),
        (mk("__Host-session", true, true, Some("/"), None), false, false),
        (mk("__Host-Http-session", true, true, Some("/"), None), true, true),
        (mk("session", false, false, None, Some("example.com")), false, false),
    ];
    for (c, secure_origin, by_script) in &cases {
        let line = set_cookie_header(c, "x");
        let how = if *by_script { "スクリプトで設定" } else { "HTTP で設定" };
        let origin = if *secure_origin { "https" } else { "http" };
        match prefix_check(c, *secure_origin, *by_script) {
            Ok(()) => println!("  保存   {line}  ({origin}、{how})"),
            Err(e) => println!("  破棄   {line}  ({origin}、{how}): {e}"),
        }
    }

    println!();
    println!("[3] SameSite ごとに Cookie を送るか(BFF は app.example.com)");
    let reqs = [
        ("同一オリジンの fetch", Req { from: "app.example.com", to: "app.example.com", top_level_nav: false, method: "POST" }),
        ("他サイトのリンクから GET で遷移", Req { from: "evil.example.net", to: "app.example.com", top_level_nav: true, method: "GET" }),
        ("他サイトのフォームから POST", Req { from: "evil.example.net", to: "app.example.com", top_level_nav: true, method: "POST" }),
        ("他サイトのスクリプトから fetch(include)", Req { from: "evil.example.net", to: "app.example.com", top_level_nav: false, method: "POST" }),
        ("同一サイトの別サブドメインから fetch(include)", Req { from: "b.example.com", to: "app.example.com", top_level_nav: false, method: "POST" }),
    ];
    println!("  SameSite の条件だけで判定。(include) は fetch に credentials: \"include\" を指定した場合");
    println!("  Strict   Lax      None");
    for (label, r) in &reqs {
        let row: Vec<String> = [SameSite::Strict, SameSite::Lax, SameSite::None]
            .iter()
            .map(|s| {
                let c = Cookie { same_site: *s, ..mk("__Host-Http-session", true, true, Some("/"), None) };
                mark(sends(&c, r)).to_string()
            })
            .collect();
        println!("  {} {label}", row.join(" "));
    }
}
