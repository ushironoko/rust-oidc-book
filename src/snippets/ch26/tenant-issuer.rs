use std::collections::HashMap;

// マルチテナント OP が発行した ID トークンのうち、検証に関わるクレームだけを持つ
// 署名はテナント共通の鍵で検証済みとする(共通鍵の OP では署名だけではテナントを区別できない)
struct Claims {
    iss: &'static str,
    tid: &'static str,
    aud: &'static str,
    sub: &'static str,
}

const CLIENT_ID: &str = "saas-app";

// 誤り: issuer をテンプレートで一括許可する
fn by_template(c: &Claims) -> Result<String, String> {
    let ok = c.iss.starts_with("https://login.example.com/") && c.iss.ends_with("/v2");
    if !ok || c.aud != CLIENT_ID {
        return Err("iss または aud が不正".into());
    }
    Ok(format!("ユーザー {}", c.sub))
}

// 誤り: テンプレート + iss と tid の一致確認(どのテナントかは分かるが、許可はしていない)
fn by_template_and_tid(c: &Claims) -> Result<String, String> {
    by_template(c)?;
    if c.iss != format!("https://login.example.com/{}/v2", c.tid) {
        return Err("iss と tid が一致しない".into());
    }
    Ok(format!("テナント {} のユーザー {}", c.tid, c.sub))
}

// 正: 契約済みテナントの issuer を完全一致で引き、(iss, sub) を利用者のキーにする
fn by_allowlist(c: &Claims, tenants: &HashMap<&str, &str>) -> Result<String, String> {
    let org = tenants.get(c.iss).ok_or(format!("未登録の issuer {}", c.iss))?;
    if c.aud != CLIENT_ID {
        return Err("aud が不正".into());
    }
    if c.iss != format!("https://login.example.com/{}/v2", c.tid) {
        return Err("iss と tid が一致しない".into());
    }
    Ok(format!("組織 {org} の利用者 ({}, {})", c.iss, c.sub))
}

fn main() {
    let tenants = HashMap::from([
        ("https://login.example.com/acme/v2", "Acme 社"),
        ("https://login.example.com/globex/v2", "Globex 社"),
    ]);
    let tokens = [
        ("Acme 社の正規ユーザー", Claims { iss: "https://login.example.com/acme/v2", tid: "acme", aud: CLIENT_ID, sub: "u-100" }),
        ("攻撃者が自分で作ったテナント", Claims { iss: "https://login.example.com/evil/v2", tid: "evil", aud: CLIENT_ID, sub: "u-100" }),
        ("iss と tid が食い違うトークン", Claims { iss: "https://login.example.com/acme/v2", tid: "evil", aud: CLIENT_ID, sub: "x-1" }),
    ];
    let show = |r: Result<String, String>| match r {
        Ok(s) => format!("受理: {s}"),
        Err(e) => format!("拒否: {e}"),
    };
    for (label, c) in &tokens {
        println!("== {label} (iss={}, tid={}, sub={})", c.iss, c.tid, c.sub);
        println!("  テンプレート           {}", show(by_template(c)));
        println!("  テンプレート + tid     {}", show(by_template_and_tid(c)));
        println!("  許可リスト             {}", show(by_allowlist(c, &tenants)));
    }
}
