use std::collections::HashMap;

// リフレッシュトークン1つの記録。family は同じ認可から派生したトークンの集まり
struct RefreshRecord {
    family: u32,
    used: bool,
}

struct Family {
    client_id: &'static str,
    scope: Vec<&'static str>,
    revoked: bool,
}

struct AuthServer {
    rotation: bool,
    tokens: HashMap<String, RefreshRecord>,
    families: HashMap<u32, Family>,
    issued: u32,
}

fn new_server(rotation: bool) -> AuthServer {
    AuthServer { rotation, tokens: HashMap::new(), families: HashMap::new(), issued: 0 }
}

fn mint(asv: &mut AuthServer, family: u32) -> String {
    asv.issued += 1;
    let rt = format!("RT{}", asv.issued);
    asv.tokens.insert(rt.clone(), RefreshRecord { family, used: false });
    rt
}

// 認可コードの交換が終わった時点を表す。新しいファミリーを作る
fn login(asv: &mut AuthServer, family: u32, scope: Vec<&'static str>) -> String {
    asv.families.insert(family, Family { client_id: "spa-client", scope, revoked: false });
    mint(asv, family)
}

// RFC 6749 6節の refresh_token グラントと、RFC 9700 4.14.2 の再利用検知
fn refresh(asv: &mut AuthServer, client_id: &str, rt: &str, scope: Option<Vec<&str>>) -> Result<String, String> {
    let rec = asv.tokens.get(rt).ok_or("invalid_grant (未知のトークン)")?;
    let fam_id = rec.family;
    let already_used = rec.used;
    let fam = asv.families.get_mut(&fam_id).unwrap();
    if fam.client_id != client_id {
        return Err("invalid_grant (別のクライアントに発行されたトークン)".into());
    }
    if fam.revoked {
        return Err("invalid_grant (ファミリーは失効済み)".into());
    }
    if already_used {
        fam.revoked = true;
        return Err(format!("invalid_grant (再利用を検知。ファミリー{fam_id}を失効)"));
    }
    if let Some(req) = scope {
        if let Some(extra) = req.iter().find(|s| !fam.scope.contains(s)) {
            return Err(format!("invalid_scope (元の同意にない {extra})"));
        }
    }
    if !asv.rotation {
        return Ok(format!("AT を発行 (RT は {rt} のまま)"));
    }
    asv.tokens.get_mut(rt).unwrap().used = true;
    let next = mint(asv, fam_id);
    Ok(format!("AT と新しい {next} を発行"))
}

fn show(who: &str, rt: &str, r: Result<String, String>) {
    match r {
        Ok(m) => println!("  {who} が {rt} を提示 -> {m}"),
        Err(e) => println!("  {who} が {rt} を提示 -> {e}"),
    }
}

fn main() {
    println!("[1] ローテーションなし: 盗まれたトークンを並行して使える");
    let mut asv = new_server(false);
    let rt = login(&mut asv, 1, vec!["orders:read"]);
    show("正規クライアント", &rt, refresh(&mut asv, "spa-client", &rt, None));
    show("攻撃者", &rt, refresh(&mut asv, "spa-client", &rt, None));
    show("正規クライアント", &rt, refresh(&mut asv, "spa-client", &rt, None));
    show("攻撃者", &rt, refresh(&mut asv, "spa-client", &rt, None));

    println!("\n[2] ローテーションあり: 攻撃者が先に使った場合");
    let mut asv = new_server(true);
    let rt1 = login(&mut asv, 2, vec!["orders:read"]);
    show("攻撃者", &rt1, refresh(&mut asv, "spa-client", &rt1, None));
    show("正規クライアント", &rt1, refresh(&mut asv, "spa-client", &rt1, None));
    show("攻撃者", "RT2", refresh(&mut asv, "spa-client", "RT2", None));

    println!("\n[3] ローテーションあり: 正規クライアントが先に使った場合");
    let mut asv = new_server(true);
    let rt1 = login(&mut asv, 3, vec!["orders:read"]);
    show("正規クライアント", &rt1, refresh(&mut asv, "spa-client", &rt1, None));
    show("正規クライアント", "RT2", refresh(&mut asv, "spa-client", "RT2", None));
    show("攻撃者", &rt1, refresh(&mut asv, "spa-client", &rt1, None));
    show("正規クライアント", "RT3", refresh(&mut asv, "spa-client", "RT3", None));

    println!("\n[4] スコープの拡大と、別クライアントによる提示");
    let mut asv = new_server(true);
    let rt1 = login(&mut asv, 4, vec!["orders:read"]);
    show("正規クライアント", &rt1, refresh(&mut asv, "spa-client", &rt1, Some(vec!["orders:read", "orders:write"])));
    show("別のクライアント", &rt1, refresh(&mut asv, "other-client", &rt1, None));
    show("正規クライアント", &rt1, refresh(&mut asv, "spa-client", &rt1, Some(vec!["orders:read"])));
}
