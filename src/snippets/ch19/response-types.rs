use std::collections::BTreeSet;

#[derive(Debug, Clone, Copy, PartialEq)]
enum Mode {
    Query,
    Fragment,
    FormPost,
}

struct Profile {
    flow: &'static str,
    from_authz: Vec<&'static str>,
    default_mode: Mode,
    nonce_required: bool,
}

// 空白区切りの集合として比較する(順序は意味を持たない)
fn parse(response_type: &str) -> BTreeSet<&str> {
    response_type.split(' ').filter(|s| !s.is_empty()).collect()
}

fn profile(rt: &BTreeSet<&str>) -> Result<Profile, String> {
    let has = |v| rt.contains(v);
    if rt.iter().any(|v| !["code", "id_token", "token", "none"].contains(v)) {
        return Err("unsupported_response_type".into());
    }
    let mut from_authz = vec![];
    if has("code") { from_authz.push("code"); }
    if has("id_token") { from_authz.push("id_token"); }
    if has("token") { from_authz.extend(["access_token", "token_type"]); }
    let (flow, default_mode, nonce_required) = match (has("code"), has("id_token"), has("token")) {
        (true, false, false) => ("認可コードフロー", Mode::Query, false),
        (false, true, _) => ("インプリシットフロー", Mode::Fragment, true),
        (true, true, _) => ("ハイブリッドフロー", Mode::Fragment, true),
        (true, false, true) => ("ハイブリッドフロー", Mode::Fragment, false),
        (false, false, true) => ("OAuthのインプリシットグラント(OIDCでは使わない)", Mode::Fragment, false),
        _ if has("none") && rt.len() == 1 => ("none(何も返さない)", Mode::Query, false),
        _ => return Err("invalid_request".into()),
    };
    Ok(Profile { flow, from_authz, default_mode, nonce_required })
}

// 応答モードの決定。既定がフラグメントの組み合わせに query は使えない
fn choose_mode(p: &Profile, requested: Option<Mode>) -> Result<Mode, String> {
    match requested {
        None => Ok(p.default_mode),
        Some(Mode::Query) if p.default_mode == Mode::Fragment => {
            Err("query は MUST NOT (トークンがURLのクエリに入る)".into())
        }
        Some(m) => Ok(m),
    }
}

fn main() {
    let cases = [
        ("code", None),
        ("id_token", None),
        ("id_token token", None),
        ("code id_token", None),
        ("id_token code", None),
        ("code token", None),
        ("code id_token token", None),
        ("code id_token", Some(Mode::FormPost)),
        ("code id_token", Some(Mode::Query)),
        ("token", None),
        ("code idtoken", None),
    ];
    for (rt, requested) in cases {
        let set = parse(rt);
        print!("{:<22} ", format!("{rt:?}"));
        match profile(&set) {
            Err(e) => println!("-> エラー {e}"),
            Ok(p) => {
                let mode = choose_mode(&p, requested);
                let at_in_authz = set.contains("token");
                println!("-> {}", p.flow);
                println!("{:23}認可エンドポイントから返る値: {:?}", "", p.from_authz);
                println!("{:23}応答モード(要求 {requested:?}): {mode:?}", "");
                println!("{:23}nonce 必須: {} / 認可応答にアクセストークン: {}", "", p.nonce_required, at_in_authz);
            }
        }
    }
}
