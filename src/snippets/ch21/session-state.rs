use sha2::{Digest, Sha256};

const CLIENT_ID: &str = "s6BhdRkqt3";
const RP_ORIGIN: &str = "https://client.example.org";

// Session Management 1.0 3.2節の擬似コードと同じ計算
// session_state = hex(SHA-256(client_id + " " + origin + " " + OPのUA状態 + " " + salt)) + "." + salt
fn session_state(client_id: &str, origin: &str, opuas: &str, salt: &str) -> String {
    let d = Sha256::digest(format!("{client_id} {origin} {opuas} {salt}").as_bytes());
    let hex: String = d.iter().map(|b| format!("{b:02x}")).collect();
    format!("{hex}.{salt}")
}

// OP iframe: RP iframe から postMessage で届いた "client_id session_state" を検査する
// opuas は OP のオリジンのCookieから読む値。読めなければ None
fn op_iframe(data: &str, sender_origin: &str, opuas: Option<&str>) -> &'static str {
    if sender_origin != RP_ORIGIN {
        return "error";
    }
    let Some((client_id, ss)) = data.rsplit_once(' ') else { return "error" };
    let Some((_, salt)) = ss.split_once('.') else { return "error" };
    let recalculated = session_state(client_id, sender_origin, opuas.unwrap_or(""), salt);
    if recalculated == ss { "unchanged" } else { "changed" }
}

// prompt=none の再認証要求(非表示 iframe 内)。OP のCookieが届かなければ login_required
fn prompt_none(op_cookie_visible: bool, logged_in: bool) -> Result<&'static str, &'static str> {
    if op_cookie_visible && logged_in { Ok("新しいIDトークンと session_state") } else { Err("login_required") }
}

fn main() {
    let salt = "dummysalt";
    let mut opuas = "op-ua-state-1";
    let ss = session_state(CLIENT_ID, RP_ORIGIN, opuas, salt);
    println!("認証応答の session_state = {ss}\n");
    let msg = format!("{CLIENT_ID} {ss}");

    println!("== サードパーティCookieが読める場合 ==");
    println!("1回目の確認: {}", op_iframe(&msg, RP_ORIGIN, Some(opuas)));
    println!("他オリジンからの問い合わせ: {}", op_iframe(&msg, "https://evil.example", Some(opuas)));
    opuas = "op-ua-state-2";
    println!("OPでログアウトした後: {}", op_iframe(&msg, RP_ORIGIN, Some(opuas)));
    println!("  RPは prompt=none で確認 -> {:?} -> RPもログアウト", prompt_none(true, false));

    println!("\n== サードパーティCookieが遮断された場合 ==");
    let opuas = "op-ua-state-1";
    let ss = session_state(CLIENT_ID, RP_ORIGIN, opuas, salt);
    let msg = format!("{CLIENT_ID} {ss}");
    for round in 1..=3 {
        println!("{round}回目の確認: {}", op_iframe(&msg, RP_ORIGIN, None));
    }
    println!("  OPではログイン中だが prompt=none -> {:?}", prompt_none(false, true));
    println!("  RPは利用者がログアウトしたと誤って判断する");
}
