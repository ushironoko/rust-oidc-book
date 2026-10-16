use std::collections::HashMap;

#[derive(Clone, Debug)]
enum SessionData {
    Anonymous,
    LoggedIn { sub: String },
}

// サーバ側のセッションストア。実際の ID は CSPRNG で作るが、出力を固定するため連番にする
struct Store {
    sessions: HashMap<String, SessionData>,
    next: u32,
}

fn new_session(store: &mut Store) -> String {
    store.next += 1;
    let sid = format!("sid-{:04}", store.next);
    store.sessions.insert(sid.clone(), SessionData::Anonymous);
    sid
}

// ログイン成功時の処理。cycle が true ならセッション ID を再発行する
fn complete_login(store: &mut Store, cookie_sid: &str, sub: &str, cycle: bool) -> String {
    let sid = if cycle {
        store.sessions.remove(cookie_sid);
        new_session(store)
    } else {
        cookie_sid.to_string()
    };
    store.sessions.insert(sid.clone(), SessionData::LoggedIn { sub: sub.to_string() });
    sid
}

fn whoami(store: &Store, sid: &str) -> String {
    match store.sessions.get(sid) {
        Some(SessionData::LoggedIn { sub }) => format!("ログイン中 sub={sub}"),
        Some(SessionData::Anonymous) => "未ログイン".to_string(),
        None => "セッションなし".to_string(),
    }
}

fn run(cycle: bool) {
    println!("== セッション ID の再発行: {}", if cycle { "する" } else { "しない" });
    let mut store = Store { sessions: HashMap::new(), next: 0 };

    // 1. 攻撃者が RP にアクセスしてセッション ID を得る
    let attacker_sid = new_session(&mut store);
    println!("攻撃者が得た ID: {attacker_sid}");

    // 2. 攻撃者はその ID を被害者のブラウザの Cookie に設定させる
    let victim_cookie = attacker_sid.clone();
    println!("被害者のブラウザの Cookie: {victim_cookie}");

    // 3. 被害者が OP でログインし、RP のコールバックが成功する
    let victim_sid = complete_login(&mut store, &victim_cookie, "victim-0001", cycle);
    println!("ログイン後に被害者へ渡す ID: {victim_sid}");

    // 4. 攻撃者が自分の持つ ID で RP にアクセスする
    println!("被害者の ID で見た状態: {}", whoami(&store, &victim_sid));
    println!("攻撃者の ID で見た状態: {}", whoami(&store, &attacker_sid));
    let debug: Vec<_> = {
        let mut v: Vec<_> = store.sessions.iter().collect();
        v.sort_by_key(|(k, _)| k.to_string());
        v.into_iter().map(|(k, d)| format!("{k}={d:?}")).collect()
    };
    println!("ストアの中身: {}\n", debug.join(", "));
}

fn main() {
    run(false);
    run(true);
}
