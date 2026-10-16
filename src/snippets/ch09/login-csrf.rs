use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use subtle::ConstantTimeEq;

fn random() -> String {
    let mut b = [0u8; 32];
    rand::fill(&mut b);
    URL_SAFE_NO_PAD.encode(b)
}

fn s256(v: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(v.as_bytes()))
}

fn eq(a: &str, b: &str) -> bool {
    a.as_bytes().ct_eq(b.as_bytes()).into()
}

// OP。認可コードを、ログインしたユーザー・nonce・code_challenge と結びつける
#[derive(Default)]
struct Op {
    codes: HashMap<String, (String, String, Option<String>)>,
    next: u32,
}

impl Op {
    fn authorize(&mut self, user: &str, nonce: &str, code_challenge: Option<String>) -> String {
        self.next += 1;
        let code = format!("code-{}", self.next);
        self.codes
            .insert(code.clone(), (user.into(), nonce.into(), code_challenge));
        code
    }

    // 戻り値は ID トークンの (sub, nonce)。署名と他のクレームの検証は8章で扱う
    fn token(&mut self, code: &str, verifier: Option<&str>) -> Result<(String, String), String> {
        let (user, nonce, challenge) = self.codes.remove(code).ok_or("invalid_grant")?;
        match (challenge, verifier) {
            (Some(c), Some(v)) if eq(&s256(v), &c) => Ok((user, nonce)),
            (None, None) => Ok((user, nonce)),
            _ => Err("invalid_grant (PKCE の照合に失敗)".into()),
        }
    }
}

// ログイン開始時に RP がブラウザのセッションに保存する値
#[derive(Clone)]
struct Pending {
    state: String,
    nonce: String,
    verifier: String,
}

#[derive(Clone, Copy)]
struct Defense {
    check_state: bool,
    check_nonce: bool,
    use_pkce: bool,
}

fn start_login(sessions: &mut HashMap<&'static str, Pending>, browser: &'static str) -> Pending {
    let p = Pending { state: random(), nonce: random(), verifier: random() };
    sessions.insert(browser, p.clone());
    p
}

// RP のコールバック: /cb?code=...&state=...
fn callback(
    op: &mut Op,
    pending: &Pending,
    code: &str,
    state: &str,
    d: Defense,
) -> Result<String, String> {
    if d.check_state && !eq(state, &pending.state) {
        return Err("state がこのブラウザのセッションの値と一致しない".into());
    }
    let verifier = d.use_pkce.then_some(pending.verifier.as_str());
    let (sub, nonce) = op.token(code, verifier)?;
    if d.check_nonce && !eq(&nonce, &pending.nonce) {
        return Err("ID トークンの nonce がこのブラウザのセッションの値と一致しない".into());
    }
    Ok(sub)
}

fn main() {
    let cases = [
        ("検査なし", Defense { check_state: false, check_nonce: false, use_pkce: false }),
        ("state だけ", Defense { check_state: true, check_nonce: false, use_pkce: false }),
        ("nonce だけ", Defense { check_state: false, check_nonce: true, use_pkce: false }),
        ("PKCE だけ", Defense { check_state: false, check_nonce: false, use_pkce: true }),
    ];
    for (label, d) in cases {
        let mut op = Op::default();
        let mut sessions = HashMap::new();

        // 1. 攻撃者が自分のブラウザでログインを開始し、OP で自分のアカウントにログインする
        let a = start_login(&mut sessions, "攻撃者のブラウザ");
        let challenge = d.use_pkce.then(|| s256(&a.verifier));
        let attacker_code = op.authorize("mallory", &a.nonce, challenge);
        // 2. コールバックには進まず、URL を被害者のブラウザに開かせる。被害者側にもログイン開始の値がある
        let v = start_login(&mut sessions, "被害者のブラウザ");
        let result = callback(&mut op, &v, &attacker_code, &a.state, d);

        match result {
            Ok(sub) => println!("[{label}] 被害者のブラウザが {sub} としてログインしました"),
            Err(e) => println!("[{label}] 拒否しました: {e}"),
        }
    }

    // 正規のログインはどの防御でも通る
    let mut op = Op::default();
    let mut sessions = HashMap::new();
    let p = start_login(&mut sessions, "alice のブラウザ");
    let code = op.authorize("alice", &p.nonce, Some(s256(&p.verifier)));
    let all = Defense { check_state: true, check_nonce: true, use_pkce: true };
    match callback(&mut op, &p, &code, &p.state, all) {
        Ok(sub) => println!("[3つすべて] 正規のログイン: {sub} としてログインしました"),
        Err(e) => println!("[3つすべて] 正規のログイン: 拒否 {e}"),
    }
}
