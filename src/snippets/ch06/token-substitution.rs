use std::collections::HashMap;

// OP の内部。IdToken は OP のモジュールの外では作れず、書き換えられない(署名の代わり。署名は7章と8章で扱う)
mod op {
    use std::collections::HashMap;

    pub const ISSUER: &str = "https://op.example.com";

    #[derive(Debug, Clone)]
    pub struct IdToken {
        iss: String,
        sub: String,
        aud: String,
    }

    // 読み取り専用のアクセサ。フィールドは非公開のため、モジュールの外からは変更できない
    impl IdToken {
        pub fn iss(&self) -> &str {
            &self.iss
        }
        pub fn sub(&self) -> &str {
            &self.sub
        }
        pub fn aud(&self) -> &str {
            &self.aud
        }
    }

    pub struct Grant {
        pub access_token: String,
        pub id_token: IdToken,
    }

    #[derive(Default)]
    pub struct Op {
        // アクセストークン → (ユーザー, 発行先 client_id)
        access_tokens: HashMap<String, (String, String)>,
        counter: u32,
    }

    impl Op {
        // ユーザーがログインし、client_id 宛てにトークンを発行する
        pub fn login(&mut self, user: &str, client_id: &str) -> Grant {
            self.counter += 1;
            let access_token = format!("at-{:04}", self.counter);
            self.access_tokens
                .insert(access_token.clone(), (user.to_string(), client_id.to_string()));
            let id_token = IdToken {
                iss: ISSUER.to_string(),
                sub: user.to_string(),
                aud: client_id.to_string(),
            };
            Grant { access_token, id_token }
        }

        // UserInfo 相当: 有効なトークンなら持ち主を返す。発行先は返さない
        pub fn userinfo(&self, access_token: &str) -> Option<String> {
            self.access_tokens.get(access_token).map(|(user, _)| user.clone())
        }
    }
}

// OAuth だけでログインする RP: アクセストークンで UserInfo を呼び、返ったユーザーをログインさせる
fn oauth_only_login(op: &op::Op, access_token: &str) -> Result<String, String> {
    op.userinfo(access_token)
        .ok_or_else(|| "無効なアクセストークン".to_string())
}

// OIDC の RP: ID トークンの iss と aud を自分の設定と照合してからログインさせる
fn oidc_login(my_client_id: &str, id_token: &op::IdToken) -> Result<String, String> {
    if id_token.iss() != op::ISSUER {
        return Err(format!("iss={} は信頼する OP ではない", id_token.iss()));
    }
    if id_token.aud() != my_client_id {
        return Err(format!(
            "aud={} は自分の client_id {} と一致しない",
            id_token.aud(),
            my_client_id
        ));
    }
    Ok(id_token.sub().to_string())
}

fn show(result: Result<String, String>) {
    match result {
        Ok(user) => println!("    結果: {user} としてログインさせました"),
        Err(reason) => println!("    結果: 拒否しました ({reason})"),
    }
}

fn main() {
    let mut op = op::Op::default();
    let mut sessions: HashMap<&str, String> = HashMap::new();

    println!("[1] alice が攻撃者の運営するクイズアプリ(client_id=quiz-app)にログインします");
    let stolen = op.login("alice", "quiz-app");
    println!(
        "    OP → quiz-app: access_token={} / ID トークン(aud={})",
        stolen.access_token,
        stolen.id_token.aud()
    );

    println!("[2] 攻撃者は受け取ったトークンを、家計簿アプリ(client_id=kakeibo)に自分のものとして提示します");

    println!("--- OAuth だけでログインする家計簿アプリ ---");
    let result = oauth_only_login(&op, &stolen.access_token);
    if let Ok(user) = &result {
        println!("    UserInfo の応答: sub={user} (どのクライアント宛てのトークンかは返らない)");
        sessions.insert("攻撃者のブラウザ", user.clone());
    }
    show(result);

    println!("--- OIDC の家計簿アプリ (ID トークンの aud を検査) ---");
    let t = &stolen.id_token;
    println!("    ID トークン: iss={} sub={} aud={}", t.iss(), t.sub(), t.aud());
    show(oidc_login("kakeibo", t));

    println!("--- 正規の利用: alice 本人が家計簿アプリでログインします ---");
    let own = op.login("alice", "kakeibo");
    let t = &own.id_token;
    println!("    ID トークン: iss={} sub={} aud={}", t.iss(), t.sub(), t.aud());
    show(oidc_login("kakeibo", t));

    println!();
    for (browser, user) in &sessions {
        println!("OAuth だけの家計簿アプリのセッション: {browser} → {user}");
    }
}
