use std::collections::{HashMap, HashSet};

// 写真共有サービスの API が受け付ける操作と、必要なスコープ
const OPERATIONS: [(&str, &str); 4] = [
    ("写真を読む", "photos:read"),
    ("写真を削除する", "photos:delete"),
    ("住所を読む", "profile:address"),
    ("パスワードを変更する", "account:admin"),
];

// 方式A: 第三者アプリがユーザーのパスワードを保持して API を呼ぶ
struct PasswordApi {
    password: String,
}

impl PasswordApi {
    fn call(&self, presented_password: &str, _op: &str) -> bool {
        // パスワードが合えば、どの操作も本人の操作と区別できない
        presented_password == self.password
    }
}

// 方式B: 認可サーバがアプリごとにスコープ付きトークンを発行する
struct TokenApi {
    // トークン → (発行先アプリ, 許可されたスコープ)
    tokens: HashMap<String, (String, HashSet<String>)>,
}

impl TokenApi {
    fn issue(&mut self, token: &str, client: &str, scopes: &[&str]) {
        let scopes = scopes.iter().map(|s| s.to_string()).collect();
        self.tokens.insert(token.to_string(), (client.to_string(), scopes));
    }

    fn revoke_client(&mut self, client: &str) {
        self.tokens.retain(|_, (c, _)| c != client);
    }

    fn call(&self, token: &str, required_scope: &str) -> bool {
        self.tokens
            .get(token)
            .is_some_and(|(_, scopes)| scopes.contains(required_scope))
    }
}

fn mark(ok: bool) -> &'static str {
    if ok { "許可" } else { "拒否" }
}

fn print_table(title: &str, holders: &[(&str, &dyn Fn(&str) -> bool)]) {
    println!("{title}");
    for (op, scope) in OPERATIONS {
        let cells: Vec<String> = holders
            .iter()
            .map(|(name, can)| format!("{name}={}", mark(can(scope))))
            .collect();
        println!("  {op}: {}", cells.join(" / "));
    }
    println!();
}

fn main() {
    // 方式A
    let mut api_a = PasswordApi { password: "alice-dummy-pw".to_string() };
    let print_app_pw = "alice-dummy-pw".to_string();
    let photobook_pw = "alice-dummy-pw".to_string();
    print_table(
        "[方式A] パスワードを共有した場合",
        &[
            ("印刷アプリ", &|op| api_a.call(&print_app_pw, op)),
            ("フォトブック", &|op| api_a.call(&photobook_pw, op)),
        ],
    );

    // 印刷アプリだけを止めたい。手段はパスワード変更しかない
    api_a.password = "alice-new-dummy-pw".to_string();
    print_table(
        "[方式A] 印刷アプリを止めるためにパスワードを変更した後",
        &[
            ("印刷アプリ", &|op| api_a.call(&print_app_pw, op)),
            ("フォトブック", &|op| api_a.call(&photobook_pw, op)),
        ],
    );

    // 方式B
    let mut api_b = TokenApi { tokens: HashMap::new() };
    api_b.issue("dummy-token-print", "印刷アプリ", &["photos:read"]);
    api_b.issue("dummy-token-book", "フォトブック", &["photos:read", "profile:address"]);
    print_table(
        "[方式B] スコープ付きトークンを発行した場合",
        &[
            ("印刷アプリ", &|s| api_b.call("dummy-token-print", s)),
            ("フォトブック", &|s| api_b.call("dummy-token-book", s)),
        ],
    );

    api_b.revoke_client("印刷アプリ");
    print_table(
        "[方式B] 印刷アプリのトークンだけを失効させた後",
        &[
            ("印刷アプリ", &|s| api_b.call("dummy-token-print", s)),
            ("フォトブック", &|s| api_b.call("dummy-token-book", s)),
        ],
    );
}
