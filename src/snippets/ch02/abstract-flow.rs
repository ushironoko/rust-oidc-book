use std::collections::BTreeSet;

// 各ロールが保持している秘密の値を記録する
struct Role {
    name: &'static str,
    knows: BTreeSet<&'static str>,
}

fn role(name: &'static str, initial: &[&'static str]) -> Role {
    Role { name, knows: initial.iter().copied().collect() }
}

// from から to へ値が渡ったことを記録して表示する
fn send(step: &str, from: &Role, to: &mut Role, what: &'static str, note: &str) {
    println!("({step}) {} → {}: {what}  {note}", from.name, to.name);
    to.knows.insert(what);
}

fn main() {
    let mut owner = role("リソースオーナー", &["パスワード"]);
    let mut client = role("クライアント", &[]);
    let mut authz = role("認可サーバ", &["パスワード"]);
    let mut resource = role("リソースサーバ", &["写真"]);

    send("A", &client, &mut owner, "認可の依頼", "(写真を読ませてください)");
    // 利用者は認可サーバに対してだけパスワードを入力する
    send("B", &owner, &mut client, "権限付与 (認可コード)", "(利用者の許可を表す値)");
    send("C", &client, &mut authz, "権限付与 (認可コード)", "(クライアント自身も認証する)");
    // 認可サーバはコードを検証し、アクセストークンを生成する
    authz.knows.insert("アクセストークン");
    send("D", &authz, &mut client, "アクセストークン", "(範囲: photos:read)");
    send("E", &client, &mut resource, "アクセストークン", "");
    send("F", &resource, &mut client, "写真", "");

    println!("\n各ロールが保持している値:");
    for r in [&owner, &client, &authz, &resource] {
        let list: Vec<&str> = r.knows.iter().copied().collect();
        println!("  {}: {}", r.name, list.join(", "));
    }
    println!(
        "\nクライアントはパスワードを保持しているか: {}",
        client.knows.contains("パスワード")
    );
}
