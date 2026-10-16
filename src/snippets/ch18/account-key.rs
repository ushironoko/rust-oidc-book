use std::collections::HashMap;

// 検証済みIDトークンから取り出したクレーム(署名検証は済んでいる前提)
#[derive(Clone)]
struct Claims {
    iss: &'static str,
    sub: &'static str,
    email: &'static str,
    email_verified: bool,
}

#[derive(Clone, Copy)]
enum Policy {
    Email,
    VerifiedEmail,
    IssSub,
}

struct Rp {
    accounts: Vec<&'static str>,
    by_email: HashMap<String, usize>,
    by_iss_sub: HashMap<(String, String), usize>,
}

impl Rp {
    fn new() -> Self {
        Rp { accounts: vec![], by_email: HashMap::new(), by_iss_sub: HashMap::new() }
    }

    fn register(&mut self, owner: &'static str, c: &Claims) -> usize {
        self.accounts.push(owner);
        let id = self.accounts.len() - 1;
        self.by_email.insert(c.email.to_string(), id);
        self.by_iss_sub.insert((c.iss.to_string(), c.sub.to_string()), id);
        id
    }

    // ログイン時に対応づけるアカウントを決める
    fn login(&self, policy: Policy, c: &Claims) -> Option<usize> {
        match policy {
            Policy::Email => self.by_email.get(c.email).copied(),
            Policy::VerifiedEmail if c.email_verified => self.by_email.get(c.email).copied(),
            Policy::VerifiedEmail => None,
            Policy::IssSub => self.by_iss_sub.get(&(c.iss.to_string(), c.sub.to_string())).copied(),
        }
    }
}

fn main() {
    let alice = Claims {
        iss: "https://idp-a.example",
        sub: "a-1001",
        email: "alice@corp.example",
        email_verified: true,
    };
    let mut rp = Rp::new();
    rp.register("Alice", &alice);

    let scenarios = [
        (
            "1. 未検証メール(別のIdPで自己申告)",
            Claims { iss: "https://idp-b.example", sub: "b-77", email: "alice@corp.example", email_verified: false },
        ),
        (
            "2. マルチテナントIdP(攻撃者テナントの管理者が設定)",
            Claims { iss: "https://login.multi.example", sub: "t9-501", email: "alice@corp.example", email_verified: true },
        ),
        (
            "3. 同じIdPでメールアドレスが再割り当て",
            Claims { iss: "https://idp-a.example", sub: "a-2002", email: "alice@corp.example", email_verified: true },
        ),
        ("4. 本人の再ログイン", alice.clone()),
    ];

    let policies = [
        ("email で照合", Policy::Email),
        ("email_verified=true の email で照合", Policy::VerifiedEmail),
        ("(iss, sub) で照合", Policy::IssSub),
    ];

    for (title, claims) in &scenarios {
        println!("{title}");
        println!("  iss={} sub={} email_verified={}", claims.iss, claims.sub, claims.email_verified);
        for (label, policy) in policies {
            let result = match rp.login(policy, claims) {
                Some(id) if claims.sub == alice.sub && claims.iss == alice.iss => {
                    format!("{} のアカウントでログイン(正当)", rp.accounts[id])
                }
                Some(id) => format!("{} のアカウントでログイン(乗っ取り成立)", rp.accounts[id]),
                None => "該当なし。新規アカウントとして扱う".to_string(),
            };
            println!("  {label:<36} -> {result}");
        }
        println!();
    }
}
