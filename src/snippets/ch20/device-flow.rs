use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ring::rand::{SecureRandom, SystemRandom};
use std::collections::HashMap;

const CHARSET: &[u8] = b"BCDFGHJKLMNPQRSTVWXZ";

#[derive(Clone, Copy, PartialEq, Debug)]
enum Status {
    Pending,
    Approved,
    Denied,
}

struct Grant {
    user_code: String,
    expires_at: u64,
    interval: u64,
    last_poll: Option<u64>,
    status: Status,
}

struct AuthServer {
    rng: SystemRandom,
    grants: HashMap<String, Grant>,
}

impl AuthServer {
    // 8文字の base20 ユーザーコード(棄却法で偏りをなくす)
    fn user_code(&self) -> String {
        let mut out = String::new();
        while out.len() < 9 {
            let mut b = [0u8; 1];
            self.rng.fill(&mut b).unwrap();
            if b[0] < 240 {
                if out.len() == 4 {
                    out.push('-');
                }
                out.push(CHARSET[(b[0] % 20) as usize] as char);
            }
        }
        out
    }

    fn device_authorization(&mut self, now: u64) -> (String, String) {
        let mut raw = [0u8; 32];
        self.rng.fill(&mut raw).unwrap();
        let device_code = URL_SAFE_NO_PAD.encode(raw);
        let user_code = self.user_code();
        let grant = Grant {
            user_code: user_code.clone(),
            expires_at: now + 1800,
            interval: 5,
            last_poll: None,
            status: Status::Pending,
        };
        self.grants.insert(device_code.clone(), grant);
        (device_code, user_code)
    }

    // 利用者が別の端末で入力したコードを正規化して照合する
    fn approve(&mut self, typed: &str, allow: bool) -> bool {
        let norm: String = typed.to_uppercase().chars().filter(|c| c.is_ascii_alphabetic()).collect();
        for g in self.grants.values_mut() {
            if g.user_code.replace('-', "") == norm && g.status == Status::Pending {
                g.status = if allow { Status::Approved } else { Status::Denied };
                return true;
            }
        }
        false
    }

    fn token(&mut self, device_code: &str, now: u64) -> Result<String, &'static str> {
        let g = self.grants.get_mut(device_code).ok_or("invalid_grant")?;
        if now >= g.expires_at {
            return Err("expired_token");
        }
        let too_fast = g.last_poll.is_some_and(|t| now - t < g.interval);
        g.last_poll = Some(now);
        if too_fast {
            g.interval += 5;
            return Err("slow_down");
        }
        match g.status {
            Status::Pending => Err("authorization_pending"),
            Status::Denied => Err("access_denied"),
            Status::Approved => {
                self.grants.remove(device_code);
                Ok("dummy-access-token".to_string())
            }
        }
    }
}

// 端末側のポーリング。impatient なら最初は interval に従わない
fn run(as_: &mut AuthServer, impatient: bool, approve_at: u64, typed_lower: bool) {
    let (device_code, user_code) = as_.device_authorization(0);
    println!("t=0   端末: user_code={user_code} を表示 (device_code は表示しない)");
    let mut interval = 5;
    let mut step = if impatient { 2 } else { interval };
    let mut t = 0;
    let mut approved = false;
    loop {
        t += step;
        if !approved && t >= approve_at {
            let typed = if typed_lower { user_code.to_lowercase().replace('-', " ") } else { user_code.clone() };
            approved = as_.approve(&typed, true);
            println!("t={approve_at:<3} 利用者: スマートフォンで \"{typed}\" を入力して承認 (照合={approved})");
        }
        match as_.token(&device_code, t) {
            Ok(at) => {
                println!("t={t:<3} 端末: トークン取得 access_token={at}");
                break;
            }
            Err("slow_down") => {
                interval += 5;
                step = interval;
                println!("t={t:<3} 端末: slow_down を受信。間隔を {interval} 秒に延ばす");
            }
            Err("authorization_pending") => println!("t={t:<3} 端末: authorization_pending"),
            Err(e) => {
                println!("t={t:<3} 端末: {e} で停止");
                break;
            }
        }
    }
}

fn main() {
    let mut as_ = AuthServer { rng: SystemRandom::new(), grants: HashMap::new() };

    println!("== 1. interval に従う端末 ==");
    run(&mut as_, false, 12, true);

    println!("\n== 2. 2秒ごとに問い合わせる端末 ==");
    run(&mut as_, true, 30, false);

    println!("\n== 3. 承認されないまま期限切れ ==");
    let (dc, _) = as_.device_authorization(0);
    println!("t=1800 端末: {:?}", as_.token(&dc, 1800));

    let bits = 8.0 * (20f64).log2();
    println!("\nユーザーコードの空間: 20^8 = {} 通り (約{bits:.1}ビット)", 20u64.pow(8));
}
