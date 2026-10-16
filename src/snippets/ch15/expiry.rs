// 時刻の単位は日。認可を得た日を0日目とする
struct Policy {
    name: &'static str,
    idle: Option<u32>,
    absolute: Option<u32>,
}

// リフレッシュを試みた日の列を受け取り、最初に失敗した日を返す
fn first_failure(p: &Policy, attempts: &[u32]) -> Option<u32> {
    let mut last_used = 0;
    for &day in attempts {
        let idle_expired = p.idle.is_some_and(|idle| day > last_used + idle);
        let absolute_expired = p.absolute.is_some_and(|abs| day > abs);
        if idle_expired || absolute_expired {
            return Some(day);
        }
        last_used = day;
    }
    None
}

fn main() {
    let policies = [
        Policy { name: "期限なし", idle: None, absolute: None },
        Policy { name: "スライディング14日", idle: Some(14), absolute: None },
        Policy { name: "絶対90日", idle: None, absolute: Some(90) },
        Policy { name: "スライディング14日+絶対90日", idle: Some(14), absolute: Some(90) },
    ];
    let users: [(&str, Vec<u32>); 3] = [
        ("毎日使う利用者", (1..=120).collect()),
        ("月に1回使う利用者", vec![30, 60, 90, 120]),
        ("盗んだトークンを週1回使う攻撃者", (1..=52).map(|w| w * 7).collect()),
    ];
    for (who, attempts) in &users {
        println!("{who} (試行 {} 回、最終 {} 日目)", attempts.len(), attempts.last().unwrap());
        for p in &policies {
            match first_failure(p, attempts) {
                Some(day) => println!("  {}: {day} 日目に失効し再ログインが必要", p.name),
                None => println!("  {}: 最後まで使える", p.name),
            }
        }
    }
}
