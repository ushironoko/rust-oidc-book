// 時刻は秒単位の整数で表し、外から与える(Playground はネットワークに接続できないため OP も同じプロセス内に置く)

struct Op {
    published: Vec<String>,
    jwks_requests: u32,
}

impl Op {
    fn serve_jwks(&mut self) -> Vec<String> {
        self.jwks_requests += 1;
        self.published.clone()
    }
}

struct Policy {
    max_age: u64,
    min_refetch_interval: Option<u64>,
}

struct Cache {
    keys: Vec<String>,
    fetched_at: Option<u64>,
}

#[derive(Debug)]
enum Outcome {
    Hit,
    FetchedOnExpiry,
    RefetchedForUnknownKid,
    Unknown,
    UnknownRefetchSuppressed,
}

fn lookup(cache: &mut Cache, policy: &Policy, op: &mut Op, kid: &str, now: u64) -> Outcome {
    let expired = cache.fetched_at.is_none_or(|t| now - t >= policy.max_age);
    if expired {
        cache.keys = op.serve_jwks();
        cache.fetched_at = Some(now);
        return if cache.keys.iter().any(|k| k == kid) { Outcome::FetchedOnExpiry } else { Outcome::Unknown };
    }
    if cache.keys.iter().any(|k| k == kid) {
        return Outcome::Hit;
    }
    let since = now - cache.fetched_at.unwrap();
    if policy.min_refetch_interval.is_some_and(|min| since < min) {
        return Outcome::UnknownRefetchSuppressed;
    }
    cache.keys = op.serve_jwks();
    cache.fetched_at = Some(now);
    if cache.keys.iter().any(|k| k == kid) { Outcome::RefetchedForUnknownKid } else { Outcome::Unknown }
}

fn run(name: &str, policy: Policy) {
    println!("== {name}");
    let mut op = Op { published: vec!["k1".into()], jwks_requests: 0 };
    let mut cache = Cache { keys: vec![], fetched_at: None };
    let mut step = |t: u64, kid: &str, op: &mut Op| lookup(&mut cache, &policy, op, kid, t);

    for (t, kid) in [(0, "k1"), (10, "k1"), (100, "k2"), (110, "k1")] {
        if t == 100 {
            op.published.push("k2".into());
            println!("  t=  100s OP が k2 を JWKS に追加し、すぐに k2 で署名を始める");
        }
        let r = step(t, kid, &mut op);
        println!("  t={t:>5}s kid={kid} {r:?} (JWKS 取得の累計 {})", op.jwks_requests);
    }

    let before = op.jwks_requests;
    let mut suppressed = 0;
    let mut legit_found = 0;
    for i in 0..600u64 {
        let t = 200 + i;
        if matches!(step(t, &format!("evil-{i}"), &mut op), Outcome::UnknownRefetchSuppressed) {
            suppressed += 1;
        }
        if matches!(step(t, "k2", &mut op), Outcome::Hit | Outcome::FetchedOnExpiry) {
            legit_found += 1;
        }
    }
    println!(
        "  t=200..799s 未知の kid を毎秒1回(計600回)受けた間の JWKS 取得: {} 回、抑制: {} 回",
        op.jwks_requests - before,
        suppressed
    );
    println!("  同じ期間の正規の kid=k2: 600回中 {legit_found} 回、鍵を見つけた");
    let r = step(3600, "k2", &mut op);
    println!("  t= 3600s kid=k2 {r:?} (JWKS 取得の累計 {})", op.jwks_requests);
    println!();
}

fn main() {
    run(
        "A: max-age 3600秒、未知の kid での再取得は60秒に1回まで",
        Policy { max_age: 3600, min_refetch_interval: Some(60) },
    );
    run(
        "B: max-age 3600秒、未知の kid で毎回再取得する",
        Policy { max_age: 3600, min_refetch_interval: None },
    );
    run(
        "C: max-age 3600秒、未知の kid では再取得しない",
        Policy { max_age: 3600, min_refetch_interval: Some(u64::MAX) },
    );
}
