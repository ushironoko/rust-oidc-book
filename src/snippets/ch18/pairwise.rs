use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use sha2::{Digest, Sha256};
use url::Url;

// OIDC Core 8.1 の例1: SHA-256(sector_identifier || local_account_id || salt)
fn pairwise_naive(sector: &str, local_id: &str, salt: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(sector.as_bytes());
    h.update(local_id.as_bytes());
    h.update(salt);
    URL_SAFE_NO_PAD.encode(h.finalize())
}

// 各要素の前に長さを置き、連結の境界を一意にした版
fn pairwise(sector: &str, local_id: &str, salt: &[u8]) -> String {
    let mut h = Sha256::new();
    for part in [sector.as_bytes(), local_id.as_bytes(), salt] {
        h.update((part.len() as u32).to_be_bytes());
        h.update(part);
    }
    URL_SAFE_NO_PAD.encode(h.finalize())
}

// sector_identifier_uri がなければ redirect_uri のホスト部分
fn sector_of(uri: &str) -> String {
    Url::parse(uri).unwrap().host_str().unwrap().to_string()
}

fn main() {
    let salt = b"dummy-op-secret-salt";
    let user = "1048576";

    println!("== 1. RPごとに異なる sub ==");
    let rps = [
        ("RP-A", "https://shop.example/cb"),
        ("RP-B", "https://news.example/callback"),
        ("RP-A(2回目)", "https://shop.example/cb"),
        ("RP-C(同じホスト)", "https://shop.example/other-cb"),
    ];
    for (name, redirect) in rps {
        let sector = sector_of(redirect);
        println!("{name:<18} sector={sector:<14} sub={}", pairwise(&sector, user, salt));
    }

    println!("\n== 2. ソルトが漏れると local_account_id を逆算できる ==");
    let sector = "shop.example";
    let observed = pairwise(sector, user, b"");
    let mut tries = 0u32;
    let found = (0..2_000_000u32).find(|id| {
        tries += 1;
        pairwise(sector, &id.to_string(), b"") == observed
    });
    println!("ソルトなしの sub={observed}");
    println!("候補を{tries}個試して local_account_id={found:?} を特定");
    let with_salt = pairwise(sector, user, salt);
    let hit = (0..2_000_000u32).any(|id| pairwise(sector, &id.to_string(), b"") == with_salt);
    println!("秘密のソルトありの sub に同じ探索を行った結果: 一致={hit}");

    println!("\n== 3. 区切りのない連結は別セクターで衝突する ==");
    let a = ("rp.example", "12");
    let b = ("rp.example1", "2");
    println!("単純連結   {a:?} -> {}", pairwise_naive(a.0, a.1, salt));
    println!("単純連結   {b:?} -> {}", pairwise_naive(b.0, b.1, salt));
    println!("長さ前置き {a:?} -> {}", pairwise(a.0, a.1, salt));
    println!("長さ前置き {b:?} -> {}", pairwise(b.0, b.1, salt));
}
