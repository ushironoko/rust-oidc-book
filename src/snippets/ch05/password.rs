use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ring::pbkdf2;
use ring::rand::{SecureRandom, SystemRandom};
use sha2::{Digest, Sha256};
use std::num::NonZeroU32;
use std::time::Instant;

// 保存するレコード: ソルトと反復回数と導出結果
struct Stored {
    salt: [u8; 16],
    iterations: NonZeroU32,
    hash: [u8; 32],
}

fn register(password: &str, iterations: u32, rng: &SystemRandom) -> Stored {
    let mut salt = [0u8; 16];
    rng.fill(&mut salt).unwrap();
    let iterations = NonZeroU32::new(iterations).unwrap();
    let mut hash = [0u8; 32];
    pbkdf2::derive(pbkdf2::PBKDF2_HMAC_SHA256, iterations, &salt, password.as_bytes(), &mut hash);
    Stored { salt, iterations, hash }
}

fn login(stored: &Stored, password: &str) -> bool {
    // verify は内部で定数時間比較を行う
    pbkdf2::verify(
        pbkdf2::PBKDF2_HMAC_SHA256,
        stored.iterations,
        &stored.salt,
        password.as_bytes(),
        &stored.hash,
    )
    .is_ok()
}

fn main() {
    let rng = SystemRandom::new();

    println!("[1] ソルトなしの SHA-256: 同じパスワードは同じ値になる");
    for user in ["alice", "bob"] {
        let h = Sha256::digest(b"dummy-password");
        println!("  {user}: {}", URL_SAFE_NO_PAD.encode(h));
    }

    println!("\n[2] ソルト付き PBKDF2: 同じパスワードでも値が異なる (出力は実行ごとに変わる)");
    let alice = register("dummy-password", 600_000, &rng);
    let bob = register("dummy-password", 600_000, &rng);
    for (user, s) in [("alice", &alice), ("bob", &bob)] {
        println!("  {user}: salt={} hash={}", URL_SAFE_NO_PAD.encode(s.salt), URL_SAFE_NO_PAD.encode(s.hash));
    }

    println!("\n[3] 照合");
    println!("  正しいパスワード  : {}", login(&alice, "dummy-password"));
    println!("  誤ったパスワード  : {}", login(&alice, "dummy-passwore"));

    println!("\n[4] 1回の計算にかかる時間 (環境によって変わる)");
    let start = Instant::now();
    for _ in 0..1000 {
        std::hint::black_box(Sha256::digest(b"dummy-password"));
    }
    let sha_us = start.elapsed().as_secs_f64() * 1e6 / 1000.0;
    let start = Instant::now();
    login(&alice, "dummy-password");
    let pbkdf2_ms = start.elapsed().as_secs_f64() * 1e3;
    println!("  SHA-256 1回           : 約 {sha_us:.2} マイクロ秒");
    println!("  PBKDF2 60万回反復 1回 : 約 {pbkdf2_ms:.0} ミリ秒");
    println!("  比: 約 {:.0} 倍", pbkdf2_ms * 1000.0 / sha_us);
}
