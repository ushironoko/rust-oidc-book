use sha2::{Digest, Sha256};
use std::collections::HashMap;

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn sha256(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}

// ダイジェストの先頭 bits ビットだけを取り出す (短いハッシュ関数の代わり)
fn truncated(data: &[u8], bits: u32) -> u32 {
    let d = sha256(data);
    u32::from_be_bytes([d[0], d[1], d[2], d[3]]) >> (32 - bits)
}

fn main() {
    println!("[1] SHA-256 のテストベクタ (FIPS 180 の例)");
    let d = sha256(b"abc");
    println!("  SHA-256(\"abc\") = {}", hex(&d));
    let expected = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
    println!("  期待値と一致: {}", hex(&d) == expected);
    println!("  入力の長さに関係なく 32 バイト: {} バイト", sha256(&[0u8; 100_000]).len());

    println!("\n[2] 入力を1文字変えると、出力のビットの約半分が変わる");
    let a = sha256(b"amount=100");
    let b = sha256(b"amount=900");
    let diff: u32 = a.iter().zip(b.iter()).map(|(x, y)| (x ^ y).count_ones()).sum();
    println!("  SHA-256(\"amount=100\") = {}", hex(&a));
    println!("  SHA-256(\"amount=900\") = {}", hex(&b));
    println!("  256 ビット中 {diff} ビットが異なる");

    let bits = 20;
    println!("\n[3] 出力を {bits} ビットに切り詰めたハッシュで、衝突と原像を探す");

    // 衝突: 同じ出力になる2つの異なる入力を、どれでもよいから見つける
    let mut seen: HashMap<u32, u64> = HashMap::new();
    let mut tries = 0u64;
    let (m1, m2) = loop {
        tries += 1;
        let msg = format!("message-{tries}");
        let h = truncated(msg.as_bytes(), bits);
        if let Some(prev) = seen.insert(h, tries) {
            break (format!("message-{prev}"), msg);
        }
    };
    println!("  衝突: {m1:?} と {m2:?} が同じ値 (試行 {tries} 回)");

    // 原像: 決められた出力になる入力を見つける
    let target = truncated(b"target", bits);
    let mut tries = 0u64;
    let found = loop {
        tries += 1;
        let msg = format!("guess-{tries}");
        if truncated(msg.as_bytes(), bits) == target {
            break msg;
        }
    };
    println!("  原像: {found:?} が目標値 {target:#07x} になる (試行 {tries} 回)");
    println!("  目安: 衝突は 2^{} = {} 回程度、原像は 2^{bits} = {} 回程度", bits / 2, 1u64 << (bits / 2), 1u64 << bits);
}
