use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ring::rand::{SecureRandom, SystemRandom};
use std::time::{SystemTime, UNIX_EPOCH};

// 線形合同法 (暗号用ではない乱数生成器)。内部状態は 64 ビットの整数1つ
fn lcg_next(state: u64) -> u64 {
    state
        .wrapping_mul(6364136223846793005)
        .wrapping_add(1442695040888963407)
}

fn main() {
    println!("[1] 暗号用ではない乱数生成器で「推測不能なはずの値」を作る");
    let seed = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos() as u64;
    let s1 = lcg_next(seed);
    let s2 = lcg_next(s1);
    let s3 = lcg_next(s2);
    println!("  サーバが発行した state (1件目): {s1:016x}");
    println!("  サーバが発行した state (2件目): {s2:016x}");
    println!("  サーバが発行した state (3件目): {s3:016x}");

    // 攻撃者は自分宛ての1件目を見ただけで、以後の値をすべて計算できる
    let predicted2 = lcg_next(s1);
    let predicted3 = lcg_next(predicted2);
    println!("  攻撃者が1件目から計算した2件目: {predicted2:016x} (一致: {})", predicted2 == s2);
    println!("  攻撃者が1件目から計算した3件目: {predicted3:016x} (一致: {})", predicted3 == s3);

    println!("\n[2] CSPRNG で同じことを試す (出力は実行ごとに変わる)");
    let mut a = [0u8; 32];
    let mut b = [0u8; 32];
    rand::fill(&mut a);
    rand::fill(&mut b);
    println!("  rand::fill (ThreadRng)  1件目: {}", URL_SAFE_NO_PAD.encode(a));
    println!("  rand::fill (ThreadRng)  2件目: {}", URL_SAFE_NO_PAD.encode(b));

    let sys = SystemRandom::new();
    let mut c = [0u8; 32];
    sys.fill(&mut c).unwrap();
    println!("  ring SystemRandom (OS)       : {}", URL_SAFE_NO_PAD.encode(c));

    println!("\n[3] エントロピーと文字列の長さ");
    for bytes in [16usize, 32] {
        let bits = bytes * 8;
        let encoded_len = URL_SAFE_NO_PAD.encode(vec![0u8; bytes]).len();
        println!("  乱数 {bytes} バイト = {bits} ビット → Base64url で {encoded_len} 文字。推測できる確率 2^-{bits}");
    }
    let weak = "user-1234";
    println!("  参考: {weak:?} のように 0〜9999 から一様に選んでも約 13.3 ビット。連番なら次の値を予測できる");
}
