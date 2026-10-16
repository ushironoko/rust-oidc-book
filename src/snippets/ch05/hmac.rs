use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;
use subtle::ConstantTimeEq;

type HmacSha256 = Hmac<Sha256>;

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn hmac_sha256(key: &[u8], msg: &[u8]) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC は任意長の鍵を受け付ける");
    mac.update(msg);
    mac.finalize().into_bytes().into()
}

// 先頭から比べ、最初に異なるバイトで打ち切る比較。比べたバイト数も返す
fn naive_eq(a: &[u8], b: &[u8]) -> (bool, usize) {
    for i in 0..a.len() {
        if a[i] != b[i] {
            return (false, i + 1);
        }
    }
    (true, a.len())
}

// 定数時間比較。常に全バイトを比べる
fn constant_time_eq(a: &[u8], b: &[u8]) -> (bool, usize) {
    (a.ct_eq(b).into(), a.len())
}

// 攻撃者は「比較にかかった手間」(ここではバイト数) だけを観測できるとする。
// 1バイトずつ候補を試し、手間が増えた候補をそのバイトの正解とみなす
fn timing_attack(compare: fn(&[u8], &[u8]) -> (bool, usize), secret_tag: &[u8; 32]) -> (Vec<u8>, u32) {
    let mut guess = [0u8; 32];
    let mut queries = 0;
    for pos in 0..32 {
        let mut best = (0u8, 0usize);
        for candidate in 0..=255u8 {
            guess[pos] = candidate;
            queries += 1;
            let (ok, work) = compare(&guess, secret_tag);
            if ok {
                return (guess.to_vec(), queries);
            }
            if work > best.1 {
                best = (candidate, work);
            }
        }
        guess[pos] = best.0;
    }
    (guess.to_vec(), queries)
}

fn main() {
    println!("[1] RFC 4231 4.3節 (Test Case 2)");
    let tag = hmac_sha256(b"Jefe", b"what do ya want for nothing?");
    let expected = "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843";
    println!("  HMAC-SHA256 = {}", hex(&tag));
    println!("  期待値と一致: {}", hex(&tag) == expected);

    println!("\n[2] 鍵を知らない者はタグを作れない");
    let key = b"dummy-shared-key-for-book-only!!";
    let msg = b"user=alice&role=member";
    let tag = hmac_sha256(key, msg);
    let tampered = b"user=alice&role=admin";
    println!("  元のメッセージのタグ    : {}", hex(&tag));
    println!("  改ざん後の正しいタグ    : {}", hex(&hmac_sha256(key, tampered)));
    let mut verifier = HmacSha256::new_from_slice(key).unwrap();
    verifier.update(tampered);
    println!("  改ざん後に元のタグで検証: {:?}", verifier.verify_slice(&tag).map_err(|_| "不一致"));

    println!("\n[3] 比較方法とタイミング攻撃 (比較したバイト数を観測できる場合)");
    let (found, queries) = timing_attack(naive_eq, &tag);
    println!("  打ち切り比較  : 復元 {} / 問い合わせ {queries} 回",
        if found == tag { "成功" } else { "失敗" });
    let (found, queries) = timing_attack(constant_time_eq, &tag);
    println!("  定数時間比較  : 復元 {} / 問い合わせ {queries} 回",
        if found == tag { "成功" } else { "失敗" });
    println!("  総当たりに必要な回数: 2^256 回");
}
