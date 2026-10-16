use ring::rand::SystemRandom;
use ring::signature::{
    ECDSA_P256_SHA256_ASN1, ECDSA_P256_SHA256_ASN1_SIGNING, ECDSA_P256_SHA256_FIXED,
    ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, KeyPair, UnparsedPublicKey,
};

// P-256 の位数 n(ビッグエンディアン)
const N: [u8; 32] = [
    0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84, 0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63, 0x25, 0x51,
];

// 32バイトの多倍長整数の引き算 a - b(a >= b を前提)
fn sub(a: &[u8; 32], b: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    let mut borrow = 0i16;
    for i in (0..32).rev() {
        let mut d = a[i] as i16 - b[i] as i16 - borrow;
        borrow = if d < 0 { d += 256; 1 } else { 0 };
        out[i] = d as u8;
    }
    out
}

fn result(ok: bool) -> &'static str {
    if ok { "受理" } else { "拒否" }
}

fn main() {
    let rng = SystemRandom::new();
    let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng).unwrap();
    let fixed = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8.as_ref(), &rng).unwrap();
    let asn1 = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, pkcs8.as_ref(), &rng).unwrap();
    let public = fixed.public_key().as_ref().to_vec();
    let verify_fixed = |msg: &[u8], sig: &[u8]| {
        UnparsedPublicKey::new(&ECDSA_P256_SHA256_FIXED, &public).verify(msg, sig).is_ok()
    };
    let verify_asn1 = |msg: &[u8], sig: &[u8]| {
        UnparsedPublicKey::new(&ECDSA_P256_SHA256_ASN1, &public).verify(msg, sig).is_ok()
    };
    let msg = b"eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJhbGljZSJ9";

    println!("[1] 署名形式: JWS の raw(r||s) と DER");
    let raw = fixed.sign(&rng, msg).unwrap();
    let der = asn1.sign(&rng, msg).unwrap();
    println!("  raw: {} バイト", raw.as_ref().len());
    println!("  DER: {} バイト、先頭 {:02x?}", der.as_ref().len(), &der.as_ref()[..4]);
    println!("  raw を raw として検証: {}", result(verify_fixed(msg, raw.as_ref())));
    println!("  DER を raw として検証: {}", result(verify_fixed(msg, der.as_ref())));

    println!();
    println!("[2] r = s = 0 の署名(CVE-2022-21449 で Java が受理した形)");
    let zero_raw = [0u8; 64];
    let zero_der = [0x30, 0x06, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00];
    println!("  raw 64バイトの0: {}", result(verify_fixed(msg, &zero_raw)));
    println!("  DER 30 06 02 01 00 02 01 00: {}", result(verify_asn1(msg, &zero_der)));

    println!();
    println!("[3] 署名の展性: (r, s) が有効なら (r, n - s) も有効");
    let (r, s) = raw.as_ref().split_at(32);
    let s2 = sub(&N, s);
    let mut alt = r.to_vec();
    alt.extend_from_slice(&s2);
    println!("  元の s    : {:02x?}...", &s[..6]);
    println!("  n - s     : {:02x?}...", &s2[..6]);
    println!("  元の署名  : {}", result(verify_fixed(msg, raw.as_ref())));
    println!("  (r, n - s): {}", result(verify_fixed(msg, &alt)));
    println!("  2つの署名のバイト列は同じか: {}", raw.as_ref() == alt.as_slice());
}
