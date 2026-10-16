use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ring::rand::SystemRandom;
use ring::signature::{
    ECDSA_P256_SHA256_FIXED, ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, KeyPair,
    UnparsedPublicKey,
};

fn b64(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

fn verify(public_key: &[u8], msg: &[u8], sig: &[u8]) -> &'static str {
    let key = UnparsedPublicKey::new(&ECDSA_P256_SHA256_FIXED, public_key);
    match key.verify(msg, sig) {
        Ok(()) => "成功",
        Err(_) => "失敗",
    }
}

fn main() {
    let rng = SystemRandom::new();

    // 鍵ペアの生成。秘密鍵は PKCS#8 形式のバイト列として得られる
    let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng).unwrap();
    let key_pair =
        EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8.as_ref(), &rng).unwrap();
    let public_key = key_pair.public_key().as_ref().to_vec();

    println!("[1] 鍵ペア (出力は実行ごとに変わる)");
    println!("  秘密鍵 (PKCS#8): {} バイト。外部に出さない", pkcs8.as_ref().len());
    println!("  公開鍵: {} バイト (先頭 0x{:02x} + x 32 バイト + y 32 バイト)",
        public_key.len(), public_key[0]);
    println!("    x = {}", b64(&public_key[1..33]));
    println!("    y = {}", b64(&public_key[33..65]));

    let msg = br#"{"sub":"alice","scope":"photos:read"}"#;
    let sig = key_pair.sign(&rng, msg).unwrap();
    let sig = sig.as_ref().to_vec();
    println!("\n[2] 署名");
    println!("  メッセージ: {}", String::from_utf8_lossy(msg));
    println!("  署名: {} バイト (r 32 バイト + s 32 バイト)", sig.len());
    println!("    {}", b64(&sig));

    let sig2 = key_pair.sign(&rng, msg).unwrap();
    println!("  同じメッセージをもう一度署名すると同じ値か: {}", sig2.as_ref() == sig.as_slice());

    println!("\n[3] 公開鍵による検証");
    println!("  元のメッセージと署名        : {}", verify(&public_key, msg, &sig));
    println!("  2回目の署名                 : {}", verify(&public_key, msg, sig2.as_ref()));

    let tampered = br#"{"sub":"alice","scope":"photos:delete"}"#;
    println!("  メッセージを改ざん          : {}", verify(&public_key, tampered, &sig));

    let mut bad_sig = sig.clone();
    bad_sig[10] ^= 0x01;
    println!("  署名の1ビットを反転         : {}", verify(&public_key, msg, &bad_sig));

    let other_pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng).unwrap();
    let other = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, other_pkcs8.as_ref(), &rng).unwrap();
    println!("  別の鍵ペアの公開鍵で検証    : {}", verify(other.public_key().as_ref(), msg, &sig));
    let forged = other.sign(&rng, tampered).unwrap();
    println!("  攻撃者の鍵で改ざん文に署名  : {}", verify(&public_key, tampered, forged.as_ref()));
}
