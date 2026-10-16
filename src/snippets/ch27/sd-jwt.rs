use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD as B64};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

// RFC 9901 の例と同じ区切り(カンマの後に空白1つ)で JSON 配列を書く
fn rfc_style_array(items: &[Value]) -> String {
    let parts: Vec<String> = items.iter().map(|v| v.to_string()).collect();
    format!("[{}]", parts.join(", "))
}

// 4.2.1節: 配列の UTF-8 バイト列を base64url にしたものが Disclosure
fn disclosure_from_json(json_text: &str) -> String {
    B64.encode(json_text.as_bytes())
}

// 4.2.3節: Disclosure の文字列そのもの(ASCII)を SHA-256 にかけ、base64url にする
fn digest_of(disclosure: &str) -> String {
    B64.encode(Sha256::digest(disclosure.as_bytes()))
}

fn check(label: &str, got: &str, expected: &str) {
    let mark = if got == expected { "一致" } else { "不一致" };
    println!("{label}: {got} ({mark})");
}

fn main() {
    println!("== 1. RFC 9901 4.2.1節 / 4.2.3節: family_name = Möbius");
    let items = [json!("_26bc4LT-ac6q2KI6cBW5es"), json!("family_name"), json!("Möbius")];
    let spaced = rfc_style_array(&items);
    let d1 = disclosure_from_json(&spaced);
    println!("配列: {spaced}");
    check(
        "Disclosure",
        &d1,
        "WyJfMjZiYzRMVC1hYzZxMktJNmNCVzVlcyIsICJmYW1pbHlfbmFtZSIsICJNw7ZiaXVzIl0",
    );
    check("ダイジェスト", &digest_of(&d1), "X9yH0Ajrdm1Oij4tWso9UzzKJvPoDxwmuEcO3XAdRC0");

    println!();
    println!("== 2. 同じ値の別表現(serde_json の空白なし出力)");
    let compact = serde_json::to_string(&Value::Array(items.to_vec())).unwrap();
    let d2 = disclosure_from_json(&compact);
    println!("配列: {compact}");
    check(
        "Disclosure",
        &d2,
        "WyJfMjZiYzRMVC1hYzZxMktJNmNCVzVlcyIsImZhbWlseV9uYW1lIiwiTcO2Yml1cyJd",
    );
    println!("ダイジェスト: {}", digest_of(&d2));
    println!("1. とダイジェストが同じか: {}", digest_of(&d1) == digest_of(&d2));

    println!();
    println!("== 3. RFC 9901 4.2.2節 / 4.2.4.2節: 配列要素 FR");
    let arr = rfc_style_array(&[json!("lklxF5jMYlGTPUovMNIvCA"), json!("FR")]);
    let d3 = disclosure_from_json(&arr);
    check("Disclosure", &d3, "WyJsa2x4RjVqTVlsR1RQVW92TU5JdkNBIiwgIkZSIl0");
    check("ダイジェスト", &digest_of(&d3), "w0I8EKcdCtUPkGCNUrfwVp2xEgNjtoIDlOxc9-PlOhs");

    println!();
    println!("== 4. RFC 9901 5.1節: Disclosure を内容から作り直す");
    let cases: [(Value, &str); 9] = [
        (json!(["2GLC42sKQveCfGfryNRN9w", "given_name", "John"]), "jsu9yVulwQQlhFlM_3JlzMaSFzglhQG0DpfayQwLUK4"),
        (json!(["eluV5Og3gSNII8EYnsxA_A", "family_name", "Doe"]), "TGf4oLbgwd5JQaHyKVQZU9UdGE0w5rtDsrZzfUaomLo"),
        (json!(["6Ij7tM-a5iVPGboS5tmvVA", "email", "johndoe@example.com"]), "JzYjH4svliH0R3PyEMfeZu6Jt69u5qehZo7F7EPYlSE"),
        (json!(["eI8ZWm9QnKPpNPeNenHdhQ", "phone_number", "+1-202-555-0101"]), "PorFbpKuVu6xymJagvkFsFXAbRoc2JGlAUA2BA4o7cI"),
        (json!(["Qg_O64zqAxe412a108iroA", "phone_number_verified", true]), "XQ_3kPKt1XyX7KANkqVR6yZ2Va5NrPIvPYbyMvRKBMM"),
        (json!(["Pc33JM2LchcU_lHggv_ufQ", "birthdate", "1940-01-01"]), "gbOsI4Edq2x2Kw-w5wPEzakob9hV1cRD0ATN3oQL9JM"),
        (json!(["G02NSrQfjFXQ7Io09syajA", "updated_at", 1570000000]), "CrQe7S5kqBAHt-nMYXgc6bdt2SH5aTY1sU_M-PgkjPI"),
        (json!(["lklxF5jMYlGTPUovMNIvCA", "US"]), "pFndjkZ_VCzmyTa6UjlZo3dh-ko8aIKQc9DlGzhaVYo"),
        (json!(["nPuoQnkRFq3BIeAm7AnXFA", "DE"]), "7Cf6JkPudry3lcbwHgeZ8khAv1U1OSlerP0VkBJrWZ0"),
    ];
    let matched = cases
        .iter()
        .filter(|(content, expected)| {
            let arr = content.as_array().unwrap();
            let ok = digest_of(&disclosure_from_json(&rfc_style_array(arr))) == *expected;
            let label = match arr.len() {
                3 => arr[1].as_str().unwrap().to_string(),
                _ => format!("配列要素 {}", arr[1]),
            };
            println!("  {label}: {}", if ok { "一致" } else { "不一致" });
            ok
        })
        .count();
    println!("一致した数: {matched} / {}", cases.len());

    println!();
    println!("== 4b. address (値がオブジェクト)");
    let address_expected = "XzFrzwscM6Gn6CJDc6vVK8BkMnfG8vOSKfpPIZdAfdE";
    let rebuilt = rfc_style_array(&[
        json!("AJx-095VPrpTtN4QMOqROA"),
        json!("address"),
        json!({"street_address": "123 Main St", "locality": "Anytown",
               "region": "Anystate", "country": "US"}),
    ]);
    println!("serde_json で作り直した配列: {rebuilt}");
    let rebuilt_ok = digest_of(&disclosure_from_json(&rebuilt)) == address_expected;
    println!("作り直した Disclosure のダイジェスト: {}", if rebuilt_ok { "一致" } else { "不一致" });
    let issued = concat!(
        "WyJBSngtMDk1VlBycFR0TjRRTU9xUk9BIiwgImFkZHJlc3MiLCB7InN0cmVldF9",
        "hZGRyZXNzIjogIjEyMyBNYWluIFN0IiwgImxvY2FsaXR5IjogIkFueXRvd24iLC",
        "AicmVnaW9uIjogIkFueXN0YXRlIiwgImNvdW50cnkiOiAiVVMifV0",
    );
    println!("RFC の Disclosure の中身: {}", String::from_utf8(B64.decode(issued).unwrap()).unwrap());
    check("RFC の Disclosure のダイジェスト", &digest_of(issued), address_expected);

    println!();
    println!("== 5. 新しい Disclosure を作る(salt は128ビットの乱数)");
    let mut salt = [0u8; 16];
    rand::fill(&mut salt);
    let fresh = rfc_style_array(&[json!(B64.encode(salt)), json!("family_name"), json!("Möbius")]);
    let d5 = disclosure_from_json(&fresh);
    println!("配列: {fresh}");
    println!("Disclosure: {d5}");
    println!("_sd に入れる値: {}", digest_of(&d5));
}
