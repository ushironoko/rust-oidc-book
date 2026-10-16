use percent_encoding::percent_decode_str;
use std::collections::HashMap;

fn encode(value: &str) -> String {
    form_urlencoded::byte_serialize(value.as_bytes()).collect()
}

fn main() {
    println!("[1] RFC 6749 付録B の例");
    let value = " %&+\u{00A3}\u{20AC}";
    let bytes: Vec<String> = value.bytes().map(|b| format!("{b:02X}")).collect();
    println!("  UTF-8 のバイト列: {}", bytes.join(" "));
    let encoded = encode(value);
    println!("  エンコード結果  : {encoded}");
    println!("  RFC の値と一致  : {}", encoded == "+%25%26%2B%C2%A3%E2%82%AC");

    println!("\n[2] redirect_uri の値をクエリに入れる");
    let redirect_uri = "https://client.example.com/cb";
    let ours = encode(redirect_uri);
    let rfc = "https%3A%2F%2Fclient%2Eexample%2Ecom%2Fcb";
    println!("  このコード   : {ours}");
    println!("  RFC 4.1.1節  : {rfc}");
    let decoded_rfc = percent_decode_str(rfc).decode_utf8().unwrap();
    println!("  復号すると同じ値か: {}", decoded_rfc == redirect_uri);

    println!("\n[3] エンコードしないと、値の中の & と = が区切りとして解釈される");
    let state = "a&scope=admin";
    let broken = format!("response_type=code&state={state}");
    let correct = format!("response_type=code&state={}", encode(state));
    for (label, q) in [("エンコードなし", &broken), ("エンコードあり", &correct)] {
        let pairs: Vec<(String, String)> = form_urlencoded::parse(q.as_bytes()).into_owned().collect();
        println!("  {label}: {q}");
        println!("    解析結果: {pairs:?}");
    }

    println!("\n[4] 同じパラメータが2回現れるクエリ");
    let q = "client_id=s6BhdRkqt3&scope=photos%3Aread&scope=admin";
    let pairs: Vec<(String, String)> = form_urlencoded::parse(q.as_bytes()).into_owned().collect();
    let last_wins: HashMap<String, String> = pairs.iter().cloned().collect();
    println!("  解析結果 (順序どおり): {pairs:?}");
    println!("  HashMap に入れると   : scope = {:?}", last_wins["scope"]);
    let mut seen = std::collections::HashSet::new();
    let dup = pairs.iter().find(|(k, _)| !seen.insert(k.clone()));
    match dup {
        Some((k, _)) => println!("  重複を検出: {k} (invalid_request として拒否すべき)"),
        None => println!("  重複なし"),
    }
}
