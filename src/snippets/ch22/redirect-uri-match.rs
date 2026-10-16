use url::Url;

// 登録済みの値と、認可リクエストで届いた redirect_uri を比べる4つの方法

// 前方一致: 登録値で始まれば許可
fn prefix_match(registered: &str, requested: &str) -> bool {
    requested.starts_with(registered)
}

// ホスト名の後方一致: ホスト名が登録ドメインで終われば許可
fn host_suffix_match(registered_host: &str, requested: &str) -> bool {
    match Url::parse(requested) {
        Ok(u) => u.host_str().is_some_and(|h| h.ends_with(registered_host)),
        Err(_) => false,
    }
}

// 素朴なワイルドカード: '*' を「任意の文字列」として扱う
fn naive_wildcard(pattern: &str, requested: &str) -> bool {
    fn go(p: &[u8], s: &[u8]) -> bool {
        match p.split_first() {
            None => s.is_empty(),
            Some((b'*', rest)) => (0..=s.len()).any(|i| go(rest, &s[i..])),
            Some((c, rest)) => s.first() == Some(c) && go(rest, &s[1..]),
        }
    }
    go(pattern.as_bytes(), requested.as_bytes())
}

// ループバックIPリテラルなら、元の文字列からポート番号だけを取り除く
fn strip_loopback_port(uri: &str) -> Option<String> {
    for base in ["http://127.0.0.1", "http://[::1]"] {
        let Some(rest) = uri.strip_prefix(base) else { continue };
        let rest = match rest.strip_prefix(':') {
            Some(r) => {
                let digits = r.chars().take_while(|c| c.is_ascii_digit()).count();
                if digits == 0 {
                    return None;
                }
                &r[digits..]
            }
            None => rest,
        };
        if !(rest.is_empty() || rest.starts_with(['/', '?', '#'])) {
            return None;
        }
        return Some(format!("{base}{rest}"));
    }
    None
}

// RFC 9700 4.1.3: 単純な文字列比較。ループバックIPリテラルのみポートを無視
fn exact_match(registered: &str, requested: &str) -> bool {
    if registered == requested {
        return true;
    }
    match (strip_loopback_port(registered), strip_loopback_port(requested)) {
        (Some(r), Some(q)) => r == q,
        _ => false,
    }
}

fn mark(ok: bool) -> &'static str {
    if ok { "許可" } else { "拒否" }
}

fn main() {
    let candidates = [
        ("正規", "https://app1.somesite.example/cb"),
        ("別ホスト(前方一致狙い)", "https://app1.somesite.example.attacker.example/cb"),
        ("パス遡り", "https://app1.somesite.example/cb/../logout?next=https://attacker.example/"),
        ("後方一致狙い", "https://evilsomesite.example/cb"),
        ("パスにドメイン名", "https://attacker.example/.somesite.example/cb"),
        ("クエリ追加", "https://app1.somesite.example/cb?x=1"),
    ];

    let prefix_reg = "https://app1.somesite.example";
    let suffix_reg = "somesite.example";
    let wildcard_reg = "https://*.somesite.example/*";
    let exact_reg = "https://app1.somesite.example/cb";
    println!("登録値: 前方={prefix_reg} 後方={suffix_reg} *={wildcard_reg} 完全={exact_reg}");
    println!("前方 後方 *    完全  候補");
    for (label, uri) in candidates {
        println!(
            "{} {} {} {}  {}",
            mark(prefix_match(prefix_reg, uri)),
            mark(host_suffix_match(suffix_reg, uri)),
            mark(naive_wildcard(wildcard_reg, uri)),
            mark(exact_match(exact_reg, uri)),
            label,
        );
    }

    println!();
    println!("ブラウザが実際にアクセスする先(URLの解析結果):");
    for (label, uri) in candidates.iter().skip(1) {
        let u = Url::parse(uri).unwrap();
        println!("  host={} path={}  ({})", u.host_str().unwrap(), u.path(), label);
    }

    println!();
    println!("ネイティブアプリのループバック(RFC 8252 7.3):");
    let reg = "http://127.0.0.1/oauth2redirect";
    for req in [
        "http://127.0.0.1:51004/oauth2redirect",
        "http://127.0.0.1:61023/oauth2redirect",
        "http://127.0.0.1:51004/other",
        "http://127.0.0.1:51004/x/../oauth2redirect",
        "http://localhost:51004/oauth2redirect",
    ] {
        println!("  {} {}", mark(exact_match(reg, req)), req);
    }
}
