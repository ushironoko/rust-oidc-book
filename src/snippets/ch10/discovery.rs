use serde::Deserialize;
use url::Url;

// Discovery 3節で REQUIRED のメタデータ項目と、RP が使う項目
#[derive(Deserialize)]
struct ProviderMetadata {
    issuer: String,
    authorization_endpoint: String,
    token_endpoint: Option<String>,
    userinfo_endpoint: Option<String>,
    jwks_uri: String,
    response_types_supported: Vec<String>,
    subject_types_supported: Vec<String>,
    id_token_signing_alg_values_supported: Vec<String>,
}

// Discovery 4.1節: issuer の末尾の / を除き、後ろに付け足す
fn openid_configuration_url(issuer: &str) -> String {
    format!("{}/.well-known/openid-configuration", issuer.trim_end_matches('/'))
}

// RFC 8414 3.1節: ホストとパスの間に挿入する
fn rfc8414_url(issuer: &str, suffix: &str) -> String {
    let url = Url::parse(issuer).expect("issuer は URL");
    let path = url.path().trim_end_matches('/');
    format!("{}/.well-known/{suffix}{path}", url.origin().ascii_serialization())
}

// Discovery 4.3節: 問い合わせに使った issuer と、応答の issuer の完全一致
fn validate(requested_issuer: &str, body: &str) -> Result<ProviderMetadata, String> {
    let meta: ProviderMetadata =
        serde_json::from_str(body).map_err(|e| format!("メタデータとして解析できない: {e}"))?;
    if meta.issuer != requested_issuer {
        return Err(format!("issuer が一致しない: 問い合わせ {requested_issuer} / 応答 {}", meta.issuer));
    }
    let endpoints = [Some(&meta.authorization_endpoint), meta.token_endpoint.as_ref(),
                     meta.userinfo_endpoint.as_ref(), Some(&meta.jwks_uri)];
    if let Some(bad) = endpoints.into_iter().flatten().find(|u| !u.starts_with("https://")) {
        return Err(format!("https ではないエンドポイント: {bad}"));
    }
    if !meta.response_types_supported.iter().any(|r| r == "code") {
        return Err("response_type=code に対応していない".to_string());
    }
    Ok(meta)
}

fn metadata(issuer: &str, endpoint_base: &str) -> String {
    format!(r#"{{
        "issuer": "{issuer}",
        "authorization_endpoint": "{endpoint_base}/authorize",
        "token_endpoint": "{endpoint_base}/token",
        "userinfo_endpoint": "{endpoint_base}/userinfo",
        "jwks_uri": "{endpoint_base}/jwks",
        "response_types_supported": ["code"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["ES256", "RS256"]
    }}"#)
}

fn main() {
    println!("== メタデータの URL");
    for issuer in ["https://op.example.com", "https://op.example.com/tenant-a"] {
        println!("issuer = {issuer}");
        println!("  Discovery 4節 : {}", openid_configuration_url(issuer));
        println!("  RFC 8414 3節 : {}", rfc8414_url(issuer, "oauth-authorization-server"));
    }

    println!("\n== issuer の検証");
    let legit = "https://op.example.com";
    let cases = [
        ("正しい OP", legit, metadata(legit, legit)),
        ("末尾に / がある", legit, metadata("https://op.example.com/", legit)),
        ("ホスト名の大文字小文字が違う", legit, metadata("https://OP.example.com", legit)),
        ("攻撃者が正規の issuer を名乗る", "https://evil.example",
         metadata(legit, "https://evil.example")),
        ("http のエンドポイント", legit, metadata(legit, "http://op.example.com")),
        ("jwks_uri がない", legit, r#"{"issuer": "https://op.example.com",
            "authorization_endpoint": "https://op.example.com/authorize",
            "response_types_supported": ["code"], "subject_types_supported": ["public"],
            "id_token_signing_alg_values_supported": ["ES256"]}"#.to_string()),
    ];
    for (label, requested, body) in &cases {
        match validate(requested, body) {
            Ok(meta) => println!("[受理] {label}: jwks_uri={} subject_types={:?} algs={:?}",
                meta.jwks_uri, meta.subject_types_supported, meta.id_token_signing_alg_values_supported),
            Err(e) => println!("[拒否] {label}: {e}"),
        }
    }

    println!("\n== URL として比較すると何が起きるか");
    let a = Url::parse("https://OP.example.com").unwrap();
    let b = Url::parse("https://op.example.com").unwrap();
    println!("文字列として等しいか: {}", "https://OP.example.com" == "https://op.example.com");
    println!("Url 型として等しいか: {} (解析時に {} へ正規化される)", a == b, a);
    let c = Url::parse("https://op.example.com").unwrap();
    println!("Url 型は末尾に / を補う: {c}");
}
