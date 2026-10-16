use serde::Deserialize;
use std::collections::HashSet;

// RFC 6749 5.1節の成功レスポンス。未知のフィールドは無視される (serde の既定)
#[derive(Debug, Deserialize)]
struct TokenResponse {
    access_token: String,
    token_type: String,
    expires_in: Option<u64>,
    refresh_token: Option<String>,
    scope: Option<String>,
}

// RFC 6749 5.2節のエラーレスポンス
#[derive(Debug, Deserialize)]
struct ErrorResponse {
    error: String,
    error_description: Option<String>,
    error_uri: Option<String>,
}

#[derive(Debug)]
enum Outcome {
    Token { token: String, expires_at: Option<u64>, granted: HashSet<String>, refresh: Option<String> },
    Rejected(String),
}

fn scopes(s: &str) -> HashSet<String> {
    s.split(' ').filter(|x| !x.is_empty()).map(String::from).collect()
}

// HTTP ステータスで成功とエラーを分けてから、それぞれの型で解析する
// sent_at はトークンリクエストを送信した時刻。レスポンス生成より前なので、期限は早めに見積もられる
fn handle(status: u16, cache_control: Option<&str>, body: &str, requested: &str, sent_at: u64) -> Outcome {
    if status != 200 {
        return match serde_json::from_str::<ErrorResponse>(body) {
            Ok(e) => Outcome::Rejected(format!(
                "error={} description={:?} uri={:?}",
                e.error, e.error_description, e.error_uri
            )),
            Err(e) => Outcome::Rejected(format!("エラーレスポンスの形式が不正: {e}")),
        };
    }
    if cache_control != Some("no-store") {
        // 認可サーバ側の MUST 違反。記録はするが、トークンは受け取る
        println!("  警告: Cache-Control: no-store がない");
    }
    let t: TokenResponse = match serde_json::from_str(body) {
        Ok(t) => t,
        Err(e) => return Outcome::Rejected(format!("JSON の形式が不正: {e}")),
    };
    // token_type は大文字小文字を区別しない。理解できない種類のトークンは使わない
    if !t.token_type.eq_ignore_ascii_case("bearer") {
        return Outcome::Rejected(format!("理解できない token_type: {}", t.token_type));
    }
    // scope が省略されたら、要求どおりに許可されたと解釈する
    let granted = scopes(t.scope.as_deref().unwrap_or(requested));
    Outcome::Token {
        token: t.access_token,
        expires_at: t.expires_in.map(|s| sent_at + s),
        granted,
        refresh: t.refresh_token,
    }
}

fn main() {
    let sent_at = 1_000_000;
    let requested = "photos:read photos:delete";
    let cases: [(&str, u16, Option<&str>, &str); 7] = [
        (
            "RFC 6750 4節の例",
            200,
            Some("no-store"),
            r#"{"access_token":"mF_9.B5f-4.1JqM","token_type":"Bearer","expires_in":3600,"refresh_token":"tGzv3JOkF0XG5Qx2TlKWIA"}"#,
        ),
        (
            "token_type が小文字、scope が縮小",
            200,
            Some("no-store"),
            r#"{"access_token":"dummy-at-1","token_type":"bearer","expires_in":600,"scope":"photos:read"}"#,
        ),
        (
            "RFC 6749 5.1節の例 (token_type=example)",
            200,
            Some("no-store"),
            r#"{"access_token":"2YotnFZFEjr1zCsicMWpAA","token_type":"example","expires_in":3600,"refresh_token":"tGzv3JOkF0XG5Qx2TlKWIA","example_parameter":"example_value"}"#,
        ),
        (
            "expires_in が文字列",
            200,
            Some("no-store"),
            r#"{"access_token":"dummy-at-2","token_type":"Bearer","expires_in":"3600"}"#,
        ),
        (
            "Cache-Control がない",
            200,
            None,
            r#"{"access_token":"dummy-at-3","token_type":"Bearer"}"#,
        ),
        (
            "RFC 6749 5.2節の例",
            400,
            Some("no-store"),
            r#"{"error":"invalid_request"}"#,
        ),
        (
            "使用済みの認可コード",
            400,
            Some("no-store"),
            r#"{"error":"invalid_grant","error_description":"authorization code already used"}"#,
        ),
    ];
    for (i, (title, status, cc, body)) in cases.iter().enumerate() {
        println!("[{}] {title} (HTTP {status})", i + 1);
        match handle(*status, *cc, body, requested, sent_at) {
            Outcome::Token { token, expires_at, granted, refresh } => {
                let mut g: Vec<_> = granted.iter().cloned().collect();
                g.sort();
                let missing: Vec<_> = scopes(requested).difference(&granted).cloned().collect();
                println!("  アクセストークン: {token}");
                println!("  有効期限 (時刻): {expires_at:?}");
                println!("  リフレッシュトークン: {refresh:?}");
                println!("  許可されたスコープ: {g:?}");
                if !missing.is_empty() {
                    println!("  要求したが許可されなかったスコープ: {missing:?}");
                }
            }
            Outcome::Rejected(reason) => println!("  使わない: {reason}"),
        }
        println!();
    }
}
