// 認可サーバとクライアントの設定が FAPI 2.0 Security Profile(Final)の要求を満たすか検査する。
// 括弧内は FAPI 2.0 Security Profile の節番号と項番号

struct AsConfig {
    issuer: &'static str,
    public_clients_allowed: bool,
    grant_types: &'static [&'static str],
    response_types: &'static [&'static str],
    client_auth: &'static [&'static str],
    sender_constraint: &'static [&'static str],
    par_required: bool,
    pkce_methods: &'static [&'static str],
    issues_iss_param: bool,
    // 署名鍵ごとの (alg, 鍵の crv または kty)
    signing_keys: &'static [(&'static str, &'static str)],
    auth_code_lifetime_s: u32,
    request_uri_expires_in_s: u32,
    refresh_token_rotation: bool,
    credential_redirect_status: u16,
    max_future_iat_s: i64,
}

enum Aud {
    Str(&'static str),
    Array(&'static [&'static str]),
}

struct ClientConfig {
    sends_only_client_id_and_request_uri: bool,
    checks_iss_param: bool,
    assertion_aud: Aud,
}

struct Report {
    ng: usize,
}

impl Report {
    fn check(&mut self, ok: bool, clause: &str, text: &str) {
        if !ok {
            self.ng += 1;
        }
        println!("  {} ({clause}) {text}", if ok { "OK" } else { "NG" });
    }
}

fn has(list: &[&str], x: &str) -> bool {
    list.contains(&x)
}

fn subset(list: &[&str], allowed: &[&str]) -> bool {
    !list.is_empty() && list.iter().all(|x| allowed.contains(x))
}

// iat/nbf の未来方向の許容: 0〜10秒は受理しなければならず、60秒超は拒否しなければならない
fn accepts_future(max_future_s: i64, offset_s: i64) -> bool {
    offset_s <= max_future_s
}

// EdDSA は多相アルゴリズムなので、鍵の crv で Ed25519 に限定する
fn alg_allowed((alg, crv): &(&str, &str)) -> bool {
    match *alg {
        "PS256" | "ES256" => true,
        "EdDSA" | "Ed25519" => *crv == "Ed25519",
        _ => false,
    }
}

fn aud_is_issuer(aud: &Aud, issuer: &str) -> bool {
    matches!(aud, Aud::Str(s) if *s == issuer)
}

fn audit(name: &str, a: &AsConfig, c: &ClientConfig) {
    println!("[{name}]");
    let mut r = Report { ng: 0 };
    r.check(!a.public_clients_allowed, "5.3.2.1-3", "機密クライアントのみ");
    r.check(!has(a.grant_types, "password"), "5.3.2.1-2", "ROPC グラントを拒否");
    r.check(subset(a.sender_constraint, &["dpop", "mtls"]), "5.3.2.1-4,5", "送信者制約付きアクセストークンのみ発行(DPoP か MTLS)");
    r.check(
        subset(a.client_auth, &["private_key_jwt", "tls_client_auth", "self_signed_tls_client_auth"]),
        "5.3.2.1-6",
        "クライアント認証は MTLS か private_key_jwt",
    );
    r.check(!a.refresh_token_rotation, "5.3.2.1-9", "リフレッシュトークンをローテーションしない");
    r.check(a.auth_code_lifetime_s <= 60, "5.3.2.1-11", "認可コードの寿命は60秒以下");
    let window_ok = (0..=10).all(|s| accepts_future(a.max_future_iat_s, s)) && !accepts_future(a.max_future_iat_s, 61);
    r.check(window_ok, "5.3.2.1-13", "未来方向10秒までの iat/nbf を受理し、60秒超を拒否");
    r.check(a.response_types == ["code"], "5.3.2.2-1", "response_type は code のみ");
    r.check(a.par_required, "5.3.2.2-2,3,4", "クライアント認証付きの PAR を必須にする");
    r.check(a.pkce_methods == ["S256"], "5.3.2.2-5", "PKCE を S256 で必須にする");
    r.check(a.issues_iss_param, "5.3.2.2-7", "認可レスポンスに iss パラメータを返す");
    r.check(a.credential_redirect_status != 307, "5.3.2.2-10", "資格情報を含むリクエストを 307 で転送しない");
    r.check(a.par_required && a.request_uri_expires_in_s < 600, "5.3.2.2-12", "request_uri の expires_in は600秒未満");
    r.check(
        !a.signing_keys.is_empty() && a.signing_keys.iter().all(alg_allowed),
        "5.4.1-1.2",
        "JWT の alg は PS256/ES256/EdDSA(Ed25519)のみ",
    );
    r.check(
        aud_is_issuer(&c.assertion_aud, a.issuer),
        "5.3.3.1-5",
        "private_key_jwt の aud は issuer 識別子と完全一致する文字列",
    );
    r.check(c.checks_iss_param, "5.3.3.2-5", "認可レスポンスの iss を検査する");
    r.check(c.sends_only_client_id_and_request_uri, "5.3.3.2-6", "認可エンドポイントには client_id と request_uri だけを送る");
    println!("  => 不適合 {} 件", r.ng);
    println!();
}

fn main() {
    let legacy = AsConfig {
        issuer: "https://as.example",
        public_clients_allowed: true,
        grant_types: &["authorization_code", "refresh_token", "password"],
        response_types: &["code", "token", "code id_token"],
        client_auth: &["client_secret_basic", "private_key_jwt"],
        sender_constraint: &[],
        par_required: false,
        pkce_methods: &["plain", "S256"],
        issues_iss_param: false,
        signing_keys: &[("RS256", "RSA"), ("HS256", "oct"), ("EdDSA", "Ed448")],
        auth_code_lifetime_s: 600,
        request_uri_expires_in_s: 0,
        refresh_token_rotation: true,
        credential_redirect_status: 302,
        max_future_iat_s: 0,
    };
    let legacy_client = ClientConfig {
        sends_only_client_id_and_request_uri: false,
        checks_iss_param: false,
        assertion_aud: Aud::Array(&["https://as.example"]),
    };
    let almost = AsConfig {
        issuer: "https://as.example",
        public_clients_allowed: false,
        grant_types: &["authorization_code", "refresh_token"],
        response_types: &["code"],
        client_auth: &["private_key_jwt"],
        sender_constraint: &["dpop"],
        par_required: true,
        pkce_methods: &["S256"],
        issues_iss_param: true,
        signing_keys: &[("ES256", "P-256"), ("PS256", "RSA"), ("EdDSA", "Ed25519")],
        auth_code_lifetime_s: 60,
        request_uri_expires_in_s: 600,
        refresh_token_rotation: false,
        credential_redirect_status: 303,
        max_future_iat_s: 5,
    };
    let fapi_client = ClientConfig {
        sends_only_client_id_and_request_uri: true,
        checks_iss_param: true,
        assertion_aud: Aud::Str("https://as.example"),
    };
    audit("従来型の OAuth 2.0 構成", &legacy, &legacy_client);
    audit("FAPI 2.0 を意図した構成", &almost, &fapi_client);

    println!("[aud の判定(期待する issuer は {})]", almost.issuer);
    for (label, aud) in [
        ("issuer の文字列", Aud::Str("https://as.example")),
        ("issuer を含む配列", Aud::Array(&["https://as.example"])),
        ("トークンエンドポイントの URL", Aud::Str("https://as.example/token")),
        ("別の issuer", Aud::Str("https://other-as.example")),
    ] {
        println!("  {} {label}", if aud_is_issuer(&aud, almost.issuer) { "OK" } else { "NG" });
    }
    println!();
    println!("[署名鍵の判定]");
    for key in [("EdDSA", "Ed25519"), ("Ed25519", "Ed25519"), ("EdDSA", "Ed448"), ("RS256", "RSA")] {
        println!("  {} alg={} crv/kty={}", if alg_allowed(&key) { "OK" } else { "NG" }, key.0, key.1);
    }
}
