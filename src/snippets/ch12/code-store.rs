use std::collections::HashMap;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use sha2::{Digest, Sha256};

const CODE_TTL: u64 = 60;
const VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";

// 認可コードに束縛する値
struct CodeGrant {
    client_id: String,
    redirect_uri: String,
    code_challenge: String,
    nonce: String,
    sub: String,
    expires_at: u64,
}

struct TokenRequest<'a> {
    authenticated_client: &'a str,
    code: &'a str,
    redirect_uri: &'a str,
    code_verifier: &'a str,
}

fn s256(verifier: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()))
}

fn issue(store: &mut HashMap<String, CodeGrant>, code: &str, now: u64) {
    store.insert(code.to_string(), CodeGrant {
        client_id: "demo-rp".to_string(),
        redirect_uri: "https://rp.example.com/callback".to_string(),
        code_challenge: s256(VERIFIER),
        nonce: "dummy-nonce-0001".to_string(),
        sub: "user-0001".to_string(),
        expires_at: now + CODE_TTL,
    });
}

fn redeem(store: &mut HashMap<String, CodeGrant>, req: &TokenRequest, now: u64) -> Result<String, String> {
    // 1. 照合より先にストアから取り除く。失敗した要求でもコードは消費される
    let grant = store.remove(req.code).ok_or("invalid_grant: 未知のコードか使用済み")?;
    if now >= grant.expires_at {
        return Err(format!("invalid_grant: 期限切れ(発行から {} 秒)", now + CODE_TTL - grant.expires_at));
    }
    if grant.client_id != req.authenticated_client {
        return Err(format!("invalid_grant: {} に発行したコード", grant.client_id));
    }
    if grant.redirect_uri != req.redirect_uri {
        return Err("invalid_grant: redirect_uri が認可リクエストと異なる".to_string());
    }
    if s256(req.code_verifier) != grant.code_challenge {
        return Err("invalid_grant: PKCE の検証に失敗".to_string());
    }
    Ok(format!("トークンを発行(sub={}, IDトークンの nonce={})", grant.sub, grant.nonce))
}

fn main() {
    let mut store = HashMap::new();
    let ok_uri = "https://rp.example.com/callback";
    let req = |client, code, uri, verifier| TokenRequest {
        authenticated_client: client, code, redirect_uri: uri, code_verifier: verifier,
    };

    // (発行時刻, 交換時刻, 新たに発行するか, 説明, 要求)
    let cases = [
        (0, 5, true, "正しい要求", req("demo-rp", "code-1", ok_uri, VERIFIER)),
        (0, 6, false, "同じコードを再送", req("demo-rp", "code-1", ok_uri, VERIFIER)),
        (100, 161, true, "61秒後に交換", req("demo-rp", "code-2", ok_uri, VERIFIER)),
        (200, 201, true, "別のクライアントが交換", req("other-rp", "code-3", ok_uri, VERIFIER)),
        (300, 301, true, "redirect_uri が異なる", req("demo-rp", "code-4", "https://rp.example.com/cb2", VERIFIER)),
        (400, 401, true, "code_verifier が異なる", req("demo-rp", "code-5", ok_uri, "attacker-verifier-attacker-verifier-0000000")),
        (400, 402, false, "直後に正しい code_verifier で再送", req("demo-rp", "code-5", ok_uri, VERIFIER)),
    ];
    for (issued_at, now, fresh, label, r) in cases {
        if fresh {
            issue(&mut store, r.code, issued_at);
        }
        let result = redeem(&mut store, &r, now);
        let mark = if result.is_ok() { "成功" } else { "拒否" };
        println!("[{mark}] {label} ({}): {}", r.code, result.unwrap_or_else(|e| e));
    }
    println!("ストアに残ったコード: {}", store.len());
}
