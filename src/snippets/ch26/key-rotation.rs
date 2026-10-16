use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD as B64};
use ring::rand::SystemRandom;
use ring::signature::{
    ECDSA_P256_SHA256_FIXED, ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, KeyPair, UnparsedPublicKey,
};
use serde_json::{Value, json};

const TOKEN_LIFETIME: u64 = 3600;
const JWKS_MAX_AGE: u64 = 3600;
const MIN_REFETCH: u64 = 60;

type Jwks = Vec<(String, Vec<u8>)>;

struct Op {
    keys: Vec<(String, EcdsaKeyPair)>,
    published: Vec<String>,
    signing_kid: String,
    rng: SystemRandom,
}

fn new_key(rng: &SystemRandom) -> EcdsaKeyPair {
    let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, rng).unwrap();
    EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8.as_ref(), rng).unwrap()
}

fn jwks_of(op: &Op) -> Jwks {
    op.keys
        .iter()
        .filter(|(kid, _)| op.published.contains(kid))
        .map(|(kid, kp)| (kid.clone(), kp.public_key().as_ref().to_vec()))
        .collect()
}

fn issue(op: &Op, now: u64) -> String {
    let header = json!({"alg": "ES256", "typ": "JWT", "kid": op.signing_kid});
    let claims = json!({"iss": "https://op.example", "iat": now, "exp": now + TOKEN_LIFETIME});
    let input = format!("{}.{}", B64.encode(header.to_string()), B64.encode(claims.to_string()));
    let (_, kp) = op.keys.iter().find(|(k, _)| *k == op.signing_kid).unwrap();
    let sig = kp.sign(&op.rng, input.as_bytes()).unwrap();
    format!("{input}.{}", B64.encode(sig.as_ref()))
}

struct Rp {
    name: &'static str,
    refetch_on_unknown_kid: bool,
    jwks: Jwks,
    fetched_at: u64,
}

fn verify(rp: &mut Rp, op: &Op, token: &str, now: u64) -> Result<(), String> {
    let parts: Vec<&str> = token.split('.').collect();
    let header: Value = serde_json::from_slice(&B64.decode(parts[0]).unwrap()).unwrap();
    let claims: Value = serde_json::from_slice(&B64.decode(parts[1]).unwrap()).unwrap();
    let kid = header["kid"].as_str().unwrap();

    if now - rp.fetched_at >= JWKS_MAX_AGE {
        rp.jwks = jwks_of(op);
        rp.fetched_at = now;
    }
    let known = |rp: &Rp| rp.jwks.iter().any(|(k, _)| k == kid);
    if !known(rp) && rp.refetch_on_unknown_kid && now - rp.fetched_at >= MIN_REFETCH {
        rp.jwks = jwks_of(op);
        rp.fetched_at = now;
    }
    let (_, public) = rp.jwks.iter().find(|(k, _)| k == kid).ok_or(format!("未知の kid {kid}"))?;
    let sig = B64.decode(parts[2]).unwrap();
    UnparsedPublicKey::new(&ECDSA_P256_SHA256_FIXED, public)
        .verify(format!("{}.{}", parts[0], parts[1]).as_bytes(), &sig)
        .map_err(|_| "署名不一致".to_string())?;
    if claims["exp"].as_u64().unwrap() <= now {
        return Err("期限切れ".into());
    }
    Ok(())
}

enum Ev {
    Publish(&'static str),
    Switch(&'static str),
    Retire(&'static str),
    Probe,
}

fn show(r: Result<(), String>) -> String {
    match r {
        Ok(()) => "成功".into(),
        Err(e) => format!("失敗({e})"),
    }
}

fn scenario(title: &str, events: &[(u64, Ev)]) {
    println!("== {title}");
    let rng = SystemRandom::new();
    let keys = vec![("k1".to_string(), new_key(&rng)), ("k2".to_string(), new_key(&rng))];
    let mut op = Op { keys, published: vec!["k1".into()], signing_kid: "k1".into(), rng };
    let mut rps = [
        Rp { name: "RP-A", refetch_on_unknown_kid: true, jwks: jwks_of(&op), fetched_at: 0 },
        Rp { name: "RP-B", refetch_on_unknown_kid: false, jwks: jwks_of(&op), fetched_at: 0 },
    ];
    let mut last_old: Option<(u64, String)> = None;

    for (t, ev) in events {
        match ev {
            Ev::Publish(k) => {
                op.published.push(k.to_string());
                println!("t={t:>5} JWKS に {k} を追加");
            }
            Ev::Switch(k) => {
                last_old = Some((t - 1, issue(&op, t - 1)));
                op.signing_kid = k.to_string();
                println!("t={t:>5} 署名鍵を {k} に切り替え (直前の t={} に旧鍵で発行したトークンを保持)", t - 1);
            }
            Ev::Retire(k) => {
                op.published.retain(|p| p != k);
                println!("t={t:>5} JWKS から {k} を削除");
            }
            Ev::Probe => {
                let fresh = issue(&op, *t);
                for rp in rps.iter_mut() {
                    let a = show(verify(rp, &op, &fresh, *t));
                    let b = match &last_old {
                        Some((iat, _)) if iat + TOKEN_LIFETIME <= *t => "寿命切れのため対象外".into(),
                        Some((_, old)) => show(verify(rp, &op, old, *t)),
                        None => "-".into(),
                    };
                    println!("t={t:>5}   {}: 新規トークン {a} / 旧鍵のトークン {b}", rp.name);
                }
            }
        }
    }
    println!();
}

fn main() {
    use Ev::*;
    scenario(
        "1. 正しい順序: 公開 -> max-age 待ち -> 切り替え -> トークン寿命待ち -> 削除",
        &[
            (1000, Publish("k2")),
            (1100, Probe),
            (4600, Switch("k2")),
            (4600, Probe),
            (6000, Probe),
            (8200, Retire("k1")),
            (8200, Probe),
        ],
    );
    scenario(
        "2. 誤り: 公開と同時に切り替える",
        &[(1000, Publish("k2")), (1000, Switch("k2")), (1000, Probe), (2000, Probe), (3600, Probe)],
    );
    scenario(
        "3. 誤り: 切り替えと同時に旧鍵を削除する",
        &[
            (1000, Publish("k2")),
            (4600, Switch("k2")),
            (4600, Retire("k1")),
            (4600, Probe),
            (6000, Probe),
            (8200, Probe),
        ],
    );
}
