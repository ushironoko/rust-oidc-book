use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD as B64};
use ring::signature::{ECDSA_P256_SHA256_FIXED, UnparsedPublicKey};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};

// RFC 9901 5.2節の SD-JWT+KB (改行を除いて連結したもの)
const ISSUER_JWT: &str = concat!(
    "eyJhbGciOiAiRVMyNTYiLCAidHlwIjogImV4YW1wbGUrc2Qtand0In0.eyJfc2QiOiBb",
    "IkNyUWU3UzVrcUJBSHQtbk1ZWGdjNmJkdDJTSDVhVFkxc1VfTS1QZ2tqUEkiLCAiSnpZ",
    "akg0c3ZsaUgwUjNQeUVNZmVadTZKdDY5dTVxZWhabzdGN0VQWWxTRSIsICJQb3JGYnBL",
    "dVZ1Nnh5bUphZ3ZrRnNGWEFiUm9jMkpHbEFVQTJCQTRvN2NJIiwgIlRHZjRvTGJnd2Q1",
    "SlFhSHlLVlFaVTlVZEdFMHc1cnREc3JaemZVYW9tTG8iLCAiWFFfM2tQS3QxWHlYN0tB",
    "TmtxVlI2eVoyVmE1TnJQSXZQWWJ5TXZSS0JNTSIsICJYekZyendzY002R242Q0pEYzZ2",
    "Vks4QmtNbmZHOHZPU0tmcFBJWmRBZmRFIiwgImdiT3NJNEVkcTJ4Mkt3LXc1d1BFemFr",
    "b2I5aFYxY1JEMEFUTjNvUUw5Sk0iLCAianN1OXlWdWx3UVFsaEZsTV8zSmx6TWFTRnpn",
    "bGhRRzBEcGZheVF3TFVLNCJdLCAiaXNzIjogImh0dHBzOi8vaXNzdWVyLmV4YW1wbGUu",
    "Y29tIiwgImlhdCI6IDE2ODMwMDAwMDAsICJleHAiOiAxODgzMDAwMDAwLCAic3ViIjog",
    "InVzZXJfNDIiLCAibmF0aW9uYWxpdGllcyI6IFt7Ii4uLiI6ICJwRm5kamtaX1ZDem15",
    "VGE2VWpsWm8zZGgta284YUlLUWM5RGxHemhhVllvIn0sIHsiLi4uIjogIjdDZjZKa1B1",
    "ZHJ5M2xjYndIZ2VaOGtoQXYxVTFPU2xlclAwVmtCSnJXWjAifV0sICJfc2RfYWxnIjog",
    "InNoYS0yNTYiLCAiY25mIjogeyJqd2siOiB7Imt0eSI6ICJFQyIsICJjcnYiOiAiUC0y",
    "NTYiLCAieCI6ICJUQ0FFUjE5WnZ1M09IRjRqNFc0dmZTVm9ISVAxSUxpbERsczd2Q2VH",
    "ZW1jIiwgInkiOiAiWnhqaVdXYlpNUUdIVldLVlE0aGJTSWlyc1ZmdWVjQ0U2dDRqVDlG",
    "MkhaUSJ9fX0.MczwjBFGtzf-6WMT-hIvYbkb11NrV1WMO-jTijpMPNbswNzZ87wY2uHz",
    "-CXo6R04b7jYrpj9mNRAvVssXou1iw",
);
const D_FAMILY: &str = "WyJlbHVWNU9nM2dTTklJOEVZbnN4QV9BIiwgImZhbWlseV9uYW1lIiwgIkRvZSJd";
const D_ADDRESS: &str = concat!(
    "WyJBSngtMDk1VlBycFR0TjRRTU9xUk9BIiwgImFkZHJlc3MiLCB7InN0cmVldF9hZGRyZXNzIjogIjEyMyBNYWluIFN0Ii",
    "wgImxvY2FsaXR5IjogIkFueXRvd24iLCAicmVnaW9uIjogIkFueXN0YXRlIiwgImNvdW50cnkiOiAiVVMifV0",
);
const D_GIVEN: &str = "WyIyR0xDNDJzS1F2ZUNmR2ZyeU5STjl3IiwgImdpdmVuX25hbWUiLCAiSm9obiJd";
const D_US: &str = "WyJsa2x4RjVqTVlsR1RQVW92TU5JdkNBIiwgIlVTIl0";
const KB_JWT: &str = concat!(
    "eyJhbGciOiAiRVMyNTYiLCAidHlwIjogImtiK2p3dCJ9.eyJub25jZSI6ICIxMjM0NTY3ODkwIiwgImF1ZCI6ICJodH",
    "RwczovL3ZlcmlmaWVyLmV4YW1wbGUub3JnIiwgImlhdCI6IDE3NDg1MzcyNDQsICJzZF9oYXNoIjogIjBfQWYtMkItRW",
    "hMV1g1eWRoX3cyeHp3bU82aU02NkJfMlFDRWFuSTRmVVkifQ.T3SIus2OidNl41nmVkTZVCKKhOAX97aOldMyHFiYjHm",
    "261eLiJ1YiuONFiMN8QlCmYzDlBLAdPvrXh52KaLgUQ",
);

// 検証者が信頼する発行者と、その公開鍵(RFC 9901 付録A.5)の対応
const TRUSTED_ISSUERS: [(&str, &str, &str); 1] = [(
    "https://issuer.example.com",
    "b28d4MwZMjw8-00CG4xfnn9SLMVMM19SlqZpVb_uNtQ",
    "Xv5zWwuoaTgdS6hV43yI6gBwTnjukmFQQnJ_kCxzqk8",
)];

// 鍵束縛 JWT の iat として受け入れる範囲(秒)
const KB_MAX_AGE: i64 = 300;
const KB_MAX_FUTURE: i64 = 60;

fn b64json(part: &str) -> Result<Value, String> {
    let bytes = B64.decode(part).map_err(|e| format!("base64url: {e}"))?;
    serde_json::from_slice(&bytes).map_err(|e| format!("JSON: {e}"))
}

fn digest_of(s: &str) -> String {
    B64.encode(Sha256::digest(s.as_bytes()))
}

// ES256 の JWS を検証し、(ヘッダ, ペイロード) を返す
fn verify_es256(jws: &str, x: &str, y: &str, expected_typ: &str) -> Result<(Value, Value), String> {
    let parts: Vec<&str> = jws.split('.').collect();
    let [h, p, s] = parts[..] else { return Err("JWS の形式が不正".into()) };
    let header = b64json(h)?;
    if header["alg"] != "ES256" {
        return Err(format!("許可していない alg: {}", header["alg"]));
    }
    if header["typ"] != expected_typ {
        return Err(format!("typ が {expected_typ} ではない: {}", header["typ"]));
    }
    let mut point = vec![0x04];
    point.extend(B64.decode(x).map_err(|e| e.to_string())?);
    point.extend(B64.decode(y).map_err(|e| e.to_string())?);
    let sig = B64.decode(s).map_err(|e| e.to_string())?;
    UnparsedPublicKey::new(&ECDSA_P256_SHA256_FIXED, &point)
        .verify(format!("{h}.{p}").as_bytes(), &sig)
        .map_err(|_| "署名が一致しない".to_string())?;
    Ok((header, b64json(p)?))
}

struct Pool {
    by_digest: HashMap<String, Value>,
    used: HashSet<String>,
    seen: HashSet<String>,
}

// RFC 9901 7.1節 手順3: _sd と "..." を辿って値を挿入する
fn process(value: Value, pool: &mut Pool) -> Result<Value, String> {
    match value {
        Value::Object(mut obj) => {
            if obj.contains_key("_sd_alg") {
                return Err("_sd_alg がトップレベル以外にある".into());
            }
            let digests = match obj.remove("_sd") {
                Some(Value::Array(a)) => a,
                Some(_) => return Err("_sd が配列ではない".into()),
                None => vec![],
            };
            let mut out = Map::new();
            for (k, v) in obj {
                out.insert(k, process(v, pool)?);
            }
            for d in digests {
                let d = d.as_str().ok_or("_sd の要素が文字列ではない")?.to_string();
                if !pool.seen.insert(d.clone()) {
                    return Err(format!("ダイジェストの重複: {d}"));
                }
                let Some(disc) = pool.by_digest.get(&d).cloned() else { continue };
                let arr = disc.as_array().filter(|a| a.len() == 3).ok_or("3要素の配列ではない")?;
                let name = arr[1].as_str().ok_or("クレーム名が文字列ではない")?;
                if name == "_sd" || name == "..." || out.contains_key(name) {
                    return Err(format!("使えないクレーム名: {name}"));
                }
                pool.used.insert(d);
                let v = process(arr[2].clone(), pool)?;
                out.insert(name.to_string(), v);
            }
            Ok(Value::Object(out))
        }
        Value::Array(items) => {
            let mut out = vec![];
            for item in items {
                let reference = item
                    .as_object()
                    .filter(|o| o.len() == 1)
                    .and_then(|o| o.get("..."))
                    .and_then(|v| v.as_str())
                    .map(str::to_string);
                match reference {
                    Some(d) => {
                        if !pool.seen.insert(d.clone()) {
                            return Err(format!("ダイジェストの重複: {d}"));
                        }
                        let Some(disc) = pool.by_digest.get(&d).cloned() else { continue };
                        let arr = disc.as_array().filter(|a| a.len() == 2).ok_or("2要素の配列ではない")?;
                        pool.used.insert(d);
                        out.push(process(arr[1].clone(), pool)?);
                    }
                    None => out.push(process(item, pool)?),
                }
            }
            Ok(Value::Array(out))
        }
        other => Ok(other),
    }
}

fn verify_presentation(presentation: &str, now: i64, nonce: &str, aud: &str) -> Result<Value, String> {
    let parts: Vec<&str> = presentation.split('~').collect();
    let (issuer_jwt, rest) = parts.split_first().ok_or("空の入力")?;
    let (kb_jwt, disclosures) = rest.split_last().ok_or("~ がない")?;
    if kb_jwt.is_empty() {
        return Err("鍵束縛 JWT が必要だが付いていない".into());
    }

    // 7.1節 手順2c: 署名前の iss で鍵を選び、署名検証後の iss と照合する
    let claimed_iss = b64json(issuer_jwt.split('.').nth(1).ok_or("JWS の形式が不正")?)?["iss"].clone();
    let (iss, x, y) = TRUSTED_ISSUERS
        .iter()
        .find(|(i, _, _)| claimed_iss == *i)
        .ok_or(format!("信頼していない発行者: {claimed_iss}"))?;
    let (_, mut payload) = verify_es256(issuer_jwt, x, y, "example+sd-jwt")?;
    if payload["iss"] != *iss {
        return Err("iss が鍵の発行者と一致しない".into());
    }

    // 4.1.1節: 省略時だけ sha-256。存在する場合は対応する文字列でなければならない
    match payload.as_object_mut().ok_or("ペイロードがオブジェクトではない")?.remove("_sd_alg") {
        None => {}
        Some(Value::String(a)) if a == "sha-256" => {}
        Some(other) => return Err(format!("未対応の _sd_alg: {other}")),
    }

    let mut by_digest = HashMap::new();
    for d in disclosures {
        let content = b64json(d)?;
        if by_digest.insert(digest_of(d), content).is_some() {
            return Err("同じ Disclosure が2回ある".into());
        }
    }
    let mut pool = Pool { by_digest, used: HashSet::new(), seen: HashSet::new() };
    let processed = process(payload, &mut pool)?;
    let unused: Vec<_> = pool.by_digest.keys().filter(|d| !pool.used.contains(*d)).collect();
    if !unused.is_empty() {
        return Err(format!("署名済みペイロードに無い Disclosure がある: {unused:?}"));
    }
    // 7.1節 手順6: 処理済みペイロードの有効性クレームを検査する(exp は必須とする)
    if processed["exp"].as_i64().ok_or("exp がないか数値ではない")? <= now {
        return Err("期限切れ".into());
    }
    if let Some(nbf) = processed.get("nbf") {
        if nbf.as_i64().ok_or("nbf が数値ではない")? > now {
            return Err("nbf より前".into());
        }
    }
    if let Some(a) = processed.get("aud") {
        let ok = match a {
            Value::String(s) => s == aud,
            Value::Array(v) => v.iter().any(|x| x == aud),
            _ => false,
        };
        if !ok {
            return Err("発行者 JWT の aud が一致しない".into());
        }
    }

    // 7.3節: 鍵束縛 JWT を cnf.jwk で検証し、nonce・aud・sd_hash を照合する
    let jwk = &processed["cnf"]["jwk"];
    let (x, y) = (jwk["x"].as_str().ok_or("cnf.jwk.x")?, jwk["y"].as_str().ok_or("cnf.jwk.y")?);
    let (_, kb) = verify_es256(kb_jwt, x, y, "kb+jwt")?;
    let sd_jwt_part = &presentation[..presentation.len() - kb_jwt.len()];
    let iat = kb["iat"].as_i64().ok_or("鍵束縛 JWT の iat がないか数値ではない")?;
    if iat < now - KB_MAX_AGE || iat > now + KB_MAX_FUTURE {
        return Err(format!("鍵束縛 JWT の iat が許容範囲外 (作成から{}秒)", now - iat));
    }
    if kb["nonce"] != nonce || kb["aud"] != aud {
        return Err("nonce または aud が一致しない".into());
    }
    if kb["sd_hash"] != digest_of(sd_jwt_part) {
        return Err("sd_hash が一致しない".into());
    }
    Ok(processed)
}

// ダイジェストを照合しない誤った実装(RFC 9901 9.2節の naive Verifier)
fn naive_claims(presentation: &str) -> Map<String, Value> {
    presentation
        .split('~')
        .skip(1)
        .filter_map(|d| b64json(d).ok())
        .filter_map(|v| {
            let a = v.as_array()?.clone();
            (a.len() == 3).then(|| (a[1].as_str().unwrap().to_string(), a[2].clone()))
        })
        .collect()
}

fn main() {
    let now = 1748537300;
    let (nonce, aud) = ("1234567890", "https://verifier.example.org");
    let disclosures = [D_FAMILY, D_ADDRESS, D_GIVEN, D_US];
    let presentation = format!("{ISSUER_JWT}~{}~{KB_JWT}", disclosures.join("~"));

    println!("== 1. RFC 9901 5.2節の提示をそのまま検証する");
    match verify_presentation(&presentation, now, nonce, aud) {
        Ok(v) => println!("受理。処理済みペイロード:\n{}", serde_json::to_string_pretty(&v).unwrap()),
        Err(e) => println!("拒否: {e}"),
    }

    println!();
    println!("== 2. 保有者が Disclosure の値を Doe から Roe に書き換える");
    let forged_family = B64.encode(r#"["eluV5Og3gSNII8EYnsxA_A", "family_name", "Roe"]"#);
    let forged = presentation.replace(D_FAMILY, &forged_family);
    println!("ダイジェストを照合しない実装の family_name: {}", naive_claims(&forged)["family_name"]);
    match verify_presentation(&forged, now, nonce, aud) {
        Ok(_) => println!("RFC 7.1節の手順の結果: 受理"),
        Err(e) => println!("RFC 7.1節の手順の結果: 拒否 ({e})"),
    }

    println!();
    println!("== 3. 別の検証者向けの提示を再利用する(aud の不一致)");
    match verify_presentation(&presentation, now, nonce, "https://other.example.net") {
        Ok(_) => println!("受理"),
        Err(e) => println!("拒否: {e}"),
    }

    println!();
    println!("== 4. 鍵束縛 JWT を付けたまま Disclosure を1つ取り除く");
    let fewer = format!("{ISSUER_JWT}~{D_FAMILY}~{D_ADDRESS}~{D_GIVEN}~{KB_JWT}");
    match verify_presentation(&fewer, now, nonce, aud) {
        Ok(_) => println!("受理"),
        Err(e) => println!("拒否: {e}"),
    }

    println!();
    println!("== 5. 同じ提示を1時間後に再送する(nonce と aud は一致)");
    match verify_presentation(&presentation, now + 3600, nonce, aud) {
        Ok(_) => println!("受理"),
        Err(e) => println!("拒否: {e}"),
    }
}
