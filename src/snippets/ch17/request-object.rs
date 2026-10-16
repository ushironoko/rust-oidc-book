use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ring::signature::{RSA_PKCS1_2048_8192_SHA256, RsaPublicKeyComponents};
use serde_json::{Value, json};
use std::collections::HashMap;

// RFC 9101 4節のリクエストオブジェクト (RS256)
const REQUEST_OBJECT: &str = "eyJhbGciOiJSUzI1NiIsImtpZCI6ImsyYmRjIn0.ewogICAgImlzcyI6ICJzNkJoZFJrcXQzIiwKICAgICJhdWQiOiAiaHR0cHM6Ly9zZXJ2ZXIuZXhhbXBsZS5jb20iLAogICAgInJlc3BvbnNlX3R5cGUiOiAiY29kZSBpZF90b2tlbiIsCiAgICAiY2xpZW50X2lkIjogInM2QmhkUmtxdDMiLAogICAgInJlZGlyZWN0X3VyaSI6ICJodHRwczovL2NsaWVudC5leGFtcGxlLm9yZy9jYiIsCiAgICAic2NvcGUiOiAib3BlbmlkIiwKICAgICJzdGF0ZSI6ICJhZjBpZmpzbGRraiIsCiAgICAibm9uY2UiOiAibi0wUzZfV3pBMk1qIiwKICAgICJtYXhfYWdlIjogODY0MDAKfQ.Nsxa_18VUElVaPjqW_ToI1yrEJ67BgKb5xsuZRVqzGkfKrOIX7BCx0biSxYGmjK9KJPctH1OC0iQJwXu5YVY-vnW0_PLJb1C2HG-ztVzcnKZC2gE4i0vgQcpkUOCpW3SEYXnyWnKzuKzqSb1wAZALo5f89B_p6QA6j6JwBSRvdVsDPdulW8lKxGTbH82czCaQ50rLAg3EYLYaCb4ik4I1zGXE4fvim9FIMs8OCMmzwIB5S-ujFfzwFjoyuPEV4hJnoVUmXR_W9typPf846lGwA8h9G9oNTIuX8Ft2jfpnZdFmLg3_wr3Wa5q3a-lfbgF3S9H_8nN3j1i7tLR_5Nz-g";

// RFC 9101 4節の公開鍵 (kid=k2bdc)。登録時にクライアントの鍵として保存したもの
const N: &str = "x5RbkAZkmpRxia65qRQ1wwSMSxQUnS7gcpVTV_cdHmfmG2ltd2yabEO9XadD8pJNZubINPpmgHh3J1aD9WRwS05ucmFq3CfFsluLt13_7oX5yDRSKX7poXmT_5ko8k4NJZPMAO8fPToDTH7kHYbONSE2FYa5GZ60CUsFhSonI-dcMDJ0Ary9lxIw5k2z4TAdARVWcS7sD07VhlMMshrwsPHBQgTatlkxyIHXbYdtak8fqvNAwr7OlVEvM_Ipf5OfmdB8Sd-wjzaBsyP4VhJKoi_qdgSzpC694XZeYPq45Sw-q51iFUlcOlTCI7z6jltUtnR6ySn6XDGFnzH5Fe5ypw";
const E: &str = "AQAB";

fn decode_json(part: &str) -> Result<Value, String> {
    let bytes = URL_SAFE_NO_PAD.decode(part).map_err(|_| "Base64url として不正")?;
    serde_json::from_slice(&bytes).map_err(|_| "JSON として不正".to_string())
}

// RFC 9101 4節の例の aud に入っている認可サーバの issuer
const ISSUER: &str = "https://server.example.com";

// RFC 9101 6.2節/6.3節: 署名を検証し、オブジェクト内のパラメータだけを使う
fn process(issuer: &str, query: &str) -> Result<HashMap<String, String>, String> {
    let q: HashMap<String, String> = form_urlencoded::parse(query.as_bytes()).into_owned().collect();
    let object = q.get("request").ok_or("invalid_request (request がない)")?;
    let parts: Vec<&str> = object.split('.').collect();
    let [h, p, s] = parts[..] else {
        return Err("invalid_request_object (JWS の形式ではない)".into());
    };
    let header = decode_json(h)?;
    if header["alg"] != "RS256" {
        return Err(format!("invalid_request_object (許可していない alg {})", header["alg"]));
    }
    if header["kid"] != "k2bdc" {
        return Err("invalid_request_object (クライアントの鍵ではない kid)".into());
    }
    let key = RsaPublicKeyComponents {
        n: URL_SAFE_NO_PAD.decode(N).unwrap(),
        e: URL_SAFE_NO_PAD.decode(E).unwrap(),
    };
    let sig = URL_SAFE_NO_PAD.decode(s).map_err(|_| "invalid_request_object")?;
    key.verify(&RSA_PKCS1_2048_8192_SHA256, format!("{h}.{p}").as_bytes(), &sig)
        .map_err(|_| "invalid_request_object (署名検証に失敗)".to_string())?;
    let claims = decode_json(p)?;
    if q.get("client_id").map(String::as_str) != claims["client_id"].as_str() {
        return Err("invalid_request (client_id がオブジェクトと一致しない)".into());
    }
    // RFC 7519 4.1.3節: aud があれば、自分を含まないオブジェクトを拒否する
    let aud_ok = match &claims["aud"] {
        Value::Null => true,
        Value::String(a) => a == issuer,
        Value::Array(list) => list.iter().any(|a| a == issuer),
        _ => false,
    };
    if !aud_ok {
        return Err(format!("invalid_request_object (aud に自分が含まれない: {})", claims["aud"]));
    }
    let params = claims
        .as_object()
        .unwrap()
        .iter()
        .filter(|(k, _)| !["iss", "aud"].contains(&k.as_str()))
        .map(|(k, v)| (k.clone(), v.as_str().map(String::from).unwrap_or(v.to_string())))
        .collect();
    Ok(params)
}

fn show(label: &str, query: &str) {
    show_at(ISSUER, label, query);
}

fn show_at(issuer: &str, label: &str, query: &str) {
    println!("{label}");
    match process(issuer, query) {
        Ok(params) => {
            let mut keys: Vec<_> = params.keys().collect();
            keys.sort();
            for k in keys {
                println!("  {k} = {}", params[k]);
            }
        }
        Err(e) => println!("  エラー応答: {e}"),
    }
}

fn main() {
    let parts: Vec<&str> = REQUEST_OBJECT.split('.').collect();
    println!("[1] RFC 9101 4節のリクエストオブジェクト");
    println!("  header : {}", decode_json(parts[0]).unwrap());
    println!("  payload: {}", decode_json(parts[1]).unwrap());

    let enc = |pairs: &[(&str, &str)]| {
        let mut s = form_urlencoded::Serializer::new(String::new());
        for (k, v) in pairs {
            s.append_pair(k, v);
        }
        s.finish()
    };

    show("\n[2] RFC の公開鍵で検証し、パラメータを取り出す",
        &enc(&[("client_id", "s6BhdRkqt3"), ("request", REQUEST_OBJECT)]));

    show("\n[3] クエリ側の redirect_uri と scope を書き換えても、オブジェクトの値が使われる",
        &enc(&[("client_id", "s6BhdRkqt3"), ("request", REQUEST_OBJECT),
               ("redirect_uri", "https://attacker.example/cb"), ("scope", "openid email offline_access")]));

    show("\n[4] クエリの client_id がオブジェクトと異なる",
        &enc(&[("client_id", "another-client"), ("request", REQUEST_OBJECT)]));

    let mut claims = decode_json(parts[1]).unwrap();
    claims["redirect_uri"] = json!("https://attacker.example/cb");
    let tampered = format!("{}.{}.{}", parts[0], URL_SAFE_NO_PAD.encode(claims.to_string()), parts[2]);
    show("\n[5] オブジェクトの redirect_uri を書き換える",
        &enc(&[("client_id", "s6BhdRkqt3"), ("request", &tampered)]));

    let none_header = URL_SAFE_NO_PAD.encode(r#"{"alg":"none"}"#);
    let unsigned = format!("{none_header}.{}.", URL_SAFE_NO_PAD.encode(claims.to_string()));
    show("\n[6] alg=none の署名なしオブジェクト",
        &enc(&[("client_id", "s6BhdRkqt3"), ("request", &unsigned)]));

    show_at("https://other-as.example.net", "\n[7] 同じオブジェクトを別の認可サーバに送る",
        &enc(&[("client_id", "s6BhdRkqt3"), ("request", REQUEST_OBJECT)]));
}
