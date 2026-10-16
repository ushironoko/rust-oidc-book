use serde_json::{Value, json};
use std::collections::HashMap;

const GRANT: &str = "urn:ietf:params:oauth:grant-type:token-exchange";
const AT: &str = "urn:ietf:params:oauth:token-type:access_token";

// 認可サーバが発行済みのトークン(値 -> 検証後のクレーム)。署名検証は省略
struct AuthServer {
    issued: HashMap<String, Value>,
    // クライアントごとに交換を許すリソース
    allowed: HashMap<&'static str, Vec<&'static str>>,
    // リソースURI -> そのリソースを運用するサービスの識別子
    owner: HashMap<&'static str, &'static str>,
    seq: u32,
}

impl AuthServer {
    fn exchange(&mut self, client_id: &str, body: &str) -> Result<(String, Value), &'static str> {
        let p: HashMap<String, String> = form_urlencoded::parse(body.as_bytes()).into_owned().collect();
        if p.get("grant_type").map(String::as_str) != Some(GRANT) {
            return Err("unsupported_grant_type");
        }
        // この認可サーバが受け付けるトークンの種類はアクセストークンだけ
        if p.get("subject_token_type").map(String::as_str) != Some(AT) {
            return Err("invalid_request");
        }
        match (p.get("actor_token"), p.get("actor_token_type").map(String::as_str)) {
            (Some(_), Some(AT)) | (None, None) => {}
            _ => return Err("invalid_request"),
        }
        let subject = self.issued.get(p.get("subject_token").ok_or("invalid_request")?).ok_or("invalid_request")?;
        let resource = p.get("resource").ok_or("invalid_request")?;
        if !self.allowed.get(client_id).is_some_and(|r| r.contains(&resource.as_str())) {
            return Err("invalid_target");
        }
        let mut claims = json!({
            "iss": "https://as.example.com",
            "sub": subject["sub"],
            "aud": resource,
            "scope": subject["scope"],
            "client_id": client_id,
        });
        if let Some(actor_token) = p.get("actor_token") {
            let actor = self.issued.get(actor_token).ok_or("invalid_request")?;
            // may_act で許された actor か、subject_token の宛先のサービス自身か
            let by_may_act = subject["may_act"]["sub"] == actor["sub"];
            let is_audience = subject["aud"].as_str().and_then(|a| self.owner.get(a)).is_some_and(|o| actor["sub"] == *o);
            if !by_may_act && !is_audience {
                return Err("invalid_request");
            }
            let mut act = json!({ "sub": actor["sub"] });
            if let Some(prior) = subject.get("act") {
                act["act"] = prior.clone();
            }
            claims["act"] = act;
        }
        self.seq += 1;
        let token = format!("dummy-exchanged-token-{}", self.seq);
        self.issued.insert(token.clone(), claims.clone());
        Ok((token, claims))
    }
}

fn body(subject: &str, actor: Option<&str>, resource: &str) -> String {
    let mut f = form_urlencoded::Serializer::new(String::new());
    f.append_pair("grant_type", GRANT)
        .append_pair("resource", resource)
        .append_pair("subject_token", subject)
        .append_pair("subject_token_type", AT);
    if let Some(a) = actor {
        f.append_pair("actor_token", a).append_pair("actor_token_type", AT);
    }
    f.finish()
}

// リソースサーバのアクセス制御: 最上位のクレームと現在のアクター(最も外側の act)だけで判断する
fn current_actor(claims: &Value) -> String {
    claims["act"]["sub"].as_str().unwrap_or("(なし: 利用者本人として扱う)").to_string()
}

fn main() {
    let mut as_ = AuthServer { issued: HashMap::new(), allowed: HashMap::new(), owner: HashMap::new(), seq: 0 };
    as_.issued.insert("dummy-user-token".into(), json!({
        "sub": "user@example.com", "scope": "orders:read",
        "may_act": { "sub": "https://frontend.example.com" }
    }));
    as_.issued.insert("dummy-frontend-token".into(), json!({ "sub": "https://frontend.example.com" }));
    as_.issued.insert("dummy-backend-token".into(), json!({ "sub": "https://backend.example.com" }));
    as_.allowed.insert("frontend", vec!["https://backend.example.com/api"]);
    as_.allowed.insert("backend", vec!["https://ledger.example.com/api"]);
    as_.owner.insert("https://backend.example.com/api", "https://backend.example.com");

    println!("== 1. なりすまし(actor_token なし) ==");
    let b = body("dummy-user-token", None, "https://backend.example.com/api");
    println!("POST /token  (client=frontend)\n{b}");
    let (_, c) = as_.exchange("frontend", &b).unwrap();
    println!("発行: {c}\n現在のアクター: {}\n", current_actor(&c));

    println!("== 2. 委任(actor_token あり) ==");
    let b = body("dummy-user-token", Some("dummy-frontend-token"), "https://backend.example.com/api");
    let (t2, c) = as_.exchange("frontend", &b).unwrap();
    println!("発行: {c}\n現在のアクター: {}\n", current_actor(&c));

    println!("== 3. 委任の連鎖(backend がさらに交換) ==");
    let b = body(&t2, Some("dummy-backend-token"), "https://ledger.example.com/api");
    let (_, c) = as_.exchange("backend", &b).unwrap();
    println!("発行: {}\n現在のアクター: {}\n", serde_json::to_string_pretty(&c).unwrap(), current_actor(&c));

    println!("== 4. 拒否される交換 ==");
    let b = body("dummy-user-token", Some("dummy-backend-token"), "https://backend.example.com/api");
    println!("may_act にないアクター: {:?}", as_.exchange("frontend", &b).map(|r| r.1));
    let b = body("dummy-user-token", None, "https://ledger.example.com/api");
    println!("許可されていないリソース: {:?}", as_.exchange("frontend", &b).map(|r| r.1));
    let b = body("dummy-user-token", None, "https://backend.example.com/api").replace("&subject_token_type=", "&x=");
    println!("subject_token_type がない: {:?}", as_.exchange("frontend", &b).map(|r| r.1));
    let b = body("dummy-user-token", None, "https://backend.example.com/api") + "&actor_token_type=" + AT;
    println!("actor_token なしの actor_token_type: {:?}", as_.exchange("frontend", &b).map(|r| r.1));
    let b = body("dummy-user-token", Some("dummy-frontend-token"), "https://backend.example.com/api")
        .replace("&actor_token_type=", "&x=");
    println!("actor_token_type のない actor_token: {:?}", as_.exchange("frontend", &b).map(|r| r.1));
}
