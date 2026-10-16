---
title: OPを作る
description: 学習用の最小の OP(examples/mini-op)を読む。認可リクエストの検証の順序、ログイン画面と同意、1回限り・短寿命で束縛された認可コード、トークンエンドポイントのクライアント認証と PKCE の検証、ES256 による IDトークンと JWT アクセストークンの署名、本物の OP が追加でしていること。
sidebar:
  label: 12. OPを作る
---

この章でわかること:

- mini-op の構成と、OP が保持する4種類の状態(クライアント、ユーザー、認可リクエスト、認可コード)
- 認可リクエストの検証の順序と、`redirect_uri` を確かめるまでリダイレクトしない理由
- 認可コードを1回限り・短寿命にし、クライアント・`redirect_uri`・PKCE・`nonce` に束縛する実装
- トークンエンドポイントのクライアント認証、PKCE の検証、ES256 による IDトークンとアクセストークンの署名
- 本物の OP が mini-op に加えて行っていること

## mini-opの構成

この章では、`examples/mini-op` を読みます。mini-op は、[11章](/rust-impl/11-build-rp/)の rp と
resource-server の相手になる、学習用の最小の OP です。対応しているのは、
認可コードフロー、`client_secret_basic` によるクライアント認証、S256 の PKCE、ES256 の署名だけです。
仕様の多くの機能(リフレッシュトークン、`pairwise` 識別子、OP 側のログインセッションなど)は
実装していません。省いた機能は章末の「本物のOPが追加でしていること」の節にまとめます。

ソースは5つのファイルに分かれています。

| ファイル | 内容 |
| --- | --- |
| `src/main.rs` | 定数、状態の型、Discovery と JWKS のハンドラ、ルーティング |
| `src/jwt.rs` | 署名鍵の生成、JWK の作成、JWS の署名と検証、`at_hash` |
| `src/authorize.rs` | 認可エンドポイント(ログイン画面の表示と送信の処理) |
| `src/token.rs` | トークンエンドポイント |
| `src/userinfo.rs` | UserInfo エンドポイント |

公開するエンドポイントは次のとおりです。Discovery と JWKS と UserInfo は
[10章](/rust-impl/10-discovery-jwks/)で読んだので、この章では認可とトークンの2つを中心に読みます。

| メソッドとパス | 役割 |
| --- | --- |
| `GET /.well-known/openid-configuration` | Discovery のメタデータ |
| `GET /jwks` | 署名検証用の公開鍵(JWK Set) |
| `GET /authorize` | 認可リクエストを検証してログイン画面を表示 |
| `POST /authorize` | ユーザー名とパスワードを検証し、認可コードを発行してリダイレクト |
| `POST /token` | 認可コードをアクセストークンと IDトークンに交換 |
| `GET` または `POST /userinfo` | アクセストークンに対応するクレームを返す |

OP が保持する状態は、`main.rs` の `AppState` に集めています。

```rust
pub struct AppState {
    pub signer: jwt::Signer,
    pub rng: SystemRandom,
    pub clients: Vec<Client>,
    pub users: Vec<User>,
    pub pending: Mutex<HashMap<String, PendingRequest>>,
    pub codes: Mutex<HashMap<String, CodeGrant>>,
}
```

`clients` と `users` は起動時に決まる固定のデータです。登録済みのクライアントは
`demo-rp` の1つで、シークレットは `demo-rp-secret-not-for-production`、
登録済みの `redirect_uri` は `http://127.0.0.1:3000/callback` です。
テストユーザーはユーザー名 `demo`、パスワード `demo-password`、`sub` が `user-0001` の1人です。
どれも明らかにダミーとわかる値にしてあります。

`pending` は検証済みの認可リクエスト、`codes` は発行済みの認可コードで、
どちらも要求のたびに変わります。`AppState` は `Arc` で包んで axum の `State` として
各ハンドラに渡しており、グローバル変数は使っていません。2つの `HashMap` は
複数のハンドラが同時に書き換えるので、`Mutex` で保護しています。

2つの `HashMap` には、どちらも `main.rs` の `insert_bounded` で追加します。

```rust
pub fn insert_bounded<V>(
    store: &Mutex<HashMap<String, V>>,
    key: String,
    value: V,
    limit: usize,
    expires_at: fn(&V) -> u64,
) -> bool {
    let mut map = store.lock().unwrap();
    let t = now();
    map.retain(|_, v| expires_at(v) > t);
    if map.len() >= limit {
        return false;
    }
    map.insert(key, value);
    true
}
```

`insert_bounded` は、追加の前に期限切れの値を削除し、件数が上限(`MAX_PENDING` と
`MAX_CODES`、どちらも1000)に達していれば追加を断ります。ログイン画面を開いたまま
送信しない認可リクエストや、交換されない認可コードは、期限が切れても取り出されないので、
削除の処理がなければメモリに残り続けます。攻撃者は `GET /authorize` を繰り返すだけで
`pending` を増やせるため、件数の上限も必要です。

## 署名鍵

OP の中心となる値は、IDトークンとアクセストークンに署名する鍵です。mini-op は起動時に
P-256 の鍵ペアを1つ生成し、ES256 の署名に使います。ES256 の署名に使う P-256 の
秘密鍵を、本書では **ES256 署名鍵**(ES256 signing key)と呼びます(`examples/mini-op/src/jwt.rs`)。

```rust
pub fn generate_signer(rng: &SystemRandom) -> anyhow::Result<Signer> {
    let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, rng)
        .map_err(|_| anyhow::anyhow!("鍵ペアを生成できない"))?;
    let key = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8.as_ref(), rng)
        .map_err(|_| anyhow::anyhow!("PKCS#8 を読めない"))?;
    let (x, y) = coordinates(&key);
    let kid = thumbprint(&x, &y);
    Ok(Signer { key, kid, rng: rng.clone() })
}
```

ring は鍵ペアを PKCS#8 という形式のバイト列で生成し、`from_pkcs8` でそれを読み込んで
署名に使える値にします。アルゴリズムに `ECDSA_P256_SHA256_FIXED_SIGNING` を指定しているのは、
JWS の ES256 の署名が、r と s をそれぞれ32バイトで連結した64バイトの形式だからです
([7章](/oidc/07-jwt-jose/))。ring にはもう1つ ASN.1 DER 形式の署名を作る指定があり、
そちらを使うと JWS として検証できない署名になります。

署名の処理は次のとおりです。

```rust
pub fn sign(signer: &Signer, typ: &str, claims: &Value) -> anyhow::Result<String> {
    let header = json!({ "alg": "ES256", "typ": typ, "kid": signer.kid });
    let signing_input = format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header)?),
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(claims)?)
    );
    let sig = signer
        .key
        .sign(&signer.rng, signing_input.as_bytes())
        .map_err(|_| anyhow::anyhow!("署名に失敗"))?;
    Ok(format!("{signing_input}.{}", URL_SAFE_NO_PAD.encode(sig.as_ref())))
}
```

ヘッダとペイロードをそれぞれ Base64url にして `.` でつないだ署名入力に署名し、
署名を Base64url にして後ろに付けます。[7章](/oidc/07-jwt-jose/)で読んだ JWS
コンパクトシリアライゼーションの手順そのものです。`typ` を引数にしているのは、
IDトークン(`JWT`)とアクセストークン(`at+jwt`)で値を変えるためです。

秘密鍵はプロセスのメモリにだけ存在し、ファイルに書き出されず、JWKS にも含まれません。
このため mini-op を再起動すると鍵が変わります。再起動の前に発行したトークンの扱いは、
検証する側によって異なります。

- mini-op 自身の UserInfo エンドポイントは、現在の鍵だけで検証するので、
  再起動の前に発行したアクセストークンを拒否します
- resource-server は、キャッシュした旧鍵を持っている間は、期限内の旧トークンを受理し続けます。
  新しい `kid` のトークンを受け取って JWKS を取り直した時点で、キャッシュが新鍵だけに
  置き換わり、旧トークンは拒否されるようになります([10章](/rust-impl/10-discovery-jwks/)の JWKS のキャッシュ)
- rp は起動時に取得した JWKS を持ち続けるので、新しい鍵で署名された IDトークンを検証できず、
  rp を再起動するまで新しいログインに失敗します

鍵の保管とローテーションは、本物の OP が追加でしていることの1つです。

## 認可エンドポイント: パラメータ検証の順序

`GET /authorize` は、認可リクエストを検証してからログイン画面を表示します
(`examples/mini-op/src/authorize.rs`)。

```rust
pub async fn show_login(
    State(state): State<Shared>,
    Query(pairs): Query<Vec<(String, String)>>,
) -> Response {
    let Some(params) = single_valued(pairs) else {
        return error_page("同じパラメータが複数回含まれています");
    };
    let get = |k: &str| params.get(k).map(String::as_str).unwrap_or("");

    // 1. client_id と redirect_uri を確かめるまでは、エラーでもリダイレクトしない
    let Some(client) = find_client(&state, get("client_id")) else {
        return error_page("client_id が不正です");
    };
    let redirect_uri = get("redirect_uri");
    if !client.redirect_uris.contains(&redirect_uri) {
        return error_page("redirect_uri が登録値と一致しません");
    }

    // 2. ここから先のエラーは redirect_uri へ返してよい
    // (fail の定義は省略。error、error_description、state、iss を付けて 303 で返す)
    // mini-op はリクエストオブジェクトに対応しないので、外側のパラメータだけで処理せずに拒否する(Core 6.1、6.2)
    if params.contains_key("request") {
        return fail("request_not_supported", "request parameter is not supported");
    }
    if params.contains_key("request_uri") {
        return fail("request_uri_not_supported", "request_uri parameter is not supported");
    }
    if get("response_type") != "code" {
        return fail("unsupported_response_type", "response_type=code only");
    }
    let scope = get("scope");
    if !scope.split(' ').any(|s| s == "openid") {
        return fail("invalid_scope", "openid scope is required");
    }
    if get("code_challenge").is_empty() || get("code_challenge_method") != "S256" {
        return fail("invalid_request", "PKCE with S256 is required");
    }
    if get("nonce").is_empty() {
        return fail("invalid_request", "nonce is required");
    }
    // mini-op は OP 側のログインセッションを持たないので、画面を出さずに認証することはできない
    if get("prompt").split(' ').any(|p| p == "none") {
        return fail("login_required", "mini-op has no login session");
    }
    // (検証済みのリクエストを保存してログイン画面を返す処理は次節)
}
```

検証は3つの段階に分かれています。

**1. 同じパラメータの重複を拒否します**。クエリを `HashMap` ではなく `Vec<(String, String)>` で
受け取っているのはこのためです。RFC 6749 の3.1節は
「Request and response parameters MUST NOT be included more than once.」と定めています。
リクエストとレスポンスのパラメータを2回以上含めてはなりません(MUST NOT)。
重複を許すと、OP の中の部品ごとに先の値と後の値のどちらを使うかが異なる可能性があり、
検証した値と使う値が食い違います。mini-op は重複を見つけた時点で、`redirect_uri` も
信用できないものとしてエラー画面を出します。

**2. `client_id` と `redirect_uri` を確かめます**。この段階で失敗したら、
エラーをリダイレクトで返さずに、OP の画面にエラーを表示します。[3章](/web-auth/03-authorization-code/)で
読んだ RFC 6749 の4.1.2.1節は、`redirect_uri` が欠けている、不正である、一致しない場合や、
`client_id` が欠けているか不正である場合に、OP がその `redirect_uri` へ自動でリダイレクトしては
ならない(MUST NOT)と定めています。検証していない `redirect_uri` へリダイレクトすると、
OP が、攻撃者の指定した任意の URL へユーザーを送るために使われます。この問題は
オープンリダイレクタとして[22章](/security/22-threats/)で扱います。

`redirect_uri` の比較は、登録値との完全一致です(`contains` は `Vec` の要素と文字列として
等しいかを調べます)。前方一致やホスト名だけの比較にすると、登録値の後ろに文字を足した
URL や、別のパスを指す URL を受理してしまいます。RFC 9700 の4.1節は、リダイレクト URI の
比較を完全一致で行うことを求めています([22章](/security/22-threats/))。

**3. 残りのパラメータを確かめます**。`redirect_uri` が登録値と一致したので、ここから先の
エラーはクライアントに返してかまいません。`fail` は `error`、`error_description`、`state`、`iss` を
`redirect_uri` のクエリに付けて `303` で返します。mini-op が要求する条件は次のとおりです。

- `request` と `request_uri` がないこと。2つは、認可リクエストのパラメータを JWT
  ([17章](/oauth-deep/17-request-protection/)のリクエストオブジェクト)にまとめて送るための
  パラメータです。OpenID Connect Core 1.0 の6.1節と6.2節は、対応していない OP がこれらを
  受け取ったら、それぞれ `request_not_supported` と `request_uri_not_supported` のエラーを
  返さなければならない(MUST)と定めています。`request_not_supported` は OP が `request`
  パラメータに、`request_uri_not_supported` は OP が `request_uri` パラメータに対応していない
  ことを表す、認可エラーのエラーコードです(3.1.2.6節)。リクエストオブジェクトの中の値は
  外側のパラメータより優先されます。このため、リクエストオブジェクトを
  無視して外側のパラメータだけで処理すると、RP が意図したものと異なる要求を認可することになります。
  Discovery では `request_uri_parameter_supported` の省略時の値が `true` なので、
  mini-op はメタデータに `false` を明示しています([10章](/rust-impl/10-discovery-jwks/))
- `response_type` が `code` であること。それ以外は `unsupported_response_type` です
- `scope` に `openid` が含まれること。OpenID Connect Core 1.0 の3.1.2.2節は、
  `openid` を含まない要求は OAuth 2.0 の要求としては正しいかもしれないが OpenID Connect の
  要求ではない、と書いています。mini-op は OpenID Connect の要求しか扱わないので `invalid_scope` にします
- PKCE の `code_challenge` があり、`code_challenge_method` が `S256` であること。
  次の「RFCを読む」の節で理由を読みます
- `nonce` があること。OpenID Connect Core 1.0 の3.1.2.1節は、認可コードフローの `nonce` を
  OPTIONAL としています。mini-op はこれを必須にしており、仕様より厳しい OP です
- `prompt` に `none` が含まれないこと。`prompt=none` は、OP が画面を出さずに処理できる場合だけ
  成功させる指定です([18章](/oidc-deep/18-claims-identity/))。mini-op は OP 側の
  ログインセッションを持たず、毎回ログイン画面を出す必要があるので、エラーコード
  `login_required` を返します。`login_required` は3.1.2.6節が定めるエラーで、`prompt=none` の
  要求をエンドユーザーの認証なしには完了できないことを表します

## RFCを読む: RFC 9700 2.1.1節

PKCE を認可サーバの側で必須にする根拠は、OAuth 2.0 のセキュリティ BCP である
RFC 9700 の2.1.1節にあります。[9章](/oidc/09-state-nonce-pkce/)では、クライアントが PKCE を
使う理由を読みました。ここでは、同じ節のうち認可サーバに向けた文を読みます。

> Authorization servers MUST support PKCE [RFC7636].
>
> If a client sends a valid PKCE code_challenge parameter in the authorization request, the authorization server MUST enforce the correct usage of code_verifier at the token endpoint.
>
> Authorization servers MUST mitigate PKCE downgrade attacks by ensuring that a token request containing a code_verifier parameter is accepted only if a code_challenge parameter was present in the authorization request; see Section 4.8.2 for details.

(RFC 9700 2.1.1節)

この節は、認可サーバが PKCE について満たすべき要求を3つ定めています。
1つ目に、認可サーバは PKCE に対応しなければなりません(MUST)。
2つ目に、認可リクエストに有効な `code_challenge` があったなら、トークンエンドポイントで
`code_verifier` が正しく使われていることを強制しなければなりません(MUST)。
3つ目に、PKCE のダウングレード攻撃を防がなければなりません(MUST)。
**PKCE ダウングレード攻撃**(PKCE downgrade attack)は、`code_challenge` を付けずに
認可リクエストを送らせ、PKCE の検証を省かせる攻撃です。認可サーバは、`code_verifier` を
含むトークンリクエストを、認可リクエストに `code_challenge` があった場合にだけ受け付けます。

同じ節は、クライアントについて、パブリッククライアントは PKCE を使わなければならず(MUST)、
機密クライアントにも PKCE を推奨する(RECOMMENDED)と書いています。機密クライアントは
代わりに `nonce` を使ってもかまいません(MAY)が、その場合は4.5.3.2節の追加の注意が必要です。
さらに、`code_challenge` の方式には、認可リクエストで `code_verifier` を露出しない方式を
使うべきであり(SHOULD)、現在そのような方式は S256 だけだ、と書いています。

mini-op は、この節が許す範囲のうち最も厳しい設定を選んでいます。すべてのクライアントに
PKCE を要求し、方式は S256 だけを受け付けます。すべての認可コードに `code_challenge` が
束縛されるので、トークンエンドポイントでは常に `code_verifier` を要求でき、
3つ目のダウングレード攻撃は成立しません。Discovery のメタデータの
`code_challenge_methods_supported` に `["S256"]` を含めているのは、同じ節が
PKCE への対応を検出できる手段を提供しなければならない(MUST)とし、
その手段としてこの項目を推奨しているためです。

## 実験: 認可リクエストの検証の順序

次のコードは、mini-op の検証の順序を取り出したもので、8通りの認可リクエストに対して
「エラー画面を表示する」「エラーをリダイレクトで返す」「ログイン画面を表示する」の
どれになるかを表示します。

<RustPlay snippet="ch12/authorize-validate" title="認可リクエストの検証とリダイレクトの判断" />

出力の読み方は次のとおりです。

- 2件目は、未登録の `client_id` と攻撃者の `redirect_uri` の組です。リダイレクトせずに
  エラー画面を表示しています。もしここでエラーをリダイレクトで返すと、ユーザーは
  `evil.example` に送られます
- 3件目は、登録値 `https://rp.example.com/callback` の後ろに `/../../open-redirect` を
  足した URL です。前方一致なら受理されますが、完全一致なので拒否されます
- 4件目は `redirect_uri` を省いた要求です。RFC 6749 は登録済みの URI が1つなら
  省略を許しますが、OpenID Connect Core 1.0 の3.1.2.1節は `redirect_uri` を REQUIRED とし、
  事前に登録した値と RFC 3986 6.2.1節の単純な文字列比較で完全に一致しなければならない(MUST)と
  定めています。mini-op も省略を認めません
- 5件目から7件目は、`redirect_uri` が正しいので、エラーを `303` で RP に返しています。
  `state` も付いているので、RP はどのログイン操作の失敗かを判断できます
- 8件目は `state` が2つある要求です。重複の検査は最初に行うので、エラー画面になります

## ログイン画面と同意

認可リクエストの検証に成功すると、mini-op はその内容を `pending` に保存し、
保存のキーにした乱数(`request_id`)だけをログイン画面のフォームに埋め込みます。

```rust
    // request_id を、このブラウザだけが持つ Cookie の値に結びつける(ログインフォームの CSRF 対策)
    let request_id = random_token(&state.rng);
    let browser_binding = random_token(&state.rng);
    let stored = insert_bounded(
        &state.pending,
        request_id.clone(),
        PendingRequest {
            client_id: client.client_id.to_string(),
            redirect_uri: redirect_uri.to_string(),
            scope: scope.to_string(),
            state: st.to_string(),
            nonce: get("nonce").to_string(),
            code_challenge: get("code_challenge").to_string(),
            browser_binding: browser_binding.clone(),
            expires_at: now() + PENDING_TTL_SECS,
        },
        MAX_PENDING,
        |p| p.expires_at,
    );
    if !stored {
        return fail("temporarily_unavailable", "too many pending requests");
    }
    let mut res = login_form(&request_id, client.client_id, scope, "");
    let cookie = format!(
        "{BINDING_COOKIE}={browser_binding}; HttpOnly; SameSite=Strict; Path=/authorize; Max-Age={PENDING_TTL_SECS}"
    );
    res.headers_mut().insert(header::SET_COOKIE, HeaderValue::from_str(&cookie).expect("Base64url と固定の文字だけ"));
    res
```

認可リクエストのパラメータを hidden フィールドにすべて並べる方法もありますが、
その場合はフォームの送信(`POST /authorize`)のときに、すべてを最初から検証し直す必要があります。
攻撃者がフォームの値を書き換えた `POST` を直接送れるからです。サーバ側に保存して
キーだけを渡せば、`POST` で受け取った値は `request_id` だけになり、検証済みの値を
そのまま使えます。`request_id` は32バイトの乱数なので推測できず、
`POST` の処理で取り出すと同時に削除するので、1回しか使えません。
`pending` が上限に達している場合は、一時的に処理できないことを表すエラーコード
`temporarily_unavailable`([3章](/web-auth/03-authorization-code/)、RFC 6749 4.1.2.1節)を RP に返します。

`request_id` と一緒に、もう1つの32バイトの乱数 `browser_binding` を作ります。
この値は `pending` に保存し、同じ値を `mini_op_login` という Cookie でブラウザに渡します。
`POST /authorize` は、フォームの `request_id` で取り出した記録の `browser_binding` と、
ブラウザが送った Cookie の値を `constant_time_eq` で比べ、一致する場合だけ処理を続けます。この照合の理由は、
後の「仕様を読む: OpenID Connect Core 1.0 3.1.2.3節と3.1.2.4節」で説明します。
Cookie は `HttpOnly` で JavaScript から読めず、`SameSite=Strict` なので他のサイトを起点とする
要求には付きません。`Path=/authorize` で送り先を認可エンドポイントに限っています。

ログイン画面の応答には、`Set-Cookie` のほかに3つのヘッダを付けています。

```rust
            (header::CACHE_CONTROL, "no-store"),
            (header::X_FRAME_OPTIONS, "DENY"),
            (header::CONTENT_SECURITY_POLICY, "frame-ancestors 'none'"),
```

`Cache-Control: no-store` は、ログイン画面をブラウザや中継のキャッシュに残さないための指定です。
**X-Frame-Options ヘッダ**(X-Frame-Options header field)は、ページを他のページの
`frame` や `iframe` の中に表示してよいかを指定するレスポンスヘッダで、`DENY` は表示を禁じます。
`Content-Security-Policy` ヘッダ(CSP、[24章](/security/24-browser-native/))の
`frame-ancestors 'none'` も同じ意味の指定で、`frame-ancestors` に対応したブラウザは
こちらを優先し、対応していないブラウザは `X-Frame-Options` を使います。
ログイン画面を透明な `iframe` に重ね、ユーザーに気づかれずに「ログインして許可する」を
押させる攻撃(クリックジャッキング、[22章](/security/22-threats/))を、この2つの指定で防ぎます。
画面に表示する `client_id` と `scope` は、HTML の特殊文字をエスケープしてから埋め込んでいます。
`scope` は認可リクエストのクエリから来た値であり、エスケープしないと攻撃者がスクリプトを埋め込めます。

## 仕様を読む: OpenID Connect Core 1.0 3.1.2.3節と3.1.2.4節

ログイン画面について、OpenID Connect Core 1.0 の3.1.2.3節は次のように定めています。

> The methods used by the Authorization Server to Authenticate the End-User (e.g., username and password, session cookies, etc.) are beyond the scope of this specification. [...] When interacting with the End-User, the Authorization Server MUST employ appropriate measures against Cross-Site Request Forgery and Clickjacking as, described in Sections 10.12 and 10.13 of OAuth 2.0 [RFC6749].

(OpenID Connect Core 1.0 3.1.2.3節)

この節は、OP がエンドユーザーを認証する段階を定めています。認証の方法
(ユーザー名とパスワード、セッションCookieなど)は、この仕様の範囲外です。
一方で、エンドユーザーと対話するときは、RFC 6749 の10.12節と10.13節にある
CSRF とクリックジャッキングへの適切な対策を取らなければなりません(MUST)。

mini-op の対策を対応させると次のとおりです。

- CSRF: ログインフォームの `POST` は、`request_id` が、同じブラウザに `mini_op_login` の
  Cookie で渡した値と結びついている場合だけ受け付けます
- クリックジャッキング: 前節の `X-Frame-Options` と `frame-ancestors` です

`request_id` が推測できない値であることだけでは、CSRF の対策になりません。
`GET /authorize` は誰でも呼べるので、攻撃者は自分のブラウザで認可リクエストを始めて、
有効な `request_id` を取得できます。そのうえで、その `request_id` を含むフォームを
被害者のブラウザに送信させると、`request_id` だけを確かめる OP は、攻撃者が始めた
認可リクエストを被害者のブラウザからの送信として処理します。mini-op はこの送信に
パスワードを要求します。一方、OP 側のログインセッションを持つ OP が同意の送信を同じ形で
受け付けると、被害者が気づかないうちに、攻撃者の認可リクエストへの同意が成立します。

RFC 6749 の10.12節は、認可サーバに対して次のように定めています。

> The authorization server MUST implement CSRF protection for its authorization endpoint and ensure that a malicious client cannot obtain authorization without the awareness and explicit consent of the resource owner.

(RFC 6749 10.12節)

認可サーバは認可エンドポイントに CSRF の対策を実装し、悪意のあるクライアントが
リソースオーナーの認識と明示的な同意なしに認可を得られないようにしなければなりません(MUST)。
mini-op の `browser_binding` は、認可リクエストを始めたブラウザと、フォームを送信した
ブラウザが同じであることを確かめます。攻撃者のブラウザで発行された `request_id` には
攻撃者の Cookie の値が結びついており、被害者のブラウザが送る Cookie とは一致しません。
flow-test の段12はこの攻撃を再現しています。

3.1.2.3節は同じ箇所で、`prompt` に `login` が含まれる場合は認証済みでも再認証しなければならず(MUST)、
`none` が含まれる場合はエンドユーザーと対話してはならない(MUST NOT)とも定めています。
mini-op は毎回ログイン画面を出すので前者は常に満たし、後者は前節のとおり
`login_required` を返して満たしています。

続く3.1.2.4節は、認証の後の段階を定めています。

> Once the End-User is authenticated, the Authorization Server MUST obtain an authorization decision before releasing information to the Relying Party.

(OpenID Connect Core 1.0 3.1.2.4節)

エンドユーザーを認証したら、OP は RP に情報を渡す前に認可の判断を得なければなりません(MUST)。
3.1.2.4節は続けて、その判断は何に同意しているかが明確な対話で得てもよく(MAY)、
事前の管理者による同意などの方法で確立してもよい、と書いています。

エンドユーザーが、RP に対して自分の情報へのアクセスを許すと意思表示することを
**同意**(consent)と呼びます。mini-op の画面は「demo-rp が次の範囲へのアクセスを求めています:
openid profile email api.read」と表示し、ボタンを「ログインして許可する」にしています。
認証と同意を1つの操作にまとめた簡略化であり、ユーザーがスコープの一部だけを拒否したり、
同意を後から取り消したりする機能はありません。

## 認可コードの発行

`POST /authorize` は、ユーザー名とパスワードを確かめて認可コードを発行します。

```rust
pub async fn submit_login(
    State(state): State<Shared>,
    headers: HeaderMap,
    Form(form): Form<LoginForm>,
) -> Response {
    let Some(req) = state.pending.lock().unwrap().remove(&form.request_id) else {
        return error_page("認可リクエストが見つかりません");
    };
    if req.expires_at < now() {
        return error_page("認可リクエストの期限が切れました");
    }
    let bound = cookie_value(&headers, BINDING_COOKIE)
        .is_some_and(|v| constant_time_eq(v.as_bytes(), req.browser_binding.as_bytes()));
    if !bound {
        println!("[mini-op] POST /authorize -> 400 (request_id が別のブラウザに発行されている)");
        return error_page("このブラウザで開始した認可リクエストではありません");
    }
    let user = state
        .users
        .iter()
        .find(|u| u.username == form.username && u.password == form.password);
    let Some(user) = user else {
        let (client_id, scope) = (req.client_id.clone(), req.scope.clone());
        if !insert_bounded(&state.pending, form.request_id.clone(), req, MAX_PENDING, |p| p.expires_at) {
            return error_page("認可リクエストを保存できません");
        }
        return login_form(&form.request_id, &client_id, &scope, "ユーザー名かパスワードが違います");
    };

    // 3. 認可コードを、クライアント・redirect_uri・PKCE・nonce に束縛して保存する
    let code = random_token(&state.rng);
    let auth_time = now();
    let stored = insert_bounded(
        &state.codes,
        code.clone(),
        CodeGrant {
            client_id: req.client_id,
            redirect_uri: req.redirect_uri.clone(),
            code_challenge: req.code_challenge,
            nonce: req.nonce,
            scope: req.scope,
            sub: user.sub.to_string(),
            auth_time,
            expires_at: auth_time + CODE_TTL_SECS,
        },
        MAX_CODES,
        |g| g.expires_at,
    );
    if !stored {
        return error_page("認可コードを発行できません。時間をおいてやり直してください");
    }
    // (redirect_uri に code、state、iss を付けて 303 で返す処理は省略)
}
```

パスワードを平文のまま比較しているのは、テストユーザーが1人だけのダミーだからです。
本物の OP はパスワードをパスワードハッシュで保存し、ハッシュの検証で比べます
([5章](/web-auth/05-crypto/))。パスワードを間違えた場合は、`pending` から取り出した
認可リクエストを同じ `request_id` で戻し、もう一度ログイン画面を表示します。
Cookie の照合はパスワードの照合より前に行います。Cookie の照合を経ていない送信でパスワードの
正誤を判定すると、攻撃者は被害者のブラウザを使ってパスワードを試せるからです。

認可コードは32バイトの乱数を Base64url にした43文字の値で、`codes` に次の値と一緒に保存します。

| フィールド | 束縛する理由 |
| --- | --- |
| `client_id` | 別のクライアントがコードを交換できないようにする |
| `redirect_uri` | 認可リクエストと異なる `redirect_uri` での交換を拒否する |
| `code_challenge` | `code_verifier` を知らない者が交換できないようにする(PKCE) |
| `nonce` | IDトークンに入れる値を、認可リクエストの値に固定する |
| `scope` / `sub` / `auth_time` | 発行するトークンの中身を、ユーザーが同意した内容に固定する |
| `expires_at` | 発行から60秒で無効にする |

このように、認可コードを発行した時点の文脈(どのクライアントの、どの `redirect_uri` への、
どの PKCE の、どのユーザーの要求か)をコードと一緒に保存し、交換のときに照合することを、
本書では **認可コードの束縛**(authorization code binding)と呼びます。認可コードは
ブラウザの URL に含まれて送られるので、漏洩する可能性があります。束縛があれば、漏洩したコードを
入手した者は、束縛された条件をすべて満たさない限りトークンを得られません。

`nonce` を束縛していることにも意味があります。トークンエンドポイントで発行する IDトークンの
`nonce` は、認可リクエストの `nonce` でなければなりません。保存しておかなければ、OP は
トークンエンドポイントでどの値を入れるべきかを決める手段がありません。OpenID Connect Core 1.0 の
15.5.1節は、IDトークンに入れる状態を認可コードの値そのものに符号化する実装と、
認可コードをデータベースのキーにする実装があると書いており、mini-op は後者です。

有効期限の60秒は、[3章](/web-auth/03-authorization-code/)で読んだ RFC 6749 4.1.2節の
「A maximum authorization code lifetime of 10 minutes is RECOMMENDED.」より短い値です。
正しい RP は認可コードを受け取った直後に交換するので、数十秒あれば足ります。

最後に `redirect_uri` に `code`、`state`、`iss` を付けて、`Redirect::to` で `303 See Other` を
返します。ステータスコードに `303` を使う理由は、次の RFC で読みます。

## RFCを読む: RFC 9700 4.12節

ログインフォームは `POST` で送られ、OP はその応答としてブラウザを RP へリダイレクトします。
このリダイレクトに使うステータスコードについて、RFC 9700 の4.12節は次のように書いています。

> When the status code 307 is used for redirection instead, the user agent will send the user's credentials via HTTP POST to the client.
>
> This discloses the sensitive credentials to the client. If the client is malicious, it can use the credentials to impersonate the user at the authorization server.

(RFC 9700 4.12節)

この節は、ログインフォームの `POST` に `307` でリダイレクトを返すと何が起きるかを述べています。
`307` は、ブラウザに同じメソッドと同じボディで要求を送り直させるステータスコードです。
OP がログインフォームの `POST` に `307` を返すと、ブラウザはユーザー名とパスワードを含む
ボディをそのまま RP へ `POST` します。悪意のある RP は、そのパスワードで OP に
ユーザーとしてログインできます。

同じ節の結論は次の段落です。

> Authorization servers that redirect a request that potentially contains the user's credentials therefore MUST NOT use the HTTP 307 status code for redirection. If an HTTP redirection (and not, for example, JavaScript) is used for such a request, the authorization server SHOULD use HTTP status code 303 (See Other).

(RFC 9700 4.12節)

ユーザーの資格情報を含みうる要求をリダイレクトする認可サーバは、`307` を使ってはなりません
(MUST NOT)。HTTP のリダイレクトを使うなら `303 See Other` を使うべきです(SHOULD)。
`303 See Other` は、[1章](/web-auth/01-http-auth/)で見たとおり、`Location` の URL を
`GET` で開き直すようブラウザに指示するステータスコードです。
4.12節は、HTTP の仕様の上で `POST` を `GET` に書き換えることを明確に強制するのは `303` だけであり、
RFC 6749 の例が使っている `302` でも、ブラウザが `POST` のまま送り直すことは
仕様上禁じられていない、と説明しています。

mini-op の `POST /authorize` は axum の `Redirect::to` を使っており、これは `303` を返します。
flow-test の出力でも、段3の応答は `303 See Other` でした。RP の `/callback` は `GET` で
呼ばれ、ボディは送られません。

## トークンエンドポイント

`POST /token` は、5つの段階で処理します(`examples/mini-op/src/token.rs`)。
重複したパラメータを `invalid_request` で拒否する処理は、認可エンドポイントと同じなので省略します。

### 1. クライアントを認証する

```rust
fn authenticate_client<'a>(state: &'a Shared, headers: &HeaderMap) -> Option<&'a Client> {
    let value = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    let encoded = value.strip_prefix("Basic ")?;
    let decoded = String::from_utf8(STANDARD.decode(encoded).ok()?).ok()?;
    let (raw_id, raw_secret) = decoded.split_once(':')?;
    // RFC 6749 2.3.1: Base64 の前に form-urlencode されているので戻す
    let (client_id, secret) = (form_decode(raw_id)?, form_decode(raw_secret)?);
    let client = find_client(state, &client_id)?;
    constant_time_eq(client.client_secret.as_bytes(), secret.as_bytes()).then_some(client)
}
```

`client_secret_basic` は、[1章](/web-auth/01-http-auth/)の Basic 認証の形式でクライアントIDと
シークレットを送る方式です。ただし RFC 6749 の2.3.1節は、Base64 にする前に
クライアントIDとシークレットを `application/x-www-form-urlencoded` で符号化すると定めており、
OP の側ではその逆の処理が必要です。この規定と実装の差は[13章](/oauth-deep/13-client-auth/)で扱います。

`form_decode` は、`:` で分けたクライアントIDとシークレットを、それぞれ1つの値として復号します。

```rust
fn form_decode(raw: &str) -> Option<String> {
    // 1つの値として復号する。& や = を区切りとして扱うと、その後ろの文字が失われる
    let plus_as_space = raw.replace('+', " ");
    percent_decode_str(&plus_as_space).decode_utf8().ok().map(|s| s.into_owned())
}
```

`+` を空白に戻してから `%XX` を復号する処理で、`&` や `=` は文字のまま残ります。
`v=` を前に付けてフォーム全体として解析する方法では、符号化されていない `&` が
パラメータの区切りとして扱われます。その場合、`demo-rp&x` というクライアントIDが
`demo-rp` に切り詰められ、別のクライアントとして認証される可能性があります。

シークレットの比較には、`main.rs` の `constant_time_eq` を使っています。

```rust
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}
```

`==` による比較は、最初に異なるバイトを見つけた時点で終わるため、比較にかかる時間から
一致した先頭の長さを推測される可能性があります([5章](/web-auth/05-crypto/)のタイミング攻撃)。
この関数は、全バイトの XOR の論理和を取ってから判定するので、途中で終わりません。
ただし、コンパイラの最適化がこの性質を保つ保証はありません。本物の OP では、
5章で使った subtle クレートのように、最適化への対策を施したライブラリを使います。

認証に失敗した場合、mini-op はエラーコード `invalid_client` を返します。`invalid_client` は、
クライアント認証に失敗したこと(未知のクライアント、認証情報がない、未対応の方式など)を表す
トークンエンドポイントのエラーコードです。ステータスコードは `401` で、
`WWW-Authenticate: Basic realm="mini-op"` を付けます。RFC 6749 の5.2節は、
`invalid_client` について次のように定めています。

> If the client attempted to authenticate via the "Authorization" request header field, the authorization server MUST respond with an HTTP 401 (Unauthorized) status code and include the "WWW-Authenticate" response header field matching the authentication scheme used by the client.

(RFC 6749 5.2節)

クライアントが `Authorization` ヘッダで認証しようとした場合、認可サーバは `401` を返し、
クライアントが使った認証方式に対応する `WWW-Authenticate` ヘッダを含めなければなりません(MUST)。

クライアント認証は、認可コードを取り出すより前に行います。認証に失敗した要求で
認可コードを消費すると、シークレットを知らない攻撃者が、漏洩した認可コードを
無効にできてしまうためです。

### 2. 認可コードを取り出して即座に消す

```rust
    // 2. 認可コードを取り出して即座に消す(2回目以降は見つからない)
    let code = get("code");
    let Some(grant) = state.codes.lock().unwrap().remove(code) else {
        return token_error(StatusCode::BAD_REQUEST, "invalid_grant", "unknown or already used code");
    };
```

`get` ではなく `remove` を使うことで、検証の結果にかかわらず、1つの認可コードで
トークンリクエストを処理するのは1回だけになります。認可コードが1回しか使えない性質を、
本書では **ワンタイム性**(one-time use)と呼びます。`Mutex` の中で取り出しと削除を
1つの操作として行うので、同じコードを持つ2つの要求が同時に届いても、
`Some` を得るのは片方だけです。

RFC 6749 の4.1.2節は、認可コードが2回以上使われた場合、認可サーバは要求を拒否しなければならず
(MUST)、そのコードに基づいて発行済みのトークンを可能なら失効させるべきだ(SHOULD)と
定めています。mini-op は拒否だけを行い、失効はさせていません。mini-op のアクセストークンは
自己完結した JWT で、resource-server は失効を問い合わせる手段を持たないからです。
失効の仕組みは[14章](/oauth-deep/14-token-validation/)で扱います。

### 3. 束縛した値と照合する

```rust
    // 3. コードに束縛した値と照合する
    if now() >= grant.expires_at {
        return token_error(StatusCode::BAD_REQUEST, "invalid_grant", "code expired");
    }
    if grant.client_id != client.client_id {
        return token_error(StatusCode::BAD_REQUEST, "invalid_grant", "code was issued to another client");
    }
    if grant.redirect_uri != get("redirect_uri") {
        return token_error(StatusCode::BAD_REQUEST, "invalid_grant", "redirect_uri mismatch");
    }
    let verifier = get("code_verifier");
    if !valid_verifier_syntax(verifier) {
        return token_error(StatusCode::BAD_REQUEST, "invalid_request", "code_verifier is missing or malformed");
    }
    if !constant_time_eq(pkce_s256(verifier).as_bytes(), grant.code_challenge.as_bytes()) {
        return token_error(StatusCode::BAD_REQUEST, "invalid_grant", "PKCE verification failed");
    }
```

照合に失敗したときのエラーコードは、ほとんどが `invalid_grant` です。RFC 6749 の5.2節は
`invalid_grant` を、認可コードが無効、期限切れ、失効済み、認可リクエストの `redirect_uri` と
一致しない、別のクライアントに発行された、という場合のエラーとして定めています。
PKCE の検証の失敗も `invalid_grant` にすることは、[9章](/oidc/09-state-nonce-pkce/)で読んだ
RFC 7636 の4.6節の規定です。

`valid_verifier_syntax` は、`code_verifier` が RFC 7636 の4.1節の構文
(`code-verifier = 43*128unreserved`)を満たすかを調べます。43文字から128文字で、
英数字と `-`、`.`、`_`、`~` だけからなる値です。構文の誤りは `invalid_request` として、
値の不一致(`invalid_grant`)と区別しています。

`pkce_s256` は `BASE64URL-ENCODE(SHA256(ASCII(code_verifier)))` を計算し、
保存しておいた `code_challenge` と定数時間で比べます。

### 4. トークンを発行する

```rust
    let iat = now();
    let exp = iat + TOKEN_TTL_SECS;
    let access_claims = json!({
        "iss": ISSUER, "sub": grant.sub, "aud": RESOURCE_ID, "client_id": client.client_id,
        "scope": grant.scope, "iat": iat, "exp": exp, "jti": random_token(&state.rng),
    });
    let Ok(access_token) = jwt::sign(&state.signer, "at+jwt", &access_claims) else {
        return token_error(StatusCode::INTERNAL_SERVER_ERROR, "server_error", "signing failed");
    };
    let id_claims = json!({
        "iss": ISSUER, "sub": grant.sub, "aud": client.client_id, "iat": iat, "exp": exp,
        "auth_time": grant.auth_time, "nonce": grant.nonce,
        "at_hash": jwt::at_hash(&access_token),
    });
    let Ok(id_token) = jwt::sign(&state.signer, "JWT", &id_claims) else {
        return token_error(StatusCode::INTERNAL_SERVER_ERROR, "server_error", "signing failed");
    };
```

アクセストークンは、RFC 9068 の JWT アクセストークンの形式です。必須のクレーム
(`iss`、`exp`、`aud`、`sub`、`client_id`、`iat`、`jti`)をすべて含め、ヘッダの `typ` を
`at+jwt` にしています。`aud` は resource-server の識別子 `http://127.0.0.1:4000` です。
RFC 9068 の形式と検証の規則は[14章](/oauth-deep/14-token-validation/)で読みます。

IDトークンの `aud` はクライアントID、`nonce` は認可コードに束縛した値です。
`at_hash` は、アクセストークンの SHA-256 の左半分を Base64url にした値です
([8章](/oidc/08-id-token-validation/))。

```rust
pub fn at_hash(access_token: &str) -> String {
    // ES256 は SHA-256 なので、ダイジェストの左半分(16バイト)を使う
    let digest = Sha256::digest(access_token.as_bytes());
    URL_SAFE_NO_PAD.encode(&digest[..16])
}
```

2つのトークンは同じ署名鍵で署名していますが、ヘッダの `typ` が異なります。
IDトークンは `JWT`、アクセストークンは `at+jwt` です。resource-server はアクセストークンの
`typ` が `at+jwt` であることを確かめるので、IDトークンをアクセストークンの代わりに送っても
受け付けません。鍵を分けなくてもトークンの種類を区別できるのは、この `typ` の検査のためです
([23章](/security/23-jwt-attacks/)の明示的型付け)。

### 5. 応答を返す

```rust
    (
        [(header::CACHE_CONTROL, "no-store"), (header::PRAGMA, "no-cache")],
        Json(json!({
            "access_token": access_token,
            "token_type": "Bearer",
            "expires_in": TOKEN_TTL_SECS,
            "scope": grant.scope,
            "id_token": id_token,
        })),
    )
        .into_response()
```

RFC 6749 の5.1節は、トークンや資格情報を含む応答に `Cache-Control: no-store` と
`Pragma: no-cache` を含めなければならない(MUST)と定めています([4章](/web-auth/04-tokens/))。
エラー応答にも `Cache-Control: no-store` を付けています。

## 仕様を読む: OpenID Connect Core 1.0 3.1.3.2節

トークンエンドポイントでの検証の手順は、OpenID Connect Core 1.0 の3.1.3.2節にまとまっています。

> The Authorization Server MUST validate the Token Request as follows:
> * Authenticate the Client if it was issued Client Credentials or if it uses another Client Authentication method, per Section 9.
> * Ensure the Authorization Code was issued to the authenticated Client.
> * Verify that the Authorization Code is valid.
> * If possible, verify that the Authorization Code has not been previously used.
> * Ensure that the redirect_uri parameter value is identical to the redirect_uri parameter value that was included in the initial Authorization Request. [...]
> * Verify that the Authorization Code used was issued in response to an OpenID Connect Authentication Request (so that an ID Token will be returned from the Token Endpoint).

(OpenID Connect Core 1.0 3.1.3.2節)

この節は、OP がトークンリクエストを検証する手順を定めており、次の6項目を行わなければなりません(MUST)。

1. クライアントクレデンシャルを発行したクライアントなら、クライアントを認証します
2. 認可コードが、認証したクライアントに発行されたものであることを確かめます
3. 認可コードが有効であることを確かめます
4. 可能なら、認可コードが以前に使われていないことを確かめます
5. `redirect_uri` が、最初の認可リクエストの `redirect_uri` と同一であることを確かめます
6. 認可コードが OpenID Connect の認証リクエストに対して発行されたものであること
   (トークンエンドポイントが IDトークンを返すべき要求であること)を確かめます

4つ目だけが「If possible」で始まっています。認可コードを状態として保存しない実装
(15.5.1節の、状態をコードの値に符号化する実装)では、使用済みかどうかを判定する手段が
ないためです。一方、RFC 6749 の4.1.2節は2回目の使用を拒否しなければならない(MUST)と
しているので、OAuth 2.0 の認可サーバとしては拒否が必須です。mini-op は認可コードを保存して
取り出すと同時に消すので、この項目を常に満たします。

mini-op の処理との対応は次のとおりです。

| 3.1.3.2節の項目 | mini-op の処理 |
| --- | --- |
| 1. クライアントの認証 | 段階1の `authenticate_client` |
| 2. 認証したクライアントへの発行か | 段階3の `grant.client_id != client.client_id` |
| 3. コードが有効か | 段階2の `remove` が `Some` を返すこと、段階3の `expires_at` |
| 4. 未使用か | 段階2の `remove` |
| 5. `redirect_uri` の同一性 | 段階3の `grant.redirect_uri != get("redirect_uri")` |
| 6. OpenID Connect の要求か | 認可エンドポイントで `openid` スコープを必須にしているので常に満たす |

PKCE の検証はこの一覧にありません。OpenID Connect Core 1.0(2014年)は PKCE の RFC 7636(2015年)より前に
発行されており、PKCE の検証は RFC 7636 の4.6節と、前に読んだ RFC 9700 の2.1.1節が求めているものです。

## 実験: 1回限りの認可コード

次のコードは、mini-op の認可コードのストアを取り出し、模擬的な時刻で7通りのトークンリクエストを
処理します。`code_verifier` には RFC 7636 付録B の値を使っています。

<RustPlay snippet="ch12/code-store" title="認可コードのワンタイム性と束縛の検証" />

出力の読み方は次のとおりです。

- 1件目の正しい要求だけが成功し、IDトークンに入れる `nonce` が認可リクエストの値になっています
- 2件目は1件目と同じコードの再送で、`remove` で消えているため「未知のコードか使用済み」です
- 3件目から5件目は、期限(61秒後)、クライアント、`redirect_uri` の束縛による拒否です
- 6件目は誤った `code_verifier` で、PKCE の検証に失敗しています
- 7件目は、6件目と同じコードを正しい `code_verifier` で直後に送った場合です。
  6件目の処理で照合の前にコードを消していたので、正しい値でも拒否されます
- 最後の行で、ストアに残ったコードが0個であることを確かめています

7件目の結果は、照合より先にコードを消すという設計の結果です。この設計では、
漏洩したコードを入手した攻撃者が誤った `code_verifier` で交換を試みると、
そのコードは正規の RP にとっても使えなくなります。正規の RP のログインは失敗しますが、
攻撃者もトークンを得られません。逆に照合に成功するまでコードを残す設計にすると、
攻撃者は同じコードに対して `code_verifier` を何度でも試せます。
mini-op は前者を選んでいます。

## UserInfoエンドポイント

`GET /userinfo` と `POST /userinfo` は同じハンドラで処理します。OpenID Connect Core 1.0 の
5.3節が両方のメソッドへの対応を必須(MUST)としているためです。
アクセストークンの検証とスコープに応じたクレームの選択は、[10章](/rust-impl/10-discovery-jwks/)の
「仕様を読む: OpenID Connect Core 1.0 5.3節」で読みました。

## 本物のOPが追加でしていること

mini-op は、認可コードフローが成り立つための最小限の処理だけを実装しています。
本物の OP は、これに加えて多くの処理をしています。主なものを、mini-op との対比で挙げます。

| 項目 | mini-op | 本物の OP | 扱う章 |
| --- | --- | --- | --- |
| 同意の管理 | ログインと同時に全スコープを許可 | ユーザー・クライアント・スコープごとに同意を保存し、確認と取り消しの画面を提供 | この章 |
| 認証の方法 | パスワード1つ | 多要素認証、パスキーなどを組み合わせ、認証の強さを `acr`・`amr` で伝える | [18章](/oidc-deep/18-claims-identity/)、[27章](/practice/27-ecosystem/) |
| OP のログインセッション | なし(毎回ログイン画面) | OP 側にセッションを持ち、`prompt`・`max_age` に従って再認証を判断する | [18章](/oidc-deep/18-claims-identity/) |
| 試行回数の制限 | なし | ログインとトークンエンドポイントにレート制限を設ける | [26章](/practice/26-operations/) |
| 記録 | 標準出力に数行 | 認証・同意・トークン発行を監査ログに記録する | [26章](/practice/26-operations/) |
| 署名鍵 | 起動ごとに生成し、メモリにだけ置く | 秘密鍵を安全な保管場所に置き、ローテーションの手順で入れ替える | [10章](/rust-impl/10-discovery-jwks/)、[26章](/practice/26-operations/) |
| 状態の保存 | プロセス内の `HashMap` | 複数のサーバで共有するストアに置き、認可コードの取り出しと削除を不可分な操作で行う | この章 |
| クライアントの登録 | コードに固定 | 管理画面や動的クライアント登録。シークレットはハッシュで保存 | [13章](/oauth-deep/13-client-auth/) |
| トークンの寿命の管理 | アクセストークン300秒のみ | リフレッシュトークン、失効、イントロスペクション | [14章](/oauth-deep/14-token-validation/)、[15章](/oauth-deep/15-refresh-tokens/) |
| ログアウト | なし | RP-Initiated Logout、Back-Channel Logout など | [21章](/oidc-deep/21-logout-session/) |
| 認可リクエストの保護 | なし | PAR、JAR、送信者制約トークン | [16章](/oauth-deep/16-sender-constrained/)、[17章](/oauth-deep/17-request-protection/) |
| 仕様への適合 | `RS256` を公開しない、`nonce` を必須にするなど独自の逸脱がある | 適合性テストで確認する | [25章](/security/25-high-security/) |

表のうち、この章で定義していない語をいくつか補足します。

同意の管理では、一度同意した RP に次回は同意画面を出さない、という処理が一般的です。
そのためには、どのユーザーがどのクライアントにどのスコープを許したかを保存しておく
必要があります。ユーザーが同意を取り消せる画面も必要で、取り消したときには、
そのクライアントに発行済みのリフレッシュトークンを失効させます。

**多要素認証**(multi-factor authentication、MFA)は、知っているもの(パスワード)、
持っているもの(スマートフォンやセキュリティキー)、本人の特徴(指紋など)のうち、
種類の異なる2つ以上の要素を組み合わせて認証する方法です。パスワードが漏洩しても、
もう1つの要素がなければログインできません。OP は、どの方法で認証したかを
IDトークンの `amr` クレームなどで RP に伝えます。

レート制限(rate limiting)は、一定時間内の要求の回数に上限を設けることです。mini-op のログイン画面は
パスワードを何度でも試せるので、総当たりの攻撃を防ぐ手段がありません。
監査ログ(audit log)は、誰がいつ何をしたかを後から調べられるように残す記録です。
どちらも[26章](/practice/26-operations/)で扱います。

状態の保存については、OP を複数のサーバで動かすと、`HashMap` に置いた認可コードを
別のサーバで交換できなくなります。共有のストアに置く場合も、取り出しと削除を
不可分に行わなければ、同じコードを2つのサーバが同時に交換できてしまい、ワンタイム性が失われます。
mini-op の `Mutex` の中の `remove` が保証していた性質を、分散したストアでも保つ必要があります。

## 手元での実行結果

3つのサーバの起動と flow-test の実行手順は、[11章](/rust-impl/11-build-rp/)の
「手元での実行結果」の節のとおりです。flow-test の後半(段8から段12)は、flow-test 自身が
RP や攻撃者の役をして、mini-op と resource-server に直接要求を送ります。
rp の内部で行われるため段4では見えなかったやり取りと、OP に対する攻撃の再現を、ここで観測します。
各段は期待するステータスコードとエラーコードを照合しており、一致しなければ終了コード1で終わります。

```text
== 8. RP → OP: POST /token (flow-test が RP の役をして直接送る)
  HTTP/1.1 200 OK
  content-type: application/json
  cache-control: no-store
  pragma: no-cache
  本文: token_type="Bearer" expires_in=300 scope="openid profile email api.read"
  access_token のヘッダ:     {"alg":"ES256","kid":"hroHSbcW1XY-YkEw...","typ":"at+jwt"}
  access_token のペイロード: {"aud":"http://127.0.0.1:4000","client_id":"demo-rp","exp":1792131056,"iat":1792130756,"iss":"http://127.0.0.1:9000","jti":"peGk0_wny40zNjpV...","scope":"openid profile email api.read","sub":"user-0001"}
  id_token のヘッダ:     {"alg":"ES256","kid":"hroHSbcW1XY-YkEw...","typ":"JWT"}
  id_token のペイロード: {"at_hash":"Yyx_Bn2JiVrHTHg5...","aud":"demo-rp","auth_time":1792130756,"exp":1792131056,"iat":1792130756,"iss":"http://127.0.0.1:9000","nonce":"flow-test-nonce","sub":"user-0001"}

== 9. 攻撃の再現: 同じ認可コードでもう一度 POST /token
  HTTP/1.1 400 Bad Request
  本文: {"error":"invalid_grant","error_description":"unknown or already used code"}

== 10. 攻撃の再現: 誤ったクライアントシークレット、誤った code_verifier
  HTTP/1.1 401 Unauthorized
  www-authenticate: Basic realm="mini-op"
  本文: {"error":"invalid_client","error_description":"client authentication failed"}
  HTTP/1.1 400 Bad Request
  本文: {"error":"invalid_grant","error_description":"PKCE verification failed"}

== 11. RP → リソースサーバ: アクセストークンの有無と種類を変えて GET /api/me
  -- トークンなし
  HTTP/1.1 401 Unauthorized
  www-authenticate: Bearer realm="resource-server"
  -- IDトークンを Bearer として送る
  HTTP/1.1 401 Unauthorized
  www-authenticate: Bearer realm="resource-server", error="invalid_token", error_description="typ must be at+jwt"
  -- ペイロードを1文字改ざんしたアクセストークン
  HTTP/1.1 401 Unauthorized
  www-authenticate: Bearer realm="resource-server", error="invalid_token", error_description="signature verification failed"
  -- 正しいアクセストークン
  HTTP/1.1 200 OK
  本文: {"client_id":"demo-rp","message":"保護されたリソースにアクセスしました","scope":"openid profile email api.read","sub":"user-0001"}

== 12. 攻撃の再現: 攻撃者のブラウザで発行された request_id を被害者のブラウザから POST /authorize
  HTTP/1.1 400 Bad Request
  本文: mini-op 認可リクエストのエラー このブラウザで開始した認可リクエストではありません

すべての段が完了しました
```

`kid`、`jti`、`at_hash`、時刻の値は実行ごとに変わります。各段の読み方は次のとおりです。

- 段8は正しいトークンリクエストの応答です。`Cache-Control: no-store` と `Pragma: no-cache` が
  付いています。2つのトークンは同じ `kid` の鍵で署名され、`typ` だけが異なります。
  IDトークンの `nonce` は、flow-test が認可リクエストに付けた `flow-test-nonce` です。
  `exp` は `iat` の300秒後です
- 段9は、段8で使った認可コードの再送です。ワンタイム性によって `invalid_grant` になりました
- 段10の1つ目は、新しい認可コードを誤ったシークレットで交換しようとした結果で、
  `401` と `WWW-Authenticate: Basic` が返っています(RFC 6749 5.2節)。
  クライアント認証はコードを取り出す前に行うので、このコードはまだ有効です。
  2つ目は、そのコードを正しいシークレットと誤った `code_verifier` で交換しようとした結果で、
  PKCE の検証で `invalid_grant` になりました
- 段11は resource-server の検証です。トークンがない要求には `error` を含まない
  `WWW-Authenticate` を返しています(RFC 6750 3.1節、[4章](/web-auth/04-tokens/))。
  IDトークンは `typ` の検査で、1文字改ざんしたアクセストークンは署名の検証で拒否され、
  正しいアクセストークンだけが `200` になりました
- 段12は、ログインフォームへの CSRF の再現です。攻撃者のクライアントで `GET /authorize` を送って
  `request_id` を得て、`mini_op_login` の Cookie を別に持つ被害者のクライアントから、
  その `request_id` で `POST /authorize` を送っています。Cookie の値が `request_id` に
  結びついた値と一致しないので、mini-op は認可コードを発行せずにエラー画面を返しました

このときの mini-op の出力は次のとおりです。11章の rp のログイン1回分に続けて、
flow-test の後半の2回分の認可コードの発行、4回分のトークンリクエスト、
段12で拒否したログインフォームの送信が記録されています。

```text
[mini-op] 認可コードを発行 sub=user-0001 code=_Akabd1J...
[mini-op] POST /token client_id=demo-rp sub=user-0001 -> 200
[mini-op] POST /token client_id=demo-rp -> 400 invalid_grant (unknown or used code)
[mini-op] 認可コードを発行 sub=user-0001 code=8ZA1dfs8...
[mini-op] POST /token -> 401 invalid_client
[mini-op] POST /token client_id=demo-rp -> 400 invalid_grant (PKCE)
[mini-op] POST /authorize -> 400 (request_id が別のブラウザに発行されている)
```

mini-op の出力には、認可コードの先頭8文字だけを表示しています。認可コードやトークンの全体を
ログに書くと、ログを読める者がそれを使えるようになるためです。

認可エンドポイントのエラーの扱いは、`curl` で確かめられます。

```sh
curl -s -i 'http://127.0.0.1:9000/authorize?client_id=demo-rp&redirect_uri=http://127.0.0.1:3000/callback/evil&response_type=code'
curl -s -i 'http://127.0.0.1:9000/authorize?client_id=demo-rp&redirect_uri=http://127.0.0.1:3000/callback&response_type=code&scope=openid&state=xyz'
curl -s -i 'http://127.0.0.1:9000/authorize?client_id=demo-rp&redirect_uri=http://127.0.0.1:3000/callback&response_type=code&scope=openid&state=xyz&request_uri=https://rp.example/request.jwt'
```

1つ目は登録されていない `redirect_uri` で、リダイレクトせずにエラー画面を返します。
2つ目は `redirect_uri` が正しく PKCE がない要求で、エラーを RP に返します。
3つ目は `request_uri` を含む要求で、`request_uri_not_supported` を RP に返します。
手元での応答の先頭は次のとおりです。

```http
HTTP/1.1 400 Bad Request
content-type: text/html; charset=utf-8
cache-control: no-store
```

```http
HTTP/1.1 303 See Other
location: http://127.0.0.1:3000/callback?error=invalid_request&error_description=PKCE+with+S256+is+required&state=xyz&iss=http%3A%2F%2F127.0.0.1%3A9000
```

```http
HTTP/1.1 303 See Other
location: http://127.0.0.1:3000/callback?error=request_uri_not_supported&error_description=request_uri+parameter+is+not+supported&state=xyz&iss=http%3A%2F%2F127.0.0.1%3A9000
```

確認が終わったら、3つのサーバを Ctrl+C で停止してください。

## まとめ

- mini-op は、登録済みのクライアントとユーザー、検証済みの認可リクエスト、発行済みの認可コードを
  状態として持ち、起動時に生成した ES256 署名鍵で IDトークンとアクセストークンに署名します
- 認可リクエストは、重複の検査、`client_id` と `redirect_uri` の完全一致、残りのパラメータの順に
  検証します。`redirect_uri` を確かめるまではエラーでもリダイレクトしません
- PKCE は S256 だけを全クライアントに要求します。RFC 9700 2.1.1節は、認可サーバに PKCE への対応と
  ダウングレード攻撃の防止を求めています
- ログイン画面には CSRF とクリックジャッキングへの対策が必須です(Core 3.1.2.3節)。
  mini-op は `request_id` をブラウザの Cookie に結びつけ、別のブラウザからの送信を拒否します。
  ログインフォームの `POST` へのリダイレクトには `303` を使い、`307` を使いません(RFC 9700 4.12節)
- 対応しない `request` と `request_uri` はエラーで返し、Discovery にも `false` を明示します。
  保留中の認可リクエストと認可コードは、追加のたびに期限切れを削除し、件数に上限を置きます
- 認可コードは60秒で失効し、クライアント・`redirect_uri`・`code_challenge`・`nonce` に束縛し、
  照合より先に取り出して消すことで1回しか使えなくします
- トークンエンドポイントは、クライアント認証、コードの取り出し、束縛の照合、PKCE の検証の順に処理し、
  失敗はほとんどが `invalid_grant` です(Core 3.1.3.2節)
- 本物の OP は、同意の管理、多要素認証、レート制限、監査ログ、鍵の保管とローテーション、
  共有ストアでのワンタイム性の維持などを、mini-op に加えて行っています

Part III では、RP と OP を自分で書き、メッセージを1つずつ観測しました。
次章から始まる応用編では、ここで簡略化した部分を順に詳しく扱います。
最初の[13章](/oauth-deep/13-client-auth/)では、トークンエンドポイントで行ったクライアント認証の
方式を比較します。
