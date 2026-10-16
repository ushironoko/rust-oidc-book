---
title: RPを作る
description: openidconnect クレート、axum、tower-sessions で書いた RP(examples/rp)を読む。型状態パターンによるクライアントの型、state・nonce・PKCE のセッション保存、コールバックでの検証の順序、セッションIDの再発行とCookieの属性、3つのサーバを起動して flow-test で全体を動かす手順と実行結果。
sidebar:
  label: 11. RPを作る
---

この章でわかること:

- openidconnect クレートの主要な型と、エンドポイントの設定状態を型で表す型状態パターン
- ログイン開始時に state・nonce・PKCE をサーバ側に保存し、コールバックで1回だけ取り出す実装
- コールバックで行う検証の順序(state の照合、コードの交換、IDトークンの検証、UserInfo の取得)
- ログイン成功時にセッションIDを再発行する理由と、セッションCookieの属性の選び方
- mini-op・rp・resource-server を起動し、flow-test でログインから API 呼び出しまでを動かす手順と結果

## rpの構成

この章では、`examples/rp` を読みます。rp は、[6章](/oidc/06-oauth-to-oidc/)で見た
認可コードフローの OpenID Connect 版を、Web サーバとして実装した RP です。
rp は次の4つのクレートを組み合わせています。

- **openidconnect クレート**(openidconnect crate): OpenID Connect の RP 側の処理
  (Discovery、認可リクエストの組み立て、トークンリクエスト、IDトークンの検証、UserInfo の取得)を
  提供する Rust のライブラリです。OAuth 2.0 の部分は、同じ作者の oauth2 クレートを使って実装されています
- **axum**: HTTP サーバを書くための Web フレームワークです。URL のパスと、そのリクエストを
  処理する関数である **ハンドラ**(handler)を対応づけます。リクエストのクエリやヘッダを
  型付きの値として取り出す **エクストラクタ**(extractor)という仕組みも提供します
- **tokio**: Rust の非同期ランタイムです。axum と reqwest は tokio のランタイムで実行されます
- **tower-sessions**: axum のハンドラにセッションを提供する **ミドルウェア**(middleware)です。
  ミドルウェアは、ハンドラの前後に共通の処理を追加する仕組みです。tower-sessions は
  セッションIDを Cookie で送受信し、セッションの中身はサーバ側のストアに置きます

OP やリソースサーバへの要求には、**HTTP クライアント**(HTTP client)のクレートである
**reqwest** を使います。
HTTP クライアントは、サーバに HTTP リクエストを送って応答を受け取るライブラリで、
ブラウザが人の操作で行う通信をプログラムから行います。

rp のソースは3つのファイルに分かれています。

| ファイル | 内容 |
| --- | --- |
| `src/main.rs` | 定数、Discovery、クライアントの組み立て、セッションの設定、ルーティング |
| `src/handlers.rs` | `/`、`/login`、`/callback`、`/api-call`、`/logout` のハンドラと、ログイン操作中の値のストア |
| `src/error.rs` | エラーの型と、エラーを HTTP 応答に変換する処理、HTML のエスケープ |

rp が公開するパスと、それぞれの役割は次のとおりです。

| パス | 役割 |
| --- | --- |
| `GET /` | ログイン状態を表示します |
| `GET /login` | state・nonce・PKCE を作ってサーバ側に保存し、OP の認可エンドポイントへリダイレクトします |
| `GET /callback` | OP からの認可レスポンスを受け取り、検証してログインを完了します |
| `GET /api-call` | セッションに保存したアクセストークンで resource-server の API を呼びます |
| `GET /logout` | rp のセッションを破棄します |

`/callback` のように、OP がブラウザをリダイレクトさせて認可レスポンスを届ける先の
RP の処理を、本書では **コールバック**(callback)と呼びます。
[3章](/web-auth/03-authorization-code/)のリダイレクトエンドポイントを実装したハンドラのことです。

ログイン全体の流れを、rp の内部の処理も含めて次の図に示します。

```mermaid
sequenceDiagram
    participant ブラウザ
    participant RP
    participant OP
    ブラウザ->>RP: GET /login
    Note over RP: state, nonce, code_verifier を生成し<br/>サーバ側に保存
    RP-->>ブラウザ: 303 Location: OP の /authorize?...<br/>Set-Cookie: rp_session=A
    ブラウザ->>OP: GET /authorize?...
    OP-->>ブラウザ: ログイン画面
    ブラウザ->>OP: POST /authorize (ユーザー名とパスワード)
    OP-->>ブラウザ: 303 Location: RP の /callback?code&state&iss
    ブラウザ->>RP: GET /callback?code&state&iss<br/>Cookie: rp_session=A
    Note over RP: 1. 保存した値を取り出して state を照合
    RP->>OP: 2. POST /token (Basic 認証, code, code_verifier)
    OP-->>RP: access_token, id_token
    Note over RP: 3. IDトークンを検証 (署名, iss, aud, exp, nonce, at_hash)
    RP->>OP: 4. GET /userinfo (Bearer)
    OP-->>RP: sub, name, email
    Note over RP: 5. セッションIDを A から B に再発行して<br/>ログイン状態を保存
    RP-->>ブラウザ: 303 Location: /<br/>Set-Cookie: rp_session=B
```

番号を付けた5つの処理が、この章の中心です。

## openidconnectクレートの型

rp は起動時に1回だけ Discovery を実行し、その結果からクライアントを組み立てます
(`examples/rp/src/main.rs`)。

```rust
// 型引数は順に 認可/デバイス認可/イントロスペクション/失効/トークン/UserInfo の各エンドポイントの設定状態
pub type OidcClient = CoreClient<
    EndpointSet,
    EndpointNotSet,
    EndpointNotSet,
    EndpointNotSet,
    EndpointMaybeSet,
    EndpointMaybeSet,
>;
```

```rust
    let metadata = discover(&http).await?;
    let oidc = CoreClient::from_provider_metadata(
        metadata,
        ClientId::new(CLIENT_ID.to_string()),
        Some(ClientSecret::new(CLIENT_SECRET.to_string())),
    )
    .set_redirect_uri(RedirectUrl::new(REDIRECT_URI.to_string())?);
```

`discover` は `CoreProviderMetadata::discover_async` を呼ぶ関数で、mini-op がまだ起動していない
場合に備えて0.5秒間隔で最大20回まで再試行します。`discover_async` は
[10章](/rust-impl/10-discovery-jwks/)で読んだとおり、メタデータを取得して `issuer` の一致を
検証し、続けて `jwks_uri` から JWKS を取得します。

`OidcClient` の6つの型引数は、クライアントに設定されたエンドポイントを型で表しています。
openidconnect 4 は、エンドポイントの設定状態を3種類の型で区別します。

| 型 | 意味 |
| --- | --- |
| `EndpointSet` | 設定済み。そのエンドポイントを使うメソッドは失敗しない |
| `EndpointNotSet` | 未設定。そのエンドポイントを使うメソッドは呼べない(コンパイルエラー) |
| `EndpointMaybeSet` | 実行時まで不明。そのエンドポイントを使うメソッドは `Result` を返す |

`from_provider_metadata` は、認可エンドポイントを `EndpointSet` にします。Discovery 3節で
`authorization_endpoint` は REQUIRED なので、メタデータの解析に成功した時点で必ず存在するからです。
トークンエンドポイントと UserInfo エンドポイントは、メタデータで省略されうる項目なので
`EndpointMaybeSet` になります。このため rp のコードでは、`authorize_url` は値を直接返し、
`exchange_code` と `user_info` は `Result` を返します。デバイス認可などは使わないので
`EndpointNotSet` のままで、それらを使うメソッドを呼ぶとコンパイルエラーになります。

このように、値の状態を型引数で表し、状態によって呼べるメソッドを変える設計を
**型状態パターン**(typestate pattern)と呼びます。設定漏れのエンドポイントを使う誤りは
コンパイルエラーとして検出され、実行時のエラーにはなりません。

クライアントID以外の秘密の値は、`ClientSecret`、`CsrfToken`、`Nonce`、
`PkceCodeVerifier` のような専用の型で包まれています。これらの型の `Debug` の出力は
`ClientSecret([redacted])` のように値を伏せた形になり、ログやエラーメッセージに
誤って秘密の値を書き出すことを防ぎます。値を取り出すには `secret()` を明示的に呼びます。

## HTTPクライアントの設定: リダイレクトを追跡しない

rp は OP と通信する reqwest のクライアントを、リダイレクトを追跡しない設定で作っています。

```rust
    // リダイレクトを追跡すると SSRF の経路になるため、OP との通信では追跡しない
    let http = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(5))
        .build()?;
```

reqwest の既定の設定では、応答が 3xx のリダイレクトなら `Location` の URL へ
自動で要求を送り直します。openidconnect クレートの説明は、OP との通信でこの動作を
無効にするよう求めており、その理由を「Following redirects opens the client up to SSRF vulnerabilities.」
と書いています。

**SSRF**(server-side request forgery)は、攻撃者がサーバに任意の宛先へ HTTP リクエストを
送らせる攻撃です。サーバは、外部からは届かない社内のネットワークやクラウドの
管理用のアドレスに接続できることが多く、攻撃者はサーバを経由してそれらに到達しようとします。
RP が OP からのリダイレクトを追跡すると、OP の応答(あるいは OP になりすました応答)が
RP の要求の宛先を決められるようになります。Discovery、トークン、UserInfo の各要求は
本来リダイレクトを必要としないので、追跡しない設定にしても正しい OP との通信には影響しません。

## ログインを開始する: /login

`/login` のハンドラは、3つの値を作ってサーバ側に保存し、OP へリダイレクトします
(`examples/rp/src/handlers.rs`)。

```rust
pub async fn login(State(app): State<Shared>, session: Session) -> Result<Redirect, AppError> {
    let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();
    let (auth_url, csrf_state, nonce) = app
        .oidc
        .authorize_url(CoreAuthenticationFlow::AuthorizationCode, CsrfToken::new_random, Nonce::new_random)
        .add_scope(Scope::new("profile".to_string()))
        .add_scope(Scope::new("email".to_string()))
        .add_scope(Scope::new("api.read".to_string()))
        .set_pkce_challenge(pkce_challenge)
        .url();
    // nonce と code_verifier はサーバ側のストアに、state をキーにして保存する。セッションには state だけを置く
    let login = PendingLogin {
        nonce: nonce.secret().clone(),
        pkce_verifier: pkce_verifier.secret().clone(),
        created_at: Instant::now(),
    };
    if !store_pending(&app, csrf_state.secret().clone(), login) {
        return Err(AppError::TooManyPendingLogins);
    }
    session.insert(PENDING_KEY, csrf_state.secret()).await?;
    Ok(Redirect::to(auth_url.as_str()))
}
```

3つの値の役割は[9章](/oidc/09-state-nonce-pkce/)で読みました。ここでは実装上の要点を挙げます。

- `PkceCodeChallenge::new_random_sha256` は、32バイトの乱数から `code_verifier`
  (43文字)を作り、その S256 の `code_challenge` と組にして返します
- `CsrfToken::new_random` と `Nonce::new_random` は、どちらも16バイトの乱数を
  Base64url で符号化した22文字の値を作ります。`CsrfToken` は `state` に使う値の型です
- `authorize_url` は `openid` スコープを自動で加えます。`add_scope` で足したのは
  `profile`、`email` と、resource-server が要求する `api.read` です
- 3つの値はサーバ側に保存し、ブラウザには `state`、`nonce`、`code_challenge` だけが
  URL のクエリとして渡ります。`code_verifier` はブラウザに一度も渡りません

保存先は2か所に分かれています。`nonce` と `code_verifier` は、rp の `AppState` が持つ
`Mutex<HashMap<String, PendingLogin>>` に、`state` の値をキーにして保存します。
`store_pending` は、保存の前に作成から600秒を過ぎた記録を削除し、記録が1000件に達していれば
保存を断ります。ログインを始めたまま戻ってこないブラウザの記録が、メモリに際限なく
残らないようにするためです。

`state` の値はセッションに保存します。`session` は tower-sessions の `Session` 型の
エクストラクタで、`insert` で値を保存すると、応答に `Set-Cookie` が付きます。
Cookie の値はセッションIDだけで、セッションの中身はサーバ側の `MemoryStore` に置かれます。
セッションは、ログイン操作とそれを始めたブラウザを対応づけるために使います。
ストアを別にしている理由は、コールバックの段階1で説明します。

`Redirect::to` は `303 See Other` の応答を作ります。flow-test で観測した実際の応答は次のとおりです
(乱数の値は16文字で切り、`...` で省略しています)。

```http
HTTP/1.1 303 See Other
location: http://127.0.0.1:9000/authorize?response_type=code&client_id=demo-rp&state=ZdS9oyX309BNtfb4...&code_challenge=xQCfv0Kr3g-N1WXC...&code_challenge_method=S256&redirect_uri=http%3A%2F%2F127.0.0.1%3A3000%2Fcallback&scope=openid+profile+email+api.read&nonce=b4Hg3ZWGggiNYnfb...
set-cookie: rp_session=tfL4ETX3fZWpIc5I...; HttpOnly; SameSite=Lax; Path=/; Max-Age=1800
```

## 実験: 認可リクエストのURLを組み立てる

openidconnect クレートは Playground で使えないので、同じ URL を url クレートで組み立てて、
中身を確かめます。`code_verifier` には RFC 7636 付録B の値を使っているので、
`code_challenge` が付録B の `E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM` と一致するはずです。
続けて、コールバックの処理を3通りの入力で試します。

<RustPlay snippet="ch11/auth-url" title="認可リクエストのURLとコールバックの照合" />

出力の読み方は次のとおりです。

- URL の `redirect_uri` は `https%3A%2F%2F...` とパーセントエンコードされ、
  `scope` の空白は `+` になっています。これは `application/x-www-form-urlencoded` の
  規則による符号化で([3章](/web-auth/03-authorization-code/))、デコードすると
  2つ目の表示の値に戻ります
- `code_challenge` は RFC 7636 付録B の値と一致しています
- コールバックの1件目は、攻撃者が別の `state` で送った場合で、拒否されています。
  この失敗でセッションの記録も消えるため、2件目の前でログインをやり直しています
- 2件目は正しい認可レスポンスで、`code_verifier` と `nonce` を取り出せています
- 3件目は、2件目と同じ認可レスポンスの再送です。2件目の処理で記録を取り出して
  消したため、照合の相手がなく拒否されます
- 最後の乱数で生成した値は、実行ごとに変わります。16バイトの乱数は22文字、
  32バイトの乱数は43文字になります

## コールバックを処理する: /callback

`/callback` は rp の中で最も長いハンドラです。5つの段階に分けて読みます。

### 1. セッションから取り出してstateを照合する

```rust
    // 1. このブラウザの state でストアから取り出す。取り出しと削除は Mutex の中の1つの操作
    let expected_state: String = session.remove(PENDING_KEY).await?.ok_or(AppError::NoPendingLogin)?;
    let pending = take_pending(&app, &expected_state).ok_or(AppError::NoPendingLogin)?;
    if params.state.as_deref() != Some(expected_state.as_str()) {
        return Err(AppError::StateMismatch);
    }
    if params.iss.as_deref().is_some_and(|iss| iss != ISSUER) {
        return Err(AppError::IssuerMismatch);
    }
    if let Some(error) = params.error {
        let description = params.error_description.unwrap_or_default();
        return Err(AppError::AuthorizationDenied(format!("{error} {description}")));
    }
    let code = params.code.ok_or(AppError::MissingCode)?;
```

コールバックは、セッションから `state` を取り出し、その値をキーにして `take_pending` で
`nonce` と `code_verifier` を取り出します。`take_pending` は `Mutex` のロックを取得してから
`HashMap::remove` を呼ぶので、取り出しと削除は1つの操作になります。同じセッションCookieを
持つ2つのコールバックが同時に届いても、記録を得るのは片方だけで、もう片方は
`NoPendingLogin` になります。記録は照合より前に削除するので、この後の検証が成功しても
失敗しても、1つのログイン操作に対して認可レスポンスを受け付けるのは1回だけです。

セッションの `remove` だけでは、この性質は得られません。tower-sessions の `Session` は、
要求ごとにストアからセッションの中身を読み込んだ複製を持ち、`remove` はその複製から
値を消します。ストアへの書き戻しは応答を返すときに行われます。このため、同じセッションIDの
2つの要求が同時に処理されると、両方の複製に保存した値が残っており、両方が同じ
`code_verifier` を取り出せます。rp はセッションを、ブラウザとログイン操作を対応づける
用途だけに使い、1回限りの取り出しは `Mutex` で保護したストアで行っています。
rp を複数のプロセスで動かす場合は、このストアを、取り出しと削除を不可分に行える
共有のストアにする必要があります([12章](/rust-impl/12-build-op/)の「本物のOPが追加でしていること」)。

照合の順序にも理由があります。`state` の照合は、`error` パラメータを調べるより前に行います。
`state` が一致しない認可レスポンスは、この RP が始めたログイン操作に対する応答ではないので、
エラーであっても内容を信用しません。

`iss` パラメータは、mini-op が認可レスポンスに付けている RFC 9207 の拡張で、
どの OP がこの認可レスポンスを出したかを示します。複数の OP を使う RP で、
別の OP の認可レスポンスを取り違えさせる攻撃を防ぐためのものです
([17章](/oauth-deep/17-request-protection/)のミックスアップ攻撃)。
rp は OP が1つだけなので、値があれば issuer と一致することだけを確かめています。

### 2. 認可コードをトークンに交換する

```rust
    // 2. 認可コードをトークンに交換する(client_secret_basic + PKCE)
    let token_response = app
        .oidc
        .exchange_code(AuthorizationCode::new(code))
        .map_err(|e| AppError::TokenExchange(e.to_string()))?
        .set_pkce_verifier(PkceCodeVerifier::new(pending.pkce_verifier))
        .request_async(&app.http)
        .await
        .map_err(|e| AppError::TokenExchange(describe_token_error(&e)))?;
```

`exchange_code` が `Result` を返すのは、トークンエンドポイントの型が `EndpointMaybeSet` だからです。
このコードが送るトークンリクエストは次の形です(コードと `code_verifier` は省略しています)。

```http
POST /token HTTP/1.1
Host: 127.0.0.1:9000
Accept: application/json
Content-Type: application/x-www-form-urlencoded
Authorization: Basic ZGVtby1ycDpkZW1vLXJwLXNlY3JldC1ub3QtZm9yLXByb2R1Y3Rpb24=

grant_type=authorization_code&code=9FggYjMCtF_uy9D4...&code_verifier=...&redirect_uri=http%3A%2F%2F127.0.0.1%3A3000%2Fcallback
```

`Authorization` ヘッダの値は、クライアントIDとクライアントシークレットを `:` でつないで
Base64 で符号化したものです。この `client_secret_basic` という方式では、
Base64 の前にクライアントIDとシークレットを form-urlencode する規定があり
(RFC 6749 2.3.1節)、oauth2 クレートはこの規定に従っています。
方式の詳細と、実装によって符号化が異なる問題は[13章](/oauth-deep/13-client-auth/)で扱います。
mini-op の応答の形は、この章の最後の「手元での実行結果」で示します。

トークンリクエストのエラーは、`describe_token_error` で種類だけの文字列にしています。

```rust
// 応答の本文はトークンを含みうるので、エラーの種類だけを文字列にする
fn describe_token_error<RE, T>(e: &RequestTokenError<RE, T>) -> String
where
    RE: std::error::Error + 'static,
    T: openidconnect::ErrorResponse + std::fmt::Display + 'static,
{
    match e {
        RequestTokenError::ServerResponse(r) => format!("OP のエラー応答 {r}"),
        RequestTokenError::Request(_) => "通信に失敗しました".to_string(),
        RequestTokenError::Parse(_, _) => "応答を解析できません".to_string(),
        RequestTokenError::Other(_) => "予期しない応答です".to_string(),
    }
}
```

oauth2 クレートの `RequestTokenError::Parse` は、解析できなかった応答の本文をバイト列として
保持しています。OP が `200` で返した応答の解析に失敗した場合、その本文には
アクセストークンや IDトークンが入っています。エラーを `Debug` の形式(`{e:?}`)で
文字列にすると、このバイト列がエラーページとログに出力されます。
`ServerResponse` は OP が返したエラー応答で、`error` と `error_description` の値だけを含むので、
そのまま表示しています。UserInfo の取得のエラーも、同じ理由で `describe_userinfo_error` で
種類だけにしています(`UserInfoError::Response` も応答の本文を保持しています)。

### 3. IDトークンを検証する

```rust
    // 3. IDトークンを検証する(署名、iss、aud、exp、nonce)
    let id_token = token_response
        .id_token()
        .ok_or_else(|| AppError::IdToken("id_token がありません".to_string()))?;
    let verifier = app.oidc.id_token_verifier();
    let nonce = Nonce::new(pending.nonce);
    let claims = id_token
        .claims(&verifier, &nonce)
        .map_err(|e| AppError::IdToken(e.to_string()))?;
    if let Some(expected) = claims.access_token_hash() {
        let alg = id_token.signing_alg().map_err(|e| AppError::IdToken(e.to_string()))?;
        let key = id_token.signing_key(&verifier).map_err(|e| AppError::IdToken(e.to_string()))?;
        let actual = AccessTokenHash::from_token(token_response.access_token(), alg, key)
            .map_err(|e| AppError::IdToken(e.to_string()))?;
        if actual != *expected {
            return Err(AppError::IdToken("at_hash が一致しません".to_string()));
        }
    }
```

`id_token_verifier()` が返す検証器は、Discovery で得た JWKS、issuer、クライアントID、
`id_token_signing_alg_values_supported` の値を持っています。`claims` を呼ぶと、
[8章](/oidc/08-id-token-validation/)で読んだ OpenID Connect Core 1.0 3.1.3.7節の手順のうち、
次の項目を検証します。

- 署名: ヘッダの `alg` が許可リスト(メタデータの `id_token_signing_alg_values_supported`)に
  含まれ、`kid` に対応する JWKS の鍵で署名が正しいことを確かめます
- `iss`: issuer と完全一致することを確かめます
- `aud`: クライアントIDを含み、信頼しない他の audience を含まないことを確かめます
- `exp`: 現在時刻より後であることを確かめます
- `nonce`: セッションに保存した値と一致することを確かめます

openidconnect 4.0.1 の既定の検証には、2つの注意点があります。1つは、`exp` の比較に
許容誤差(leeway)を設けていないことです。OP と RP の時計がずれていると、
発行直後のトークンでも期限切れと判定されることがあります。もう1つは、`azp` クレームを
検証しないことです。クレームのソースには、仕様の記述が曖昧なため検証を保留している、
という説明があります。rp は単一の audience の IDトークンしか受け取らないので、
どちらも問題になりません。

`at_hash` は、IDトークンとアクセストークンの組を結びつける値です([8章](/oidc/08-id-token-validation/))。
`claims` は `at_hash` を検証しないので、rp は `AccessTokenHash::from_token` で計算した値と
比べています。mini-op は常に `at_hash` を入れているので、この比較は毎回実行されます。

### 4. UserInfoを取得する

```rust
    // 4. UserInfo を取得する。sub が IDトークンと一致しなければエラーになる
    let userinfo: CoreUserInfoClaims = app
        .oidc
        .user_info(token_response.access_token().clone(), Some(claims.subject().clone()))
        .map_err(|e| AppError::UserInfo(e.to_string()))?
        .request_async(&app.http)
        .await
        .map_err(|e| AppError::UserInfo(describe_userinfo_error(&e)))?;
```

`user_info` の2つ目の引数に、検証済みの IDトークンの `sub` を渡しています。
openidconnect は、UserInfo レスポンスの `sub` がこの値と一致しなければエラーを返します。
UserInfo レスポンスの `sub` を IDトークンの `sub` と照合しなければならない(MUST)という規定は、
[6章](/oidc/06-oauth-to-oidc/)で読んだ OpenID Connect Core 1.0 5.3.2節の NOTE です。
引数に `None` を渡すとこの照合は行われないので、`Some` を渡す必要があります。

### 5. セッションIDを再発行してログイン状態を保存する

```rust
    // 5. セッション ID を再発行してからログイン状態を保存する(セッション固定攻撃への対策)
    session.cycle_id().await?;
    session
        .insert(
            USER_KEY,
            LoggedInUser {
                iss: claims.issuer().to_string(),
                sub: claims.subject().to_string(),
                name: userinfo.name().and_then(|n| n.get(None)).map(|n| n.to_string()),
                email: userinfo.email().map(|e| e.to_string()),
                access_token: token_response.access_token().secret().clone(),
            },
        )
        .await?;
```

`cycle_id` は、ストアからこれまでのセッションIDの記録を削除し、同じ中身を新しい
セッションIDで保存し直します。応答には新しいIDの `Set-Cookie` が付きます。
この処理の理由は次の節で説明します。

ログイン状態として保存するのは、`iss` と `sub` の組、表示用の `name` と `email`、
API を呼ぶためのアクセストークンです。ユーザーを識別するキーは `iss` と `sub` の組であり、
`email` ではありません([18章](/oidc-deep/18-claims-identity/))。アクセストークンは
サーバ側のストアにだけ置き、ブラウザには渡しません。

## 仕様を読む: OpenID Connect Core 1.0 3.1.3.5節

コールバックの2と3の処理は、トークンレスポンスの検証にあたります。
OpenID Connect Core 1.0 は、その手順を3.1.3.5節にまとめています。

> The Client MUST validate the Token Response as follows:
> 1. Follow the validation rules in RFC 6749, especially those in Sections 5.1 and 10.12.
> 2. Follow the ID Token validation rules in Section 3.1.3.7.
> 3. Follow the Access Token validation rules in Section 3.1.3.8.

(OpenID Connect Core 1.0 3.1.3.5節)

この節は、クライアントがトークンレスポンスを検証する手順を定めており、
次の3つをすべて行わなければなりません(MUST)。1つ目は RFC 6749 の規則、特に5.1節
(成功時のトークンレスポンスの形、[4章](/web-auth/04-tokens/))と10.12節
(CSRF、[9章](/oidc/09-state-nonce-pkce/))に従うことです。2つ目は IDトークンの
検証規則(3.1.3.7節)、3つ目はアクセストークンの検証規則(3.1.3.8節、`at_hash` による照合)に
従うことです。

rp のコードとの対応は次のとおりです。

| 3.1.3.5節の項目 | rp の処理 |
| --- | --- |
| RFC 6749 5.1節 | oauth2 クレートがトークンレスポンスを解析し、`access_token` と `token_type` を必須として読む |
| RFC 6749 10.12節 | コールバックの段階1の `state` の照合 |
| 3.1.3.7節 | `id_token.claims(&verifier, &nonce)` |
| 3.1.3.8節 | `at_hash` の比較 |

3.1.3.5節は、10.12節の CSRF 対策をトークンレスポンスの検証の項目に含めています。
認可レスポンスの `state` を照合せずにコードを交換すると、得られたトークンレスポンスが
どれほど正しく検証できても、それは攻撃者が始めたログイン操作の結果かもしれません。
このため rp は、トークンリクエストを送る前に `state` を照合しています。

## セッション固定攻撃とセッションIDの再発行

**セッション固定攻撃**(session fixation)は、攻撃者が自分の知っているセッションIDを
被害者のブラウザに使わせる攻撃です。被害者がそのセッションでログインした後、
攻撃者は同じセッションIDを使って被害者として RP を操作します。手順は次のとおりです。

1. 攻撃者が RP にアクセスし、未ログインのセッションIDを得ます
2. 攻撃者はそのセッションIDを、被害者のブラウザの Cookie に設定させます。
   方法には、同じ親ドメインを持つ別のサブドメインから Cookie を設定する、
   セッションIDを URL で受け付ける RP に細工したリンクを開かせる、などがあります
3. 被害者がそのブラウザで RP にログインします
4. RP がセッションIDを変えずにログイン状態を保存すると、攻撃者が持っているセッションIDも
   ログイン済みのセッションを指すようになります

対策は、ログインが成功した時点でセッションIDを新しい値に取り替えることです。
攻撃者が知っているのはログイン前のIDだけなので、ログイン後のIDは知りません。
rp の `session.cycle_id()` はこの処理です。

rp は、ログイン開始時に `state` などを保存するためにセッションを必要とします。
このセッションはログインより前に作られるので、ログインの前後で同じセッションを使い続けると、上の手順4の状態になります。
OpenID Connect の RP はログイン前のセッションを必ず使うので、IDの再発行が必須です。

## 実験: セッションIDを再発行しない場合

次のコードは、サーバ側のセッションストアを `HashMap` で再現し、
セッションIDを再発行しない場合とする場合で、攻撃者が持っているIDがどうなるかを比べます。
セッションIDは本来 CSPRNG([5章](/web-auth/05-crypto/))で作る値ですが、出力を固定するために連番にしています。

<RustPlay snippet="ch11/session-fixation" title="セッション固定攻撃と再発行の効果" />

再発行しない場合は、被害者がログインした後、攻撃者のID `sid-0001` で見た状態が
「ログイン中 sub=victim-0001」になっています。攻撃者は被害者のアカウントで
RP を操作できます。再発行する場合は、被害者に新しいID `sid-0002` が渡り、
`sid-0001` はストアから削除されたので「セッションなし」になります。
ストアの中身を見ると、ログイン済みのセッションは `sid-0002` の1つだけです。

## Cookieの設定

セッションCookieの属性は、`main.rs` の `SessionManagerLayer` の設定で決めています。

```rust
    let sessions = SessionManagerLayer::new(MemoryStore::default())
        .with_name("rp_session")
        .with_http_only(true)
        .with_same_site(SameSite::Lax)
        .with_secure(false)
        .with_expiry(Expiry::OnInactivity(CookieDuration::minutes(30)));
```

この設定から、`Set-Cookie: rp_session=...; HttpOnly; SameSite=Lax; Path=/; Max-Age=1800` が
作られます。各属性の意味は[1章](/web-auth/01-http-auth/)で読みました。ここでは
RP に固有の判断を説明します。

- `HttpOnly`: JavaScript からセッションIDを読めなくします。rp のページは
  JavaScript を使わないので、外す理由がありません
- `Secure`: 手元の実行は http なので `false` にしています。https で運用する RP では
  `true` にしなければ、http の通信路でセッションIDが送信される可能性が残ります
- `SameSite=Lax`: 他のサイトからのトップレベルの `GET` による遷移には Cookie を付け、
  それ以外のサイト間の要求には付けません。理由は次の「RFCを読む」の節で説明します
- `Max-Age=1800` と `Expiry::OnInactivity`: セッションを最後に保存してから30分で失効します。
  tower-sessions の既定では、期限が延びるのはセッションの中身を変更して保存したときだけです。
  要求のたびに期限を延ばすには `with_always_save(true)` を加えます
- `MemoryStore`: セッションをプロセスのメモリに置きます。rp を再起動すると
  すべてのセッションが消え、複数のプロセスでセッションを共有できません。
  本番では外部のストア(データベースなど)を使います

## RFCを読む: RFC 10017 6.1.3.2節

RFC 10017(OAuth 2.0 for Browser-Based Applications、2026年8月)は、ブラウザで動く
アプリケーションのための BCP です。その中の6.1節は、ブラウザ側の JavaScript の代わりに
サーバ側のコンポーネントが OAuth のクライアントとして振る舞う構成を扱っています。
この構成の全体は[24章](/security/24-browser-native/)で扱います。
rp も、トークンをサーバ側に保持し、ブラウザとはセッションCookieだけでやり取りする点で、
この構成と同じ性質を持っています。原文の BFF(Backend for Frontend)は、この構成のサーバ側のコンポーネントを指す語で、
[24章](/security/24-browser-native/)で定義しています。
6.1.3.2節は、そのセッションCookieについての要求を挙げています。

> * The BFF MUST enable the Secure flag for its cookies.
> * The BFF MUST enable the HttpOnly flag for its cookies.
> * The BFF SHOULD enable the SameSite=Strict flag for its cookies.
> * The BFF SHOULD set its cookie path to /.
> * The BFF SHOULD NOT set the Domain attribute for cookies.
> * The BFF SHOULD start the name of its cookie with a prefix indicating the cookie was set via HTTP, for example, by using the __Host-Http- prefix defined in [COOKIES].

(RFC 10017 6.1.3.2節)

この節は、サーバ側でトークンを保持するコンポーネントがセッションCookieに設定すべき属性を
定めています。`Secure` と `HttpOnly` は有効にしなければならず(MUST)、
`SameSite=Strict` にすべきであり(SHOULD)、パスは `/` にすべきです(SHOULD)。
`Domain` 属性は設定すべきではなく(SHOULD NOT)、Cookie の名前は HTTP で設定された
ことを示す接頭辞(例えば `__Host-Http-`)で始めるべきです(SHOULD)。

rp の設定と比べると、次の3点が異なります。

- `Secure`: 手元の http での実行のために無効にしています。https で運用するなら
  この MUST に従って有効にします
- 名前の接頭辞: `__Host-` で始まる名前の Cookie は `Secure` 属性を必須とするため
  ([24章](/security/24-browser-native/))、http では使えません。https で運用するなら
  接頭辞を付けた名前にします
- `SameSite`: rp は `Lax` にしており、`Strict` にはしていません

`SameSite` の違いには、RP に固有の理由があります。`Strict` の Cookie は、
他のサイトを起点とする要求には、トップレベルの遷移であっても付きません。
OP から RP の `/callback` へのリダイレクトは、OP のサイトを起点とする遷移です。
OP と RP が別のサイトにあると、`Strict` のセッションCookieは `/callback` の要求に付きません。
rp は `/login` で保存した `state` を見つけられないため、ログインは毎回失敗します。

手元の実行では、OP(`127.0.0.1:9000`)と RP(`127.0.0.1:3000`)はポート番号だけが異なります。
Cookie の SameSite の判定はポート番号を区別しないため、2つは同じサイトとして扱われます。
このため手元では `Strict` にしてもログインが成功し、OP と RP が別のサイトにある環境で初めて失敗が現れます。

`Strict` を使いたい場合の方法としては、ログイン操作中の値だけを `Lax` の別の Cookie に
保存し、ログイン後のセッションCookieを `Strict` にする構成があります。
`/callback` で `Lax` の Cookie から `state` を取り出し、ログイン後のセッションは
`Strict` の Cookie で始めます。`Lax` の Cookie は、他のサイトを起点とする `POST` には
付かないので、ログイン後の状態を変える操作に対する CSRF の防御は `Strict` の Cookie と
大きくは変わりません。rp は構成を単純にするために1つの `Lax` の Cookie で済ませています。

## エラー処理

rp のエラーは、`error.rs` の1つの列挙型にまとめています。

```rust
#[derive(Debug, thiserror::Error)]
pub enum AppError {
    #[error("ログイン処理が開始されていないか、すでに使われました")]
    NoPendingLogin,
    #[error("state が一致しません")]
    StateMismatch,
    #[error("認可レスポンスの iss が一致しません")]
    IssuerMismatch,
    #[error("OP がエラーを返しました: {0}")]
    AuthorizationDenied(String),
    // (中略)
}
```

`thiserror` の `#[error]` 属性は、各バリアントの `Display` の実装を生成します。
`AppError` は axum の `IntoResponse` を実装しており、ハンドラが `Err(AppError::...)` を
返すと、バリアントに応じたステータスコード(ログインの検証の失敗は `400`、
OP や resource-server との通信の失敗は `502` など)とエラーページに変換されます。

エラー処理の規則は次の3つです。

- エラーメッセージにトークンや認可コードの値を含めません。IDトークンの検証エラーは
  openidconnect のエラーの説明文だけを使い、トークン本体は出しません。
  トークンリクエストと UserInfo のエラーは、応答の本文を含まない種類の文字列にします
- OP が返した `error` と `error_description` は、`state` の照合に成功した後でだけ表示します。
  照合の前に表示すると、攻撃者が作った認可レスポンスで任意の文言を
  RP の画面に出せてしまいます
- エラーページに埋め込む文字列は、すべて HTML の特殊文字をエスケープします。
  `error_description` は OP が決める値で、URL のクエリとして届くので、
  エスケープしないと `<script>` を含む値でスクリプトを実行させられます

3つ目の規則は `into_response` の中で、`error.rs` の `escape` を呼んで適用しています。

```rust
        // error_description など OP や攻撃者が決められる文字列を含むので、HTML として解釈させない
        let message = escape(&self.to_string());
        (status, Html(format!("<!doctype html><meta charset=\"utf-8\"><h1>エラー</h1><p>{message}</p>"))).into_response()
```

`state` が一致した状態で `error_description=<script>alert(1)</script>` を送ると、
エラーページの本文は `OP がエラーを返しました: access_denied &lt;script&gt;alert(1)&lt;/script&gt;` になり、
スクリプトとしては解釈されません。

本番の RP では、検証の失敗の詳細をユーザーに見せず、ログに記録するだけにするのが一般的です。
ログに何を記録してはいけないかは[26章](/practice/26-operations/)で扱います。

## APIを呼ぶ: /api-call

ログイン後、rp はセッションに保存したアクセストークンで resource-server を呼びます。

```rust
pub async fn api_call(State(app): State<Shared>, session: Session) -> Result<Response, AppError> {
    let user: LoggedInUser = session.get(USER_KEY).await?.ok_or(AppError::NotLoggedIn)?;
    let res = app.http.get(API_URL).bearer_auth(&user.access_token).send().await?;
    // (応答の表示は省略)
}
```

`bearer_auth` は `Authorization: Bearer <トークン>` のヘッダを付けます([4章](/web-auth/04-tokens/))。
rp はアクセストークンの中身を読みません。アクセストークンを検証するのは resource-server の
役割です。resource-server の検証は、`typ`・`iss`・`aud`・`exp`・`scope` を順に確かめる実装で
(`examples/resource-server/src/verify.rs`)、JWT アクセストークンの仕様である RFC 9068 とともに
[14章](/oauth-deep/14-token-validation/)で読みます。

アクセストークンの有効期限は mini-op の設定で300秒です。rp はリフレッシュトークンを
扱わないので、期限が切れたら再ログインが必要です。リフレッシュトークンは
[15章](/oauth-deep/15-refresh-tokens/)で扱います。

## 手元での実行結果

3つのサーバを起動し、flow-test でログインから API 呼び出しまでを実行します。
最初にワークスペース全体をビルドします。

```sh
cd examples
cargo build
```

次に、3つのサーバを別々の端末で起動します。rp と resource-server は起動時に
mini-op の Discovery を取得するので(取得できるまで最大10秒再試行します)、
mini-op を先に起動すると待ち時間がありません。

```sh
cargo run -p mini-op          # 端末1: 127.0.0.1:9000
cargo run -p resource-server  # 端末2: 127.0.0.1:4000
cargo run -p rp               # 端末3: 127.0.0.1:3000
```

最後に、4つ目の端末で flow-test を実行します。

```sh
cargo run -p flow-test
```

flow-test は reqwest で、Cookie の保存を有効にし、リダイレクトの自動追跡を無効にした
クライアントを作ります。リダイレクトを追跡しないことで、ブラウザが自動でたどる
各段の `303` と `Location` を1つずつ表示できます。ログインフォームの送信も
flow-test が行います。手元での実行結果の前半(ブラウザとして振る舞う段)は次のとおりです。

```text
== 1. ブラウザ → RP: GET /login
  HTTP/1.1 303 See Other
  location: http://127.0.0.1:9000/authorize?response_type=code&client_id=demo-rp&state=ZdS9oyX309BNtfb4...&code_challenge=xQCfv0Kr3g-N1WXC...&code_challenge_method=S256&redirect_uri=http%3A%2F%2F127.0.0.1%3A3000%2Fcallback&scope=openid+profile+email+api.read&nonce=b4Hg3ZWGggiNYnfb...
  set-cookie: rp_session=tfL4ETX3fZWpIc5I...; HttpOnly; SameSite=Lax; Path=/; Max-Age=1800
  認可リクエストのパラメータ:
    response_type = code
    client_id = demo-rp
    state = ZdS9oyX309BNtfb4D-yoVA
    code_challenge = xQCfv0Kr3g-N1WXCXgQG4gdt0cFnYDxMeOygqLJHamQ
    code_challenge_method = S256
    redirect_uri = http://127.0.0.1:3000/callback
    scope = openid profile email api.read
    nonce = b4Hg3ZWGggiNYnfbCfmW5g

== 2. ブラウザ → OP: GET /authorize (ログインフォームの表示)
  HTTP/1.1 200 OK
  content-type: text/html; charset=utf-8
  cache-control: no-store
  x-frame-options: DENY
  set-cookie: mini_op_login=_j7F89sG7QHsC44J...; HttpOnly; SameSite=Strict; Path=/authorize; Max-Age=600
  フォームの hidden: request_id = bRCHB73xQrkz0fEA...

== 3. ブラウザ → OP: POST /authorize (ユーザー名とパスワード)
  HTTP/1.1 303 See Other
  location: http://127.0.0.1:3000/callback?code=9FggYjMCtF_uy9D4...&state=ZdS9oyX309BNtfb4...&iss=http%3A%2F%2F127.0.0.1%3A9000
  認可レスポンスのパラメータ:
    code = 9FggYjMCtF_uy9D4...
    state = ZdS9oyX309BNtfb4...
    iss = http://127.0.0.1:9000

== 4. ブラウザ → RP: GET /callback (RP の裏で トークン交換・IDトークン検証・UserInfo)
  HTTP/1.1 303 See Other
  location: /
  set-cookie: rp_session=C25QD827BdI6E-B0...; HttpOnly; SameSite=Lax; Path=/; Max-Age=1800
  セッションIDの再発行: tfL4ETX3fZWpIc5I... → C25QD827BdI6E-B0... (変わった: true)

== 5. ブラウザ → RP: GET /
  HTTP/1.1 200 OK
  本文: rp ログイン中: iss=http://127.0.0.1:9000 sub=user-0001 name=Demo User email=demo@example.com API を呼ぶ ログアウト

== 6. ブラウザ → RP: GET /api-call (RP → リソースサーバ)
  HTTP/1.1 200 OK
  本文: API の応答 status=200 OK {"client_id":"demo-rp","message":"保護されたリソースにアクセスしました","scope":"openid profile email api.read","sub":"user-0001"}

== 7. 攻撃の再現: 同じ認可レスポンスをもう一度 RP に送る
  HTTP/1.1 400 Bad Request
  本文: エラー ログイン処理が開始されていないか、すでに使われました
```

`state`、`nonce`、`code_challenge`、認可コード、セッションIDは乱数なので、
値は実行ごとに変わります。各段の読み方は次のとおりです。

- 段1は `/login` の応答です。`Location` に認可リクエストのパラメータがそろい、
  `Set-Cookie` でログイン前のセッションID(`tfL4...`)が渡っています
- 段2と段3は mini-op とのやり取りで、OP の側の処理は[12章](/rust-impl/12-build-op/)で読みます。
  段2の `mini_op_login` の Cookie は、ログインフォームの送信をこのブラウザに結びつける値です。
  段3の `Location` の `state` は、段1で rp が送った値と同じです
- 段4で rp は、ブラウザから見えないところでトークンの交換、IDトークンの検証、
  UserInfo の取得を行い、`303` で `/` へ戻しています。`Set-Cookie` のセッションIDは
  `C25Q...` に変わっており、`cycle_id` によって再発行されています
- 段5の表示の `name` と `email` は UserInfo から、`iss` と `sub` は IDトークンから得た値です
- 段6は rp が resource-server を呼んだ結果で、resource-server がアクセストークンの
  `sub`、`client_id`、`scope` を返しています
- 段7は段3と同じ認可レスポンスの再送です。段4でセッションの `state` とストアの記録を
  取り出して消したため、rp は `400` で拒否しています。この段では mini-op にトークンリクエストを送っていません。
  認可コードの再利用を OP が拒否する様子は、flow-test の後半の段9で別に確かめます

このときの3つのサーバの出力は次のとおりです。mini-op と resource-server の出力は、
段1から段7に対応する部分だけを抜き出しています。署名鍵の `kid` は起動ごとに変わります。

```text
[mini-op] 署名鍵 kid=hroHSbcW1XY-YkEwD2SrtycBxo5cJKD0RN_1zenTnfw
[mini-op] listening on http://127.0.0.1:9000
[mini-op] 認可コードを発行 sub=user-0001 code=9FggYjMC...
[mini-op] POST /token client_id=demo-rp sub=user-0001 -> 200
[rp] listening on http://127.0.0.1:3000
[rp] ログイン成功 iss=http://127.0.0.1:9000 sub=user-0001
[rp] 400 Bad Request ログイン処理が開始されていないか、すでに使われました
[resource-server] jwks_uri=http://127.0.0.1:9000/jwks
[resource-server] listening on http://127.0.0.1:4000
[resource-server] JWKS を取得: kid=["hroHSbcW1XY-YkEwD2SrtycBxo5cJKD0RN_1zenTnfw"]
```

resource-server は、段6で最初のアクセストークンを受け取った時点で JWKS を取得しています。
起動時には Discovery で `jwks_uri` を得ただけで、鍵はまだ取得していません。
未知の `kid` を受け取ったときに取得する、という[10章](/rust-impl/10-discovery-jwks/)の規則が
最初の1回にも適用されています。

flow-test の後半(段8から段12)は、flow-test 自身が RP や攻撃者の役をして mini-op と
resource-server に直接要求を送り、トークンエンドポイントとリソースサーバのやり取りを表示します。
その結果は[12章](/rust-impl/12-build-op/)の「手元での実行結果」で読みます。

flow-test は、各段の応答を表示するだけでなく、期待する結果と照合します。照合する項目は、
ステータスコード、`Location` の宛先と `state`・`iss`、`Cache-Control` などのヘッダ、
エラー応答の `error` の値、`WWW-Authenticate` の内容です。攻撃を再現する段(段7、段9から段12)も、
期待どおりに拒否されたことを確かめます。1つでも一致しなければ、その場で
「ステータスが 200 OK ではなく 502 Bad Gateway」のようなエラーを表示し、終了コード1で終了します。
すべて一致すれば、最後に「すべての段が完了しました」と表示します。
確認が終わったら、3つのサーバを各端末で Ctrl+C で停止します。

## まとめ

- rp は openidconnect クレートで Discovery、認可リクエスト、トークン交換、IDトークン検証、
  UserInfo を行い、axum と tower-sessions で Web サーバとセッションを実装しています
- openidconnect 4 はエンドポイントの設定状態を型引数で表します(型状態パターン)。
  未設定のエンドポイントは呼べず、メタデータ次第のエンドポイントは `Result` を返します
- OP との通信ではリダイレクトを追跡しません。追跡すると SSRF の経路になります
- `state` はセッションに、`nonce`・`code_verifier` は `Mutex` で保護したストアに保存し、
  コールバックで取り出すと同時に削除して1回だけ使います。セッションの `remove` は
  要求ごとの複製を変えるだけなので、1回限りの取り出しには使えません。
  `state` の照合はトークンリクエストより前に行います
- エラーページの文字列は HTML のエスケープをしてから埋め込み、トークンを含みうる応答の本文は
  エラーメッセージに入れません
- IDトークンの検証は `claims` で行い、`at_hash` の照合と、UserInfo の `sub` の照合
  (期待する `sub` を渡す)は呼び出し側で指定します
- ログイン成功時にセッションIDを再発行します(セッション固定攻撃への対策)。
  セッションCookieは `HttpOnly`・`Secure`・`SameSite` を設定し、OP からの
  リダイレクトを受けるために `Lax` を使う理由を理解して選びます

次章では、相手側の mini-op を読みます。認可リクエストの検証の順序、認可コードの束縛と
1回限りの使用、トークンエンドポイントでのクライアント認証と PKCE の検証、
IDトークンへの署名を、OP の立場から実装します。
