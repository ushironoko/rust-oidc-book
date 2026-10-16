---
title: DiscoveryとJWKS
description: RP と リソースサーバ が OP の設定値と署名鍵を取得する仕組み。OpenID Connect Discovery 1.0 の well-known URI とメタデータ、issuer の完全一致検証、JWKS からの鍵の選択、鍵ローテーションとキャッシュ、UserInfo エンドポイントの規則を、Part III の mini-op を動かしながら読む。
sidebar:
  label: 10. DiscoveryとJWKS
---

この章でわかること:

- RP が OP のエンドポイントの URL や署名鍵の場所を、設定ファイルに書かずに取得する仕組み
- issuer 識別子を文字列として完全一致で比べる理由と、比べ損ねたときに成立するなりすまし
- JWKS から `kid`・`alg`・`use` で鍵を選ぶ手順と、鍵ローテーションの間も検証を続けられるキャッシュの設計
- UserInfo エンドポイントが満たすべき要求と、UserInfo レスポンスの形
- Part III で動かす3つのサーバの全体像と、mini-op の Discovery・JWKS の実際の応答

## Part IIIで作るもの

Part III では、ここまでの章で読んだ仕様を Rust のコードにして動かします。
リポジトリの `examples/` は Cargo のワークスペースで、次の4つのクレートからなります。

| クレート | 役割 | 待ち受け |
| --- | --- | --- |
| `mini-op` | 学習用の最小の OP。Discovery、JWKS、認可・トークン・UserInfo の各エンドポイント | `127.0.0.1:9000` |
| `rp` | openidconnect クレートで書いた RP | `127.0.0.1:3000` |
| `resource-server` | JWT アクセストークンを検証する API | `127.0.0.1:4000` |
| `flow-test` | 3つのサーバを相手にログインから API 呼び出しまでを自動で実行し、各段の HTTP メッセージを表示するプログラム | (クライアント) |

3つのサーバの関係を次の図に示します。

```mermaid
flowchart LR
    B["ブラウザ<br/>(flow-test が代行)"]
    RP["RP<br/>rp :3000"]
    OP["OP<br/>mini-op :9000"]
    RS["リソースサーバ<br/>resource-server :4000"]
    B -- "/login, /callback, /api-call" --> RP
    B -- "/authorize (ログイン画面)" --> OP
    RP -- "Discovery, JWKS,<br/>/token, /userinfo" --> OP
    RP -- "Bearer アクセストークン" --> RS
    RS -- "Discovery, JWKS" --> OP
```

図では、RP とリソースサーバの両方が OP に Discovery と JWKS を問い合わせています。
RP は IDトークンの署名を、リソースサーバはアクセストークンの署名を
検証するために、OP の公開鍵を必要とします。どちらも、OP の公開鍵をどこから取得するか、
その鍵が本当にその OP のものかを判断しなければなりません。
この章は、その共通の前提を扱います。RP の実装は[11章](/rust-impl/11-build-rp/)、
OP の実装は[12章](/rust-impl/12-build-op/)で読みます。

依存クレートの版は、ワークスペースの `examples/Cargo.toml` で `=` を付けて固定しています。

```toml
[workspace]
resolver = "3"
members = ["mini-op", "rp", "resource-server", "flow-test"]

[workspace.package]
edition = "2024"
publish = false

[workspace.dependencies]
axum = { version = "=0.8.9", features = ["form"] }
tokio = { version = "=1.53.1", features = ["macros", "rt-multi-thread", "net", "sync"] }
openidconnect = "=4.0.1"
reqwest = { version = "=0.12.28", default-features = false, features = ["json", "cookies", "rustls-tls"] }
tower-sessions = "=0.15.0"
ring = "=0.17.14"
serde = { version = "=1.0.229", features = ["derive"] }
serde_json = "=1.0.151"
base64 = "=0.23.1"
sha2 = "=0.11.0"
rand = "=0.10.3"
url = "=2.5.8"
percent-encoding = "=2.3.2"
anyhow = "=1.0.104"
thiserror = "=2.0.21"
```

openidconnect 4.0.1 は内部で sha2 0.10、base64 0.21、rand 0.8 を使っています。
本書のワークスペースが固定した sha2 0.11、base64 0.23、rand 0.10 とは版が異なりますが、
Cargo は互換性のない版(0.x の x が異なる版)を別のクレートとして同時にリンクできるため、
依存の解決は衝突しません。reqwest は openidconnect が要求する 0.12 系と同じ 0.12.28 に
揃えてあり、ビルドされる reqwest は1つだけです。

## OPの設定値をどう知るか

RP が OP と通信するには、少なくとも次の値が必要です。

- 認可エンドポイントとトークンエンドポイントの URL が必要です([3章](/web-auth/03-authorization-code/))
- IDトークンの署名を検証する公開鍵の場所が必要です([7章](/oidc/07-jwt-jose/)の JWK Set)
- OP が署名に使うアルゴリズム(`alg` の値)と、対応している `response_type` やスコープが必要です
- UserInfo エンドポイントの URL が必要です([6章](/oidc/06-oauth-to-oidc/))

これらを RP の設定ファイルに1つずつ書く方法もあります。この方法には2つの問題があります。
1つは、OP がエンドポイントの URL や対応アルゴリズムを変えたときに、すべての RP の設定を
書き換える必要があることです。もう1つは、署名鍵を入れ替えるたびに、公開鍵を RP に
配り直す必要があることです。

**Discovery**(OpenID Connect Discovery 1.0)は、この問題を解くための仕様です。
OP は自分の設定値を JSON 文書として決まった URL で公開し、RP はその URL を
組み立てて取得します。RP が事前に保持しておく必要があるのは、OP を表す1つの URL だけです。

その URL が **issuer 識別子**(Issuer Identifier)です。OpenID Connect Core 1.0 は
issuer 識別子を次のように定義しています。

> Verifiable Identifier for an Issuer. An Issuer Identifier is a case-sensitive URL using the https scheme that contains scheme, host, and optionally, port number and path components and no query or fragment components.

(OpenID Connect Core 1.0 1.2節)

issuer 識別子は、https スキームの URL で、スキーム・ホストと、必要ならポート番号と
パスを含み、クエリとフラグメントは含みません。大文字と小文字を区別する(case-sensitive)
と明記されている点は、後の「issuer識別子の比較規則」の節で意味を持ちます。
IDトークンの `iss` クレーム([7章](/oidc/07-jwt-jose/))に入るのもこの値です。

Discovery は2つの段階を定めています。

1. **Issuer の発見**(2節): エンドユーザーが入力したメールアドレスなどから、
   **WebFinger**(RFC 7033)という問い合わせの仕組みを使って issuer 識別子を
   特定します。2節自身が「Issuer discovery is OPTIONAL」と書いているとおり、
   RP が issuer をあらかじめ保持している場合は省略できます
2. **設定値の取得**(4節): issuer 識別子から決まる URL に GET を送り、
   OP の設定値を JSON で受け取ります

実際の RP のほとんどは、ログインボタンごとに OP が決まっているので、
1つ目の段階を使わずに2つ目だけを使います。本書の rp も同じで、
issuer 識別子 `http://127.0.0.1:9000` を定数として持っています。

## 仕様を読む: OpenID Connect Discovery 1.0 4節と4.1節

設定値を置く場所について、4節は次のように定めています。

> OpenID Providers supporting Discovery MUST make a JSON document available at the path formed by concatenating the string /.well-known/openid-configuration to the Issuer. [...] openid-configuration MUST point to a JSON document compliant with this specification and MUST be returned using the application/json content type.

(OpenID Connect Discovery 1.0 4節)

この節は、Discovery に対応する OP が設定値の JSON 文書をどこに置くかを定めています。
OP は、issuer 識別子の後ろに文字列 `/.well-known/openid-configuration` を連結したパスで
JSON 文書を公開しなければなりません(MUST)。応答は `application/json` の
コンテントタイプで返さなければなりません(MUST)。

`/.well-known/` で始まるパスは **well-known URI**(well-known URI)と呼ばれ、
サイト全体に関する情報を置く場所として予約されたパスです(RFC 5785、現在は
RFC 8615)。どのサーバでも同じパスに同じ種類の情報があるため、
クライアントは URL を推測せずに組み立てられます。

4.1節は、issuer にパスが含まれる場合の組み立て方を補っています。

> If the Issuer value contains a path component, any terminating / MUST be removed before appending /.well-known/openid-configuration.

(OpenID Connect Discovery 1.0 4.1節)

issuer にパスがある場合は、末尾の `/` を取り除いてから
`/.well-known/openid-configuration` を付け足さなければなりません(MUST)。
例えば issuer が `https://example.com/issuer1` なら、要求先は
`https://example.com/issuer1/.well-known/openid-configuration` です。
4.1節は、パスを使えば1つのホストで複数の issuer を運用できることも説明しています。

mini-op に対する実際の要求と応答は次のとおりです(応答の JSON は整形してあります)。

```http
GET /.well-known/openid-configuration HTTP/1.1
Host: 127.0.0.1:9000
Accept: application/json
```

```http
HTTP/1.1 200 OK
content-type: application/json

{
  "issuer": "http://127.0.0.1:9000",
  "authorization_endpoint": "http://127.0.0.1:9000/authorize",
  "token_endpoint": "http://127.0.0.1:9000/token",
  "userinfo_endpoint": "http://127.0.0.1:9000/userinfo",
  "jwks_uri": "http://127.0.0.1:9000/jwks",
  "scopes_supported": ["openid", "profile", "email", "api.read"],
  "response_types_supported": ["code"],
  "grant_types_supported": ["authorization_code"],
  "subject_types_supported": ["public"],
  "id_token_signing_alg_values_supported": ["ES256"],
  "token_endpoint_auth_methods_supported": ["client_secret_basic"],
  "code_challenge_methods_supported": ["S256"],
  "authorization_response_iss_parameter_supported": true,
  "request_parameter_supported": false,
  "request_uri_parameter_supported": false,
  "claims_supported": ["sub", "iss", "aud", "exp", "iat", "auth_time", "nonce",
                       "at_hash", "name", "email", "email_verified"]
}
```

mini-op は手元で動かすために http を使っています。Discovery は issuer と
各エンドポイントに https を要求しており(次節)、本番の OP では https 以外を使えません。

## 仕様を読む: OpenID Connect Discovery 1.0 3節

応答の JSON に並ぶ項目は **OpenID プロバイダメタデータ**(OpenID Provider Metadata)と
呼ばれ、3節が一覧を定めています。全部で35項目あるので、要請の強さで分けて
主なものを示します。

| 項目 | 要請 | 意味 |
| --- | --- | --- |
| `issuer` | REQUIRED | issuer 識別子 |
| `authorization_endpoint` | REQUIRED | 認可エンドポイントの URL |
| `token_endpoint` | インプリシットフローだけの場合を除き REQUIRED | トークンエンドポイントの URL |
| `jwks_uri` | REQUIRED | OP の JWK Set の URL |
| `response_types_supported` | REQUIRED | 対応する `response_type` の値 |
| `subject_types_supported` | REQUIRED | `sub` の種類(`public` / `pairwise`) |
| `id_token_signing_alg_values_supported` | REQUIRED | IDトークンの署名に使う `alg` の値 |
| `userinfo_endpoint` | RECOMMENDED | UserInfo エンドポイントの URL |
| `scopes_supported` | RECOMMENDED | 対応するスコープ値 |
| `claims_supported` | RECOMMENDED | 返しうるクレーム名 |
| `token_endpoint_auth_methods_supported` | OPTIONAL | トークンエンドポイントのクライアント認証方式(省略時は `client_secret_basic`) |
| `grant_types_supported` | OPTIONAL | 対応するグラント種別 |
| `request_uri_parameter_supported` | OPTIONAL | `request_uri` パラメータに対応するか(省略時は `true`) |

`subject_types_supported` の `pairwise` は[18章](/oidc-deep/18-claims-identity/)、
クライアント認証方式は[13章](/oauth-deep/13-client-auth/)で扱います。
`request_parameter_supported` は、OP が `request` パラメータに対応しているかを表す項目で、
省略時の値は `false` です。`request_uri_parameter_supported` は、OP が `request_uri`
パラメータに対応しているかを表す項目で、省略時の値は `true` です。mini-op はどちらにも
対応していないので、2つとも `false` を明示しています。`request_uri_parameter_supported` を
省略すると、対応していると広告したことになるためです。2つのパラメータは
[17章](/oauth-deep/17-request-protection/)で扱います。
`code_challenge_methods_supported` は RFC 8414 が定めた項目、
`authorization_response_iss_parameter_supported` は RFC 9207 が定めた項目で、
どちらも Discovery 3節の一覧にはありません。mini-op はこの2つを、3節の最後にある
「Additional OpenID Provider Metadata parameters MAY also be used.」に基づいて追加しています。

`issuer` の定義は次のとおりです。

> REQUIRED. URL using the https scheme with no query or fragment components that the OP asserts as its Issuer Identifier. If Issuer discovery is supported (see Section 2), this value MUST be identical to the issuer value returned by WebFinger. This also MUST be identical to the iss Claim value in ID Tokens issued from this Issuer.

(OpenID Connect Discovery 1.0 3節)

この項目は必須で、OP が自分の issuer 識別子だと主張する値を入れます。
WebFinger を使う場合は WebFinger が返した値と同一でなければならず(MUST)、
この OP が発行する IDトークンの `iss` の値とも同一でなければなりません(MUST)。
ここで使われている語は「identical」(同一)であり、「equivalent」(同等)ではありません。

`jwks_uri` の定義には、JWK Set の中身についての制約があります。

> REQUIRED. URL of the OP's JWK Set [JWK] document, which MUST use the https scheme. [...] The JWK Set MUST NOT contain private or symmetric key values.

(OpenID Connect Discovery 1.0 3節)

`jwks_uri` は、OP の JWK Set 文書の URL です。https を使わなければならず(MUST)、
JWK Set に秘密鍵や共通鍵の値を含めてはなりません(MUST NOT)。
JWK Set は誰でも取得できる公開の文書なので、秘密鍵の成分(EC 鍵の `d` など)を
含めると、JWK Set を取得した誰もが署名を偽造できるようになります。

`id_token_signing_alg_values_supported` には、次の一文があります。

> The algorithm RS256 MUST be included.

(OpenID Connect Discovery 1.0 3節)

`RS256` を必ず含めなければならない(MUST)という規定です。mini-op は ES256 だけを
公開しており、この規定を満たしていません。ring 0.17 は RSA 鍵の生成に対応していないため、
mini-op は鍵を起動時に生成できる ES256 だけを使っています。学習用の OP であるための
逸脱であり、相互接続を前提にする本物の OP では RS256 を含める必要があります。

## 実験: メタデータを解析してissuerを検証する

次のコードは、Discovery の URL の組み立て(4節)と RFC 8414 の組み立て(後述)を並べたうえで、
いくつかのメタデータを検証します。検証の規則は、必須項目がそろっていること、
問い合わせに使った issuer と応答の `issuer` が文字列として一致すること、
エンドポイントが https であることの3つです。

<RustPlay snippet="ch10/discovery" title="メタデータの解析とissuerの検証" />

出力の読み方は次のとおりです。

- 「メタデータの URL」の2行目では、パス `/tenant-a` を持つ issuer について、
  Discovery 4節の方式と RFC 8414 の方式で異なる URL ができています
- 「issuer の検証」では、受理されたのは1件目だけです。2件目(末尾の `/`)と
  3件目(ホスト名の大文字)は、人間には同じ OP に見えますが、文字列としては
  異なるため拒否されます
- 4件目は、攻撃者のサーバ `https://evil.example` から取得したメタデータが、
  正規の OP の issuer を名乗っている場合です。問い合わせに使った issuer と
  一致しないため拒否されます。この検査の意味は後の「issuerの一致検証」の節で説明します
- 6件目は `jwks_uri` が欠けた応答で、serde の解析の段階で失敗しています。
  必須項目を `Option` ではない型にしておくと、欠落を型の解析で検出できます
- 最後の「URL として比較すると何が起きるか」では、`url::Url` 型で解析すると
  ホスト名が小文字に変わり、末尾に `/` が補われることを示しています。
  issuer を URL 型に変換してから比較すると、2件目と3件目を誤って受理します

## RFCを読む: RFC 8414 3節と5節

Discovery は OpenID Connect の仕様として作られましたが、OP の設定値を公開する
という考え方は OAuth 2.0 の認可サーバ全般に役立ちます。そこで IETF は、
Discovery 4節の仕組みを OAuth 2.0 向けに一般化した
**認可サーバメタデータ**(OAuth 2.0 Authorization Server Metadata、RFC 8414、2018年6月)を
定めました。メタデータの項目の多くは Discovery と共通で、`code_challenge_methods_supported`
のような OAuth 2.0 の拡張に関する項目が加わっています。

設定値を置く場所は、Discovery と少し異なります。

> Authorization servers supporting metadata MUST make a JSON document containing metadata as specified in Section 2 available at a path formed by inserting a well-known URI string into the authorization server's issuer identifier between the host component and the path component, if any. By default, the well-known URI string used is "/.well-known/oauth-authorization-server".

(RFC 8414 3節)

この節は、認可サーバがメタデータを置くパスを定めています。well-known URI の文字列を、
issuer 識別子のホスト部分とパス部分の間に挿入したパスで公開しなければなりません(MUST)。
既定の文字列は `/.well-known/oauth-authorization-server` です。

Discovery は issuer の後ろに付け足し、RFC 8414 はホストとパスの間に挿入します。
issuer にパスがなければ両者は同じ URL になり、パスがあると異なる URL になります。
5節はこの違いを明示しています。

> However, they are different when there is a path component, because OpenID Connect Discovery 1.0 specifies that the well-known URI string is appended to the issuer identifier (e.g., "https://example.com/issuer1/.well-known/openid-configuration"), whereas this specification specifies that the well-known URI string is inserted before the path component of the issuer identifier (e.g., "https://example.com/.well-known/openid-configuration/issuer1").

(RFC 8414 5節)

この節は、issuer にパスがある場合に2つの仕様の URL が異なることを、例を挙げて述べています。
5節は続けて、今後のメタデータの配置は RFC 8414 の方式によるべきだとしつつ、
既存の OpenID Connect の環境では移行期間中に両方の場所で公開する必要があるかもしれない、
と書いています。実験の出力の2行目は、この2つの URL を並べたものです。

RFC 8414 の 3.3節は、取得したメタデータの検証についても Discovery と同じ規則を定めています。

> The "issuer" value returned MUST be identical to the authorization server's issuer identifier value into which the well-known URI string was inserted to create the URL used to retrieve the metadata. If these values are not identical, the data contained in the response MUST NOT be used.

(RFC 8414 3.3節)

返された `issuer` は、メタデータの URL を作るのに使った issuer 識別子と同一でなければならず
(MUST)、同一でなければ応答の内容を使ってはなりません(MUST NOT)。

本書の resource-server は、OpenID Connect の OP である mini-op から鍵を取得するため、
Discovery の `/.well-known/openid-configuration` を使っています。JWT アクセストークンの
仕様である RFC 9068 の4節は、認可サーバが RFC 8414 のメタデータで `jwks_uri` と `issuer` を
公開すべきだとしたうえで(SHOULD)、OpenID Connect を実装する認可サーバは Discovery を
使ってもかまわない(MAY)と書いています。リソースサーバ側の検証の全体は
[14章](/oauth-deep/14-token-validation/)で扱います。

## issuerの一致検証

Discovery を使うと、RP は issuer 識別子という1つの値から、エンドポイントと公開鍵を
すべて自動で取得します。このことは、取得の過程で別の OP の値が混入すると、
RP がその OP を正規の OP として扱うことを意味します。

次の図は、issuer の一致検証をしない RP に対する攻撃の流れです。攻撃者は自分の
サーバ `https://evil.example` に、正規の OP `https://op.example.com` の issuer を名乗る
メタデータを置きます。エンドポイントと `jwks_uri` は攻撃者のサーバを指し、
JWK Set には攻撃者の公開鍵が入っています。RP は、WebFinger の応答や設定の誤りによって、
`https://evil.example` を issuer として問い合わせます。

```mermaid
sequenceDiagram
    participant RP
    participant 攻撃者 as 攻撃者のサーバ<br/>evil.example
    Note over RP: WebFinger の応答や設定の誤りで<br/>https://evil.example を issuer として扱う
    RP->>攻撃者: GET https://evil.example/.well-known/openid-configuration
    攻撃者-->>RP: {"issuer": "https://op.example.com",<br/>"jwks_uri": "https://evil.example/jwks", ...}
    RP->>攻撃者: GET /jwks
    攻撃者-->>RP: 攻撃者の公開鍵
    Note over 攻撃者: 攻撃者の秘密鍵で<br/>iss=https://op.example.com,<br/>sub=被害者 の IDトークンを作る
    攻撃者->>RP: 偽の IDトークン
    Note over RP: 署名は攻撃者の公開鍵で検証に成功し、<br/>iss も正規の OP の値なので受理してしまう
```

RP が IDトークンの `iss` だけを検証していると、この攻撃は成立します。IDトークンの
`iss` は攻撃者が自由に書けるうえ、署名は攻撃者の鍵で正しく作られているからです。
結果として攻撃者は、正規の OP でログインできる任意のユーザーとして RP にログインできます。

この攻撃を防ぐのが、問い合わせに使った issuer とメタデータの `issuer` の一致検証です。
図の RP は `https://evil.example` を issuer として問い合わせたので、応答の `issuer` が
`https://op.example.com` なら一致せず、メタデータを拒否できます。攻撃者が正直に
`https://evil.example` と書けば検証は通ります。その場合、RP は攻撃者のサーバを
`https://evil.example` という別の OP として扱い、IDトークンの `iss` も
`https://evil.example` でなければ受理しません。RP はユーザーを `iss` と `sub` の組で
識別するので、攻撃者は正規の OP のユーザーとしてはログインできません。

この検証が防ぐのは、別の issuer で取得した文書が正規の OP の issuer を名乗る場合です。
DNS の改ざんなどで、RP が `https://op.example.com` に接続したつもりで攻撃者のサーバに
接続した場合は、問い合わせに使った issuer も `https://op.example.com` なので、
攻撃者は一致する `issuer` を返せます。この攻撃は issuer の一致検証では防げず、
TLS のサーバ証明書の検査で防ぎます(次節で読む7.2節の1段落目)。

## 仕様を読む: OpenID Connect Discovery 1.0 4.3節

この検証を定めているのが4.3節です。

> If any of the validation procedures defined in this specification fail, any operations requiring the information that failed to correctly validate MUST be aborted and the information that failed to validate MUST NOT be used.
>
> The issuer value returned MUST be identical to the Issuer URL that was used as the prefix to /.well-known/openid-configuration to retrieve the configuration information. This MUST also be identical to the iss Claim value in ID Tokens issued from this Issuer.

(OpenID Connect Discovery 1.0 4.3節)

この節は、取得した設定値の検証規則を定めています。1段落目は、検証に失敗したときの扱いです。
検証に失敗した情報を必要とする処理は中止しなければならず(MUST)、
その情報を使ってはなりません(MUST NOT)。メタデータの一部だけが不正な場合に、
正しそうな項目だけを拾って使うことも禁じられています。

2段落目は、3つの値の関係を定めています。

1. RP が `/.well-known/openid-configuration` の前に付けた issuer の URL です
2. 応答のメタデータの `issuer` です
3. その OP が発行する IDトークンの `iss` です

1と2は同一でなければならず(MUST)、2と3も同一でなければなりません(MUST)。
1は RP が自分の設定として持っている値なので、攻撃者は変えられません。
この2つの一致によって、IDトークンの `iss` は RP の設定値と同一であることが保証されます。

7.2節(Impersonation Attacks)は、この検証が防ぐ攻撃を具体的に書いています。

> An attacker may also attempt to impersonate an OpenID Provider by publishing a Discovery document that contains an issuer Claim using the Issuer URL of the OP being impersonated, but with its own endpoints and signing keys. This would enable it to issue ID Tokens as that OP, if accepted by the RP.

(OpenID Connect Discovery 1.0 7.2節)

この段落は、なりすます OP の issuer と、攻撃者自身のエンドポイントと署名鍵を記載した
Discovery 文書を、攻撃者が公開する攻撃を述べています。RP がその文書を受け入れると、
攻撃者はその OP として IDトークンを発行できるようになります。前節の図はこの攻撃を描いたものです。
7.2節は同じ段落で、RP は設定値の要求に使った issuer、メタデータの `issuer`、
IDトークンの `iss` の3つが完全に一致することを確かめなければならない(MUST)と
結論づけています。

7.2節の1段落目は、Discovery の要求で TLS のサーバ証明書を検査しなければならない(MUST)
とも定めています。証明書の検査は、DNS の改ざんなどで攻撃者のサーバへ接続させられることを
防ぎます。issuer の一致検証と TLS の証明書検査は、それぞれ別の経路の攻撃を防いでおり、
片方だけでは足りません。

本書の rp が使う openidconnect クレートは、Discovery の応答を受け取った時点で
この比較をしています。クレートの `discovery_response` 関数は、解析したメタデータの
`issuer()` が引数の issuer と等しくなければ `DiscoveryError::Validation` を返します。
resource-server は自前で同じ検査をしています(`examples/resource-server/src/jwks.rs`)。

```rust
pub async fn discover_jwks_uri(http: &reqwest::Client, issuer: &str) -> anyhow::Result<String> {
    let url = format!("{issuer}/.well-known/openid-configuration");
    let meta: Metadata = http.get(url).send().await?.error_for_status()?.json().await?;
    // OIDC Discovery 4.3: 取得した issuer は問い合わせに使った issuer と完全一致しなければならない
    anyhow::ensure!(meta.issuer == issuer, "issuer mismatch: {}", meta.issuer);
    Ok(meta.jwks_uri)
}
```

`meta.issuer == issuer` は `String` と `&str` の比較で、バイト列として等しいかを調べます。
次節で説明するとおり、この単純な比較が仕様の要求する比較です。

## issuer識別子の比較規則

「同一」(identical)をどう判定するかについて、Discovery は5節で文字列の比較方法を
定めています。

> 1. Remove any JSON applied escaping to produce an array of Unicode code points.
> 2. Unicode Normalization [USA15] MUST NOT be applied at any point to either the JSON string or to the string it is to be compared against.
> 3. Comparisons between the two strings MUST be performed as a Unicode code point to code point equality comparison.

(OpenID Connect Discovery 1.0 5節)

この節は、JSON の文字列と他の文字列を比べる方法を定めています。まず JSON の
エスケープ(`\/` や `\u0041` など)を解いて Unicode のコードポイントの列にします。
どちらの文字列にも Unicode の正規化を適用してはならず(MUST NOT)、
比較はコードポイントごとの等価比較で行わなければなりません(MUST)。

この規則から、次の値はすべて互いに異なる issuer として扱われます。

| 値 | `https://op.example.com` との関係 |
| --- | --- |
| `https://op.example.com/` | 末尾の `/` が多い |
| `https://OP.example.com` | ホスト名の大文字小文字が違う |
| `https://op.example.com:443` | 既定のポート番号を明示している |
| `https://op.example.com/tenant-a` | パスが異なる |

URL の仕様(RFC 3986)の上では、1行目から3行目はどれも同じ資源を指す URL として
正規化できます。それでも issuer の比較では区別します。正規化の規則は実装ごとに
細部が異なり、RP と OP が別の正規化をすると、一方が同じと判定した値を他方が
別と判定する不一致が生じるためです。比較を文字列の完全一致に限れば、
この不一致は起きません。

4行目のパスの違いについて、OpenID Connect Core 1.0 の16.15節は、パスも issuer 識別子の
一部だと明記しています。

> OpenID Connect treats the path component of any Issuer URI as being part of the Issuer Identifier. For instance, the subject "1234" with an Issuer Identifier of "https://example.com" is not equivalent to the subject "1234" with an Issuer Identifier of "https://example.com/sales".

(OpenID Connect Core 1.0 16.15節)

issuer `https://example.com` の `sub` "1234" と、issuer `https://example.com/sales` の
`sub` "1234" は、別のユーザーです。1つのホストで複数の issuer を運用する OP では、
パスを無視して比較すると、別の issuer のユーザーを同じユーザーとして扱ってしまいます。
ユーザーを `iss` と `sub` の組で識別する理由は[18章](/oidc-deep/18-claims-identity/)で扱います。

実装での注意点は、issuer を URL 型に変換してから比較しないことです。
実験で示したとおり、`url::Url` は解析時にホスト名を小文字にし、パスが空なら `/` を補います。
openidconnect の `IssuerUrl` 型は、解析した URL と一緒に元の文字列を保持しており、
等価比較は元の文字列どうしで行います。issuer は設定ファイルに書いた文字列のまま保持し、
文字列として比べてください。

## JWKSと鍵の選び方

メタデータの `jwks_uri` を取得すると、OP の JWK Set(JWKS)が返ります。
JWK と JWK Set の形式は[7章](/oidc/07-jwt-jose/)で読みました。
mini-op の JWKS は次のとおりです。

```http
GET /jwks HTTP/1.1
Host: 127.0.0.1:9000
```

```http
HTTP/1.1 200 OK
content-type: application/json

{"keys":[{"alg":"ES256","crv":"P-256","kid":"_6_4YV8I4KR0zzSQOkIcrtrsZAm_vL0htjiV1b0CVSQ",
  "kty":"EC","use":"sig","x":"A3ljsFX7MeMBVakcfUC0Ej1LE8945dwlDPd6UTFZHEc",
  "y":"xVLkbMalTP1ljgIfcb7foPh29CadAQoDBJRDmp0EJsQ"}]}
```

mini-op は起動のたびに P-256 の鍵ペアを生成するので、`kid`・`x`・`y` の値は
起動ごとに変わります。`kid` には、[7章](/oidc/07-jwt-jose/)で扱った RFC 7638 の
JWK Thumbprint を使っています(`examples/mini-op/src/jwt.rs`)。

```rust
fn thumbprint(x: &str, y: &str) -> String {
    // RFC 7638: 必須メンバーだけを辞書順に並べた JSON の SHA-256
    let canonical = format!(r#"{{"crv":"P-256","kty":"EC","x":"{x}","y":"{y}"}}"#);
    URL_SAFE_NO_PAD.encode(Sha256::digest(canonical.as_bytes()))
}
```

Thumbprint を `kid` にすると、鍵の内容が変われば `kid` も必ず変わります。
新しい鍵に古い `kid` を付けてしまう運用の誤りが起きません。

JWKS には複数の鍵が入ることがあります。署名用と暗号化用の鍵、入れ替え中の新旧の鍵、
RSA と EC の鍵などです。署名を検証する側は、JWS のヘッダを手がかりに鍵を1つ選びます。
選ぶ手順は次のとおりです。

1. ヘッダの `alg` が、自分の許可リストに含まれることを確かめます。許可リストは
   検証する側の設定で決め、トークンの `alg` から決めてはなりません
   ([8章](/oidc/08-id-token-validation/)のアルゴリズム許可リスト)
2. ヘッダの `kid` と同じ `kid` を持つ鍵を探します
3. 見つかった鍵の `kty` と `crv` が `alg` に合うこと(ES256 なら `EC` と `P-256`)、
   `use` があれば `sig` であること、`alg` があればヘッダの `alg` と同じであることを確かめます

`kid` を必須にするかについて、OpenID Connect Core 1.0 の10.1節は
「If there are multiple keys in the referenced JWK Set document, a kid value MUST be provided in the JOSE Header.」
と定めています。JWK Set に複数の鍵があるなら、署名した側は JOSE ヘッダに `kid` を
入れなければなりません(MUST)。mini-op は鍵が1つでも常に `kid` を付けています。
鍵を追加した日に、`kid` のない古いトークンと新しいトークンが混在するのを避けるためです。

`use` パラメータについて、RFC 7517 の4.2節は値 `sig`(署名)と `enc`(暗号化)を定め、
その使用は OPTIONAL だとしています。一方 Discovery 3節の `jwks_uri` の定義は、
署名用と暗号化用の鍵を両方公開する場合は、すべての鍵に `use` が必須だとしています。
このため検証する側は、`use` がない鍵を署名用として扱ってよく、`use` が `enc` の鍵は
署名の検証に使いません。

## 鍵ローテーション

署名鍵は、いつか入れ替える必要があります。鍵が漏洩した疑いがある場合はもちろん、
漏洩に気づいていない場合に備えて定期的に入れ替える運用も一般的です。
署名鍵を新しい鍵に切り替えることを **鍵ローテーション**(key rotation)と呼びます。

鍵ローテーションを難しくしているのは、OP が鍵を切り替えた瞬間に、
すべての RP とリソースサーバが新しい公開鍵を取得済みとは限らないことです。
OP が新しい鍵で署名を始めても、検証する側のキャッシュに古い JWKS しかなければ、
正しいトークンの検証が失敗します。逆に OP が古い鍵を JWKS からすぐに消すと、
古い鍵で署名され、まだ有効期限の残っているトークンが検証できなくなります。

この問題を、JWKS に新旧の鍵を一時的に並べることで解決します。
手順を次の図に示します。

```mermaid
sequenceDiagram
    participant OP
    participant RP
    Note over OP: JWKS = [旧鍵]<br/>旧鍵で署名
    OP->>OP: 1. 新鍵を JWKS に追加
    Note over OP: JWKS = [旧鍵, 新鍵]<br/>まだ旧鍵で署名
    OP->>OP: 2. 新鍵で署名を開始
    OP->>RP: kid=新鍵 の IDトークン
    Note over RP: キャッシュにない kid
    RP->>OP: GET /jwks (再取得)
    OP-->>RP: [旧鍵, 新鍵]
    Note over RP: 新鍵で検証できる
    OP->>OP: 3. 旧鍵で署名したトークンが<br/>すべて期限切れになるまで待つ
    OP->>OP: 4. 旧鍵を JWKS から削除
    Note over OP: JWKS = [新鍵]
```

手順1と2の間隔を空けると、検証する側が定期的に JWKS を取得し直す場合に、
新しい鍵を事前に取り込む時間ができます。手順3の待ち時間は、旧鍵で署名した
トークンの最長の有効期限より長くします。鍵の退役を含む運用手順の全体は
[26章](/practice/26-operations/)で扱います。

## 仕様を読む: OpenID Connect Core 1.0 10.1.1節

この手順の考え方は、OpenID Connect Core 1.0 の10.1.1節に書かれています。

> The signer publishes its keys in a JWK Set at its jwks_uri location and includes the kid of the signing key in the JOSE Header of each message to indicate to the verifier which key is to be used to validate the signature. Keys can be rolled over by periodically adding new keys to the JWK Set at the jwks_uri location. The signer can begin using a new key at its discretion and signals the change to the verifier using the kid value. The verifier knows to go back to the jwks_uri location to re-retrieve the keys when it sees an unfamiliar kid value. The JWK Set document at the jwks_uri SHOULD retain recently decommissioned signing keys for a reasonable period of time to facilitate a smooth transition.

(OpenID Connect Core 1.0 10.1.1節)

この節は、非対称鍵の署名鍵を入れ替える方法を定めています。署名する側は鍵を
`jwks_uri` の JWK Set で公開し、各メッセージの JOSE ヘッダに署名鍵の `kid` を入れて、
どの鍵で検証すべきかを伝えます。新しい鍵は JWK Set に定期的に追加し、
署名する側は自分の判断で新しい鍵を使い始め、その変更を `kid` で伝えます。
検証する側は、見たことのない `kid` を受け取ったら `jwks_uri` から鍵を取り直します。
`jwks_uri` の JWK Set は、退役したばかりの署名鍵を相応の期間残しておくべきです(SHOULD)。

この節の方式では、署名する側は鍵の切り替えを `kid` の値の変化で伝えます。検証する側は、
未知の `kid` を受け取るまで JWKS を取り直す必要がありません。
ただし「未知の `kid` を受け取ったら取り直す」という規則をそのまま実装すると、
攻撃者が存在しない `kid` のトークンを大量に送るだけで、検証する側に JWKS の取得を
繰り返させることができます。OP への要求が増えるうえ、検証する側の応答も遅くなります。
10.1.1節はこの点に触れていないので、取り直しの頻度は実装側で制限します。

## JWKSのキャッシュと未知のkid

JWKS を毎回取得すると、トークンを1つ検証するたびに OP への HTTP 要求が発生します。
そこで検証する側は JWKS をキャッシュします。キャッシュの規則は、次の3つを組み合わせます。

- キャッシュには有効期間を設け、期間を過ぎたら取り直します。
  OP が鍵を削除したことを、期間の長さ以内に反映できます
- 未知の `kid` を受け取ったら、期間内でも1回だけ取り直します(10.1.1節)
- ただし直前に取り直しを試みていたら、取り直しません。失敗した試行も数えます。
  未知の `kid` による取得の繰り返しを防ぎます

resource-server の実装は、2つ目と3つ目の規則を持っています(`examples/resource-server/src/jwks.rs`)。

```rust
const MIN_REFRESH_INTERVAL: Duration = Duration::from_secs(10);

pub struct JwksCache {
    jwks_uri: String,
    keys: RwLock<HashMap<String, Vec<u8>>>,
    last_attempt: Mutex<Option<Instant>>,
}

impl JwksCache {
    async fn refresh(&self, http: &reqwest::Client) -> anyhow::Result<()> {
        let mut last_attempt = self.last_attempt.lock().await;
        // 未知の kid を送りつけて JWKS を取得させ続ける攻撃を防ぐため、取得の試行の間隔に下限を置く
        if last_attempt.is_some_and(|t| t.elapsed() < MIN_REFRESH_INTERVAL) {
            return Ok(());
        }
        // 失敗した試行も間隔の計算に含めるため、通信の前に時刻を記録する
        *last_attempt = Some(Instant::now());
        let set: JwkSet = http.get(&self.jwks_uri).send().await?.error_for_status()?.json().await?;
        let fresh: HashMap<String, Vec<u8>> = set.keys.iter().filter_map(es256_public_key).collect();
        println!("[resource-server] JWKS を取得: kid={:?}", fresh.keys().collect::<Vec<_>>());
        *self.keys.write().await = fresh;
        Ok(())
    }

    pub async fn key_for(&self, http: &reqwest::Client, kid: &str) -> Option<Vec<u8>> {
        if let Some(key) = self.keys.read().await.get(kid) {
            return Some(key.clone());
        }
        self.refresh(http).await.ok()?;
        self.keys.read().await.get(kid).cloned()
    }
}
```

キャッシュは2つのロックで保護しています。`keys` は tokio の `RwLock` で、鍵の参照は
読み取りロック、取得した鍵への置き換えは書き込みロックで行います。書き込みロックを
持つのは置き換えの代入の間だけで、OP との通信の間は持ちません。このため、キャッシュに
ある鍵での検証は、JWKS の取得が遅れていても待たされません。

`last_attempt` は tokio の `Mutex` で、取得を試みた時刻を持ちます。取得の処理は
このロックを持ったまま行うので、同時に届いた多数の要求が未知の `kid` を含んでいても、
取得するのは1つずつです。2つ目以降は `last_attempt` を調べて取得を省きます。
時刻は通信の前に記録するので、OP が応答しない間や取得に失敗した後も、
取得の試行は10秒に1回までに制限されます。成功した時刻だけを記録すると、
取得に失敗している間は未知の `kid` が届くたびに取得を試みることになります。

`es256_public_key` は、`kty` が `EC`、`crv` が `P-256`、`use` が `sig` か省略、
`alg` が `ES256` か省略の鍵だけを残し、`x` と `y` から非圧縮形式の公開鍵
(先頭の `0x04` に続けて x と y)を作る関数です。条件に合わない鍵は、
キャッシュに入る前に除かれます。

一方 rp が使う openidconnect クレートは、`discover_async` を呼んだ時点で JWKS を
1回取得し、その鍵をクライアントの値の中に保持します。クレートは未知の `kid` を受け取っても
取り直さず、検証は `No matching key found` のエラーになります。本書の rp は起動時に
1回だけ Discovery を実行する簡略化した構成なので、mini-op を再起動して鍵が変わると、
rp も再起動するまでログインに失敗します。本番の RP では、検証が鍵の不一致で
失敗したときや一定時間ごとに Discovery をやり直す処理を加えます。

## 実験: kidで鍵を選び、ローテーションの経過を確かめる

次のコードは、OP の JWKS が v1(旧鍵のみ)、v2(旧鍵と新鍵)、v3(新鍵のみ)と
変わる間に、検証する側のキャッシュの内容と検証の結果がどう変わるかを再現します。時刻は秒単位の
模擬的な値で、キャッシュの有効期間は3600秒、取り直しの最小間隔は60秒にしています。
JWKS には暗号化用(`use` が `enc`)の RSA 鍵も1つ入っています。

<RustPlay snippet="ch10/jwks-select" title="kidによる鍵の選択と鍵ローテーション" />

出力の読み方は次のとおりです。

- t=0 で初めて JWKS を取得し、t=10 ではキャッシュの鍵で検証しています。
  暗号化用の RSA 鍵は「使える鍵」に入っていません
- t=100 で OP が新鍵で署名を始めると、未知の `kid` をきっかけに2回目の取得が起き、
  新鍵で検証できました。10.1.1節の手順どおりの動作です
- t=110 の未知の `kid`(攻撃者が作った値)では、直前の t=100 に取得したばかりなので
  取り直さずに拒否しています。取得の回数は増えていません
- t=120 の `alg` が `HS256` のトークンは、鍵を探す前に許可リストで拒否されています。
  `kid` は正規の旧鍵を指していますが、`alg` の判定が先なので鍵の種類との
  取り違えは起きません([23章](/security/23-jwt-attacks/)のアルゴリズム混同攻撃)
- t=200 の暗号化用の鍵を指す `kid` は、取り直しても使える鍵の中にないため拒否されます
- t=300 では、v2 に旧鍵が残っているので、旧鍵で署名したトークンをまだ検証できます。
  10.1.1節の、退役した鍵を相応の期間残すべき(SHOULD)という規定の効果です
- t=4000 ではキャッシュの有効期間を過ぎたため取り直し、旧鍵が退役した v3 を取得しました。
  旧鍵のトークンはここで初めて拒否されます

署名に使う鍵は実行のたびに生成していますが、表示している値は `kid` と検証の結果だけなので、
出力は毎回同じになります。

## UserInfoエンドポイント

メタデータの `userinfo_endpoint` は、[6章](/oidc/06-oauth-to-oidc/)で導入した
UserInfo エンドポイントの URL です。UserInfo エンドポイントは、アクセストークンを
受け付けてエンドユーザーのクレームを返す、OP の保護されたリソースです。
6章では応答の `sub` を IDトークンの `sub` と照合する規則を読みました。
ここでは、UserInfo エンドポイントを OP として実装し、RP として呼び出すときに
必要な規則を読みます。

## 仕様を読む: OpenID Connect Core 1.0 5.3節

5.3節は、UserInfo エンドポイントそのものへの要求を並べています。

> Communication with the UserInfo Endpoint MUST utilize TLS. [...] The UserInfo Endpoint MUST support the use of the HTTP GET and HTTP POST methods defined in RFC 7231 [RFC7231]. The UserInfo Endpoint MUST accept Access Tokens as OAuth 2.0 Bearer Token Usage [RFC6750].

(OpenID Connect Core 1.0 5.3節)

この節は、UserInfo エンドポイントの通信方法を定めています。通信には TLS を使わなければならず
(MUST)、HTTP の GET と POST の両方に対応しなければならず(MUST)、
アクセストークンを RFC 6750 の Bearer トークン([4章](/web-auth/04-tokens/))として
受け付けなければなりません(MUST)。5.3.1節は、GET を使い `Authorization` ヘッダで
アクセストークンを送ることを推奨しています(RECOMMENDED)。

応答の形は5.3.2節が定めています。応答の JSON を **UserInfo レスポンス**(UserInfo Response)と
呼びます。

> The sub (subject) Claim MUST always be returned in the UserInfo Response. [...] If a Claim is not returned, that Claim Name SHOULD be omitted from the JSON object representing the Claims; it SHOULD NOT be present with a null or empty string value.

(OpenID Connect Core 1.0 5.3.2節)

UserInfo レスポンスには、`sub` クレームを常に含めなければなりません(MUST)。
返さないクレームは JSON から名前ごと省くべきであり(SHOULD)、`null` や空文字列の値で
含めるべきではありません(SHOULD NOT)。5.3.2節はさらに、応答が JSON の場合は
`Content-Type` を `application/json` にしなければならず(MUST)、署名や暗号化をした
JWT で返す場合は `application/jwt` にしなければならない(MUST)と定めています。

エラーの返し方について、5.3.3節は RFC 6750 の3節に従うと定めています。
アクセストークンが不正なら `401 Unauthorized` と
`WWW-Authenticate: Bearer error="invalid_token"` を返します。

mini-op の UserInfo エンドポイントは、アクセストークンのスコープに応じて返すクレームを
選んでいます(`examples/mini-op/src/userinfo.rs`)。

```rust
    let mut body = Map::new();
    body.insert("sub".into(), json!(user.sub));
    if scopes.contains(&"profile") {
        body.insert("name".into(), json!(user.name));
    }
    if scopes.contains(&"email") {
        body.insert("email".into(), json!(user.email));
        body.insert("email_verified".into(), json!(true));
    }
```

`sub` は無条件に入れ、`name` は `profile` スコープ、`email` と `email_verified` は
`email` スコープがある場合だけ入れています。スコープがない場合は `"name": null` とせずに
キーごと省いており、5.3.2節の SHOULD に従っています。手元で rp がログインしたときの
要求と応答は次のとおりです。

```http
GET /userinfo HTTP/1.1
Host: 127.0.0.1:9000
Authorization: Bearer eyJhbGciOiJFUzI1NiIsImtpZCI6Il82XzRZVjhJNEtS...
Accept: application/json
```

```http
HTTP/1.1 200 OK
content-type: application/json
cache-control: no-store

{"email":"demo@example.com","email_verified":true,"name":"Demo User","sub":"user-0001"}
```

mini-op の UserInfo エンドポイントは、アクセストークンの署名、`typ`、`iss`、`exp` と、
スコープに `openid` があることを確かめています。アクセストークンの `aud` は
リソースサーバの識別子であり、UserInfo エンドポイントの識別子は入っていません。
mini-op は、自分が発行したアクセストークンであることを署名と `iss` で確かめた上で、
`aud` を検査せずに受け付けています。アクセストークンの `aud` の設計は
[14章](/oauth-deep/14-token-validation/)で扱います。

## 手元での実行結果: mini-opのDiscoveryとJWKS

mini-op を起動して Discovery と JWKS を取得する手順は次のとおりです。

```sh
cd examples
cargo run -p mini-op
```

別の端末で次を実行します。

```sh
curl -s http://127.0.0.1:9000/.well-known/openid-configuration
curl -s -i http://127.0.0.1:9000/jwks
```

起動時に mini-op は署名鍵の `kid` を表示します。

```text
[mini-op] 署名鍵 kid=_6_4YV8I4KR0zzSQOkIcrtrsZAm_vL0htjiV1b0CVSQ
[mini-op] listening on http://127.0.0.1:9000
```

`curl` の出力は、この章の「仕様を読む: OpenID Connect Discovery 1.0 4節と4.1節」と
「JWKSと鍵の選び方」の節に示したものと同じ形になります。`kid`、`x`、`y` の値は
mini-op を起動するたびに変わります。表示された `kid` と JWKS の `kid` が
一致していることを確かめてください。終わったら mini-op を Ctrl+C で停止します。

3つのサーバを同時に起動してログインまで動かす手順は、
[11章](/rust-impl/11-build-rp/)の「手元での実行結果」の節に書きました。

## まとめ

- Discovery は、OP の設定値を issuer 識別子の後ろの `/.well-known/openid-configuration` に
  JSON で公開する仕組みです。RP が事前に知る必要があるのは issuer 識別子だけです
- RFC 8414 は同じ仕組みを OAuth 2.0 の認可サーバ向けに一般化しました。
  issuer にパスがある場合、well-known URI を挿入する位置が Discovery と異なります
- 問い合わせに使った issuer、メタデータの `issuer`、IDトークンの `iss` の3つは
  完全に一致しなければなりません(Discovery 4.3節)。この検証がないと、
  攻撃者は正規の OP を名乗るメタデータで自分の鍵を RP に使わせられます
- issuer の比較は、正規化をしない文字列の完全一致です。URL 型に変換して比較すると、
  末尾の `/` や大文字小文字の違いを誤って同一と判定します
- 検証する側は `alg` の許可リストを先に確かめ、`kid` で鍵を選び、`kty`・`crv`・`use`・`alg` を
  照合します。未知の `kid` で JWKS を取り直し(Core 10.1.1節)、取り直しの頻度には下限を置きます
- UserInfo エンドポイントは GET と POST、Bearer トークンに対応し、UserInfo レスポンスには
  `sub` を常に含め、返さないクレームは省きます

次章では、ここで取得した設定値と鍵を使って、openidconnect クレートで RP を組み立てます。
ログインの開始からコールバックの処理、セッションの再発行までを、rp のコードで読みます。
