---
title: リソースサーバとトークンの検証
description: 不透明トークンと自己完結型トークン、RFC 9068 の JWT アクセストークンの検証、イントロスペクションと失効、Resource Indicators による宛先の制限、Protected Resource Metadata。
sidebar:
  label: 14. リソースサーバとトークンの検証
---

この章でわかること:

- 不透明トークンと自己完結型トークンの違いと、それぞれをリソースサーバが検証する方法
- RFC 9068 の JWT アクセストークンの検証手順(`typ`、`iss`、`aud`、署名、`exp`)と、ID トークンを受け入れてはならない理由
- イントロスペクションと失効の手順、イントロスペクション結果のキャッシュが失効を遅らせる時間(実験)
- Resource Indicators による宛先の指定と、Protected Resource Metadata による認可サーバの発見
- なぜ体系に必須か: アクセストークンを最終的に受け入れるか拒否するかを決めるのはリソースサーバです。認可サーバとクライアントが正しく動作していても、リソースサーバの検証の項目が欠けていれば、別の宛先のトークンや ID トークンで API が呼べてしまいます

## 基礎編からの接続

[2章](/web-auth/02-delegation/)では、OAuth 2.0 の4つのロールの1つとしてリソースサーバを紹介しました。[4章](/web-auth/04-tokens/)では、クライアントがアクセストークンを `Authorization: Bearer` で送る形式と、リソースサーバが返す `WWW-Authenticate` の `invalid_token` と `insufficient_scope` を扱いました。ただし4章では、受け取ったトークンをリソースサーバがどう検証するかには立ち入りませんでした。

この章はその検証を扱います。JWT アクセストークンの検証は、[7章](/oidc/07-jwt-jose/)の JWS と、[8章](/oidc/08-id-token-validation/)の ID トークン検証とほぼ同じ構造です。鍵の取得とキャッシュは[10章](/rust-impl/10-discovery-jwks/)の JWKS の扱いをそのまま使います。8章で「ID トークンを API の認可に使わない」と書いた理由も、この章で具体的に確かめます。

## アクセストークンの2つの形式

アクセストークンの形式は OAuth 2.0 では決められておらず、認可サーバが選びます。形式は大きく2つに分かれます。

**不透明トークン**(opaque token)は、それ自体には意味のある情報を含まない、推測できないランダムな文字列のトークンです。トークンが誰のもので、どのスコープを持ち、いつまで有効かは、認可サーバのデータベースにだけ記録されています。リソースサーバは、トークンを受け取るたびに認可サーバに問い合わせて情報を得ます。

**自己完結型トークン**(self-contained token)は、検証に必要な情報をトークン自体に含め、発行者が署名したトークンです。構造化トークンとも呼ばれます。JWT が代表的な形式で、リソースサーバは認可サーバの公開鍵だけを使って、問い合わせなしに検証できます。

| 観点 | 不透明トークン | 自己完結型トークン(JWT) |
| --- | --- | --- |
| リソースサーバの検証 | 認可サーバへの問い合わせ | 公開鍵で署名を検証 |
| 1リクエストあたりの通信 | 問い合わせ1回(キャッシュがなければ) | なし(鍵の取得は初回と更新時のみ) |
| 失効の反映 | 問い合わせの時点で反映 | ローカル検証だけなら `exp` まで反映されない |
| トークンの長さ | 数十バイト程度 | 数百バイト以上 |
| クライアントから中身が見えるか | 見えない | 署名だけなので見える |

最後の行は見落とされやすい性質です。JWT は署名されているだけで暗号化されていないため、クライアントも利用者も Base64url を復号すれば中身を読めます。RFC 9068 の6節は、クライアントはアクセストークンの中身を調べてはならない(MUST NOT)と定めています。認可サーバとリソースサーバが形式をいつ変えてもよいように、クライアントはアクセストークンを不透明な文字列として扱うという OAuth 2.0 の前提を明文化したものです。一方で、認可サーバの管理者に対しては、中身がクライアントから見えることを考慮するよう求めています。

## JWT アクセストークン: RFC 9068

JWT をアクセストークンに使う方法は、長い間、製品ごとに異なっていました。RFC 9068 は、その共通の形式を定めたプロファイルです。ヘッダとペイロードの例を示します。

```json
{"typ": "at+jwt", "alg": "ES256", "kid": "as-key-1"}
```

```json
{
  "iss": "https://as.example.com",
  "sub": "user-5821",
  "aud": "https://api.example.com/orders",
  "client_id": "s6BhdRkqt3",
  "iat": 1759999990,
  "exp": 1760000300,
  "jti": "at-0001",
  "scope": "orders:read"
}
```

ヘッダの `typ` にある `at+jwt`(at+jwt メディアタイプ)は、この JWT が RFC 9068 のアクセストークンであることを示す値です。メディアタイプ `application/at+jwt` から `application/` を省いた形です。ペイロードの各クレームは次の意味を持ちます。

| クレーム | 要否 | 意味 |
| --- | --- | --- |
| `iss` | 必須 | 発行した認可サーバの issuer 識別子 |
| `exp` | 必須 | 有効期限 |
| `aud` | 必須 | このトークンを受け入れるべきリソースサーバ |
| `sub` | 必須 | リソースオーナー(クライアントクレデンシャルではクライアント) |
| `client_id` | 必須 | トークンを要求したクライアント |
| `iat` | 必須 | 発行時刻 |
| `jti` | 必須 | トークンの一意な識別子 |
| `scope` | 要求に含まれていれば推奨 | 付与されたスコープ(空白区切り) |
| `auth_time` / `acr` / `amr` | 任意 | 利用者の認証時刻と認証の強さ |

`iss`、`sub`、`exp`、`iat` は ID トークンと同じクレームです。ID トークンと比べて加わったのは `client_id` と `scope` で、`nonce` や `at_hash` はありません。この2つの JWT はよく似ているため、区別の手段が必要になります。

## RFCを読む: RFC 9068 2節

> JWT access tokens MUST include this media type in the "typ" header parameter to explicitly declare that the JWT represents an access token complying with this profile. Per the definition of "typ" in Section 4.1.9 of [RFC7515], it is RECOMMENDED that the "application/" prefix be omitted. Therefore, the "typ" value used SHOULD be "at+jwt".

(RFC 9068 2.1節)

この節は、JWT アクセストークンのヘッダを定めています。`typ` ヘッダには `application/at+jwt` というメディアタイプを含めなければなりません(MUST)。`application/` の接頭辞は省くことが推奨されるため(RECOMMENDED)、実際の値は `at+jwt` にすべきです(SHOULD)。同じ節の後半は、この明示的な型付けの目的を「ID トークンがアクセストークンとして受け入れられることを防ぐため」と述べています。`typ` によって JWT の用途を区別する考え方は、[23章](/security/23-jwt-attacks/)で JWT 全般の防御策として扱います。

2.1節は署名についても定めています。JWT アクセストークンは署名されていなければならず(MUST)、`none` を使ってはなりません(MUST NOT)。非対称の署名アルゴリズムが推奨されます(RECOMMENDED)。この仕様に準拠する認可サーバとリソースサーバは、サポートするアルゴリズムに `RS256` を含めなければなりません(MUST)。本書の examples は ES256 だけを使っているため、この点では RFC 9068 に完全には準拠していません。

> All the individual scope strings in the "scope" claim MUST have meaning for the resources indicated in the "aud" claim.

(RFC 9068 2.2.3節)

2.2.3節は、`scope` クレームの各スコープが、`aud` で示されたリソースにとって意味を持たなければならない(MUST)と定めています。スコープは宛先と組で解釈されます。例えば `read` というスコープは、`aud` が注文 API なら注文の読み取りを、`aud` が決済 API なら決済履歴の読み取りを意味します。宛先を確認せずにスコープだけを見るリソースサーバは、別の API 向けの `read` を自分の `read` として扱ってしまいます。

## RFCを読む: RFC 9068 4節

4節は、リソースサーバが JWT アクセストークンを検証する手順を箇条書きで定めています。暗号化に関する項目を除いて順に読みます。

> The resource server MUST verify that the "typ" header value is "at+jwt" or "application/at+jwt" and reject tokens carrying any other value.

(RFC 9068 4節)

リソースサーバは、`typ` ヘッダが `at+jwt` か `application/at+jwt` であることを確認し、それ以外の値のトークンを拒否しなければなりません(MUST)。`typ` がないトークンも拒否されます。

> The issuer identifier for the authorization server (which is typically obtained during discovery) MUST exactly match the value of the "iss" claim.

(RFC 9068 4節)

認可サーバの issuer 識別子(通常は Discovery で取得した値)は、`iss` クレームの値と完全に一致しなければなりません(MUST)。[10章](/rust-impl/10-discovery-jwks/)の issuer の比較規則と同じく、末尾のスラッシュの有無も区別します。

> The resource server MUST validate that the "aud" claim contains a resource indicator value corresponding to an identifier the resource server expects for itself. The JWT access token MUST be rejected if "aud" does not contain a resource indicator of the current resource server as a valid audience.

(RFC 9068 4節)

リソースサーバは、`aud` クレームに自分の識別子に対応するリソース指示子(後述の Resource Indicators の値)が含まれることを確認しなければなりません(MUST)。含まれないトークンは拒否しなければなりません(MUST)。`aud` は文字列の場合も配列の場合もあり、配列なら要素のどれかが一致すれば受け入れます。

> The resource server MUST validate the signature of all incoming JWT access tokens according to [RFC7515] using the algorithm specified in the JWT "alg" Header Parameter. The resource server MUST reject any JWT in which the value of "alg" is "none". The resource server MUST use the keys provided by the authorization server.

(RFC 9068 4節)

署名は `alg` ヘッダで指定されたアルゴリズムで検証しなければなりません(MUST)。`alg` が `none` の JWT は拒否し(MUST)、鍵は認可サーバが提供したものを使わなければなりません(MUST)。この文は「`alg` ヘッダの値をそのまま信用してよい」と読めますが、そのように実装すると[23章](/security/23-jwt-attacks/)で扱うアルゴリズム混同攻撃を受けます。[8章](/oidc/08-id-token-validation/)と同じく、受け入れる `alg` をあらかじめ許可リストで固定し、`alg` ヘッダはその許可リストの中から1つを選ぶためだけに使います。RFC 8725(JWT BCP)の3.1節もアルゴリズムの検証を求めています。

> The current time MUST be before the time represented by the "exp" claim. Implementers MAY provide for some small leeway, usually no more than a few minutes, to account for clock skew.

(RFC 9068 4節)

現在時刻は `exp` より前でなければならず(MUST)、時計のずれのために通常は数分以内の小さな余裕(leeway、[8章](/oidc/08-id-token-validation/))を設けてもかまいません(MAY)。

これらの検査のどれかに失敗した場合、リソースサーバは RFC 6750 3.1節の形式で `invalid_token` のエラーを返さなければなりません(MUST)。検査がすべて成功した後で、`scope` などの認可に関するクレームを使ってリクエストを許可するかを判断すべきです(SHOULD)。その判断の詳細は RFC 9068 の範囲外です。

5節(セキュリティの考慮事項)は、検証の背景を2つ説明しています。1つは、同じ発行者が別々のリソース向けに発行するアクセストークンには、リソースごとに異なる `aud` を使わなければならない(MUST)ことです。もう1つは、リソースサーバには ID トークン用とアクセストークン用の鍵を区別する手段がないため、認可サーバが公開している鍵のどれかが漏洩すれば、それだけでリソースサーバに受け入れられる JWT を作れるということです。

## ID トークンをアクセストークンとして受け入れない

`typ` の検査が必要な理由を、具体的な攻撃で確かめます。同じ OP が ID トークンとアクセストークンの両方を発行し、同じ署名鍵を使っている構成を考えます。

ID トークンの `aud` は RP の `client_id` です。リソースサーバが `typ` を見ずに、署名、`iss`、`exp` だけを検査している場合、問題が起きるのは `aud` の検査も緩い実装です。例えば「`aud` は自社のクライアントのどれかであればよい」とする実装では、ある RP が受け取った利用者の ID トークンを、その RP が `Authorization: Bearer` で API に送れます。ID トークンは利用者がログインしたという事実を RP に伝えるものであり、API の呼び出しを許可した記録ではありません。スコープの同意も経ていません。ID トークンを受け入れると、ログインできた RP は、利用者が同意していない API を呼べることになります。

`aud` を正しく検査していれば、ID トークンの `aud` は RP の `client_id` なので拒否されます。`typ` の検査は、`aud` の設計に依存せずに ID トークンを拒否する手段です。RP とリソースサーバの識別子を同じ文字列にする構成(自社の Web アプリとその API に同じ識別子を使う構成など)では、`aud` の検査だけでは区別できないため、`typ` の検査が必要になります。

## 実験: JWT アクセストークンを検証する

認可サーバの鍵で JWT アクセストークンを発行し、リソースサーバ側で RFC 9068 4節の検証とスコープの検査を行います。検証の順序は、`typ` と `alg` の確認、`kid` による鍵の選択、署名検証、`iss`、`aud`、`exp`、スコープです。ペイロードは署名検証に成功した後でのみ読みます。現在時刻は固定値で、leeway は60秒です。

<RustPlay snippet="ch14/jwt-access-token" title="JWT アクセストークンの検証と、受け入れてはならないトークン" />

[1] は正しいトークンで、検証に成功します。[2] は同じトークンで書き込みの操作を要求した場合です。トークン自体は有効なので、スコープ不足を示す 403 と `insufficient_scope` を返し、401 は返しません。4章で見たとおり、401 はトークンを取り直せば解決する可能性があることを示します。403 は、同じ権限のトークンでは何度送っても解決しないことを示します。

[3] は同じ認可サーバの同じ鍵で署名した ID トークンです。署名は正しいのですが、`typ` が `JWT` なので拒否されます。[4] は決済 API 宛てに発行されたアクセストークンで、署名も `typ` も正しく、`aud` の検査だけで拒否されます。決済 API を運用する組織がこのトークンを受け取り、注文 API に送る攻撃は、この検査で防げます。[5] は期限切れ、[6] は `alg` を `none` にした署名なしのトークンです。

[7] は、キャッシュにない `kid` を持つトークンです。認可サーバが鍵をローテーションした直後に、この状況が正当に発生します。この実験では拒否していますが、実際のリソースサーバは JWKS を取得し直してから判断します。[10章](/rust-impl/10-discovery-jwks/)で扱った方法と同じです。

出力では、`WWW-Authenticate` ヘッダには `error` だけを入れ、詳しい理由は「ログにだけ残す」と表示しています。RFC 6750 の `error_description` は、引用符とバックスラッシュを除く ASCII の印字可能文字だけで構成すると定められており、日本語は使えません。加えて、どの検査で拒否したかを詳しく返すと、トークンを偽造しようとする攻撃者がその情報を偽造の試行に利用できます。

## examples/resource-server の検証コード

[11章](/rust-impl/11-build-rp/)と[12章](/rust-impl/12-build-op/)で動かした examples には、RFC 9068 のアクセストークンを検証するリソースサーバ(examples/resource-server、127.0.0.1:4000)が含まれています。mini-op は、`aud` に `http://127.0.0.1:4000` を、`typ` に `at+jwt` を入れたアクセストークンを発行します(`mini-op/src/token.rs`)。リソースサーバの `GET /api/me` は、`verify.rs` の `authorize` 関数でトークンを検証してから応答します。

`authorize` 関数の検証は、コメントで4段に分かれています。

```rust
// 1. ヘッダ: alg は ES256 に固定し、typ で JWT アクセストークンだけを受け入れる
let header: Header = decode_json(h)?;
if header.alg != "ES256" {
    return Err(AuthError::InvalidToken("unexpected alg"));
}
let typ = header.typ.unwrap_or_default().to_ascii_lowercase();
if typ != "at+jwt" && typ != "application/at+jwt" {
    return Err(AuthError::InvalidToken("typ must be at+jwt"));
}
// RFC 7515 4.1.11: crit に挙げられた拡張を理解できなければ無効。対応している拡張はない
if header.crit.is_some() {
    return Err(AuthError::InvalidToken("unsupported crit"));
}

// 2. 署名: kid で鍵を選び、未知なら JWKS を取り直す
let kid = header.kid.ok_or(AuthError::InvalidToken("kid is required"))?;
let key = state
    .jwks
    .key_for(&state.http, &kid)
    .await
    .ok_or(AuthError::InvalidToken("unknown kid"))?;
```

1段目の最後では、`crit` ヘッダ([8章](/oidc/08-id-token-validation/))があれば拒否します。RFC 7515 4.1.11節は、`crit` に挙げられた拡張を受信者が理解しない場合、その JWS を無効とすると定めており、このリソースサーバが理解する拡張は1つもないためです。

3段目は、署名検証の後で初めてペイロードを解析します。RFC 9068 2.2節が必須とする `iss`、`exp`、`aud`、`sub`、`client_id`、`iat`、`jti` のどれかが欠けていれば、解析の時点で拒否します。続いて `iss`、`aud`、`exp` を検査します。`nbf` があれば、その時刻が現在時刻に leeway を加えた時刻より後でないことを確かめます。`iat` も同じ基準で未来の値を拒否し、`jti` が空文字列であれば拒否します。leeway は30秒です。4段目で `api.read` スコープを確認します。スコープが足りない場合は 403 と `insufficient_scope` を返します。エラー応答の `error_description` には ASCII の短い説明文だけを入れています。

`jwks.rs` の `JwksCache` は、未知の `kid` を受け取ると JWKS を取得し直します。このとき、前回の取得の試行から10秒(`MIN_REFRESH_INTERVAL`)以内であれば取得を省きます。攻撃者が存在しない `kid` のトークンを大量に送ると、取得間隔に下限がない実装では、リソースサーバが認可サーバの `jwks_uri` に同じ回数だけリクエストを送ることになります。この下限は、その増幅を防ぐためのものです。試行の時刻は通信の前に記録するため、取得に失敗した試行も間隔の計算に含まれます。成功した取得の時刻だけを記録する実装では、`jwks_uri` が応答しない間は下限が適用されず、未知の `kid` のトークンが届くたびに取得が繰り返されます。

examples/flow-test の11段目は、リソースサーバに対して、トークンなし、ID トークン、ペイロードを1文字改ざんしたアクセストークン、正しいアクセストークンの4通りで `GET /api/me` を送り、応答のステータスと `WWW-Authenticate` を表示します。コードから読み取れる結果は、順に 401(`error` なし)、401(`typ` の検査)、401(署名検証)、200 です。起動の手順は11章と12章を参照してください。

## 不透明トークンとイントロスペクション

不透明トークンを受け取ったリソースサーバは、認可サーバに問い合わせてトークンの状態を取得する必要があります。この問い合わせの方法を標準化したのが RFC 7662 の**トークンイントロスペクション**(token introspection)です。リソースサーバは認可サーバの**イントロスペクションエンドポイント**(introspection endpoint)にトークンを送り、トークンが現在有効かどうかと、付随する情報を JSON で受け取ります。

```mermaid
sequenceDiagram
    participant C as クライアント
    participant RS as リソースサーバ
    participant AS as 認可サーバ
    C->>RS: GET /orders<br/>Authorization: Bearer mF_9.B5f-4.1JqM
    RS->>AS: POST /introspect<br/>Authorization: Basic (RS の資格情報)<br/>token=mF_9.B5f-4.1JqM
    AS->>AS: トークンの記録を検索し、失効と期限を確認
    AS-->>RS: {"active": true, "scope": "orders:read", ...}
    RS->>RS: aud とスコープを確認
    RS-->>C: 200 OK
```

リソースサーバから認可サーバへのリクエストと応答は次のようになります。

```http
POST /introspect HTTP/1.1
Host: server.example.com
Accept: application/json
Content-Type: application/x-www-form-urlencoded
Authorization: Basic czZCaGRSa3F0MzpnWDFmQmF0M2JW

token=mF_9.B5f-4.1JqM&token_type_hint=access_token
```

```http
HTTP/1.1 200 OK
Content-Type: application/json

{
 "active": true,
 "client_id": "l238j323ds-23ij4",
 "username": "jdoe",
 "scope": "read write dolphin",
 "sub": "Z5O3upPC88QrAjx00dis",
 "aud": "https://protected.example.net/resource",
 "iss": "https://server.example.com/",
 "exp": 1419356238,
 "iat": 1419350238
}
```

応答の `active`(active メンバー)は、トークンが現在有効かどうかを示す真偽値で、唯一の必須メンバーです。`token_type_hint`(token_type_hint パラメータ)は、送ったトークンがアクセストークンかリフレッシュトークンかを伝える任意のヒントです。

## RFCを読む: RFC 7662 2.1節と2.2節

> To prevent token scanning attacks, the endpoint MUST also require some form of authorization to access this endpoint, such as client authentication as described in OAuth 2.0 [RFC6749] or a separate OAuth 2.0 access token such as the bearer token described in OAuth 2.0 Bearer Token Usage [RFC6750].

(RFC 7662 2.1節)

この節は、イントロスペクションのリクエストを定めています。パラメータは必須の `token` と任意の `token_type_hint` です。引用した文は、エンドポイントの保護を定めています。イントロスペクションエンドポイントは、何らかの形で呼び出し元の認可を要求しなければなりません(MUST)。手段としては、[13章](/oauth-deep/13-client-auth/)のクライアント認証か、イントロスペクション専用の別のアクセストークンが挙げられています。

この要求がないと、誰でもエンドポイントに任意の文字列を送り、`active` が `true` になる値を探せます。このように有効なトークンを総当たりで探す攻撃を**トークンスキャン攻撃**(token scanning attack)と呼びます。認証を要求すれば、攻撃者は試行のたびに正規のリソースサーバの資格情報を必要とします。

`token_type_hint` について、同じ節は、認可サーバがヒントの種類でトークンを見つけられなかった場合は、サポートするすべての種類に検索を広げなければならない(MUST)と定めています。ヒントは検索の効率化のためのものであり、ヒントが誤っていても結果は変わりません。

> If the introspection call is properly authorized but the token is not active, does not exist on this server, or the protected resource is not allowed to introspect this particular token, then the authorization server MUST return an introspection response with the "active" field set to "false". Note that to avoid disclosing too much of the authorization server's state to a third party, the authorization server SHOULD NOT include any additional information about an inactive token, including why the token is inactive.

(RFC 7662 2.2節)

2.2節は応答を定めています。呼び出しが正しく認可されていても、トークンが無効な場合、存在しない場合、呼び出し元のリソースサーバにそのトークンを調べる権限がない場合は、`active` を `false` にした応答を返さなければなりません(MUST)。この3つの場合を応答で区別せず、無効な理由も含めるべきではありません(SHOULD NOT)。失効したのか、期限が切れたのか、存在しないのかを区別して返すと、認可サーバの内部状態が第三者に伝わるためです。

2.2節には、応答のキャッシュについての記述もあります。リソースサーバは性能のために応答をキャッシュしてもかまいませんが(MAY)、その代わりに認可の判断に使う情報の鮮度が下がります。この鮮度の問題は、後の実験で失効と組み合わせて確かめます。

応答は JSON であり、それ自体には署名がありません。TLS で認可サーバを確認していれば内容は保護されますが、応答を後から第三者に提示して検証させることはできません。RFC 9701 は、イントロスペクションの応答を署名付きの JWT で返す方法を定めています。リソースサーバが `Accept: application/token-introspection+jwt` を付けて要求すると、認可サーバは `typ` が `token-introspection+jwt` の JWT を返し、本来の応答のメンバーを `token_introspection` クレームの中に入れます。RFC 9701 5節は、この JWT に `sub` と `exp` を含めるべきではない(SHOULD NOT)と定めています。応答の JWT がアクセストークンとして誤用されることを防ぐためです。

## トークンの失効: RFC 7009

**失効**(revocation)は、有効期限より前にトークンを無効にする操作です。利用者がログアウトしたときや、クライアントがアプリの連携を解除するときに、クライアントは保持しているトークンを認可サーバに失効させることができます。RFC 7009 は、この操作のための**失効エンドポイント**(revocation endpoint)を定めています。

```http
POST /revoke HTTP/1.1
Host: server.example.com
Content-Type: application/x-www-form-urlencoded
Authorization: Basic czZCaGRSa3F0MzpnWDFmQmF0M2JW

token=45ghiukldjahdnhzdauz&token_type_hint=refresh_token
```

```http
HTTP/1.1 200 OK
```

## RFCを読む: RFC 7009 2.1節

> The authorization server first validates the client credentials (in case of a confidential client) and then verifies whether the token was issued to the client making the revocation request. If this validation fails, the request is refused and the client is informed of the error by the authorization server as described below.

(RFC 7009 2.1節)

この節は失効リクエストの処理を定めています。リクエストのパラメータは、必須の `token` と任意の `token_type_hint` で、クライアント認証の資格情報も付けます。認可サーバは、機密クライアントであればまず資格情報を検証し、次にそのトークンが要求元のクライアントに発行されたものかを確認します。他のクライアントのトークンを失効させることはできません。

同じ節は、失効は即時に行われ、失効後のトークンは再び使えないと述べています。ただし、複数のサーバの間で失効の情報が伝わるまでに遅延がありうることも認めています。さらに、リフレッシュトークンを失効させた場合、認可サーバがアクセストークンの失効をサポートしているなら、同じ認可に基づくすべてのアクセストークンも無効にすべきです(SHOULD)。アクセストークンを失効させた場合に、対応するリフレッシュトークンも失効させてもかまいません(MAY)。2節の冒頭は、実装はリフレッシュトークンの失効をサポートしなければならず(MUST)、アクセストークンの失効をサポートすべきだ(SHOULD)と定めています。

2.2節は応答を定めています。失効に成功した場合だけでなく、クライアントが無効なトークンを送った場合も、認可サーバは 200 を返します。同節は理由を、クライアントはそのエラーを合理的に処理できず、トークンを無効にするという目的は既に達成されているからだと説明しています。

失効とトークンの形式の関係が、この章の要点の1つです。不透明トークンは、イントロスペクションの時点で認可サーバの記録を参照するため、失効が反映されます。自己完結型の JWT アクセストークンを、失効状態を確認しないローカル検証だけで受け入れるリソースサーバは、認可サーバでの失効を検出できません。この構成では、JWT アクセストークンは失効させても `exp` まで使えます。RFC 7009 の3節(実装上の注記)は、即時の失効が必要な場合に、認可サーバとリソースサーバの間のバックエンドでの連携(標準化されていません)を使ってもよいと述べています。同節は別の設計として、短寿命のアクセストークンをリフレッシュトークンで更新する方法を挙げています。JWT アクセストークンの有効期限を短く(数分程度に)するのは後者の設計であり、長い利用期間は次章のリフレッシュトークンで補います。

## 実験: イントロスペクションのキャッシュと失効

認可サーバ、リソースサーバ、クライアントを1つのプロセスの中で関数として再現し、イントロスペクションの応答と、キャッシュと失効の時間差を確かめます。リソースサーバは応答を最大60秒キャッシュします。応答に `exp` がある場合、キャッシュの期限は「取得時刻+60秒」と `exp` の早いほうです。RFC 7662 4節が、応答に `exp` があればその時刻を超えてキャッシュしてはならない(MUST NOT)と定めているためです。失効エンドポイントは、クライアントの資格情報を検証し、要求元のクライアントに発行したトークンだけを失効させます。時刻は秒単位の模擬時計で、出力は実行ごとに変わりません。

<RustPlay snippet="ch14/introspection" title="イントロスペクションの応答と、キャッシュが失効を遅らせる時間" />

[1] の1行目は有効なトークンの応答で、`active` が `true` になり、`sub`、`scope`、`aud` などが返ります。存在しないトークンと、別のリソースサーバ宛てのトークンは、どちらも `{"active":false}` だけが返り、区別できません。RFC 7662 2.2節の規定どおりです。資格情報なしの呼び出しは 401 で拒否されます。この拒否がトークンスキャン攻撃への対策です。

[2] がキャッシュと失効の時間差です。t=0 でリソースサーバがイントロスペクションを行い、結果をキャッシュします。t=5 の2行は、失効の要求が拒否される場合です。誤った資格情報で送った要求は `401 invalid_client` で拒否されます。正しい資格情報を持つ別のクライアント `other-client` の要求は、トークンが `other-client` に発行されたものではないため、400 で拒否されます。RFC 7009 2.1節が定める2つの検査の結果です。RFC 7009 はこの場合の専用のエラーコードを定めていないため、実験では状態コードと理由だけを返しています。t=10 で、トークンの発行先である `s6BhdRkqt3` がトークンを失効させ、認可サーバは 200 を返します。しかし t=20 と t=59 では、リソースサーバはキャッシュした `active: true` を使ってリクエストを受け入れます。キャッシュの期限を過ぎた t=61 で初めて認可サーバに問い合わせ、失効を検出して 401 を返します。

キャッシュの期限(この実験では60秒)が、失効が反映されるまでの最大の遅れになります。キャッシュしなければ遅れはなくなりますが、すべてのリクエストで認可サーバへの通信が発生します。JWT アクセストークンは、この期限がトークンの有効期限全体に広がった状態と見ることができます。キャッシュの期限は、失効の遅れとして許容できる時間と、認可サーバの負荷の兼ね合いで決めます。[2] の最後の行は、失効エンドポイントに無効なトークンを送っても 200 が返ることを示しています。

[3] は `exp` が30のトークンです。キャッシュの期限は60秒ではなく30秒になるため、t=29 まではキャッシュを使い、t=30 で認可サーバに問い合わせて `active: false` を受け取ります。`exp` を超えてキャッシュする実装は、認可サーバでの失効の有無とは無関係に、期限切れのトークンを受け入れます。

## Resource Indicators と audience

アクセストークンを受け入れるべきリソースサーバを示す値を、本書では JWT のクレーム名に合わせて **audience**(オーディエンス、宛先)と呼びます。宛先を限定しないアクセストークンは、受け取ったどのリソースサーバでも使えます。この性質は攻撃に使えます。

クライアントが注文 API と、別の組織が運用する広告 API の両方を呼ぶ場合を考えます。両方に同じアクセストークンを送ると、広告 API の運用者(または広告 API に侵入した攻撃者)は、受け取ったトークンを注文 API に送り、利用者として注文を操作できます。RFC 9700 はこの問題について次のように推奨しています。

> In particular, access tokens SHOULD be audience-restricted to a specific resource server or, if that is not feasible, to a small set of resource servers.

(RFC 9700 2.3節)

アクセストークンは特定のリソースサーバに宛先を制限すべきであり(SHOULD)、それが難しい場合も少数のリソースサーバに限定すべきです。同じ節は、宛先が自分でないトークンを受け取ったリソースサーバは、そのリクエストを拒否しなければならない(MUST)と定めています。

宛先を制限するには、クライアントがどのリソースサーバ向けのトークンが欲しいかを認可サーバに伝える必要があります。**Resource Indicators**(リソース指示子、RFC 8707)は、そのための `resource`(resource パラメータ)を定めた仕様です。

次のリクエストは RFC 8707 2.2節の例で、クライアントは `https://cal.example.com/` で使うアクセストークンを要求しています。

```http
POST /as/token.oauth2 HTTP/1.1
Host: authorization-server.example.com
Authorization: Basic czZCaGRSa3F0Mzpoc3FFelFsVW9IQUU5cHg0RlNyNHlJ
Content-Type: application/x-www-form-urlencoded

grant_type=authorization_code
&redirect_uri=https%3A%2F%2Fclient.example.org%2Fcb
&code=10esc29BWC2qZB0acc9v8zAv9ltc2pko105tQauZ
&resource=https%3A%2F%2Fcal.example.com%2F
```

## RFCを読む: RFC 8707 2節

> resource
> Indicates the target service or resource to which access is being requested. Its value MUST be an absolute URI, as specified by Section 4.3 of [RFC3986]. The URI MUST NOT include a fragment component. It SHOULD NOT include a query component, but it is recognized that there are cases that make a query component a useful and necessary part of the resource parameter, such as when one or more query parameters are used to scope requests to an application.

(RFC 8707 2節)

この節は、`resource` パラメータの値を定めています。値は絶対 URI でなければなりません(MUST)。フラグメントを含めてはならず(MUST NOT)、クエリも含めるべきではありません(SHOULD NOT)。ただしクエリでアプリケーションを区別する場合のように、クエリが必要な場合もあると認めています。同じ節は、複数の `resource` パラメータを指定して、複数のリソースで使うトークンを要求してもかまわない(MAY)としています。クライアントは、API の基底 URI のように、アクセスしたい範囲を表す最も具体的な URI を使うべきです(SHOULD)。

`https://api.example.com/` は、そのホストで提供される唯一のアプリケーションを示す値の例です。同じホストに複数のアプリケーションがある場合は `https://api.example.com/app/` のように、より具体的な値を使います。

> The authorization server SHOULD audience-restrict issued access tokens to the resource(s) indicated by the "resource" parameter.

(RFC 8707 2節)

認可サーバは、発行するアクセストークンの宛先を、`resource` パラメータで示されたリソースに制限すべきです(SHOULD)。JWT では `aud` クレームで、イントロスペクションでは応答の `aud` メンバーで宛先を伝えます。認可サーバは `resource` の値をそのまま `aud` に使ってもよく、より抽象的な識別子に対応づけてもかまいません。要求された `resource` が不正、未知、または許可されない場合、認可サーバは `invalid_target`(invalid_target エラーコード)を返します。

2.1節と2.2節によれば、`resource` は認可リクエストとトークンリクエストの両方で使えます。認可リクエストの `resource` は、認可(認可コードで表される権限全体)の対象を示します。トークンリクエストの `resource` は、今回発行するトークンを使う先を示し、認可で同意された範囲の部分集合を指定できます。クライアントは、注文 API と決済 API の両方について1回の認可で同意を得たうえで、リフレッシュトークンを使って API ごとに宛先を限定したトークンを別々に取得できます。

## Protected Resource Metadata

ここまでの説明では、クライアントは「どの認可サーバからトークンを取得すればよいか」をあらかじめ設定されている前提でした。[10章](/rust-impl/10-discovery-jwks/)の Discovery は、認可サーバ(OP)が自分のメタデータを公開する仕組みでした。**Protected Resource Metadata**(保護されたリソースのメタデータ、RFC 9728)は、リソースサーバが同様に自分のメタデータを公開する仕組みで、2025年4月に RFC になりました。

```mermaid
sequenceDiagram
    participant C as クライアント
    participant RS as リソースサーバ
    participant AS as 認可サーバ
    C->>RS: GET /orders (トークンなし)
    RS-->>C: 401 WWW-Authenticate: Bearer resource_metadata="..."
    C->>RS: GET /.well-known/oauth-protected-resource/orders
    RS-->>C: {"resource": "...", "authorization_servers": [...]}
    C->>C: resource が要求先の URL と一致するか確認
    C->>AS: GET /.well-known/oauth-authorization-server
    AS-->>C: 認可サーバのメタデータ
    Note over C,AS: 認可コードフローでトークンを取得 (resource を指定)
    C->>RS: GET /orders (Authorization: Bearer ...)
    RS-->>C: 200 OK
```

リソースサーバは、トークンのないリクエストに 401 を返すとき、`WWW-Authenticate` ヘッダの `resource_metadata`(resource_metadata パラメータ)でメタデータの URL を示せます。

```http
HTTP/1.1 401 Unauthorized
WWW-Authenticate: Bearer resource_metadata="https://api.example.com/.well-known/oauth-protected-resource/orders"
```

メタデータの URL は、リソース識別子のホストとパスの間に `/.well-known/oauth-protected-resource` を挿入して作ります。リソース識別子が `https://api.example.com/orders` なら、メタデータは `https://api.example.com/.well-known/oauth-protected-resource/orders` にあります。

```http
HTTP/1.1 200 OK
Content-Type: application/json

{
 "resource": "https://api.example.com/orders",
 "authorization_servers": ["https://as.example.com"],
 "bearer_methods_supported": ["header"],
 "scopes_supported": ["orders:read", "orders:write"]
}
```

`resource` は必須で、リソースサーバの識別子です。`authorization_servers` は、このリソースのトークンを発行できる認可サーバの issuer 識別子の一覧です。`bearer_methods_supported` は、Bearer トークンの送り方のうち受け付けるものを示します。

RFC 9728 3.3節は、取得したメタデータの `resource` が、メタデータの URL を作るのに使ったリソース識別子と同一でなければならず(MUST)、一致しなければメタデータを使ってはならない(MUST NOT)と定めています。`WWW-Authenticate` から URL を得た場合は、`resource` がクライアントがリクエストを送った URL と同一でなければなりません(MUST)。攻撃者のリソースサーバが、正規のリソースサーバの識別子を名乗るメタデータを返す攻撃を、この検査で防ぎます。

RFC 9728 7.4節は、この仕組みと宛先の制限の関係を述べています。宛先を制限しない構成では、悪意のあるリソースサーバが `WWW-Authenticate` を使ってクライアントに正規のリソースサーバのスコープでトークンを取得させ、送られてきたトークンを正規のリソースサーバで使えます。そのため、RFC 9728 を使う場合は Resource Indicators による宛先の制限が推奨されています(RECOMMENDED)。クライアントがリソースサーバの指示で接続先の認可サーバを決める構成は、AI エージェントが MCP サーバに接続する場面で使われており、[27章](/practice/27-ecosystem/)で扱います。

## スコープの検査とその先の認可

トークンの検証に成功した後、リソースサーバは、そのリクエストを許可するかを判断します。最初の判断はスコープです。エンドポイントごとに必要なスコープを決め、トークンの `scope` に含まれていなければ 403 と `insufficient_scope` を返します。

スコープの検査だけでは足りない場合があります。`orders:read` スコープを持つトークンで `GET /orders/123` が要求されたとき、スコープが表すのは「クライアントに委譲された操作の種類」であり、注文123がトークンの `sub` の利用者のものかどうかは表しません。「どのデータに対して操作できるか」は、リソースサーバが自分のデータと `sub` を照合して判断します。この照合を省くと、利用者 A のトークンで利用者 B の注文が読めます。

判断に使う情報の出所も確認します。`sub`、`client_id`、`scope` は署名で保護されたクレームから取り、リクエストのクエリや本文で送られた利用者 ID を信用しません。JWT アクセストークンの `sub` は、`iss` と組み合わせて初めて一意になります。この点は[18章](/oidc-deep/18-claims-identity/)で ID トークンについて詳しく扱います。

## まとめ

- アクセストークンには、認可サーバへの問い合わせで検証する不透明トークンと、署名で検証する自己完結型トークンがあります。JWT は中身がクライアントから見えますが、クライアントはその中身に依存してはなりません
- RFC 9068 は、`typ` が `at+jwt` であること、`iss` の完全一致、`aud` に自分が含まれること、署名、`exp` の検証を求めています。`alg` は許可リストで固定します
- `typ` の検査は、同じ鍵で署名された ID トークンを拒否します。実験では、ID トークン、別の宛先のトークン、期限切れ、`alg=none` がすべて 401 になりました
- イントロスペクションは呼び出し元の認証を必須とし、無効なトークンには理由を示さずに `{"active": false}` を返します。失効エンドポイントは機密クライアントの資格情報を検証し、要求元に発行したトークンだけを失効させます。無効なトークンには 200 を返します
- イントロスペクション結果をキャッシュすると、失効の反映はキャッシュの期限まで遅れます。実験では、失効の10秒後と49秒後のリクエストが受け入れられました。キャッシュの期限は応答の `exp` を超えてはなりません。失効状態を確認せずにローカル検証する JWT アクセストークンでは遅れが有効期限全体に及ぶため、有効期限を短くします
- Resource Indicators の `resource` パラメータで宛先を指定し、リソースサーバは `aud` で自分宛てであることを確認します。Protected Resource Metadata は、リソースサーバから認可サーバを発見する仕組みです

次章では、短い有効期限のアクセストークンを補うリフレッシュトークンを扱います。リフレッシュトークンの寿命の設計と、盗まれたリフレッシュトークンをローテーションで検知する方法を実験で確かめます。
