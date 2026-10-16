---
title: 認可コード以外のグラント
description: クライアントクレデンシャル、JWTベアラーグラント、デバイス認可グラントとポーリング、トークン交換による委任となりすまし、CIBA、ROPCが廃止される理由、クロスデバイスフローのBCP(RFC 10027)。
sidebar:
  label: 20. 認可コード以外のグラント
---

この章でわかること:

- 利用者が関与しないサーバ間の通信に使うクライアントクレデンシャルグラントと、JWTベアラーグラント
- 入力手段の少ない端末のためのデバイス認可グラントの手順と、ポーリングの規則(`authorization_pending`と`slow_down`)
- トークン交換における委任となりすましの違いと、`act`クレームの読み方
- CIBAの仕組みと、クロスデバイスフローが同意のフィッシングに弱い理由(RFC 10027)、ROPCが廃止される理由
- なぜ体系に必須か: OAuthのグラントは拡張できるように設計されており、基礎編の認可コードフローはその1つにすぎません。サーバ間の連携、テレビやCLI、マイクロサービスの連鎖では別のグラントが使われ、それぞれに固有の攻撃があります

## グラントの一覧

[2章](/web-auth/02-delegation/)で、クライアントがアクセストークンを得るための資格を権限付与(authorization grant)と呼び、[3章](/web-auth/03-authorization-code/)でトークンリクエストの`grant_type`がその種類を示すことを説明しました。RFC 6749は4種類のグラントを定め、4.5節で新しいグラントを追加する方法も定めています。

> The client uses an extension grant type by specifying the grant type using an absolute URI (defined by the authorization server) as the value of the "grant_type" parameter of the token endpoint, and by adding any additional parameters necessary.

(RFC 6749 4.5節)

この節は、`grant_type`の値に絶対URIを指定し、必要なパラメータを追加することで、新しい種類のグラントを使えることを定めています。この方法で追加されたグラントを**拡張グラント**(extension grant)と呼びます。この章で扱うグラントの多くは拡張グラントです。

| グラント | `grant_type` | 定義 |
| --- | --- | --- |
| クライアントクレデンシャル | `client_credentials` | RFC 6749 4.4節 |
| JWTベアラー | `urn:ietf:params:oauth:grant-type:jwt-bearer` | RFC 7523 2.1節 |
| デバイス認可 | `urn:ietf:params:oauth:grant-type:device_code` | RFC 8628 3.4節 |
| トークン交換 | `urn:ietf:params:oauth:grant-type:token-exchange` | RFC 8693 2.1節 |
| CIBA | `urn:openid:params:grant-type:ciba` | CIBA Core 1.0 10.1節 |
| ROPC | `password` | RFC 6749 4.3節(廃止) |

## クライアントクレデンシャルグラント

**クライアントクレデンシャルグラント**(client credentials grant)は、クライアントが自分自身の資格情報だけでアクセストークンを得るグラントです。利用者は関与しません。夜間のバッチ処理が自社の別のAPIを呼ぶ場合のように、クライアントが自分の権限でリソースにアクセスする場面で使います。

## RFCを読む: RFC 6749 4.4節

> The client can request an access token using only its client credentials (or other supported means of authentication) when the client is requesting access to the protected resources under its control, or those of another resource owner that have been previously arranged with the authorization server (the method of which is beyond the scope of this specification).
>
> The client credentials grant type MUST only be used by confidential clients.

(RFC 6749 4.4節)

この節は、クライアントクレデンシャルグラントを使える場面と、使えるクライアントを定めています。対象は、クライアント自身が管理する保護されたリソースか、別のリソースオーナーのリソースのうち認可サーバとの間で事前に取り決めたものです。このグラントは機密クライアント([13章](/oauth-deep/13-client-auth/))だけが使わなければなりません(MUST)。クライアント認証そのものが権限付与の役割を持つので、資格情報を安全に保持できないパブリッククライアントには意味がないからです。

リクエストは、トークンエンドポイントへのPOSTです。

```http
POST /token HTTP/1.1
Host: server.example.com
Authorization: Basic czZCaGRSa3F0MzpnWDFmQmF0M2JW
Content-Type: application/x-www-form-urlencoded

grant_type=client_credentials&scope=reports%3Aread
```

4.4.3節は、応答にリフレッシュトークンを含めるべきではない(SHOULD NOT)と定めています。クライアントはいつでも同じ方法で新しいアクセストークンを取得できるので、リフレッシュトークンを持たせる理由がないからです。利用者が認証されていないので、OpenID ConnectのIDトークンも発行されません。

注意点は、リソースサーバがアクセストークンの`sub`を読む場合にあります。RFC 9700 4.15節は、[14章](/oauth-deep/14-token-validation/)のJWTアクセストークン(RFC 9068)では、利用者が関与するグラントの`sub`は利用者の識別子、クライアントクレデンシャルグラントの`sub`はクライアントの識別子になると指摘しています。クライアントが登録時に自分の`client_id`を選べる場合、攻撃者は`client_id`を特定の利用者の`sub`と同じ値にして登録し、クライアントクレデンシャルで得たトークンでその利用者のリソースにアクセスしようとします。

> Authorization servers SHOULD NOT allow clients to influence their client_id or any other claim that could cause confusion with a genuine resource owner if a common namespace for client IDs and user identifiers exists [...]. Where this cannot be avoided, authorization servers MUST provide other means for the resource server to distinguish between the two types of access tokens.

(RFC 9700 4.15.1節)

認可サーバは、`client_id`と利用者の識別子が同じ名前空間にある場合、クライアントが自分の`client_id`を選べるようにすべきではありません(SHOULD NOT)。避けられない場合は、2種類のアクセストークンをリソースサーバが区別できる別の手段を提供しなければなりません(MUST)。

## JWTベアラーグラント

**JWTベアラーグラント**(JWT bearer grant)は、信頼できる発行者が署名したJWTを提示して、アクセストークンを得るグラントです。RFC 7523(2015-05)が定めています。JWTの発行者は、別のIdPや、組織内の認証基盤などです。クライアントは、その発行者が「この主体についてトークンを発行してよい」と主張するJWTを認可サーバに渡します。

[13章](/oauth-deep/13-client-auth/)の`private_key_jwt`も、同じRFC 7523の2.2節が定めるJWTです。2つの違いは用途にあります。2.2節のJWTは「このリクエストを送っているのはこのクライアントである」というクライアント認証に使い、2.1節のJWTは「この主体についてアクセストークンを発行してよい」という権限付与に使います。

## RFCを読む: RFC 7523 2.1節・3節

> The value of the "grant_type" is "urn:ietf:params:oauth:grant-type:jwt-bearer".
>
> The value of the "assertion" parameter MUST contain a single JWT.

(RFC 7523 2.1節)

この節は、JWTベアラーグラントのトークンリクエストの形を定めています。`grant_type`は`urn:ietf:params:oauth:grant-type:jwt-bearer`で、`assertion`パラメータにはJWTを1つだけ入れなければなりません(MUST)。クライアント認証は任意です。

```http
POST /token.oauth2 HTTP/1.1
Host: as.example.com
Content-Type: application/x-www-form-urlencoded

grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer
&assertion=eyJhbGciOiJFUzI1NiIsImtpZCI6IjE2In0.eyJpc3Mi[...].J9l-ZhwP[...]
```

認可サーバがJWTを受け付ける条件は3節に10項目あります。要点は次のとおりです。

- `iss`を含まなければならず(MUST)、比較はRFC 3986 6.2.1節の単純な文字列比較で行います
- `sub`を含まなければなりません(MUST)。権限付与の場合、`sub`はアクセストークンを求める対象の主体(リソースオーナーなど)です
- `aud`に認可サーバ自身を示す値を含まなければならず(MUST)、含まないJWTを拒否しなければなりません(MUST)
- `exp`を含まなければならず(MUST)、期限切れのJWTを拒否しなければなりません(MUST)
- 署名またはMACがなければならず(MUST)、不正な署名のJWTを拒否しなければなりません(MUST)
- `jti`は任意(MAY)ですが、使われた`jti`を有効期限まで記録して再送を防いでもかまいません(MAY)

これらは、[8章](/oidc/08-id-token-validation/)のIDトークンの検証とほぼ同じ構造です。JWTベアラーグラントでは、検証に失敗したJWTを受け付けると、攻撃者は任意の`sub`のアクセストークンを得られます。発行者ごとに、どの`sub`についての発行を認めるかの方針を認可サーバ側に持つ必要があります。

## デバイス認可グラント

テレビ、ゲーム機、プリンタ、コマンドラインのツールには、ブラウザがないか、文字の入力が難しいものがあります。**デバイス認可グラント**(device authorization grant)は、このような端末が、利用者に別の端末(スマートフォンやPC)のブラウザで認可してもらい、アクセストークンを得るグラントです。RFC 8628(2019-08)が定めています。

```mermaid
sequenceDiagram
    participant 端末 as 端末(テレビ)
    participant AS as 認可サーバ
    participant スマートフォン as スマートフォンのブラウザ
    端末->>AS: POST /device_authorization (client_id、scope)
    AS-->>端末: device_code、user_code、verification_uri、interval
    端末->>端末: 画面に verification_uri と user_code を表示
    loop interval 秒ごと
        端末->>AS: POST /token (grant_type=...device_code、device_code)
        AS-->>端末: 400 authorization_pending
    end
    スマートフォン->>AS: verification_uri を開き、ログインして user_code を入力
    AS->>スマートフォン: 「この端末を許可しますか」
    スマートフォン->>AS: 許可
    端末->>AS: POST /token (device_code)
    AS-->>端末: 200 access_token
```

図の2行目で、認可サーバは2つのコードを返します。`device_code`は端末だけが保持する長いコード、`user_code`は利用者が入力する短いコードです。端末は認可サーバと直接通信しますが、スマートフォンと端末の間には直接の通信がありません。2つの端末の間の情報の受け渡しは、利用者が画面のコードを読んで別の端末に入力する操作だけで行われます。この点が、章の後半のクロスデバイスフローの問題につながります。

## RFCを読む: RFC 8628 3.1節〜3.5節

3.1節は、新しいエンドポイントであるデバイス認可エンドポイントを定めています。端末はここに`client_id`と`scope`をPOSTします。

```http
POST /device_authorization HTTP/1.1
Host: server.example.com
Content-Type: application/x-www-form-urlencoded

client_id=1406020730&scope=example_scope
```

同じ節は、端末はデバイス認可リクエストを利用者の操作を受けて開始すべきであり、アプリの起動時に自動で開始すべきではない(SHOULD)と定めています。このフローはポーリングでトークンエンドポイントの負荷を増やすからです。

3.2節の応答のパラメータは次のとおりです。

- `device_code`(device_code パラメータ): 端末がトークンリクエストに使う検証コードです。必須です
- `user_code`(user_code パラメータ): 利用者が入力するコードです。必須です
- `verification_uri`(verification_uri パラメータ): 利用者がブラウザで開く認可サーバのURIです。必須で、利用者が手で入力するので短く覚えやすくすべきとされています
- `verification_uri_complete`: `user_code`を含めたURIです。任意で、QRコードなどで渡すために使います
- `expires_in`: 2つのコードの有効期間(秒)です。必須です
- `interval`: ポーリングの最小間隔(秒)です。任意で、省略時はクライアントは5を使わなければなりません(MUST)

```http
HTTP/1.1 200 OK
Content-Type: application/json
Cache-Control: no-store

{
  "device_code": "GmRhmhcxhwAzkoEqiMEg_DnyEysNkuNhszIySk9eS",
  "user_code": "WDJB-MJHT",
  "verification_uri": "https://example.com/device",
  "verification_uri_complete": "https://example.com/device?user_code=WDJB-MJHT",
  "expires_in": 1800,
  "interval": 5
}
```

3.4節で、端末は`grant_type=urn:ietf:params:oauth:grant-type:device_code`と`device_code`をトークンエンドポイントに送ります。クライアント認証を行わないクライアントは、`client_id`も含めなければなりません(REQUIRED)。資格情報を発行されたクライアントは、RFC 6749 3.2.1節の方法で認可サーバに認証しなければなりません(MUST)。利用者が操作を終えるまで、端末はこのリクエストを繰り返します。このように、状態が変わったかを一定間隔で問い合わせ続ける方式を**ポーリング**(polling)と呼びます。

3.5節は、ポーリング中のエラーコードを定めています。

> authorization_pending: The authorization request is still pending as the end user hasn't yet completed the user-interaction steps (Section 3.3). The client SHOULD repeat the access token request to the token endpoint (a process known as polling). Before each new request, the client MUST wait at least the number of seconds specified by the "interval" parameter of the device authorization response (see Section 3.2), or 5 seconds if none was provided, and respect any increase in the polling interval required by the "slow_down" error.
>
> slow_down: A variant of "authorization_pending", the authorization request is still pending and polling should continue, but the interval MUST be increased by 5 seconds for this and all subsequent requests.

(RFC 8628 3.5節)

`authorization_pending`(authorization_pending エラー)は、利用者がまだ操作を終えていないことを示します。クライアントは問い合わせを繰り返すべきです(SHOULD)が、毎回`interval`秒(省略時は5秒)以上待たなければなりません(MUST)。`slow_down`(slow_down エラー)は`authorization_pending`の一種で、問い合わせが速すぎることを示します。クライアントは、このリクエストとそれ以降のすべてのリクエストで、間隔を5秒増やさなければなりません(MUST)。ほかに、利用者が拒否した`access_denied`と、`device_code`の期限が切れた`expired_token`があります。ポーリングを続けるのは`authorization_pending`と`slow_down`を受け取った場合だけです。`access_denied`や`expired_token`を含め、それ以外のエラーを受け取ったら、クライアントはポーリングを止めなければなりません(MUST)。

### 実験: デバイス認可グラントのポーリング

認可サーバと端末を1つのプロセスで再現します。時刻は秒を数える変数で進め、実時間は使いません。確かめる点は次の3つです。

- `interval`に従う端末が、利用者の承認後にトークンを得るまでの流れを確かめます
- 2秒ごとに問い合わせる端末が`slow_down`を受け取り、間隔を延ばす様子を確かめます
- 承認されないまま`expires_in`を過ぎた場合の応答を確かめます

<RustPlay snippet="ch20/device-flow" title="デバイス認可グラントのポーリングとslow_down" />

`user_code`は実行のたびに乱数で生成するため、出力のコードは実行ごとに変わります。それ以外の流れは毎回同じです。

1つ目の端末は、5秒ごとに`authorization_pending`を受け取り、利用者が12秒の時点で承認した後の15秒でトークンを得ます。利用者は`user_code`を小文字で空白を入れて入力していますが、照合は成功します。RFC 8628 6.1節は、認可サーバが読みやすさのために加えた区切り文字を取り除き、A〜Zだけの文字集合なら大文字にそろえてから比較すべきとしています。実験の認可サーバは、そのとおりに正規化しています。

2つ目の端末は、2秒目の問い合わせは受け付けられますが、4秒目の問い合わせで`slow_down`を受け取ります。認可サーバは間隔を10秒に延ばし、端末も同じだけ延ばします。以降の応答は`authorization_pending`だけになり、端末は承認後の34秒でトークンを得ます。3つ目は、1800秒の時点で`expired_token`になります。

最後の行は、`user_code`の空間の大きさです。`BCDFGHJKLMNPQRSTVWXZ`の20文字から8文字を選ぶので、20^8 = 256億通り、約34.6ビットです。

## デバイス認可グラントの攻撃面

RFC 8628 5節は、このフロー固有の攻撃を挙げています。

5.1節は`user_code`の総当たりを扱っています。`user_code`は人が入力するので短く、エントロピーが低くなります。5.1節は、8文字のbase20のコード(約34.5ビット)の場合、総当たりで当てられる確率を2^-32に抑えるには、試行を5回までに制限する必要があると計算しています。認可サーバは`user_code`の試行回数を制限することが推奨されています。攻撃者が総当たりで他人の`user_code`を当てると、被害者の端末が攻撃者のアカウントに結びつきます。5.1節は、これは被害者の権限が奪われる通常の総当たりとは逆向きの結果であると指摘しつつ、端末の操作権を得られる用途ではやはり保護が必要だと述べています。

5.2節は`device_code`の総当たりを扱っています。`device_code`は利用者に見せないので長くでき、非常に高いエントロピーにすべき(SHOULD)とされています。実験では32バイトの乱数を使いました。

5.4節は遠隔からのフィッシングを扱っています。攻撃者が自分の端末でフローを開始し、得た`user_code`をメールで被害者に送り、「このコードを入力してください」と誘導します。被害者が入力して承認すると、攻撃者の端末が被害者の権限のトークンを得ます。5.4節は、利用者に端末を認可しようとしていることを伝え、その端末を利用者自身が所持しているかを確認するよう推奨しています(RECOMMENDED)。この攻撃は、章の後半でRFC 10027として体系的に扱われます。

## トークン交換

マイクロサービスの構成では、利用者のアクセストークンを受け取ったAPI(フロントエンドAPI)が、さらに別のAPI(バックエンドAPI)を呼ぶことがあります。受け取ったトークンをそのまま転送すると、バックエンドAPIはフロントエンドAPI宛ての`aud`を持つトークンを受け入れることになり、[14章](/oauth-deep/14-token-validation/)の`aud`の検証と矛盾します。

**トークン交換**(token exchange)は、保持しているトークンを認可サーバに提示し、別の宛先や別の形式のトークンと交換するグラントです。RFC 8693(2020-01)が定めています。RFC 8693は、この交換を行うサービスを**STS**(security token service)と呼びます。

## RFCを読む: RFC 8693 1.1節

1.1節は、トークン交換の2つの意味づけを区別しています。

> When principal A impersonates principal B, A is given all the rights that B has within some defined rights context and is indistinguishable from B in that context.

(RFC 8693 1.1節)

**なりすまし**(impersonation)の意味づけでは、主体Aは、定められた権限の範囲の中でBの権限をすべて与えられ、その範囲ではBと区別できません。トークンを受け取る側から見ると、相手はBそのものです。

> With delegation semantics, principal A still has its own identity separate from B, and it is explicitly understood that while B may have delegated some of its rights to A, any actions taken are being taken by A representing B.

(RFC 8693 1.1節)

**委任**(delegation)の意味づけでは、AはBとは別の自分の識別子を保ったまま、Bから一部の権限を委ねられ、Bを代表して行動します。トークンには、主体であるBと、行動しているAの両方の情報が入ります。[2章](/web-auth/02-delegation/)で説明したOAuthの委譲は、リソースオーナーがクライアントに権限を委ねる関係でした。RFC 8693の委任は、その関係をサービスの連鎖の中でトークンに明示する方法です。

なりすましでは、バックエンドAPIが受け取るトークンの主体は利用者であり、権限の上では利用者本人として扱われます。フロントエンドAPIが行動したことを示す`act`はありません。トークンを要求したクライアントの識別子は、RFC 8693 4.3節の`client_id`クレームとして残ることがあります。ただし`client_id`は要求したクライアントを示すだけで、誰を代表して行動したかの関係は表しません。このため、アクセス制御や監査ログでは利用者本人の操作と同じに扱われやすく、フロントエンドAPIが侵害されて不正な呼び出しをしても区別が難しくなります。委任では、誰が誰を代表して呼んだかが`act`としてトークンに残ります。

## RFCを読む: RFC 8693 2.1節・2.2節

2.1節のリクエストの主なパラメータは次のとおりです。

- `grant_type`: `urn:ietf:params:oauth:grant-type:token-exchange`です。必須です
- `subject_token`(subject_token パラメータ): 誰のためにリクエストしているかを表すトークンです。必須で、通常、発行されるトークンの主体はこのトークンの主体になります
- `subject_token_type`: `subject_token`の種類を示すURIです。必須です。アクセストークンなら`urn:ietf:params:oauth:token-type:access_token`です
- `actor_token`(actor_token パラメータ): 行動する主体を表すトークンです。任意で、委任のときに使います
- `actor_token_type`: `actor_token`がある場合は必須で、ない場合は含めてはなりません(MUST NOT)
- `resource`、`audience`: 発行するトークンを使う先です。`resource`は絶対URI、`audience`は論理名です
- `scope`、`requested_token_type`: 求める権限の範囲と、トークンの種類です

RFC 8693 2.3節の例は、リソースサーバがクライアントの役割を兼ね、受け取ったアクセストークンをバックエンド向けのトークンに交換するものです。

```http
POST /as/token.oauth2 HTTP/1.1
Host: as.example.com
Authorization: Basic cnMwODpsb25nLXNlY3VyZS1yYW5kb20tc2VjcmV0
Content-Type: application/x-www-form-urlencoded

grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Atoken-exchange
&resource=https%3A%2F%2Fbackend.example.com%2Fapi
&subject_token=accVkjcJyb4BWCxGsndESCJQbdFMogUC5PbRDqceLTC
&subject_token_type=urn%3Aietf%3Aparams%3Aoauth%3Atoken-type%3Aaccess_token
```

```http
HTTP/1.1 200 OK
Content-Type: application/json
Cache-Control: no-cache, no-store

{
  "access_token": "eyJhbGciOiJFUzI1NiIsImtpZCI6IjllciJ9...",
  "issued_token_type": "urn:ietf:params:oauth:token-type:access_token",
  "token_type": "Bearer",
  "expires_in": 60
}
```

応答の`issued_token_type`は発行したトークンの種類、`token_type`はその使い方([4章](/web-auth/04-tokens/))です。発行したものがアクセストークンとして使えない場合は、`token_type`に`N_A`を入れます。2.2.2節は、トークンが無効な場合や方針上受け付けられない場合は`invalid_request`を、指定された宛先にトークンを発行できない場合は`invalid_target`を使うと定めています。

2.1節は、クライアント認証について次の注意を書いています。

> Note that omitting client authentication allows for a compromised token to be leveraged via an STS into other tokens by anyone possessing the compromised token.

(RFC 8693 2.1節)

クライアント認証を省略すると、漏洩したトークンを持つ誰もが、STSを通じてそのトークンを別のトークンに交換できます。トークン交換のクライアントは、[13章](/oauth-deep/13-client-auth/)の方法で認証させ、どのクライアントがどの宛先への交換を許されるかを認可サーバ側で管理します。

## RFCを読む: RFC 8693 4.1節

`act`(act クレーム)は、委任が行われたことと、行動している主体をJWTの中で表すクレームです。

> A chain of delegation can be expressed by nesting one "act" claim within another. The outermost "act" claim represents the current actor while nested "act" claims represent prior actors.
>
> For the purpose of applying access control policy, the consumer of a token MUST only consider the token's top-level claims and the party identified as the current actor by the "act" claim. Prior actors identified by any nested "act" claims are informational only and are not to be considered in access control decisions.

(RFC 8693 4.1節)

`act`を入れ子にすると、委任の連鎖を表せます。最も外側の`act`が現在のアクターで、内側の`act`は過去のアクターです。トークンを受け取る側は、アクセス制御の判断に、トークンの最上位のクレームと現在のアクターだけを使わなければなりません(MUST)。入れ子の内側のアクターは情報として記録するだけで、判断に使ってはなりません。`act`の中の`exp`や`aud`は意味を持たないので使われません。

4.4節の`may_act`(may_act クレーム)は逆向きの宣言で、「このトークンの主体を代表して行動してよい主体」を`subject_token`の中に書いておくクレームです。認可サーバは、交換の要求者や`actor_token`の主体がそこに書かれているかを確かめられます。

### 実験: なりすましと委任のトークン交換

認可サーバのトークン交換を実装し、4つの交換を試します。

1. `actor_token`なしで交換します(なりすまし)
2. `actor_token`ありで交換します(委任)
3. 委任で得たトークンを、バックエンドがさらに交換します(連鎖)
4. `may_act`にない主体による交換、許可されていない宛先への交換、トークンの種類を示すパラメータが規則に反する交換を試します

トークンの署名と検証は省略し、発行済みトークンの値と検証済みのクレームの対応表で代用しています。署名と検証は、[7章](/oidc/07-jwt-jose/)と[8章](/oidc/08-id-token-validation/)の方法で行う前提です。

<RustPlay snippet="ch20/token-exchange" title="actor_tokenの有無で発行されるトークンを比べる" />

出力の読み方は次のとおりです。

1. なりすましでは、発行されたトークンに`act`がありません。`sub`は`user@example.com`で、権限の上では利用者本人のトークンとして扱われます。`client_id`には要求したクライアントの`frontend`が残りますが、フロントエンドが利用者を代表して行動したことは表されません
2. 委任では、`act`に`https://frontend.example.com`が入ります。現在のアクターはフロントエンドです
3. 連鎖では、`act`が入れ子になります。外側の`act.sub`が`https://backend.example.com`(現在のアクター)、内側が`https://frontend.example.com`(過去のアクター)です。台帳APIはこの外側の値と最上位の`sub`で判断し、内側は監査ログに記録します
4. `may_act`に書かれていないバックエンドが利用者のトークンでの委任を求めると`invalid_request`、フロントエンドが許可されていない台帳APIの宛先を求めると`invalid_target`になります。残りの3行は、2.1節のパラメータの規則に反するリクエストです。`subject_token_type`がない場合、`actor_token`がないのに`actor_token_type`がある場合、`actor_token`があるのに`actor_token_type`がない場合は、いずれも`invalid_request`になります。この認可サーバはアクセストークンの交換だけを扱うので、種類がアクセストークン以外の場合も`invalid_request`にしています

この実験の認可サーバは、`may_act`のほかに、「`subject_token`の宛先のサービス自身がアクターである」場合も委任を許しています。3つ目の連鎖が成立するのはこの規則によります。どの交換を許すかはRFC 8693の範囲外であり、認可サーバの方針として明示的に設計する必要があります。

## CIBA

**CIBA**(Client-Initiated Backchannel Authentication)は、RPがブラウザのリダイレクトを使わずに、OPに直接「この利用者を認証してほしい」と依頼するフローです。OpenID FoundationのCIBA Core 1.0(Final、2021-09-01)が定めています。

CIBAは2つの端末を区別します。**消費デバイス**(consumption device)は、利用者がサービスを使う端末です。銀行の窓口の端末や店頭の決済端末のように、利用者自身が操作するとは限りません。**認証デバイス**(authentication device)は、利用者が認証と同意を行う端末で、多くはスマートフォンです。デバイス認可グラントでは利用者がコードを別の端末に入力しましたが、CIBAではRPが利用者の識別子を保持しており、OPがその識別子から認証デバイスに通知を送ります。

```mermaid
sequenceDiagram
    participant RP
    participant OP
    participant AD as 認証デバイス(スマートフォン)
    RP->>OP: POST /bc-authorize (scope=openid、login_hint、binding_message)
    OP-->>RP: auth_req_id、expires_in、interval
    OP->>AD: プッシュ通知「W4SCT の取引を承認しますか」
    loop interval 秒ごと(Pollモード)
        RP->>OP: POST /token (grant_type=urn:openid:params:grant-type:ciba、auth_req_id)
        OP-->>RP: 400 authorization_pending
    end
    AD->>OP: 生体認証などで承認
    RP->>OP: POST /token (auth_req_id)
    OP-->>RP: id_token、access_token
```

図の3行目で、OPは消費デバイスを経由せずに認証デバイスへ通知します。RPは`auth_req_id`を使って結果を受け取ります。

## 仕様を読む: CIBA Core 1.0 7.1節・7.3節・10.1節

7.1節は、バックチャネル認証エンドポイントへの認証リクエストを定めています。RPはクライアント認証を行い、`scope`に`openid`を含めなければなりません(MUST)。利用者を指定するヒントについては次のように定めています。

> Because in the CIBA flow, the OP does not have an interaction with the end-user through the consumption device, it is REQUIRED that the Client provides one (and only one) of the hints specified above in the authentication request, that is "login_hint_token", "id_token_hint" or "login_hint".

(CIBA Core 1.0 7.1節)

OPは消費デバイスを通じて利用者とやり取りしないので、RPは`login_hint_token`、`id_token_hint`、`login_hint`のうちちょうど1つを含めなければなりません(REQUIRED)。`login_hint`と`id_token_hint`は[18章](/oidc-deep/18-claims-identity/)のものと同じ考え方のパラメータです。

CIBAに固有のパラメータとして`binding_message`(binding_message パラメータ)があります。これは消費デバイスと認証デバイスの両方に表示する短い文字列です。利用者は2つの画面の値が一致することを見て、認証デバイスで承認しようとしている操作が目の前の取引のものであると確かめます。

```http
POST /bc-authorize HTTP/1.1
Host: server.example.com
Content-Type: application/x-www-form-urlencoded

scope=openid%20email%20example-scope&
client_notification_token=8d67dc78-7faa-4d41-aabd-67707b374255&
binding_message=W4SCT&
login_hint_token=eyJraWQiOiJsdGFjZXNidyIsImFsZyI6IkVTMjU2In0...&
client_assertion_type=urn%3Aietf%3Aparams%3Aoauth%3Aclient-assertion-type%3Ajwt-bearer&
client_assertion=eyJraWQiOiJsdGFjZXNidyIsImFsZyI6IkVTMjU2In0...
```

7.3節の応答の`auth_req_id`(auth_req_id パラメータ)は、この認証リクエストを識別する値です。推測や偽造を防ぐために最低128ビット(推奨160ビット)のエントロピーを持たなければなりません(MUST)。`interval`はポーリングの最小間隔で、省略時は5秒です。

RPが結果を受け取る方法は、登録時に3つから1つを選びます(5節)。

- Pollモード: RPがトークンエンドポイントを`auth_req_id`で問い合わせ続けます。エラーコードはRFC 8628と同じ`authorization_pending`と`slow_down`です
- Pingモード: OPが、RPが登録した通知エンドポイントに「結果の準備ができた」とだけ通知し、RPがトークンエンドポイントで受け取ります
- Pushモード: OPが、トークンそのものを通知エンドポイントに送ります

PingとPushでは、OPからRPへの通知を認証するために、RPが認証リクエストで`client_notification_token`を渡します。14節は、Pushモードではトークンエンドポイントでのクライアント認証を経ずにトークンが届くため、通知エンドポイントとその登録に適切な対策が必要だと述べています。同じ節は、`login_hint_token`は発行者が署名すべき(SHOULD)としています。署名のないヒントでは、不正なクライアントが利用者の識別子を集めたり、注入したりできるためです。

## ROPCが廃止される理由

**ROPC**(Resource Owner Password Credentials grant)は、利用者がクライアントに自分のユーザー名とパスワードを入力し、クライアントがそれをトークンエンドポイントに送ってアクセストークンを得るグラントです。RFC 6749 4.3節が定めています。

RFC 6749自身も、このグラントを限定的なものとして位置づけていました。4.3節は、利用者がクライアントを強く信頼している場合(端末のOSや高い権限を持つアプリケーション)に適するとし、ほかのフローが使えない場合にだけ許すよう認可サーバに注意を促しています。HTTPのBasic認証などを使っていた既存のクライアントをOAuthへ移行させるための手段でもありました。

RFC 9700 2.4節は、このグラントを禁止しました。

> The resource owner password credentials grant [RFC6749] MUST NOT be used. This grant type insecurely exposes the credentials of the resource owner to the client. Even if the client is benign, usage of this grant results in an increased attack surface (i.e., credentials can leak in more places than just the authorization server) and in training users to enter their credentials in places other than the authorization server.

(RFC 9700 2.4節)

ROPCを使ってはなりません(MUST NOT)。理由は3つあります。1つ目は、利用者の資格情報がクライアントに渡ることです。これは[2章](/web-auth/02-delegation/)で、OAuthが解決しようとした問題そのものです。2つ目は、クライアントが善意でも、パスワードが漏れうる場所が認可サーバ以外に広がることです。3つ目は、利用者に「認可サーバ以外の画面にパスワードを入力する」習慣を身につけさせることで、フィッシングに弱くなることです。同じ節は、このグラントが多要素認証や、複数の操作を要する認証に対応できないことも指摘しています。パスキー(WebAuthn)のように特定のWebオリジンに結びついた認証は、ROPCでは実装できないことがあります。

OAuth 2.1(draft-16)はROPCを仕様から除き、RFC 10017 7.3節も、ブラウザベースのアプリケーションでの使用を禁止しています(MUST NOT)。

## クロスデバイスフローの危険

デバイス認可グラントとCIBAのように、利用者が1つの端末で始めた操作を別の端末で完了させるフローを、**クロスデバイスフロー**(cross-device flow)と呼びます。RFC 10027(BCP 247、2026-08)は、このフローに共通する攻撃と対策をまとめたBCPです。

## RFCを読む: RFC 10027 1.1節・2節

> In these flows, the Consumption Device and the Authorization Device are not directly connected, and there are no technical mechanisms for the Authorization Device and Consumption Device to establish mutual authentication. [...] The transfer of the authorization request and context between the Consumption Device and Authorization Device is done over an unauthenticated channel. The only mitigation against this unauthenticated channel is the user's judgment.

(RFC 10027 1.1節)

この節は、クロスデバイスフローの構造上の弱点を述べています。消費デバイスと認可デバイス(RFC 10027はCIBAの認証デバイスにあたる端末をAuthorization Deviceと呼びます)は直接つながっておらず、互いを認証する技術的な手段がありません。認可リクエストとその文脈は、認証されていない経路(利用者がコードを読む、QRコードを撮る、通知を受け取る)で受け渡されます。この経路に対する防御は、利用者の判断だけです。

1.1節は、この弱点を利用する攻撃を**クロスデバイス同意フィッシング**(cross-device consent phishing、CDCP)と名づけています。攻撃者は自分の消費デバイスでフローを開始し、得たQRコードや`user_code`を、別の文脈(「ポイントを受け取るにはこのコードを入力してください」というメールなど)で被害者に見せます。被害者が自分のスマートフォンで認証して承認すると、攻撃者の端末がトークンを得ます。

```mermaid
sequenceDiagram
    participant 攻撃者 as 攻撃者の端末
    participant AS as 認可サーバ
    participant 被害者 as 被害者のスマートフォン
    攻撃者->>AS: デバイス認可リクエスト
    AS-->>攻撃者: user_code=WDJB-MJHT
    攻撃者->>被害者: メール「特典の受け取りに WDJB-MJHT を入力」
    被害者->>AS: verification_uri でログイン(多要素認証も通過)し、コードを入力して承認
    攻撃者->>AS: ポーリング
    AS-->>攻撃者: 被害者の権限のアクセストークン
```

図の4行目で、被害者は正規の認可サーバで、正規の手順に従って認証しています。資格情報は盗まれていません。1.1節は、この点を次のように述べています。

> These attacks are effective even when multi-factor authentication is deployed, since the attacker's aim is not to capture and replay the credentials, but rather to persuade the user to grant authorization.

(RFC 10027 1.1節)

攻撃者の目的は利用者に認可を与えさせることであり、資格情報を盗んで再利用することではないので、多要素認証を導入していても攻撃は成立します。

2節は、ベストプラクティスを5項目にまとめています。

1. 実装者は、クロスデバイスフローを実装する前に、リスク評価を行わなければなりません(MUST)
2. リスクを十分に軽減できない場合は、クロスデバイスフローを避けるべきです(SHOULD)
3. プロトコルの選択は、6.2節の指針に従うべきです(SHOULD)
4. リスク評価で特定したリスクに対し、6.1節の対策から適切なものを選ばなければなりません(MUST)
5. 可能であれば、近接性(2つの端末が物理的に近くにあること)の確認を対策の1つに含めるべきです(SHOULD)

6.2節は、プロトコルごとに使う場面を示しています。デバイス認可グラントは、ほかのクロスデバイスのプロトコルが端末やシステムの制約で使えない場合だけ使い、保護するリソースが重要なものであれば避けるとしています。CIBAは、消費デバイスで利用者の識別子を得られ、認可サーバが認可デバイスに通知を送れる場合に、デバイス認可グラントの代わりに使うとしています。CIBAはQRコードやコードの受け渡しがないので認証されていない経路への攻撃に強い一方で、利用者の識別子を知るか推測できる攻撃者には弱いままです。4.3.4.1節は、攻撃者が金融機関の利用者の識別子の一覧を入手して全員に取引の承認要求を送り、わずかな割合の利用者が承認する例を挙げています。6.2.4節は、**FIDO のクロスデバイス認証**(FIDO Cross-Device Authentication、CDA)が、認証されていない経路への攻撃に対して最も強い保護を与えるとまとめています。6.2.3.2節によると、CDAは、Bluetooth Low Energyのアドバタイズ(近くの端末へ向けた無線の短い送信)を使い、2つの端末が近くにあることを確かめるからです。どちらのプロトコルも、同じ端末の中で完結する場面には使わないよう求めています。

6.1節の対策のうち、本章の内容と関係の深いものは次のとおりです。

- QRコードや`user_code`の有効期間を短くし、1回限りの使用にします(6.1.2節、6.1.3節)
- 試行回数を制限します(6.1.11節)。RFC 8628 5.1節の`user_code`の総当たり対策と同じです
- 発行するトークンのスコープを限定し、有効期間を短くし、[16章](/oauth-deep/16-sender-constrained/)の送信者制約を使います(6.1.9節、6.1.10節、6.1.12節)
- 認可デバイスの画面では、誰がフローを開始したか、なぜ開始されたか、承認すると何が起きるかを利用者に明確に伝えるべきです(SHOULD)。自分で開始していない要求は拒否するよう促すべきです(SHOULD)(6.1.14節)。RFC 8628 5.4節の推奨と同じ方向の対策です

## グラントの選び方

この章のグラントを、使う場面ごとに整理します。

| 場面 | グラント | 注意点 |
| --- | --- | --- |
| 利用者のいないサーバ間通信 | クライアントクレデンシャル | 機密クライアントのみ。`client_id`と`sub`の混同(RFC 9700 4.15節) |
| 別の発行者のJWTで主体を引き継ぐ | JWTベアラー | `aud`、`exp`、署名の検証。発行者ごとの`sub`の許可方針 |
| 入力手段の少ない端末 | デバイス認可 | ポーリング間隔、`user_code`の総当たり、同意フィッシング |
| サービスの連鎖で宛先を変える | トークン交換 | なりすましより委任。クライアント認証と交換の許可方針 |
| RPが利用者の識別子を持ち、別端末で承認させる | CIBA | `binding_message`、ヒントの署名、大量の承認要求 |
| 利用者のパスワードを受け取る | ROPC | 使ってはならない(RFC 9700 2.4節) |

## まとめ

- グラントは`grant_type`で区別され、RFC 6749 4.5節の拡張グラントの仕組みで追加されます
- クライアントクレデンシャルグラントは機密クライアントだけが使い、リフレッシュトークンを含めるべきではありません。JWTベアラーグラントは、`aud`、`exp`、署名を検証したJWTで主体を引き継ぎます
- デバイス認可グラントの端末は`interval`以上の間隔でポーリングし、`slow_down`を受けたら5秒延ばします。実験では、2秒間隔の端末が`slow_down`を受けて10秒間隔に変わる様子を確かめました
- トークン交換には、権限の上で主体本人として扱われるなりすましと、`act`クレームで行動者を残す委任があります。アクセス制御には最上位のクレームと最も外側の`act`だけを使います
- CIBAは、RPが利用者の識別子をもとにOPへ直接認証を依頼し、Poll、Ping、Pushのいずれかで結果を受け取ります
- ROPCは利用者の資格情報をクライアントに渡すので、使ってはなりません(MUST NOT)
- クロスデバイスフローでは、端末間の経路が認証されないため、多要素認証を導入していても同意フィッシングが成立します。RFC 10027はリスク評価、プロトコルの選択、近接性の確認を求めています

次章では、ログアウトを扱います。RPのセッションとOPのセッションが別々に存在することから生じる問題と、それを解決するための4つの仕様、特にバックチャネルログアウトのログアウトトークンの検証を説明します。
