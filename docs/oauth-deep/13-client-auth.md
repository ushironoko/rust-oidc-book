---
title: クライアントの種類とクライアント認証
description: 機密クライアントとパブリッククライアントの区別、client_secret_basic の符号化規定による実装差、client_secret_jwt・private_key_jwt・mTLS、動的クライアント登録と Client ID Metadata Document。
sidebar:
  label: 13. クライアントの種類とクライアント認証
---

この章でわかること:

- 機密クライアントとパブリッククライアントを分ける基準と、その基準を決める主体
- `client_secret_basic` が実装間で一致しない原因(RFC 6749 2.3.1節の符号化規定)と、その実測
- シークレットを送らない方式(`client_secret_jwt`)と、認可サーバがシークレットを保存しない方式(`private_key_jwt`、mTLS)の違い
- 動的クライアント登録と Client ID Metadata Document による、事前登録を前提にしないクライアントの識別
- なぜ体系に必須か: 認可コードもリフレッシュトークンも、トークンエンドポイントで「提示したのが正規のクライアントか」を確かめて初めて安全に交換できます。この確認の方法を知らなければ、どのフローを選んでも安全性を判断できません

## 基礎編からの接続

[3章](/web-auth/03-authorization-code/)では、トークンエンドポイントでクライアントが自分を証明する手続きをクライアント認証と呼び、クライアントシークレットを送る形だけを紹介しました。[9章](/oidc/09-state-nonce-pkce/)ではパブリッククライアントと機密クライアントという区別を概要だけ示し、PKCE はどちらにも使うと説明しました。[12章](/rust-impl/12-build-op/)の mini-op は、トークンエンドポイントでクライアント認証を行ってから認可コードを検証しています。

この章では、この「クライアント認証」の部分を詳しく扱います。クライアント認証には複数の方式があり、方式ごとに「何を送るか」「認可サーバが何を保存するか」「盗まれたときに何が起きるか」が異なります。最初にクライアントの種類を定義し、次に方式を1つずつ RFC の原文と実験で確かめます。

## クライアントの種類: 資格情報を秘密にできるか

OAuth 2.0 はクライアントを2種類に分けます。分ける基準は、クライアントが自分の資格情報(クライアントシークレットや秘密鍵)を第三者から秘密にしておけるかどうかです。

**機密クライアント**(confidential client)は、資格情報を秘密に保てるクライアントです。アクセスが制限されたサーバ上で動く Web アプリケーションが典型です。利用者のブラウザにはサーバが生成した HTML が届くだけで、クライアントシークレットはサーバの外に出ません。

**パブリッククライアント**(public client)は、資格情報を秘密に保てないクライアントです。利用者の端末にインストールされるネイティブアプリや、ブラウザ上で JavaScript として動くアプリケーションが該当します。配布されたアプリのバイナリやスクリプトは利用者が自由に解析できるため、そこに埋め込んだシークレットは取り出せるものとして扱います。

RFC 6749 は、この2種類の上に次の3つの典型的な構成を挙げています。

| 構成 | 種類 | 資格情報の置き場所 |
| --- | --- | --- |
| Web アプリケーション | 機密 | Web サーバ。利用者からは参照できない |
| ユーザーエージェント上のアプリケーション | パブリック | ブラウザ。利用者が参照できる |
| ネイティブアプリケーション | パブリック | 利用者の端末。抽出できるものと仮定する |

パブリッククライアントは、トークンエンドポイントでクライアント認証を行えません。認可コードを提示したのが正規のアプリか、アプリを解析して同じ `client_id` を名乗る別のプログラムかを、認可サーバは区別できません。このため、パブリッククライアントでは PKCE([9章](/oidc/09-state-nonce-pkce/))とリダイレクト URI の完全一致が、認可コードを正規のクライアントに結びつける主な手段になります。

## RFCを読む: RFC 6749 2.1節

> OAuth defines two client types, based on their ability to authenticate securely with the authorization server (i.e., ability to maintain the confidentiality of their client credentials)

(RFC 6749 2.1節)

この節は、クライアントの種類を「認可サーバに対して安全に認証できる能力」で定義しています。括弧内で、その能力を「クライアントの資格情報の秘密を保てる能力」と言い換えています。種類は資格情報の秘密を保てるかという性質で決まり、プログラムの形態(サーバか、アプリか)では決まりません。

> The client type designation is based on the authorization server's definition of secure authentication and its acceptable exposure levels of client credentials. The authorization server SHOULD NOT make assumptions about the client type.

(RFC 6749 2.1節)

この部分は、種類を判定する主体を定めています。何を安全な認証とみなし、資格情報の露出をどこまで許容するかは、認可サーバの定義に従います。そのうえで、認可サーバはクライアントの種類を推測で決めるべきではありません(SHOULD NOT)。登録時の申告や運用者の判断で明示的に決め、例えば「リダイレクト URI が https だから機密クライアントだろう」のように推測しないことを求めています。

> It is assumed that any client authentication credentials included in the application can be extracted.

(RFC 6749 2.1節、native application の項)

この部分は、ネイティブアプリに含めたクライアント認証の資格情報を、すべて抽出できるものと仮定しています。難読化や暗号化をしても、アプリ自身が実行時に復号できる以上、解析者も同じ手順で復号できます。この仮定が、ネイティブアプリをパブリッククライアントに分類する根拠です。

同じ節には、1つのクライアントがサーバ側の機密な部分とブラウザ側のパブリックな部分から成る場合、認可サーバが特別な対応をしていなければ、それぞれを別のクライアントとして登録すべきだ(SHOULD)という記述もあります。ブラウザアプリの設計([24章](/security/24-browser-native/))で、この区別が再び問題になります。

## クライアント認証の方式の一覧

機密クライアントがトークンエンドポイントで自分を証明する方式は、IANA の「OAuth Token Endpoint Authentication Methods」レジストリに登録されています。クライアントがどの方式を使うかは、登録時のメタデータ `token_endpoint_auth_method`(トークンエンドポイント認証方式のメタデータ)で宣言します。この値は RFC 7591(動的クライアント登録、後述)で定義され、省略時の既定値は `client_secret_basic` です。

本書で扱う方式を次の表にまとめます。

| 方式 | 資格情報 | リクエストで送るもの | 認可サーバが保存するもの |
| --- | --- | --- | --- |
| `client_secret_basic` | 共有シークレット | Authorization ヘッダのシークレット | シークレット(照合用) |
| `client_secret_post` | 共有シークレット | 本文のシークレット | シークレット(照合用) |
| `client_secret_jwt` | 共有シークレット | シークレットを鍵にした HMAC 付き JWT | シークレット(HMAC の鍵として) |
| `private_key_jwt` | 秘密鍵 | 秘密鍵で署名した JWT | 公開鍵 |
| `tls_client_auth` | 証明書と秘密鍵 | TLS ハンドシェイクでの証明書 | 証明書のサブジェクト名 |
| `self_signed_tls_client_auth` | 自己署名証明書と秘密鍵 | TLS ハンドシェイクでの証明書 | 証明書そのもの |
| `none` | なし | `client_id` のみ | なし |

上の3行は共有シークレット、続く3行は公開鍵暗号に基づく方式で、最後の `none` はクライアント認証を行わないこと(パブリッククライアント)を表します。両者の違いは、認可サーバが保存する値が漏洩したときに表れます。共有シークレットの方式では、認可サーバのデータベースが漏洩すると、攻撃者はクライアントになりすませます。公開鍵の方式では、漏洩するのは公開鍵だけであり、なりすましに必要な秘密鍵はクライアントの外に出ていません。

## client_secret_basic と client_secret_post

`client_secret_basic`(client_secret_basic 方式)は、`client_id` とクライアントシークレットを HTTP の Basic 認証([1章](/web-auth/01-http-auth/))の形で Authorization ヘッダに入れて送る方式です。`client_secret_post`(client_secret_post 方式)は、同じ2つの値を `client_id` と `client_secret` という本文のパラメータとして送る方式です。

```mermaid
sequenceDiagram
    participant C as クライアント
    participant AS as 認可サーバ
    C->>AS: POST /token<br/>Authorization: Basic base64(id:secret)<br/>grant_type=authorization_code&code=...
    AS->>AS: Base64 を復号し id と secret を照合
    AS->>AS: 認可コードがこの client_id に発行されたか確認
    AS-->>C: 200 OK (アクセストークン)
```

2つの方式のリクエストは次のようになります。シークレットはダミーの値です。

```http
POST /token HTTP/1.1
Host: server.example.com
Authorization: Basic czZCaGRSa3F0Mzo3RmpmcDBaQnIxS3REUmJuZlZkbUl3
Content-Type: application/x-www-form-urlencoded

grant_type=authorization_code&code=SplxlOBeZQQYbYS6WxSbIA
&redirect_uri=https%3A%2F%2Fclient.example.com%2Fcb
```

```http
POST /token HTTP/1.1
Host: server.example.com
Content-Type: application/x-www-form-urlencoded

grant_type=authorization_code&code=SplxlOBeZQQYbYS6WxSbIA
&redirect_uri=https%3A%2F%2Fclient.example.com%2Fcb
&client_id=s6BhdRkqt3&client_secret=7Fjfp0ZBr1KtDRbnfVdmIw
```

どちらもシークレットそのものを毎回送ります。このため TLS が必須であり、認可サーバ側のログやリバースプロキシにシークレットが残らないよう注意が必要です。違いはシークレットの置き場所(ヘッダか本文か)だけに見えますが、`client_secret_basic` には符号化の規定があり、この規定が実装間の不一致の原因になっています。

## RFCを読む: RFC 6749 2.3.1節

> The client identifier is encoded using the "application/x-www-form-urlencoded" encoding algorithm per Appendix B, and the encoded value is used as the username; the client password is encoded using the same algorithm and used as the password. The authorization server MUST support the HTTP Basic authentication scheme for authenticating clients that were issued a client password.

(RFC 6749 2.3.1節)

この節は、クライアントシークレットを Basic 認証で送る手順を定めています。手順は2段階です。

1. `client_id` とクライアントシークレットを、それぞれ application/x-www-form-urlencoded の規則(付録B)で符号化します
2. 符号化した2つの値をユーザー名とパスワードとして、通常の Basic 認証の手順(コロンで連結して Base64)に渡します

認可サーバは、シークレットを発行したクライアントに対してこの Basic 認証の方式をサポートしなければなりません(MUST)。

具体的な値で比べます。シークレットが `ab+c/d` の場合、手順1で `+` は `%2B`、`/` は `%2F` になり、Base64 にかける文字列は `s6BhdRkqt3:ab%2Bc%2Fd` です。[1章](/web-auth/01-http-auth/)で見た RFC 7617 の Basic 認証は、ユーザー名とパスワードをそのままコロンで連結するため、`s6BhdRkqt3:ab+c/d` を Base64 にかけます。同じ「Basic」でも、Base64 の入力が異なります。

この規定には理由があります。RFC 7617 の Basic 認証は、ユーザー ID にコロンを含められません。最初のコロンが区切りとして扱われるためです。OAuth の `client_id` には `urn:example:client` のような URI を使う場合があり、そのまま連結すると境界が誤って解釈されます。form-urlencoded で符号化すると、コロンは `%3A` になり、区切りのコロンと区別できます。非 ASCII 文字も UTF-8 のバイト列として `%XX` 形式に変換されるため、文字コードの扱いも一意に決まります。

> Including the client credentials in the request-body using the two parameters is NOT RECOMMENDED and SHOULD be limited to clients unable to directly utilize the HTTP Basic authentication scheme (or other password-based HTTP authentication schemes).

(RFC 6749 2.3.1節)

本文に入れる方式(後の `client_secret_post`)については、推奨しないと書かれています(NOT RECOMMENDED)。使う場合も、Basic 認証を直接使えないクライアントに限るべきです(SHOULD)。認可サーバ側の対応は「サポートしてもかまいません(MAY)」です。同じ節は、パスワードによる認証を受け付けるエンドポイントを総当たり攻撃から保護しなければならない(MUST)とも定めています。

この優先順位は、策定中の OAuth 2.1 で逆転しています。draft-ietf-oauth-v2-1-16(本書執筆時の2026年10月16日に確認した最新版)の2.4.1節は、本文で送る方式のサポートを MUST とし、Basic 認証のサポートを MAY に下げました。理由は同節の注記に書かれています。

> Note: This method of initially form-encoding the client identifier and secret, and then using the encoded values as the HTTP Basic authentication username and password, has led to many interoperability problems in the past.

(draft-ietf-oauth-v2-1-16 2.4.1節)

注記は続けて、符号化の手順を省いた実装、一部の文字だけを符号化した実装、検証時に符号化を無視した実装があったこと、その結果クライアントが認可サーバごとに送り方を変える必要が生じたことを挙げています。本文で送る方式なら、この二重の符号化が発生しません。

## 実験: 記号を含むシークレットで実装がずれる

仕様どおりのクライアントに、注記が挙げた誤りに対応する2種類のクライアントを加えた3種類と、2種類の認可サーバを組み合わせて、どの組で認証が成功するかを確かめます。

- クライアント A: 仕様どおり、form-urlencoded で符号化してから Basic にします
- クライアント B: 符号化を省き、RFC 7617 の Basic 認証として送ります
- クライアント C: コロンとパーセント記号だけを符号化します
- 認可サーバ S1: Base64 を復号し、コロンで分け、それぞれを form-urlencoded として復号します
- 認可サーバ S2: Base64 を復号し、コロンで分けるだけです

<RustPlay snippet="ch13/client-secret-basic" title="client_secret_basic の符号化の差を組み合わせで確かめる" />

出力の [1] は、RFC 6749 2.3.1節の例のヘッダを復号した結果です。`client_id` は `s6BhdRkqt3`、シークレットは `7Fjfp0ZBr1KtDRbnfVdmIw` で、どちらも英数字だけなので、符号化の有無でヘッダは変わりません。[2] でも全6通りが成功します。RFC の例を見て実装を書き、英数字のシークレットで試験した場合、符号化の誤りは検出できません。

[3] のシークレット `dummy+secret/==` では結果が分かれます。

- A は `dummy%2Bsecret%2F%3D%3D` を送ります。S1 は成功し、S2 は符号化された文字列をそのまま照合して失敗します
- B は `dummy+secret/==` を送ります。S1 は `+` を空白に戻して `dummy secret/==` と解釈し、失敗します。S2 は成功します
- C は `+` を符号化しないため、B と同じ結果になります

[4] のシークレット `dummy%41:secret` では、B を受け取った S1 が `%41` を `A` に復号して `dummyA:secret` と解釈します。C はパーセント記号とコロンを符号化するので、この場合は A と同じ結果です。[5] は `client_id` にコロンを含む場合で、B はどちらのサーバでも失敗します。最初のコロンで分割されるため、`client_id` が `urn` と解釈されます。

成功するのは、クライアントとサーバが同じ規則を採用した組だけです。[12章](/rust-impl/12-build-op/)の examples/mini-op のトークンエンドポイント(`token.rs` の `authenticate_client`)は、S1 と同じく Base64 の復号後に form-urlencoded の復号を行っています。2.3.1節に従う S1 は、Base64 シークレットによく現れる `+`、`/`、`=` を含む値で、符号化しないクライアントを拒否します。この不一致は、シークレットに記号が含まれたときにだけ現れます。このため、シークレットを再発行した後に認証が失敗し始める形で発見されることが多い障害です。対策として、多くの実装は次のいずれかを選んでいます。

- 発行するシークレットを英数字と `-`、`_`、`.` だけで構成します。これらの文字は form-urlencoded の符号化で変化しません。URI で予約されていない `~` は、実験で使った form_urlencoded クレートでは `%7E` に符号化されるため、この一覧に含めません
- 認可サーバが `client_secret_post` も受け付け、相互運用で問題が出たクライアントには本文で送らせます
- 共有シークレット自体をやめ、後述の `private_key_jwt` に移行します

## シークレットを送らない方式: client_secret_jwt

`client_secret_basic` と `client_secret_post` は、リクエストのたびにシークレットそのものを送ります。TLS を終端した後の経路のログや、誤って HTTP で送信したリクエストからシークレットが漏洩すると、それ以降は第三者が何度でも認証できます。

この問題に対する方式が、JWT を使うクライアント認証です。クライアントは、自分が誰で、どの認可サーバ宛てに、いつまで有効な証明かを JWT に書き、それに署名または MAC を付けて送ります。この JWT を**クライアントアサーション**(client assertion)と呼びます。クライアントアサーションは、トークンリクエストの本文で次の2つのパラメータとして送ります。

- `client_assertion_type`(client_assertion_type パラメータ): アサーションの種類を示します。JWT の場合は `urn:ietf:params:oauth:client-assertion-type:jwt-bearer` に固定されます
- `client_assertion`(client_assertion パラメータ): アサーションの JWT そのものを入れます

`client_secret_jwt`(client_secret_jwt 方式)は、クライアントシークレットを鍵として HMAC([5章](/web-auth/05-crypto/))を計算し、`HS256` などの JWS([7章](/oidc/07-jwt-jose/))としてアサーションを作る方式です。送るのは有効期限の短い JWT であり、シークレットそのものはネットワークに出ません。JWT が漏洩しても、`exp` を過ぎれば使えず、`jti` の再利用検査があれば期限内の再送も拒否されます。

ただし、HMAC の検証には送信側と同じ鍵が必要です。認可サーバは、シークレットをパスワードのようにハッシュ化して保存することができず、HMAC の鍵として使える形で保存しなければなりません。認可サーバのデータベースが漏洩した場合の影響は、`client_secret_basic` と同じです。

## 公開鍵による方式: private_key_jwt

`private_key_jwt`(private_key_jwt 方式)は、クライアントが自分で生成した鍵ペアの秘密鍵でクライアントアサーションに署名し、認可サーバは登録済みの公開鍵で検証する方式です。クライアントは、公開鍵を登録時に JWK Set([7章](/oidc/07-jwt-jose/))として渡すか(`jwks`)、自分が公開する JWK Set の URL を渡します(`jwks_uri`)。

```mermaid
sequenceDiagram
    participant C as クライアント
    participant AS as 認可サーバ
    Note over C: 鍵ペアを生成し、公開鍵だけを登録済み
    C->>C: iss=sub=client_id, aud=認可サーバ, jti, exp の JWT に秘密鍵で署名
    C->>AS: POST /token<br/>grant_type=authorization_code&code=...<br/>client_assertion_type=...jwt-bearer<br/>client_assertion=eyJ...
    AS->>AS: 登録済み公開鍵で署名を検証
    AS->>AS: iss, sub, aud, exp, jti を検査
    AS-->>C: 200 OK (アクセストークン)
```

リクエストは次のようになります(JWT は途中を省略しています)。

```http
POST /token HTTP/1.1
Host: as.example.com
Content-Type: application/x-www-form-urlencoded

grant_type=authorization_code&code=n0esc3NRze7LTCu7iYzS6a5acc3f0ogp4
&client_assertion_type=urn%3Aietf%3Aparams%3Aoauth%3Aclient-assertion-type%3Ajwt-bearer
&client_assertion=eyJhbGciOiJFUzI1NiIsImtpZCI6ImNsaWVudC1rZXktMSJ9.eyJpc3Mi...
```

認可サーバが保存するのは公開鍵だけです。秘密鍵はクライアントのサーバから外に出ないため、認可サーバの漏洩でなりすましが可能になることはありません。鍵のローテーションも、クライアントが `jwks_uri` の内容を差し替えるだけで済み、認可サーバの管理者との調整が不要です。

## RFCを読む: RFC 7523 2.2節と3節

`client_secret_jwt` と `private_key_jwt` は、どちらも RFC 7523(JWT を使うクライアント認証と認可グラントのプロファイル)に従います。RFC 7523 は、より一般的な枠組みである RFC 7521(アサーションの枠組み)を JWT に具体化した仕様です。

> The value of the "client_assertion_type" is "urn:ietf:params:oauth:client-assertion-type:jwt-bearer".
>
> The value of the "client_assertion" parameter contains a single JWT. It MUST NOT contain more than one JWT.

(RFC 7523 2.2節)

2.2節は、クライアント認証に JWT を使うときのパラメータの値を定めています。`client_assertion_type` は固定の URN です。`client_assertion` には JWT を1つだけ入れ、複数の JWT を含めてはなりません(MUST NOT)。

3節は、認可サーバが JWT を検証する基準を10項目で定めています。クライアント認証に関わる項目を抜粋します。

> 2. The JWT MUST contain a "sub" (subject) claim identifying the principal that is the subject of the JWT. [...] B. For client authentication, the subject MUST be the "client_id" of the OAuth client.

(RFC 7523 3節)

JWT は `sub` クレームを含まなければならず(MUST)、クライアント認証では `sub` がクライアントの `client_id` でなければなりません(MUST)。同じ節の1項目めは `iss` を必須とし、比較は RFC 3986 6.2.1節の単純な文字列比較で行うと定めています。

> 3. The JWT MUST contain an "aud" (audience) claim containing a value that identifies the authorization server as an intended audience. The token endpoint URL of the authorization server MAY be used as a value for an "aud" element to identify the authorization server as an intended audience of the JWT. The authorization server MUST reject any JWT that does not contain its own identity as the intended audience.

(RFC 7523 3節)

`aud` は必須であり(MUST)、認可サーバを宛先として示す値を含まなければなりません。トークンエンドポイントの URL を `aud` に使ってもかまいません(MAY)。認可サーバは、自分を宛先に含まない JWT を拒否しなければなりません(MUST)。この検査がなければ、ある認可サーバ宛てに作ったアサーションを、それを受け取った別の認可サーバ(悪意がある場合を含む)が転用できます。

> 4. The JWT MUST contain an "exp" (expiration time) claim that limits the time window during which the JWT can be used. The authorization server MUST reject any JWT with an expiration time that has passed, subject to allowable clock skew between systems.
>
> 7. The JWT MAY contain a "jti" (JWT ID) claim that provides a unique identifier for the token. The authorization server MAY ensure that JWTs are not replayed by maintaining the set of used "jti" values for the length of time for which the JWT would be considered valid based on the applicable "exp" instant.

(RFC 7523 3節)

`exp` は必須で、期限を過ぎた JWT は時計のずれの許容範囲を考慮したうえで拒否しなければなりません(MUST)。引用を省いた5項目めは、`nbf` クレーム([7章](/oidc/07-jwt-jose/))を任意(MAY)とし、`nbf` が示す時刻より前には JWT を処理のために受け入れてはならない(MUST NOT)と定めています。`jti` は任意(MAY)で、認可サーバが使用済みの `jti` を `exp` まで記録して再送を拒否することも任意です(MAY)。RFC 7523 の6節は、リプレイ対策は必須ではないと明記しています。この点は、次の OpenID Connect Core 1.0 9節で強化されています。

> 9. The JWT MUST be digitally signed or have a Message Authentication Code (MAC) applied by the issuer. The authorization server MUST reject JWTs with an invalid signature or MAC.

(RFC 7523 3節)

JWT は署名か MAC が付いていなければならず(MUST)、検証に失敗した JWT を拒否しなければなりません(MUST)。`alg` が `none` の JWT は、この項目によって拒否されます。3.2節は、クライアント認証の JWT が不正だった場合のエラーコードを `invalid_client` と定めています([4章](/web-auth/04-tokens/)のトークンエラーレスポンスの形式です)。

`aud` に入れる値は、後続の仕様で何度も明確化されています。RFC 7523 は「認可サーバを示す値」とだけ書き、トークンエンドポイントの URL を MAY としました。後述の OpenID Connect Core 1.0 9節は、トークンエンドポイントの URL にすべきだ(SHOULD)としています。PAR を定める RFC 9126 の2節は、この曖昧さを「歴史的な理由」によるものと説明しています。同節は、認可サーバの issuer 識別子を使うべきであり(SHOULD)、認可サーバは issuer、トークンエンドポイント URL、PAR エンドポイント URL のいずれも受け入れなければならない(MUST)と定めました。FAPI 2.0 Security Profile([25章](/security/25-high-security/))はさらに限定し、認可サーバは issuer 識別子を文字列として含む `aud` だけを受け入れ、クライアントは配列を使わずに文字列で送ると定めています。OAuth 2.1(draft-16)の2.4節は、RFC 7523 の改訂版である draft-ietf-oauth-rfc7523bis(draft-16 が参照するのは2026年4月28日付の -11)の `aud` に関する指針に従わなければならない(MUST)としています。新しく実装する場合は、`aud` に認可サーバの issuer 識別子を文字列で入れます。この値は RFC 9126 と FAPI 2.0 に適合し、OAuth 2.1 の方向とも一致します。OpenID Connect Core 1.0 の推奨(トークンエンドポイントの URL、SHOULD)とは異なるため、接続先の認可サーバが受け入れる値を確認してください。

## 仕様を読む: OpenID Connect Core 1.0 9節

OpenID Connect Core 1.0 の9節は、`client_secret_basic`、`client_secret_post`、`client_secret_jwt`、`private_key_jwt`、`none` の5つの方式名を定義した節です。これらの名前は IANA のレジストリにも登録され、OAuth 全般で使われています。

> During Client Registration, the RP (Client) MAY register a Client Authentication method. If no method is registered, the default method is client_secret_basic.

(OpenID Connect Core 1.0 9節)

RP はクライアント登録時に認証方式を登録してもかまいません(MAY)。登録しなかった場合の既定値は `client_secret_basic` です。前の実験で見た符号化の問題は、この既定値によって、明示的に方式を選んでいない多くのクライアントに影響します。

> The HMAC (Hash-based Message Authentication Code) is calculated using the octets of the UTF-8 representation of the client_secret as the shared key.

(OpenID Connect Core 1.0 9節、client_secret_jwt の項)

`client_secret_jwt` の HMAC の鍵は、`client_secret` の文字列を UTF-8 で表したバイト列であり、Base64 として復号したバイト列ではありません。シークレットが Base64 文字列に見える場合、復号してから鍵にする実装と、文字列のまま鍵にする実装が分かれる余地があり、この一文がそれを防いでいます。

> jti
> REQUIRED. JWT ID. A unique identifier for the token, which can be used to prevent reuse of the token. These tokens MUST only be used once, unless conditions for reuse were negotiated between the parties; any such negotiation is beyond the scope of this specification.

(OpenID Connect Core 1.0 9節)

RFC 7523 では任意だった `jti` が、OpenID Connect では必須(REQUIRED)です。さらに、当事者間で再利用の条件を取り決めていない限り、このトークンは1回だけ使わなければなりません(MUST)。`iss` と `sub` はどちらもクライアントの `client_id` でなければならず(MUST)、`aud` はトークンエンドポイントの URL にすべきです(SHOULD)。`exp` は必須、`iat` は任意です。理解できないクレームは無視しなければなりません(MUST)。

## 実験: private_key_jwt を作って検証する

ring で ES256 の鍵ペアを生成し、クライアント側でアサーションを作り、認可サーバ側で RFC 7523 3節と OpenID Connect Core 1.0 9節の検査を行います。認可サーバは、`client_id` と公開鍵の対の一覧と、使用済みの `jti` の集合だけを持ちます。登録済みのクライアントは `s6BhdRkqt3` と `other-client` の2つです。署名の検証には、要求された `client_id` に登録された鍵だけを使います。検証は署名を先に行い、署名が正しい場合だけペイロードのクレームを読みます([8章](/oidc/08-id-token-validation/)と同じ順序です)。実験を再現可能にするため、現在時刻は固定の値にしています。署名と `jti` は乱数を使うので、アサーションの文字列は実行ごとに変わります。

<RustPlay snippet="ch13/private-key-jwt" title="private_key_jwt のアサーションを作り、検証と攻撃を試す" />

[1] のペイロードは、`iss` と `sub` がどちらも `s6BhdRkqt3`、`aud` が認可サーバの issuer、`exp` が `iat` の60秒後です。本文の `client_assertion_type` は、コロンが `%3A` に符号化されて送られています。

[2] は正しいアサーションで、認証は成功します。[3] は同じアサーションをもう1度送った場合で、`jti` が使用済みのため拒否されます。アサーションを盗聴した攻撃者が、`exp` までの60秒以内に再送しても、この検査で防げます。[4] は別の認可サーバ宛てに作ったアサーションで、`aud` の検査で拒否されます。[5] は期限切れです。

[6] は、ペイロードの `iss` と `sub` を `other-client` に書き換えた場合です。署名の入力が変わるため、`other-client` の鍵による署名検証で拒否されます。[7] は攻撃者が自分の鍵で署名した場合で、登録済みの公開鍵では検証できません。認可サーバの記録が漏洩しても、攻撃者が得られるのは [7] の状態(公開鍵だけを知っている状態)であり、正しいアサーションは作れません。

[8] は、登録済みの `other-client` が自分の秘密鍵で署名し、`iss` と `sub` に `s6BhdRkqt3` を入れて `s6BhdRkqt3` を名乗った場合です。署名は `other-client` の登録鍵に対しては正しい値です。認可サーバが登録済みの全クライアントの鍵を順に試して検証する実装では、このアサーションは署名検証を通過し、`iss` と `sub` の検査も通過します。実験の認可サーバは `s6BhdRkqt3` に登録された鍵だけで検証するため、拒否します。OpenID Connect Core 1.0 9節は `private_key_jwt` を「公開鍵を登録したクライアントがその鍵で署名する」方式と定めており、検証に使う鍵は、名乗った `client_id` に登録された鍵でなければなりません。

[9] は `nbf` が5分後のアサーションです。`nbf` があれば整数であることを確かめ、時計のずれの許容範囲(30秒)を超えて未来であれば拒否します。

## TLS で認証する方式: mTLS

公開鍵による認証は、JWT の代わりに TLS の層でも行えます。通常の TLS では、サーバだけが証明書を提示し、クライアントはサーバを確認します。**mTLS**(mutual TLS)は、TLS ハンドシェイクでクライアントも証明書を提示し、対応する秘密鍵を持つことを証明して、双方が相手を確認する TLS の使い方です。

クライアントが提示する証明書は **X.509 証明書**(X.509 certificate)です。X.509 証明書は、公開鍵と、その持ち主を示す名前(サブジェクト)などを組にし、発行者が署名したデータ構造です。発行者が信頼された**認証局**(certificate authority、CA)であれば、受け取った側は認証局の署名をたどって証明書を検証できます。認証局による証明書の発行と検証の仕組み全体を **PKI**(public key infrastructure、公開鍵基盤)と呼びます。発行者と持ち主が同じ証明書を**自己署名証明書**(self-signed certificate)と呼びます。

RFC 8705 は、mTLS をクライアント認証に使う方式を2つ定めています。

- `tls_client_auth`(PKI 方式): 認証局が発行した証明書を使います。認可サーバは証明書チェーンを検証し、証明書のサブジェクトの識別名(distinguished name、DN)か、サブジェクト代替名(subject alternative name、SAN)の1つが、そのクライアントに登録された値と一致するかを確認します
- `self_signed_tls_client_auth`(自己署名方式): 自己署名証明書を使います。認可サーバは証明書チェーンを検証せず、提示された証明書がクライアントの登録済み証明書(`jwks` または `jwks_uri` の JWK の `x5c` パラメータ)のどれかと一致するかを確認します

```http
POST /token HTTP/1.1
Host: mtls.as.example.com
Content-Type: application/x-www-form-urlencoded

grant_type=authorization_code&code=SplxlOBeZQQYbYS6WxSbIA
&redirect_uri=https%3A%2F%2Fclient.example.com%2Fcb
&client_id=s6BhdRkqt3
```

証明書と秘密鍵の所有の証明は、このリクエストを送る TLS 接続のハンドシェイクの中で済んでおり、HTTP のメッセージには資格情報が現れません。本文の `client_id` は、どのクライアントの登録情報と照合するかを認可サーバに伝えるために送ります。

## RFCを読む: RFC 8705 2節

> In order to utilize TLS for OAuth client authentication, the TLS connection between the client and the authorization server MUST have been established or re-established with mutual-TLS X.509 certificate authentication (i.e., the client Certificate and CertificateVerify messages are sent during the TLS handshake).

(RFC 8705 2節)

この節は、mTLS によるクライアント認証の前提を定めています。クライアントと認可サーバの間の TLS 接続は、クライアント証明書による相互認証で確立(または再確立)されていなければなりません(MUST)。括弧内の Certificate と CertificateVerify は TLS ハンドシェイクのメッセージで、前者では証明書を送り、後者ではその証明書の秘密鍵でハンドシェイクの内容に付けた署名を送ります。CertificateVerify によって、証明書を持っているだけでなく秘密鍵も持っていることが証明されます。

> For all requests to the authorization server utilizing mutual-TLS client authentication, the client MUST include the "client_id" parameter described in Section 2.2 of OAuth 2.0 [RFC6749].

(RFC 8705 2節)

mTLS で認証するリクエストには、必ず `client_id` を含めなければなりません(MUST)。同じ節は、その理由を「証明書の内容とは独立にクライアントを特定できるようにするため」と説明しています。認可サーバは `client_id` で登録情報を引き、提示された証明書がその登録内容と一致するかを確かめます。一致しない場合や証明書がない場合は、`invalid_client` のエラーを返します。

> In contrast to the PKI method, the client's certificate chain is not validated by the server in this case.

(RFC 8705 2.2節)

この節は、自己署名方式では認可サーバがクライアントの証明書チェーンを検証しないことを定めています。自己署名方式では、信頼の根拠は登録された証明書と同一であることであり、認可サーバは証明書チェーンも認証局の署名も検証しません。このため PKI を運用せずに使え、`jwks_uri` と組み合わせればクライアントが証明書を自分で更新できます。

mTLS の実装上の注意点は、TLS を終端する場所です。多くの構成では、ロードバランサやリバースプロキシが TLS を終端し、アプリケーションには平文の HTTP が届きます。この場合、プロキシは検証したクライアント証明書をヘッダでアプリケーションに渡します。プロキシが外部からの同名のヘッダを除去しないと、攻撃者はヘッダを偽造して任意の証明書を名乗れます。RFC 9700 の4.13節がこの構成の注意点を扱っています。mTLS はクライアント認証のほかに、アクセストークンを証明書に結びつける用途にも使われます。こちらは[16章](/oauth-deep/16-sender-constrained/)で扱います。

## 方式の比較と選び方

RFC 9700(OAuth 2.0 Security BCP)の2.5節は、クライアント認証の方式について次のように推奨しています。

> It is RECOMMENDED to use asymmetric cryptography for client authentication, such as mutual TLS for OAuth 2.0 [RFC8705] or signed JWTs ("Private Key JWT") in accordance with [RFC7521] and [RFC7523].

(RFC 9700 2.5節)

クライアント認証には非対称暗号(公開鍵暗号)を使うことを推奨しています(RECOMMENDED)。同じ節は、その理由を、認可サーバが漏洩に弱い対称鍵を保存せずに済むためと説明しています。

ここまでの方式を、攻撃と運用の観点で比べます。

| 観点 | `client_secret_basic` / `post` | `client_secret_jwt` | `private_key_jwt` | mTLS |
| --- | --- | --- | --- | --- |
| 盗聴されたリクエストの再利用 | 期限なく可能 | `exp` と `jti` で制限 | `exp` と `jti` で制限 | 不可(TLS の秘密鍵が必要) |
| 認可サーバの記録の漏洩 | なりすまし可能 | なりすまし可能 | 影響なし | 影響なし |
| 鍵の更新 | 認可サーバ側で再発行 | 認可サーバ側で再発行 | `jwks_uri` で自分で更新 | 証明書の更新(PKI 方式は同じ名前で) |
| 導入の手間 | 少ない | JWT の生成が必要 | 鍵管理と JWT の生成が必要 | TLS 層の設定と証明書の運用が必要 |

選び方の目安は次のとおりです。

- 新しく構築するサーバ間の連携や、FAPI 2.0 のような高セキュリティの要件がある場合は、`private_key_jwt` か mTLS を選びます。FAPI 2.0 はこの2つだけを認めています([25章](/security/25-high-security/))
- 既存の認可サーバが共有シークレットしか扱えない場合は、`client_secret_post` を優先し、シークレットを英数字と `-._` だけで構成します
- パブリッククライアントでは、どの方式でもクライアント認証は成立しません。`none` を登録し、PKCE とリダイレクト URI の完全一致で認可コードを保護します

OAuth 2.1(draft-16)の2.4節は、1つのリクエストで複数の認証方式を使ってはならない(MUST NOT)とも定めています。同節はその理由を、どちらの認証方式をそのリクエストの正とするかの衝突を防ぐためと説明しています。

## 動的クライアント登録

ここまでの方式はすべて、クライアントが事前に認可サーバに登録されていることを前提にしています。登録の手続きは、多くの場合、開発者が管理画面で行います。**動的クライアント登録**(dynamic client registration)は、この登録を HTTP の API として行う仕組みで、RFC 7591 が定めています。クライアントは**クライアント登録エンドポイント**(client registration endpoint)に、自分のメタデータを JSON で送ります。

```http
POST /register HTTP/1.1
Content-Type: application/json
Accept: application/json
Host: server.example.com

{
 "redirect_uris": ["https://client.example.org/callback"],
 "client_name": "My Example Client",
 "token_endpoint_auth_method": "private_key_jwt",
 "jwks_uri": "https://client.example.org/my_public_keys.jwks"
}
```

認可サーバは `client_id` を割り当て、登録したメタデータを返します。共有シークレットの方式を登録した場合は、`client_secret` と、その有効期限 `client_secret_expires_at`(0 は無期限)も返します。

```http
HTTP/1.1 201 Created
Content-Type: application/json
Cache-Control: no-store

{
 "client_id": "s6BhdRkqt3",
 "client_id_issued_at": 2893256800,
 "redirect_uris": ["https://client.example.org/callback"],
 "client_name": "My Example Client",
 "token_endpoint_auth_method": "private_key_jwt",
 "jwks_uri": "https://client.example.org/my_public_keys.jwks"
}
```

登録エンドポイントを誰でも呼べる構成(オープン登録)にすると、攻撃者も自由にクライアントを登録できます。RFC 7591 は、登録を許可するために**初期アクセストークン**(initial access token)を Bearer トークンとして要求する構成も定めています。初期アクセストークンの入手方法は仕様の範囲外です。

登録時のメタデータを、第三者が保証する方法もあります。**ソフトウェアステートメント**(software statement)は、クライアントソフトウェアについてのメタデータ(名前、URI など)を JWT にまとめ、発行者が署名したものです。RFC 7591 2.3節は、登録リクエストで提示するソフトウェアステートメントは JWS で署名または MAC されていなければならず(MUST)、主張している主体を示す `iss` を含まなければならない(MUST)と定めています。認可サーバは、信頼する発行者の署名を確認することで、申告されたメタデータを検証なしで受け入れずに済みます。どの発行者を信頼するかは仕様の範囲外であり、オープンバンキングなどのエコシステムごとに決められています。

動的クライアント登録には、運用上の課題もあります。CIMD の draft(後述)の1節は、登録データの管理や、使われなくなったクライアントの整理が負担になることを挙げています。不特定多数のクライアントが自由に登録すると、認可サーバには誰も削除しない登録が際限なく蓄積されます。

## Client ID Metadata Document

**Client ID Metadata Document**(CIMD)は、クライアントが自分のメタデータを自分の URL で公開し、その URL を `client_id` として使う仕組みです。IETF で策定中であり、本書では draft-ietf-oauth-client-id-metadata-document-02(2026年7月6日付。2026年10月16日に最新版であることを確認)に従って説明します。

```mermaid
sequenceDiagram
    participant B as ブラウザ
    participant C as クライアント
    participant AS as 認可サーバ
    C->>B: 302 認可エンドポイントへ<br/>client_id=https://app.example.com/oauth/client.json
    B->>AS: GET /authorize?client_id=https://app.example.com/oauth/client.json&...
    AS->>C: GET /oauth/client.json (リダイレクトは追わない)
    C-->>AS: 200 OK (メタデータの JSON)
    AS->>AS: JSON の client_id と URL の一致、redirect_uri の完全一致を確認
    AS-->>B: ログインと同意の画面
```

`client_id` の URL が指す JSON は、RFC 7591 のクライアントメタデータと同じ項目を持ちます。

```json
{
  "client_id": "https://app.example.com/oauth/client.json",
  "client_name": "Example App",
  "redirect_uris": ["https://app.example.com/callback"],
  "token_endpoint_auth_method": "private_key_jwt",
  "jwks_uri": "https://app.example.com/oauth/jwks.json"
}
```

draft-02 の主な規定は次のとおりです。

- `client_id` の URL は https でなければならず(MUST)、パスを含まなければなりません(MUST)。フラグメントを含めてはならず(MUST NOT)、比較は単純な文字列比較で行います。`https://example.com/client` と `https://example.com:443/client` は別の識別子として扱われます
- 文書の `client_id` プロパティは、文書を取得した URL と一致しなければなりません(MUST)
- 共有シークレットを確立する手段がないため、`token_endpoint_auth_method` に `client_secret_basic` などの対称鍵の方式を指定してはなりません(MUST NOT)。秘密鍵を文書に含めることも禁止され、公開鍵だけを `jwks` か `jwks_uri` で示します。秘密鍵を保持できるクライアントは `private_key_jwt` などで認証し、それ以外はパブリッククライアントとして扱われます
- 認可サーバは、文書の取得で HTTP リダイレクトを自動で追ってはなりません(MUST NOT)。エラー応答や不正な文書をキャッシュしてはなりません(MUST NOT)
- 認可サーバメタデータの `client_id_metadata_document_supported` で、この仕組みに対応していることを示します

この仕組みでは、認可サーバが外部から指定された URL へ HTTP リクエストを送ります。攻撃者が `client_id` に認可サーバの内部ネットワークのアドレスを指定すると、外部からは届かないはずの内部サービスに、認可サーバからリクエストが送られます。この攻撃は[11章](/rust-impl/11-build-rp/)で説明した SSRF です。draft-02 の8.6節は SSRF への対策を求めており、実装では取得先のアドレスが内部ネットワークでないことを確認する必要があります。

CIMD は、事前の関係を持たないクライアントと認可サーバが接続する場面を想定しています。AI エージェントが不特定の MCP サーバに接続する場合がその代表例で、[27章](/practice/27-ecosystem/)で扱います。

## まとめ

- クライアントの種類は、資格情報を秘密に保てるかで決まり、判定は認可サーバの定義に従います。アプリに埋め込んだシークレットは抽出できるものと仮定します
- `client_secret_basic` は、RFC 6749 2.3.1節により `client_id` とシークレットを form-urlencoded で符号化してから Basic 認証にします。実験では、`+` や `/` を含むシークレットで、規定に従う実装と従わない実装の組み合わせが認証に失敗しました
- OAuth 2.1(draft-16)は、この相互運用性の問題を理由に、本文で送る方式を MUST、Basic 認証を MAY に入れ替えています
- `client_secret_jwt` はシークレットを送りませんが、認可サーバは鍵として使える形でシークレットを保存します。`private_key_jwt` と mTLS は、認可サーバに公開鍵や証明書の情報だけを保存させます。RFC 9700 は非対称暗号の方式を推奨しています
- アサーションの `aud` は仕様ごとに規定が異なります。issuer 識別子を文字列で入れると、RFC 9126 と FAPI 2.0 の両方に適合します
- 動的クライアント登録は登録を API で行い、Client ID Metadata Document は URL を `client_id` にして登録そのものを省きます。後者では SSRF への対策が必要です

次章では、トークンを受け取る側であるリソースサーバに移ります。JWT アクセストークンの検証規則、不透明トークンのイントロスペクション、トークンの失効と宛先の制限を扱います。
