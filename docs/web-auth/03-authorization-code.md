---
title: 認可コードフロー
description: OAuth 2.0の中心となる認可コードフローを、認可リクエスト、認可レスポンス、トークンリクエストのHTTPメッセージ1つ1つまで追う。なぜコードを1度挟むのか、stateが何を防ぐのかを、RFC 6749の原文と1プロセス内の再現実験で確かめる。
sidebar:
  label: 3. 認可コードフロー
---

この章でわかること:

- 認可コードフローの全体の流れと、各段階のHTTPメッセージ
- 認可リクエストのパラメータ(`response_type`、`client_id`、`redirect_uri`、`scope`、`state`)の意味
- リダイレクトURIの登録と完全一致の比較が必要な理由
- アクセストークンを直接返さず、認可コードを1度挟む理由
- `state`パラメータが防ぐ攻撃(CSRF)と、エラーレスポンスの扱い

## 全体の流れ

[2章](/web-auth/02-delegation/)の抽象フローでは、クライアントが権限付与を受け取り、
それをアクセストークンと交換しました。**認可コードフロー**(authorization code flow)は、
権限付与として**認可コード**(authorization code)を使う手順です。認可コードは、
認可サーバがリソースオーナーの許可を得た後に発行する、有効期間が短く1回しか使えない値です。
RFC 6749ではこの手順を「Authorization Code Grant」(4.1節)と呼んでいます。

例は前章と同じで、aliceが印刷サービス(クライアント、`client.example.com`)に、
写真共有サービスの写真の読み出しを許可します。認可サーバは`server.example.com`です。
ホスト名はRFC 6749の例に合わせています。

```mermaid
sequenceDiagram
    participant B as ブラウザ
    participant C as クライアント
    participant A as 認可サーバ
    B->>C: (1) GET /login
    C-->>B: 302 Location: 認可エンドポイント?response_type=code&...&state=...
    B->>A: (2) GET /authorize?response_type=code&...
    A-->>B: 200 ログイン画面と同意画面
    B->>A: (3) POST /authorize (ログインと許可)
    A-->>B: 302 Location: リダイレクトURI?code=...&state=...
    B->>C: (4) GET /cb?code=...&state=...
    C->>A: (5) POST /token (code、クライアント認証)
    A-->>C: 200 アクセストークン
    C-->>B: 302 Location: /photos
```

(1)から(4)はブラウザを経由するフロントチャネル、(5)はクライアントと認可サーバが
直接通信するバックチャネルです。(1)と(2)が認可リクエスト、(3)の応答が認可レスポンス、
(5)がトークンリクエストとトークンレスポンスです。以下、メッセージを順に説明し、
最後に1つのプロセスの中でこの流れ全体を再現します。

フローで使うURLには名前があります。RFC 6749の3節は、認可サーバ側の2つのエンドポイントと、
クライアント側の1つのエンドポイントを定めています。**エンドポイント**(endpoint)は、
特定の役割を持つHTTPのURLのことです。

- **認可エンドポイント**(authorization endpoint): 認可サーバのURLで、ブラウザ経由で
  リソースオーナーに画面を表示し、権限付与を得るために使います。例では`https://server.example.com/authorize`です
- **トークンエンドポイント**(token endpoint): 認可サーバのURLで、クライアントが
  権限付与をアクセストークンと交換するために使います。例では`https://server.example.com/token`です
- **リダイレクトエンドポイント**(redirection endpoint): クライアントのURLで、認可サーバが
  ブラウザ経由で認可レスポンスを返す先です。例では`https://client.example.com/cb`です

リダイレクトエンドポイントのURIを**リダイレクトURI**(redirection URI)と呼びます。
クライアントは事前に認可サーバへ登録しておく必要があります。登録の手順は
RFC 6749の範囲外で、多くの認可サーバでは管理画面から登録します。登録すると
認可サーバはクライアントを識別するための文字列を発行します。これがクライアントIDで、
例では`s6BhdRkqt3`です(RFC 6749の例の値です)。

## 認可リクエスト

フローは、利用者がクライアントの「写真共有サービスから取り込む」のようなボタンを押すところから始まります。
クライアントは認可エンドポイントのURLにパラメータを付けたURLを組み立て、ブラウザにそこへ
移動するよう指示します。

```http
HTTP/1.1 302 Found
Location: https://server.example.com/authorize?response_type=code&client_id=s6BhdRkqt3&redirect_uri=https%3A%2F%2Fclient.example.com%2Fcb&scope=photos%3Aread&state=DbKQVE43RWfoeIXLycA2zA
Set-Cookie: client_sid=wjnmgQOYuW3neGnWXPSyow; Path=/; Secure; HttpOnly; SameSite=Lax
```

ステータスコード**302**(Found)は、リソースが一時的に別のURLにあることを示すステータスコードで、
ブラウザは`Location`ヘッダのURLを自動で開きます。このようにレスポンスで別のURLを開かせることを
**リダイレクト**(redirect)と呼びます。RFC 6749は例に302を使っていますが、1.7節で
ブラウザを移動させる手段は302に限らず実装の詳細である、と書いています。

ブラウザは`Location`のURLを開き、認可エンドポイントに次のリクエストが届きます。

```http
GET /authorize?response_type=code&client_id=s6BhdRkqt3&redirect_uri=https%3A%2F%2Fclient.example.com%2Fcb&scope=photos%3Aread&state=DbKQVE43RWfoeIXLycA2zA HTTP/1.1
Host: server.example.com
```

URLの`?`より後ろの部分を**クエリ文字列**(query string)と呼びます。
`名前=値`の組を`&`で区切って並べる形式で、認可リクエストのパラメータはすべてここに入ります。
クライアントから認可サーバへのメッセージが、ブラウザが開くURLとして送られています。
これがフロントチャネルの具体的な形です。

## RFCを読む: RFC 6749 4.1.1節

認可リクエストのパラメータは4.1.1節が定めています。

> The client constructs the request URI by adding the following parameters to the query component of the authorization endpoint URI using the "application/x-www-form-urlencoded" format, per Appendix B:

(RFC 6749 4.1.1節)

この文は、パラメータを認可エンドポイントのURIのクエリ部分に、
`application/x-www-form-urlencoded`形式で付け加えると定めています。この形式は次節で説明します。
パラメータは5つです。

> response_type  REQUIRED.  Value MUST be set to "code".
>
> client_id  REQUIRED.  The client identifier as described in Section 2.2.
>
> redirect_uri  OPTIONAL.  As described in Section 3.1.2.
>
> scope  OPTIONAL.  The scope of the access request as described by Section 3.3.
>
> state  RECOMMENDED.  An opaque value used by the client to maintain state between the request and callback.  The authorization server includes this value when redirecting the user-agent back to the client.  The parameter SHOULD be used for preventing cross-site request forgery as described in Section 10.12.

(RFC 6749 4.1.1節)

`response_type`(レスポンス種別)は、認可エンドポイントが何を返すかを指定するパラメータです。
必須(REQUIRED)で、認可コードフローでは値を`code`にしなければなりません(MUST)。
RFC 6749はこのほかに`token`(インプリシットフロー、[19章](/oidc-deep/19-flows/))を定めています。

`client_id`(クライアントID)は、認可サーバがクライアントの登録時に発行した識別子です。
必須です。2.2節は、クライアントIDはリソースオーナーにも見える公開の値なので、
クライアントIDだけでクライアントを認証してはならない(MUST NOT)、と定めています。
実際、上のURLにはクライアントIDがそのまま現れていて、ブラウザを使う誰もが読めます。

`redirect_uri`(リダイレクトURI)は、認可レスポンスを返す先のURIです。4.1.1節では任意(OPTIONAL)ですが、
これは登録済みのリダイレクトURIが1つだけで、それを使う場合に省略できるという意味です。
省略できる条件と、認可サーバの比較方法は3.1.2節が定めていて、後で読みます。

`scope`(スコープ)は、クライアントが求めるアクセスの範囲を指定するパラメータです。
値は空白で区切った文字列の並びで、例の`photos:read`のように、どの文字列がどの範囲を意味するかは
認可サーバが決めます。スコープの設計は[4章](/web-auth/04-tokens/)で扱います。

`state`(state パラメータ)は、クライアントが自分で生成して認可リクエストに付ける値で、
認可サーバはそれを認可レスポンスにそのまま付けて返します。RFCは推奨(RECOMMENDED)とし、
CSRFを防ぐために使うべきである(SHOULD)と書いています。原文の「opaque value」は、
認可サーバにとって中身の意味を持たない値であることを指しています。認可サーバは
`state`を解釈せず、受け取った値を返すだけです。`state`の役割はこの章の後半で説明します。

RFCの例は次のとおりです(表示のために改行が入っています)。

```http
GET /authorize?response_type=code&client_id=s6BhdRkqt3&state=xyz
    &redirect_uri=https%3A%2F%2Fclient%2Eexample%2Ecom%2Fcb HTTP/1.1
Host: server.example.com
```

(RFC 6749 4.1.1節)

3.1節は、認可エンドポイント全般の規則も定めています。認可エンドポイントへのリクエストでは
利用者の認証が行われ、資格情報が平文で送られるため、認可サーバはTLSの使用を
求めなければなりません(MUST)。値のないパラメータは省略されたものとして扱わなければならず(MUST)、
認識できないパラメータは無視しなければならず(MUST)、同じパラメータを2回以上含めてはなりません(MUST NOT)。

## URLエンコードとapplication/x-www-form-urlencoded

認可リクエストの`redirect_uri`の値は、`https%3A%2F%2Fclient.example.com%2Fcb`のように
`%`と16進数の並びに置き換えられていました。

**URLエンコード**(URL encoding)は、URLの中で特別な意味を持つ文字や、URLに使えない文字を、
`%`の後にそのバイト値を16進数2桁で書いた形に置き換える変換です。RFC 3986では
**パーセントエンコーディング**(percent-encoding)と呼ばれます。例えば`:`(0x3A)は`%3A`、
`/`(0x2F)は`%2F`になります。`redirect_uri`の値はそれ自体がURLなので、
`:`や`/`や`?`や`&`を含みます。そのまま入れると、外側のURLの区切りと区別できなくなります。

**application/x-www-form-urlencoded**は、HTMLのフォームの送信に由来する、
`名前=値`の組を`&`で連結する形式です。名前と値はURLエンコードし、空白は`+`で表します。
RFC 6749は、認可リクエストのクエリ、認可レスポンスのクエリ、トークンリクエストのボディの
すべてでこの形式を使います。RFC 6749の付録Bは、この形式の扱いを補っています。

> To address this shortcoming when generating payloads using this media type, names and values MUST be encoded using the UTF-8 character encoding scheme [RFC3629] first; the resulting octet sequence then needs to be further encoded using the escaping rules defined in [W3C.REC-html401-19991224].

(RFC 6749 付録B)

この文は、元になったHTML 4.01の定義がASCII以外の文字を考慮していなかったため、
名前と値をまずUTF-8でバイト列にし(MUST)、そのバイト列をHTMLの規則でエスケープする、と定めています。
付録Bには、空白、`%`、`&`、`+`、ポンド記号、ユーロ記号の6文字の例があります。

## 実験: application/x-www-form-urlencodedの符号化と解析

付録Bの例を再現し、`redirect_uri`の符号化と、符号化しない場合に何が起きるかを確かめます。
符号化と解析には`form_urlencoded`クレートを使います。

<RustPlay snippet="ch03/form-urlencoded" title="付録Bの例とパラメータの符号化" />

出力の[1]は、付録Bの6文字が`+%25%26%2B%C2%A3%E2%82%AC`になり、RFCの値と一致することを示しています。
空白が`+`に、`+`自体は`%2B`になる点が、URLのパス部分のパーセントエンコーディングとの違いです。

[2]では、このクレートの出力とRFC 4.1.1節の例の値が異なっています。RFCの例は`.`も
`%2E`に変換していますが、`.`はエンコードしなくてもよい文字なので、このクレートは変換しません。
復号すると同じ値になるので、どちらも正しい符号化です。このため、受信側は
復号してから値を比べる必要があります。受け取った文字列をそのまま比べると、同じ値を異なると判定します。

[3]は、`state`の値に`&`と`=`が含まれる場合です。エンコードせずに連結すると、
解析した側は`scope=admin`という別のパラメータがあると解釈します。値の中身を攻撃者が
制御できる場合、この誤りはパラメータの追加に利用されます。URLの組み立てでは、
`form_urlencoded::Serializer`や`url`クレートの`query_pairs_mut`のような
符号化を行う関数を使い、文字列の連結で組み立てないでください。

[4]は、同じパラメータが2回現れるクエリです。`HashMap`に集めると後の値で上書きされ、
`scope`は`admin`になります。解析の方法によって最初の値と最後の値のどちらが使われるかが変わるため、
RFC 6749の3.1節は、パラメータを2回以上含めてはならないと定め、4.1.2.1節は
パラメータの重複を`invalid_request`の条件に含めています。

## 認可レスポンス

認可エンドポイントは、リクエストを検証した後、ブラウザにログイン画面を表示して
aliceを認証し、続けて同意画面を表示します。同意画面には、どのクライアントが
どの範囲のアクセスを求めているかを表示します。ログインの方法と同意画面の内容は
RFC 6749の範囲外で、認可サーバごとに異なります。

aliceが許可すると、認可サーバは認可コードを生成し、リダイレクトURIにパラメータを付けて
ブラウザをリダイレクトさせます。

```http
HTTP/1.1 302 Found
Location: https://client.example.com/cb?code=0gIyJ8LSMAvBSFepD9I7Rw&state=DbKQVE43RWfoeIXLycA2zA
```

ブラウザはこのURLを開き、クライアントのリダイレクトエンドポイントに次のリクエストが届きます。

```http
GET /cb?code=0gIyJ8LSMAvBSFepD9I7Rw&state=DbKQVE43RWfoeIXLycA2zA HTTP/1.1
Host: client.example.com
Cookie: client_sid=wjnmgQOYuW3neGnWXPSyow
```

認可サーバからクライアントへのメッセージ(認可コード)が、ブラウザが開くURLとして送られています。
クライアントのセッションCookieも付いているので、クライアントはこのリクエストが
どのブラウザのセッションから来たかを特定できます。

## RFCを読む: RFC 6749 4.1.2節

認可レスポンスのパラメータは2つです。`code`の定義には、認可コードの性質に関する規則がまとまっています。

> code  REQUIRED.  The authorization code generated by the authorization server.  The authorization code MUST expire shortly after it is issued to mitigate the risk of leaks.  A maximum authorization code lifetime of 10 minutes is RECOMMENDED.  The client MUST NOT use the authorization code more than once.  If an authorization code is used more than once, the authorization server MUST deny the request and SHOULD revoke (when possible) all tokens previously issued based on that authorization code.  The authorization code is bound to the client identifier and redirection URI.

(RFC 6749 4.1.2節)

この節は、`code`パラメータ(認可コード)について、次のことを定めています。

- 漏洩の危険を減らすため、認可コードは発行後すぐに期限切れにならなければなりません(MUST)。
  最長でも10分にすることが推奨されます(RECOMMENDED)
- クライアントは認可コードを2回以上使ってはなりません(MUST NOT)
- 2回以上使われた場合、認可サーバはリクエストを拒否しなければならず(MUST)、
  可能ならそのコードに基づいて発行したすべてのトークンを失効させるべきです(SHOULD)
- 認可コードは、クライアントIDとリダイレクトURIに結びつけられています

最後の規則は、トークンリクエストの検証で使われます。認可サーバは、コードを発行したときの
クライアントIDとリダイレクトURIを記録しておき、トークンリクエストの値と照合します。

`state`は、認可リクエストに`state`があった場合は必須(REQUIRED)で、
クライアントから受け取った値をそのまま返します。

4.1.2節は続けて、クライアントは認識できないレスポンスパラメータを無視しなければならない(MUST)こと、
認可コードの長さはRFCでは定めないことを書いています。

## RFCを読む: RFC 6749 3.1.2節

リダイレクトURIの規則は3.1.2節とその下位の節が定めています。まず形式の規則です。

> The redirection endpoint URI MUST be an absolute URI as defined by [RFC3986] Section 4.3.  The endpoint URI MAY include an "application/x-www-form-urlencoded" formatted (per Appendix B) query component ([RFC3986] Section 3.4), which MUST be retained when adding additional query parameters.  The endpoint URI MUST NOT include a fragment component.

(RFC 6749 3.1.2節)

この節は、リダイレクトURIはスキームを含む絶対URIでなければならないこと(MUST)、
クエリを含んでもよいが(MAY)、認可サーバがパラメータを追加するときは既存のクエリを
保持しなければならないこと(MUST)、`#`以降のフラグメントを含んではならないこと(MUST NOT)を定めています。
RFC 3986 4.3節の絶対URIは`スキーム:`で始まるURIで、ホスト部を持つかどうかはスキームによって決まります。
例えば、RFC 8252 7.1節はネイティブアプリ向けに`com.example.app:/oauth2redirect/example-provider`のような
ホスト部のないリダイレクトURIを示しています。

登録と比較の規則は3.1.2.2節と3.1.2.3節にあります。

> The authorization server SHOULD require the client to provide the complete redirection URI (the client MAY use the "state" request parameter to achieve per-request customization).

(RFC 6749 3.1.2.2節)

> If the client registration included the full redirection URI, the authorization server MUST compare the two URIs using simple string comparison as defined in [RFC3986] Section 6.2.1.

(RFC 6749 3.1.2.3節)

3.1.2.2節は、認可サーバはクライアントにリダイレクトURIの全体を登録させるべきである(SHOULD)と定め、
リクエストごとに変えたい情報は`state`に入れればよい、と補っています。3.1.2.3節は、
全体が登録されている場合、認可サーバはリクエストの`redirect_uri`と登録値を
単純な文字列比較で比べなければならない(MUST)、と定めています。

この規則は、RFC 6749では「全体を登録させるべき(SHOULD)」にとどまっていて、
スキームとホストとパスだけを登録させ、クエリの違いを許す運用も認めていました。
その後、前方一致や部分一致で比較する実装への攻撃が多数報告され、
RFC 9700(2025年1月、BCP)はこの規則を強めています。

> When comparing client redirection URIs against pre-registered URIs, authorization servers MUST utilize exact string matching except for port numbers in localhost redirection URIs of native apps (see Section 4.1.3).

(RFC 9700 2.1節)

この文は、認可サーバはリダイレクトURIを登録値と完全一致で比較しなければならない(MUST)、
と定めています。例外は、ネイティブアプリがループバックアドレスで受ける場合のポート番号だけです
([24章](/security/24-browser-native/))。RFC 9700はRFC 6749を更新する(Updates)文書なので、
現在の実装はこの規則に従います。前方一致の比較で何が起きるかは
[22章](/security/22-threats/)で実験します。

リダイレクトURIが不正な場合の扱いは3.1.2.4節が定めています。

> If an authorization request fails validation due to a missing, invalid, or mismatching redirection URI, the authorization server SHOULD inform the resource owner of the error and MUST NOT automatically redirect the user-agent to the invalid redirection URI.

(RFC 6749 3.1.2.4節)

この節は、リダイレクトURIが欠けている、不正である、または登録値と一致しない場合、
認可サーバはリソースオーナーにエラーを知らせるべきであり(SHOULD)、
その不正なリダイレクトURIへブラウザを自動でリダイレクトさせてはならない(MUST NOT)、と定めています。
不正なリダイレクトURIへエラーを返すと、攻撃者が指定したURLへブラウザを送る手段を
攻撃者に与えることになります。このように任意のURLへブラウザを移動させられる仕組みは
オープンリダイレクタと呼ばれ、[22章](/security/22-threats/)で扱います。

## RFCを読む: RFC 6749 4.1.2.1節

認可エンドポイントでの処理が失敗する場合は2種類あり、RFC 6749はそれぞれ扱いを分けています。

> If the request fails due to a missing, invalid, or mismatching redirection URI, or if the client identifier is missing or invalid, the authorization server SHOULD inform the resource owner of the error and MUST NOT automatically redirect the user-agent to the invalid redirection URI.
>
> If the resource owner denies the access request or if the request fails for reasons other than a missing or invalid redirection URI, the authorization server informs the client by adding the following parameters to the query component of the redirection URI using the "application/x-www-form-urlencoded" format, per Appendix B:

(RFC 6749 4.1.2.1節)

この節は、失敗の扱いを次の2つに分けています。

- リダイレクトURIまたはクライアントIDに問題がある場合: エラーを返す先が信頼できないので、
  リダイレクトせずに利用者へ直接表示します
- それ以外の場合(利用者が拒否した、パラメータが不正など): リダイレクトURIにエラーを付けて
  クライアントへ知らせます

このため、認可エンドポイントは`client_id`と`redirect_uri`を最初に検証し、
それが通った後で他のパラメータを検証する順序で実装します。

エラーを知らせるパラメータは`error`(必須)、`error_description`(任意、人が読む説明)、
`error_uri`(任意、説明のページのURI)、`state`(認可リクエストにあった場合は必須)です。
`error`パラメータの値はエラーコードで、次の7つが定められています。

| エラーコード | 意味 |
| --- | --- |
| `invalid_request` | 必須のパラメータがない、値が不正、パラメータの重複など、リクエストの形式が不正 |
| `unauthorized_client` | このクライアントは、この方法で認可コードを要求することを許されていない |
| `access_denied` | リソースオーナーまたは認可サーバが要求を拒否した |
| `unsupported_response_type` | 認可サーバがこの`response_type`をサポートしていない |
| `invalid_scope` | 要求されたスコープが不正、未知、または形式が誤っている |
| `server_error` | 認可サーバの内部エラー(リダイレクトでは500を返せないため) |
| `temporarily_unavailable` | 過負荷や保守で一時的に処理できない(リダイレクトでは503を返せないため) |

**500 Internal Server Error**は、サーバ内部の予期しない障害でリクエストを処理できなかったことを表すステータスコードです。
`server_error`と`temporarily_unavailable`の注記は、フロントチャネルの性質を示しています。
認可サーバからクライアントへのメッセージはブラウザのリダイレクトとして届くので、
HTTPのステータスコードでは伝えられず、クエリのパラメータで伝える必要があります。
RFCの例は次のとおりです。

```http
HTTP/1.1 302 Found
Location: https://client.example.com/cb?error=access_denied&state=xyz
```

(RFC 6749 4.1.2.1節)

`error_description`はクライアントの開発者のための情報で、利用者に見せるためのものではありません。
またフロントチャネルを通る値なので、攻撃者が偽の値を作ってリダイレクトエンドポイントを
開かせることもできます。クライアントは`error_description`の内容をそのまま画面に表示しないでください。

## トークンリクエスト

リダイレクトエンドポイントで認可コードを受け取ったクライアントは、
ブラウザへの応答を保留したまま、トークンエンドポイントへ直接リクエストを送ります。
これがバックチャネルの通信です。

```http
POST /token HTTP/1.1
Host: server.example.com
Authorization: Basic czZCaGRSa3F0MzpnWDFmQmF0M2JW
Content-Type: application/x-www-form-urlencoded

grant_type=authorization_code&code=0gIyJ8LSMAvBSFepD9I7Rw&redirect_uri=https%3A%2F%2Fclient.example.com%2Fcb
```

ボディは`application/x-www-form-urlencoded`形式で、3つのパラメータがあります。
`grant_type`(グラントタイプ)は、どの種類の権限付与を提示しているかを示すパラメータで、
認可コードの場合は`authorization_code`です。`code`は受け取った認可コード、
`redirect_uri`は認可リクエストで送ったものと同じ値です。

Authorizationヘッダは、クライアント自身の認証です。**クライアント認証**(client authentication)は、
トークンエンドポイントへのリクエストを送ってきたのが、登録されたクライアント本人であることを
認可サーバが確かめる処理です。RFC 6749の2.3.1節は、クライアントに**クライアントシークレット**
(client secret)が発行されている場合、[1章](/web-auth/01-http-auth/)のBasic認証で
クライアントIDをユーザー名、クライアントシークレットをパスワードとして送る方法を定めています。
クライアントシークレットは、認可サーバとクライアントだけが保持する秘密の文字列で、
クライアントにとってのパスワードにあたります。2.3.1節は、クライアントIDとクライアントシークレットを
それぞれ付録Bの`application/x-www-form-urlencoded`の規則で符号化してから、
ユーザー名とパスワードとして使うと定めています。このため、ヘッダの値は
「符号化したクライアントID、コロン、符号化したクライアントシークレット」を連結してBase64にしたものになり、
受信側はBase64を復号して最初のコロンで分けた後、それぞれを復号します。
例の`s6BhdRkqt3`と`gX1fBat3bV`は符号化しても変わらない文字だけなので、例のヘッダの値は
`s6BhdRkqt3:gX1fBat3bV`をBase64にしたものと同じです(RFC 6749の例の値です)。

クライアント認証の方法はこのほかにもあり、ボディに`client_secret`を入れる方法、
秘密鍵で署名したJWT([7章](/oidc/07-jwt-jose/))を送る方法などがあります。秘密を安全に保持できないクライアントもあります。
これらは[13章](/oauth-deep/13-client-auth/)で扱います。

## RFCを読む: RFC 6749 4.1.3節と4.1.4節

> redirect_uri  REQUIRED, if the "redirect_uri" parameter was included in the authorization request as described in Section 4.1.1, and their values MUST be identical.
>
> client_id  REQUIRED, if the client is not authenticating with the authorization server as described in Section 3.2.1.

(RFC 6749 4.1.3節)

この節は、認可リクエストに`redirect_uri`を含めた場合は、トークンリクエストにも含めることが必須で、
2つの値は同一でなければならない(MUST)、と定めています。また、クライアント認証をしない
クライアントは`client_id`を送ることが必須です。

認可サーバが行う検証は、次のように列挙されています。

> The authorization server MUST:
>
> o  require client authentication for confidential clients or for any client that was issued client credentials (or with other authentication requirements),
>
> o  authenticate the client if client authentication is included,
>
> o  ensure that the authorization code was issued to the authenticated confidential client, or if the client is public, ensure that the code was issued to "client_id" in the request,
>
> o  verify that the authorization code is valid, and
>
> o  ensure that the "redirect_uri" parameter is present if the "redirect_uri" parameter was included in the initial authorization request as described in Section 4.1.1, and if included ensure that their values are identical.

(RFC 6749 4.1.3節)

この5項目は、認可サーバが必ず行わなければならない(MUST)検証です。言い換えると、
認可サーバは次の5つを行います。

- 認証が必要なクライアントにはクライアント認証を求めます
- 認証情報が提示された場合は、それを検証します
- 認可コードがそのクライアントに発行されたものかを確かめます
- 認可コードが有効か(期限内で未使用か)を確かめます
- 認可リクエストに`redirect_uri`があった場合は、トークンリクエストにも`redirect_uri`があり、
  2つの値が同一であることを確かめます

原文のconfidential client(機密クライアント)とpublic client(パブリッククライアント)は、
秘密を保持できるかどうかによるクライアントの区別で、13章で扱います。

4.1.4節は、検証に成功したら5.1節の形式でアクセストークンを返し、
失敗したら5.2節の形式でエラーを返すと定めています。成功時のレスポンスは次の形です。

```http
HTTP/1.1 200 OK
Content-Type: application/json;charset=UTF-8
Cache-Control: no-store
Pragma: no-cache

{
  "access_token":"2YotnFZFEjr1zCsicMWpAA",
  "token_type":"example",
  "expires_in":3600,
  "refresh_token":"tGzv3JOkF0XG5Qx2TlKWIA",
  "example_parameter":"example_value"
}
```

(RFC 6749 4.1.4節)

レスポンスの各項目と`Cache-Control`ヘッダの意味は[4章](/web-auth/04-tokens/)で読みます。
エラーの場合の代表的な値が`invalid_grant`で、認可コードが無効、期限切れ、使用済み、
リダイレクトURIの不一致、別のクライアントに発行されたもの、のいずれかを表すエラーコードです。

## なぜコードを1度挟むのか

認可サーバは、aliceの許可を得た時点でアクセストークンを発行できます。
それをリダイレクトURIに付けて返せば、トークンリクエストの往復を省けます。
それでも認可コードフローがコードを1度挟むのは、フロントチャネルとバックチャネルの
性質の違いによるものです。

フロントチャネルを通る値は、次の場所に残り、また読まれる可能性があります。

- ブラウザの履歴: `https://client.example.com/cb?code=...`というURLが履歴に記録されます
- Refererヘッダ: リダイレクトエンドポイントの応答のページから外部のリソースを読み込むと、
  ブラウザが送るRefererヘッダ(遷移元のページのURLを伝えるヘッダ)にURLが含まれることがあります
- サーバやプロキシのアクセスログ: URLはログに記録されるのが一般的です
- 拡張機能と他のアプリケーション: ブラウザの拡張機能や端末上の他のアプリケーションが、URLを読み取れる場合があります

RFC 6749の10.5節は、このことを次のように書いています。

> Since authorization codes are transmitted via user-agent redirections, they could potentially be disclosed through user-agent history and HTTP referrer headers.

(RFC 6749 10.5節)

認可コードがこれらの経路で漏れても、攻撃者がそれだけでアクセストークンを得られないように、
認可コードには次の制約が付いています。

- 有効期間が短く、10分以内が推奨されています
- 1回しか使えません
- 発行先のクライアントIDとリダイレクトURIに結びついています
- 本章の例のように秘密を保持できるクライアント(機密クライアント)では、
  トークンエンドポイントでの交換にクライアント認証も必要です

攻撃者が漏れた認可コードを入手しても、クライアントシークレットを知らなければ
トークンエンドポイントで交換できません。クライアントが先に交換していれば、コードは使用済みです。
一方、アクセストークンはバックチャネルで、TLSで保護された1回の応答としてクライアントに直接届き、
ブラウザのURLには一度も現れません。RFC 6749の1.3.1節は、認可コードの利点を次のように要約しています。

> The authorization code provides a few important security benefits, such as the ability to authenticate the client, as well as the transmission of the access token directly to the client without passing it through the resource owner's user-agent and potentially exposing it to others, including the resource owner.

(RFC 6749 1.3.1節)

この文は、認可コードを使う利点として、クライアントを認証できること、
アクセストークンをリソースオーナーのユーザーエージェントを経由させずにクライアントへ直接渡せることを
挙げています。

クライアントシークレットを持たないクライアント(スマートフォンのアプリなど)では、
4つ目の制約が成り立ちません。この場合に認可コードの横取りを防ぐ仕組みがPKCEで、
[9章](/oidc/09-state-nonce-pkce/)で扱います。RFC 9700は、クライアントシークレットを持つ
クライアントにもPKCEの使用を推奨しています。

## 実験: 認可コードフローを1プロセスで再現する

ここまでのメッセージを、1つのプロセスの中で再現します。ブラウザ、クライアント、認可サーバを
それぞれ関数と構造体で表し、ブラウザは`Host`ヘッダの値に応じて宛先の関数を呼び出します。
各リクエストとレスポンスはHTTP/1.1のテキストとして表示し、フロントチャネルか
バックチャネルかを示します。確かめることは2つで、各段階のメッセージの形と、
アクセストークンがブラウザの開くURLに一度も現れないことです。

<RustPlay snippet="ch03/code-flow" title="認可コードフローの全メッセージ" />

`state`、認可コード、セッションID、アクセストークンは乱数から作るため、出力は実行ごとに変わります。

[1]は、ブラウザがクライアントの`/login`を開いた結果です。クライアントは`state`を生成して
自分のセッションに保存し、`302 Found`で認可エンドポイントへリダイレクトさせています。
`Location`のURLのクエリには、4.1.1節の5つのパラメータが並んでいます。`redirect_uri`の値は
URLエンコードされ、スコープの`:`も`%3A`になっています。同時に`Set-Cookie`で
クライアントのセッションIDを渡しています。

[2]は、ブラウザが認可エンドポイントを開いた結果です。認可サーバは`client_id`と
`redirect_uri`を登録値と照合した後、ログインと同意の画面を返しています。
画面には、どのクライアントがどのスコープを求めているかが表示されます。

[3]は、aliceがログインして許可した結果です。フォームの送信先は認可サーバなので、
パスワードは認可サーバにだけ届きます。認可サーバは認可コードを生成し、`redirect_uri`に
`code`と`state`を付けてリダイレクトさせています。`state`の値は[1]で生成されたものと同じです。

[4]は、ブラウザがリダイレクトエンドポイントを開いたリクエストです。Cookieヘッダで
クライアントのセッションIDが付いています。クライアントはセッションに保存した`state`と
クエリの`state`を照合し、一致したので処理を続けます。

[5]は、[4]の処理の途中でクライアントが送ったトークンリクエストです。経路はバックチャネルで、
Authorizationヘッダの値`czZCaGRSa3F0MzpnWDFmQmF0M2JW`は、RFC 6749 4.1.3節の例と一致しています。
認可サーバはクライアント認証、認可コードの存在、発行先のクライアント、`redirect_uri`の一致を
確かめた後、認可コードをストアから削除して、アクセストークンを返しています。
レスポンスには`Cache-Control: no-store`が付いています。この例の出力には現れませんが、
認可サーバはスキーム名`Basic`を大文字小文字を区別せずに照合し、パラメータの重複や
`grant_type`の欠落には`invalid_request`を、未対応の`grant_type`には`unsupported_grant_type`を返します
(RFC 6749 5.2節)。認可エンドポイントとリダイレクトエンドポイントも、重複したパラメータを含む
リクエストを拒否します。

[4]の応答は、トークンを受け取った後にクライアントがブラウザへ返したリダイレクトです。
行き先は`/photos`で、トークンは含まれていません。

最後の一覧は、ブラウザが開いたURLのすべてです。認可コードは4番目のURLに現れていますが、
アクセストークンはどのURLにも現れていません(`false`)。アクセストークンを保持しているのは、
バックチャネルで受け取ったクライアントだけです。

このスニペットの構造(HTTPメッセージを文字列として組み立て、ロールごとの関数が処理する形)は、
後の章でも使います。OpenID Connectで何が追加されるかは[6章](/oidc/06-oauth-to-oidc/)、
PKCEを加えると何が変わるかは[9章](/oidc/09-state-nonce-pkce/)で、同じ形の実験で確かめます。

## state: CSRF対策の基本

**CSRF**(cross-site request forgery)は、攻撃者が用意したページやリンクによって、
被害者のブラウザに、被害者が意図していないリクエストを送らせる攻撃です。
[1章](/web-auth/01-http-auth/)で見たとおり、ブラウザはリクエストを誰が起こしたかに関係なく
宛先のサーバのCookieを付けるので、サーバは被害者本人の操作と区別できません。

認可コードフローのリダイレクトエンドポイントは、CSRFの対象になります。RFC 6749の10.12節は、
攻撃を次のように説明しています。

> A CSRF attack against the client's redirection URI allows an attacker to inject its own authorization code or access token, which can result in the client using an access token associated with the attacker's protected resources rather than the victim's (e.g., save the victim's bank account information to a protected resource controlled by the attacker).

(RFC 6749 10.12節)

この攻撃では、攻撃者はまず自分のアカウントでクライアントの認可コードフローを開始し、
認可サーバで自分のアカウントにログインして許可します。リダイレクトエンドポイントへの
最後の遷移(`/cb?code=攻撃者のコード`)だけを止めて、そのURLを被害者に開かせます。
クライアントは被害者のセッションで攻撃者のコードを交換し、被害者のセッションに
攻撃者の写真アカウントへのアクセストークンを結びつけます。被害者が「写真共有サービスへ保存」を
実行すると、データは攻撃者のアカウントに保存されます。

`state`はこの攻撃を防ぎます。クライアントは認可リクエストを送るときに推測できない`state`を生成して
ブラウザのセッションに保存し、リダイレクトエンドポイントでクエリの`state`と照合します。
攻撃者が被害者に開かせるURLの`state`は、攻撃者のセッションで生成されたもので、
被害者のセッションに保存された値とは一致しません。RFC 6749の10.12節は、
この値は推測できないものでなければならない(MUST)とし、クライアントは
リダイレクトURIへのCSRF対策を実装しなければならない(MUST)と定めています。

RFC 9700の2.1節は、この規則を更新し、CSRF対策の手段としてPKCEやOpenID Connectの
`nonce`も認めています。3つの値がそれぞれ何を結びつけるかは[9章](/oidc/09-state-nonce-pkce/)で、
ログインの場面で同じ攻撃がどう現れるか(ログインCSRF)とあわせて詳しく扱います。

## 実験: エラーと攻撃をリダイレクトエンドポイントで扱う

認可エンドポイントのエラーの扱いと、リダイレクトエンドポイントでの`state`の照合、
トークンエンドポイントでのコードの検証を、[1]から[7]と[3']の8つの場合について確かめます。

<RustPlay snippet="ch03/callback" title="エラーレスポンスと攻撃の検出" />

[1]は正常な場合で、リダイレクトURIに`code`と`state`が付いています。

[2]は、登録されていない`redirect_uri`(`https://attacker.example/cb`)を指定した場合です。
認可サーバはリダイレクトせず、**400 Bad Request**(リクエストの形式や内容に誤りがあることを表すステータスコード)を返して利用者に表示しています。3.1.2.4節と4.1.2.1節のとおり、
不正なリダイレクトURIへは、エラーであっても送りません。ここでリダイレクトしていれば、
攻撃者は認可サーバを経由して利用者を任意のサイトへ移動させられます。

[3]と[4]は、リダイレクトURIへエラーを返す場合です。サポートしない`response_type`には
`unsupported_response_type`、利用者の拒否には`access_denied`が返り、どちらにも`state`が付いています。
どちらの場合も、クライアントは`state`を照合した後で`error`を確認しています。
[3']は、`response_type`の値が空の場合です。3.1節により値のないパラメータは省略されたものとして
扱うので、必須のパラメータの欠落として`invalid_request`が返ります。`unsupported_response_type`は、
値はあるが認可サーバがサポートしない場合のエラーです。認可サーバは、パラメータが重複している場合も
`invalid_request`を返します。重複したのが`client_id`か`redirect_uri`であれば、返す先が定まらないので
リダイレクトせずに利用者へ表示します。

[5]は、前節のCSRFです。攻撃者のコードと攻撃者のセッションの`state`(`abc`)を含むURLを、
被害者のブラウザで開かせています。被害者のセッションに保存された`state`は`xyz`なので、
クライアントはコードを交換せずに破棄します。

[6]は、同じ認可コードを2回使った場合で、2回目は`invalid_grant`になります。
認可サーバはコードを取り出すときにストアから削除しているので、2回目の検索は失敗します。

[7]は、認可リクエストと異なる`redirect_uri`でトークンを要求した場合で、これも`invalid_grant`になります。
4.1.3節の5項目めの検証です。この検証がないと、攻撃者は別のリダイレクトURIで
受け取った認可コードを正規のものとして交換できる可能性があります。

## まとめ

- 認可コードフローは、認可エンドポイントへの認可リクエスト、リダイレクトエンドポイントへの
  認可レスポンス、トークンエンドポイントへのトークンリクエストの3段階で進みます
- 認可リクエストと認可レスポンスはブラウザのリダイレクト(フロントチャネル)で送られ、
  パラメータは`application/x-www-form-urlencoded`形式でクエリに入ります。値は必ず符号化します
- リダイレクトURIは事前に登録し、認可サーバは完全一致で比較します(RFC 9700)。
  不正なリダイレクトURIへはエラーも返しません
- 認可コードは有効期間が短く1回しか使えず、クライアントとリダイレクトURIに結びついています。
  アクセストークンはバックチャネルで受け取るため、ブラウザのURLに現れません
- `state`は、認可リクエストとリダイレクトエンドポイントへの戻りを同じブラウザのセッションに
  結びつけ、攻撃者のコードを注入するCSRFを防ぎます

次章では、トークンエンドポイントが返すレスポンスの中身と、クライアントがアクセストークンを
リソースサーバに提示する方法(Bearerトークン)を読み、スコープとリフレッシュトークンの役割を説明します。
