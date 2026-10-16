---
title: 認証はどう動くか
description: HTTPはリクエストを1つずつ独立に扱う。Basic認証とセッションCookieを題材に、Webの認証がこの性質の上でどう組み立てられているかを、RFCの原文とともに理解する。
sidebar:
  label: 1. 認証はどう動くか
---

この章でわかること:

- HTTPがステートレスであることと、それが認証の設計に与える制約
- RFCとは何か。要請語(MUST、SHOULD、MAY)の読み方
- Basic認証の仕組みと、RFC 7617が定める`user-pass`の構文
- Base64が暗号化ではない理由と、TLSが前提になる理由
- セッションCookieの仕組みと、Secure、HttpOnly、SameSiteの各属性の役割

## HTTPはリクエストを1つずつ扱う

**認証**(authentication)は、通信相手が名乗っているとおりの者であることを確かめる処理です。
Webアプリケーションにログインするとき、サーバは入力されたユーザー名とパスワードを照合して、
リクエストを送ってきた者が本人であることを確かめます。この章では、この確認がWebの上で
どう組み立てられているかを、最も単純な方式から順に説明します。

Webのブラウザとサーバは、**HTTP**(Hypertext Transfer Protocol)という取り決めに従って
メッセージをやり取りします。ブラウザがリクエストを送り、サーバがレスポンスを返す、
という1往復が基本の単位です。例えば、ブラウザがページを1枚取得するときの
リクエストとレスポンスは次の形をしています。

```http
GET /photos HTTP/1.1
Host: photos.example.com
Accept: text/html
```

```http
HTTP/1.1 200 OK
Content-Type: text/html; charset=utf-8

<html>...</html>
```

1行目は**リクエスト行**(request line)と呼ばれ、メソッド(`GET`)、対象のパス(`/photos`)、
HTTPのバージョンを並べます。2行目以降の`名前: 値`の行が**ヘッダ**(header field)で、
空行の後に本文(**ボディ**、body)が続きます。レスポンスの1行目には**ステータスコード**(status code)が入り、
`200`は成功を表します。例のヘッダのうち、**Host**ヘッダは宛先のホスト名を、**Accept**ヘッダは
ブラウザが受け付けるボディの形式を、**Content-Type**ヘッダはボディの形式を示します。本書では、このテキスト形式のHTTP/1.1のメッセージで
やり取りを示します。HTTPの新しい版である**HTTP/2**と**HTTP/3**は、メッセージの送り方(バイナリのフレーム、QUICの利用)が異なりますが、ヘッダとステータスコードの意味はHTTP/1.1と同じです。

HTTPには、認証を考えるうえで最も重要な性質があります。HTTPの仕様は、
自身を次のように定義しています。

> HTTP is defined as a stateless protocol, meaning that each request message's semantics can be understood in isolation, and that the relationship between connections and messages on them has no impact on the interpretation of those messages.

(RFC 9110 3.3節)

**ステートレス**(stateless)とは、各リクエストの意味がそのリクエストだけで決まり、
前のリクエストの内容に依存しない、という性質です。サーバは「さっきログインした人からの
続きのリクエストだ」という情報をHTTPの仕組みとしては持ちません。HTTP/1.1とHTTP/2は、
順序と到達を保証するバイト列の通信の取り決めである**TCP**(Transmission Control Protocol)の接続の上でメッセージを送ります。
同じTCP接続で届いた2つのリクエストであっても、同じブラウザから来たと仮定してはなりません。
RFC 9110は続けて、サーバは接続が保護され特定のユーザーエージェント(ブラウザなど。[2章](/web-auth/02-delegation/)で定義します)に専用でない限り、
同じ接続上の2つのリクエストが同じユーザーエージェントからのものだと仮定してはならない(MUST NOT)、
と定めています。

このため、認証の結果を後続のリクエストに引き継ぐには、**リクエストごとに何かを送る**
必要があります。毎回パスワードそのものを送るのがBasic認証で、ログイン時に発行した値を
毎回送るのがセッションCookieです。後の章で扱うOAuthのアクセストークンも、
この「毎回何かを送る」方式の1つです。

## RFCとは何か

前節で引用したRFC 9110のように、本書はプロトコルの規則を原文で確かめながら進めます。

**RFC**(Request for Comments)は、インターネットの技術仕様を収めた文書の通し番号付きの集まりです。
RFC 9110はHTTPの意味論を定めた文書で、番号は発行順に振られます。一度発行されたRFCの
本文は変更されず、内容を改めるときは新しい番号のRFCを発行し、古いものを
**廃止**(Obsoletes)または**更新**(Updates)したと文書の冒頭に記します。
例えば、RFC 9110の冒頭には`Obsoletes: 2818, 7230, 7231, ...`とあり、
2014年に分割して発行されたHTTP/1.1の仕様群を置き換えたことがわかります。

RFCの多くは**IETF**(Internet Engineering Task Force)が作成します。IETFは、
インターネットのプロトコルを標準化する団体で、誰でも参加できるワーキンググループで
議論して合意を形成します。各RFCには種別があり、冒頭の`Category:`に書かれます。
本書で扱うRFCの種別は主に次の3つです。

- **Standards Track**: 標準化の過程にある仕様です。OAuth 2.0(RFC 6749)や
  Basic認証(RFC 7617)はこの種別です
- **BCP**(Best Current Practice): 現時点で最善とされる運用上の指針です。
  OAuth 2.0のセキュリティの指針(RFC 9700)はBCPです
- **Informational**: 情報提供のための文書で、標準ではありません

RFCの本文には、大文字で書かれた**要請語**(requirement keywords)が現れます。
`MUST`、`SHOULD`、`MAY`などの語で、意味はRFC 2119とRFC 8174(2つを合わせてBCP 14と呼びます)
が定めています。RFC 2119は`MUST`を次のように定義しています。

> MUST This word, or the terms "REQUIRED" or "SHALL", mean that the definition is an absolute requirement of the specification.

(RFC 2119 1節)

RFC 8174は、これらの語が要請語としての意味を持つのは大文字で書かれた場合に限る、
と補っています。小文字の`must`は通常の英語として読みます。本書では要請語を
次のように訳し、要請の強さを省かずに書きます。

| 要請語 | 本書の訳 | 意味 |
| --- | --- | --- |
| MUST / REQUIRED / SHALL | 〜しなければなりません(MUST) | 仕様の絶対的な要件 |
| MUST NOT / SHALL NOT | 〜してはなりません(MUST NOT) | 仕様の絶対的な禁止 |
| SHOULD / RECOMMENDED | 〜すべきです(SHOULD) | 正当な理由があれば従わなくてよいが、影響を理解したうえで判断する |
| SHOULD NOT / NOT RECOMMENDED | 〜すべきではありません(SHOULD NOT) | 正当な理由があれば行ってよいが、影響を理解したうえで判断する |
| MAY / OPTIONAL | 〜してもかまいません(MAY) | 完全に任意 |

`SHOULD`は「推奨」程度の軽い語と誤解されやすい語です。RFC 2119の定義では、
従わない場合は「影響を完全に理解し、慎重に比較検討したうえで」別の選択をすることになっています。
セキュリティに関わる`SHOULD`は、従わない理由を説明できない限り従うもの、と読んでください。

RFCの構造、構文規則(ABNF)の読み方、Internet-Draftから
RFCになるまでの過程などは、[付録 RFCの読み方](/appendix/reading-rfcs/)にまとめています。
本文では、必要になった箇所で原文を引用し、その場で読み解きます。

## Basic認証: 毎回パスワードを送る

最も単純な認証方式が**Basic認証**(Basic authentication)です。ブラウザは
リクエストのたびにユーザー名とパスワードをヘッダに入れて送り、サーバはそれを毎回照合します。
HTTPがステートレスなので、毎回送ればサーバは前のリクエストの情報を保持しておく必要がありません。

Basic認証は、HTTPが定める認証の共通の枠組みに従って定められています。この枠組みは
**チャレンジ・レスポンス**(challenge-response)と呼ばれる形をしています。
サーバが「この方式で認証してください」という**チャレンジ**(challenge)を返し、
クライアントがそれに応じた**資格情報**(credentials)を付けてリクエストを送り直します。
資格情報とは、本人であることを示すために提示する値の総称で、
Basic認証ではユーザー名とパスワードの組がこれにあたります。

```mermaid
sequenceDiagram
    participant B as ブラウザ
    participant S as サーバ
    B->>S: GET /docs/ (資格情報なし)
    S-->>B: 401 Unauthorized<br/>WWW-Authenticate: Basic realm="WallyWorld"
    Note over B: 利用者にユーザー名とパスワードを入力させる
    B->>S: GET /docs/<br/>Authorization: Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==
    S-->>B: 200 OK
    B->>S: GET /docs/next.html<br/>Authorization: Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==
    S-->>B: 200 OK
```

図の最初のリクエストには資格情報がありません。
サーバはステータスコード`401`と、**WWW-Authenticateヘッダ**(WWW-Authenticate header field)を返します。

```http
HTTP/1.1 401 Unauthorized
Date: Mon, 04 Feb 2014 16:50:53 GMT
WWW-Authenticate: Basic realm="WallyWorld"
```

WWW-Authenticateヘッダは、サーバが受け付ける認証方式(**認証スキーム**、authentication scheme)と
その引数を伝えるヘッダです。ここではスキームが`Basic`で、`realm`という引数が付いています。
**realm**は、サーバ上の保護された範囲を識別する文字列で、ブラウザはこの値を
入力ダイアログに表示したり、どの資格情報を再利用するかの判断に使ったりします。

ブラウザは利用者にユーザー名とパスワードを入力させ、
**Authorizationヘッダ**(Authorization header field)に資格情報を入れて同じリクエストを送り直します。

```http
GET /docs/ HTTP/1.1
Host: example.com
Authorization: Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==
```

Authorizationヘッダは、クライアントが資格情報をサーバに提示するためのヘッダです。
値は`スキーム名 資格情報`の形で、スキーム名`Basic`の後に、ユーザー名とパスワードを
変換した文字列が続きます。この文字列の作り方は、次節で読むRFC 7617 2節が定めています。
ヘッダの名前はAuthorization(認可)ですが、含まれているのは認証のための資格情報です。
この名前の不一致は歴史的な経緯によるもので、認証と認可の区別は[2章](/web-auth/02-delegation/)で扱います。

2回目以降のリクエストでも、ブラウザは同じAuthorizationヘッダを付けて送ります。
ブラウザが入力された値を保存しておき、自動で付けます。

## RFCを読む: RFC 7617 2節

Basic認証はRFC 7617(2015年9月、Standards Track)が定めています。
資格情報の作り方は、次の4段階で書かれています。

> To receive authorization, the client
>
> 1. obtains the user-id and password from the user,
> 2. constructs the user-pass by concatenating the user-id, a single colon (":") character, and the password,
> 3. encodes the user-pass into an octet sequence (see below for a discussion of character encoding schemes),
> 4. and obtains the basic-credentials by encoding this octet sequence using Base64 ([RFC4648], Section 4) into a sequence of US-ASCII characters ([RFC0020]).

(RFC 7617 2節)

この節は、ユーザー名(原文はuser-id)とパスワードから資格情報の文字列を作る手順を定めています。
ユーザー名、コロン1文字、パスワードをこの順に連結した文字列を`user-pass`と呼び、
それをバイト列に変換し、Base64で符号化したものが資格情報になります。
RFCの例では、ユーザー名`Aladdin`とパスワード`open sesame`から次のヘッダが得られます。

```text
user-pass       = Aladdin:open sesame
Base64          = QWxhZGRpbjpvcGVuIHNlc2FtZQ==
Authorization: Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==
```

**Base64**は、任意のバイト列を、英大文字・小文字、数字、`+`、`/`の64種類の文字と、
長さを揃えるための`=`だけで表す符号化の方式です。3バイトを4文字に変換するため、
符号化後の長さは元のおおよそ4/3倍になります(詳しくは[5章](/web-auth/05-crypto/)で扱います)。
ヘッダの値には使える文字に制限があるため、任意の文字を含みうるパスワードを
安全な文字だけで表すためにBase64を使います。

コロンについて、RFCは次のように注意を書いています。

> Furthermore, a user-id containing a colon character is invalid, as the first colon in a user-pass string separates user-id and password from one another; text after the first colon is part of the password.

(RFC 7617 2節)

この文は、`user-pass`をユーザー名とパスワードに分けるときは**最初のコロン**で
分けること、このためユーザー名にコロンを含めることはできないことを定めています。
パスワードにコロンが含まれていても、最初のコロンより後ろはすべてパスワードなので問題ありません。
RFCはさらに、多くのユーザーエージェントがユーザー名のコロンを検査せずに
`user-pass`を作るため、受信側はユーザー名の一部をパスワードの一部として扱うことになる、
と書いています。この挙動は後の実験で確認します。

制御文字についても規定があり、ユーザー名とパスワードは制御文字を含んではなりません(MUST NOT)。

このRFCは、認証の共通の枠組みとしてRFC 7235を参照しています。RFC 7235は2022年に
RFC 9110によって廃止され(Obsoletes)、現在はRFC 9110の11節がチャレンジと資格情報の
構文を定めています。RFCは発行後に本文が変わらないので、このように参照先が
廃止されていることがあります。読むときは、参照先の現在の版を確認してください。

## RFCを読む: RFC 7617 2.1節

手順の3番目「バイト列に変換する」には、文字コードの問題があります。
**Unicode**は、世界の文字に番号(符号位置)を割り当てた文字集合です。
**UTF-8**は、Unicodeの文字を1〜4バイトの列で表す文字符号化方式で、ASCIIの文字は1バイトのまま表せます。

> The original definition of this authentication scheme failed to specify the character encoding scheme used to convert the user-pass into an octet sequence. In practice, most implementations chose either a locale-specific encoding such as ISO-8859-1 ([ISO-8859-1]), or UTF-8 ([RFC3629]).

(RFC 7617 2節)

この文は、Basic認証の元の定義(RFC 2617)が文字コードを定めていなかったため、
実装ごとにISO-8859-1やUTF-8など異なる文字コードが使われてきた経緯を述べています。
RFC 7617は後方互換性のために既定の文字コードを未定義のまま残し、代わりに
サーバが希望を伝える手段として`charset`引数を追加しました。2.1節がその定義です。

> The only allowed value is "UTF-8"; it is to be matched case-insensitively (see [RFC2978], Section 2.3). It indicates that the server expects character data to be converted to Unicode Normalization Form C ("NFC"; see Section 3 of [RFC5198]) and to be encoded into octets using the UTF-8 character encoding scheme ([RFC3629]).

(RFC 7617 2.1節)

この節は、チャレンジに`charset="UTF-8"`を付けたサーバは、資格情報が
**NFC**(Unicode Normalization Form C)に正規化されたうえでUTF-8で符号化されることを期待している、
と定めています。NFCは、同じ見た目の文字の異なる表現(合成済み文字と結合文字の並び)を、合成済みの形にそろえるUnicodeの正規化形式です。許される値は`UTF-8`だけで、大文字小文字は区別しません。
RFCの例は、パスワードにポンド記号(U+00A3)を含む場合です。

```text
WWW-Authenticate: Basic realm="foo", charset="UTF-8"

user-pass = 't' 'e' 's' 't' ':' '1' '2' '3' pound
            74  65  73  74  3A  31  32  33  C2  A3
Authorization: Basic dGVzdDoxMjPCow==
```

ポンド記号はUTF-8では`C2 A3`の2バイトになります。ISO-8859-1では`A3`の1バイトなので、
クライアントとサーバで文字コードが違うと、同じパスワードでも別のバイト列になり、照合に失敗します。
英数字だけのパスワードではこの問題は起きないため、気づかれにくい点です。

## 実験: Authorizationヘッダを作って復号する

RFCの2つの例を再現し、サーバ側でヘッダを解析する関数を書いて、
コロンの扱いを確かめます。「▶ 実行」を押すと、**Rust Playground**(Rustのコードをブラウザから送って、サーバ上でコンパイル・実行できる公式のサービス)の上で実行されます。

<RustPlay snippet="ch01/basic-auth" title="Basic認証のヘッダの生成と解析" />

出力の[1]と[2]は、RFC 7617の2つの例と同じ文字列が得られたことを示しています(`true`)。
[2]ではRustの文字列がUTF-8で表現されるため、`as_bytes()`がそのままUTF-8のバイト列を返し、
RFCのUTF-8の例と一致します。

[3]は、ヘッダの値を受け取った者は誰でもユーザー名とパスワードを取り出せることを示しています。
復号に鍵は必要なく、Base64の逆変換をするだけです。

[4]は、ユーザー名`team:alice`を送ったつもりでも、サーバは最初のコロンで分けるため、
ユーザー名`team`、パスワード`alice:s3cret`と解釈することを示しています。
RFCの注意書きのとおり、送信側がユーザー名のコロンを検査しないと、この不一致が起きます。
[5]のように、パスワードのコロンは問題になりません。

[6]は、解析の失敗例です。スキーム名が違う場合、Base64として不正な場合、
コロンを含まない場合に、それぞれエラーになります。スキーム名の比較に
`eq_ignore_ascii_case`を使っているのは、RFC 7617がスキーム名を大文字小文字を
区別せずに照合すると定めているためです。

## Base64は暗号化ではない

実験の[3]で見たとおり、Basic認証の資格情報は誰でも元に戻せます。
Base64は文字の種類を制限するための符号化であり、内容を隠す機能はありません。
RFC 7617の4節(セキュリティ上の考慮事項)は、このことを次のように書いています。

> Because Basic authentication involves the cleartext transmission of passwords, it SHOULD NOT be used (without enhancements such as HTTPS [RFC2818]) to protect sensitive or valuable information.

(RFC 7617 4節)

Basic認証はパスワードを平文で送るので、HTTPSのような保護なしに、重要な情報を保護する手段として
使うべきではありません(SHOULD NOT)。

ここで出てきた**TLS**(Transport Layer Security)は、通信路を暗号化し、
接続先のサーバが本物であることを証明書で確かめる仕組みです。HTTPをTLSの上で
使う方式を**HTTPS**と呼び、URLのスキームが`https`になります。TLSで保護された通信では、
経路上の第三者はAuthorizationヘッダを含むメッセージの内容を読めず、書き換えることもできません。

本書で扱う認証と認可の仕組みは、すべてTLSを前提にしています。パスワード、
後の章で扱う認可コードやアクセストークンは、どれも「持っていれば使える」値です。
TLSなしで送れば、経路上で読んだ者がそのまま使えます。OAuth 2.0の仕様も、
トークンを扱うエンドポイントにTLSの使用を義務づけています([3章](/web-auth/03-authorization-code/)で原文を読みます)。

TLSで経路を保護しても、Basic認証には別の問題が残ります。

- **送信の回数**: リクエストのたびにパスワードがサーバに届くため、
  サーバ側のログやプログラムの誤りでパスワードが漏れる機会が、ログイン時だけ送る方式より多くなります
- **ログアウト**: ブラウザが資格情報を記憶して自動で付けるため、
  サーバ側から「この利用者のログインを終わらせる」操作ができません
- **ログイン画面**: 入力ダイアログはブラウザが表示するもので、
  アプリケーションが見た目や手順(多要素認証など)を制御できません

このため、利用者がブラウザでログインするWebアプリケーションでは、
次に説明するセッションCookieが使われます。Basic認証は現在、プログラム同士の通信で
使われることが多く、本書では[3章](/web-auth/03-authorization-code/)で
クライアントが認可サーバに自身を認証する手段として再び扱います。

## 401と403

**401 Unauthorized**は、Basic認証の図にも現れたステータスコードで、リクエストに有効な資格情報がないことを表します。
名前はUnauthorized(認可されていない)ですが、意味は「認証されていない」に近く、
資格情報を付けて送り直せば成功する可能性があることを伝えます。
RFC 9110は、401を返すサーバは少なくとも1つのチャレンジを含むWWW-Authenticateヘッダを
送らなければならない(MUST)、と定めています(RFC 9110 15.5.2節)。

**403 Forbidden**は、サーバがリクエストを理解したうえで実行を拒否したことを表します。

> If authentication credentials were provided in the request, the server considers them insufficient to grant access. The client SHOULD NOT automatically repeat the request with the same credentials.

(RFC 9110 15.5.4節)

この節は、資格情報が付いていたのに403を返した場合、その資格情報では権限が足りないと
サーバが判断したことを意味し、クライアントは同じ資格情報で自動的に再送すべきではない(SHOULD NOT)、
と定めています。同じ節は続けて、資格情報とは関係のない理由でリクエストが拒否される場合もある、
と書いています。整理すると、401はリクエストに有効な資格情報がないこと、403はサーバが
リクエストを理解したうえで実行を拒否したことを表します。資格情報が付いていて403が返った場合は、
その資格情報では権限が足りないと判断されたことを意味します。この区別は、[4章](/web-auth/04-tokens/)で
アクセストークンの検証に失敗したときのエラーの返し方にそのまま現れます。

## セッションCookie: ログインを1回にする

Basic認証の問題は、パスワードを毎回送ることから生じていました。そこで多くの
Webアプリケーションは、ログイン時に1回だけパスワードを照合し、照合に成功したら
**セッションID**(session ID)という推測できない値を発行して、以後はそれを送らせます。

**セッション**(session)は、ログインしてからログアウトするまでの一連のやり取りを
1つにまとめて扱うための、サーバ側の記録です。サーバはセッションIDをキーにして
「このIDはaliceがログインしたときに発行したもの」という対応を保存しておき、
リクエストに含まれるセッションIDから利用者を特定します。

セッションIDをブラウザに保存させ、毎回送らせる仕組みが**Cookie**です。Cookieは
RFC 6265(2011年4月、Standards Track)が定めています。サーバはレスポンスの
**Set-Cookieヘッダ**(Set-Cookie header field)で名前と値の組をブラウザに保存させ、
ブラウザは以後、同じサーバへのリクエストに**Cookieヘッダ**(Cookie header field)で
その値を付けて送ります。

```mermaid
sequenceDiagram
    participant B as ブラウザ
    participant S as サーバ
    participant D as セッションストア
    B->>S: POST /login<br/>user=alice&password=...
    S->>S: パスワードを照合する
    S->>D: sid=kwVS... → alice を保存
    S-->>B: 303 See Other<br/>Set-Cookie: sid=kwVS...#59; Secure#59; HttpOnly#59; SameSite=Lax
    B->>S: GET /me<br/>Cookie: sid=kwVS...
    S->>D: sid=kwVS... を検索する
    D-->>S: alice
    S-->>B: 200 OK
```

ログインのリクエストとレスポンスは次のようになります(セッションIDの値は例です)。

```http
POST /login HTTP/1.1
Host: photos.example.com
Content-Type: application/x-www-form-urlencoded

user=alice&password=dummy-password
```

```http
HTTP/1.1 303 See Other
Location: /me
Set-Cookie: sid=kwVSGZNzV7vnj28Qf_CxYw; Path=/; Secure; HttpOnly; SameSite=Lax
```

**303 See Other**は、別のURLを`GET`で開き直すよう指示するステータスコードで、
フォームの送信後によく使われます。**Location**ヘッダは、開き直す先のURLを示すヘッダです。
以後のリクエストには、ブラウザが自動でCookieヘッダを付けます。

```http
GET /me HTTP/1.1
Host: photos.example.com
Cookie: sid=kwVSGZNzV7vnj28Qf_CxYw
```

この方式では、パスワードはログイン時に1回だけ送られます。ログアウトは、サーバが
セッションストアからそのIDを削除するだけで実現できます。削除されたIDを
ブラウザが送ってきても、検索に失敗するので利用者を特定できません。

RFC 6265の8.4節は、CookieにセッションIDだけを入れ、セッション情報そのものは
サーバ側に置く方式について次のように書いています。

> Using session identifier cookies limits the damage an attacker can cause if the attacker learns the contents of a cookie because the nonce is useful only for interacting with the server (unlike non-nonce cookie content, which might itself be sensitive).

(RFC 6265 8.4節)

原文のnonceは、ここではセッションIDを指しています。この文は、Cookieの内容が漏れても、セッションIDはそのサーバとのやり取りにしか使えないため、
個人情報そのものを入れておく場合より被害が限られる、と述べています。
ただし、漏れたセッションIDは有効な間はそのまま使えるため、セッションIDは
推測できず、経路上で読まれないように扱う必要があります。

## Cookieの属性: Secure、HttpOnly、SameSite

Set-Cookieヘッダの値の後ろに`;`で並べた語は**属性**(attribute)で、
ブラウザがそのCookieをいつ送り、どこから読めるようにするかを制御します。
セッションIDを入れるCookieには、次の3つの属性を付けるのが基本です。

- **Secure属性**: HTTPSのリクエストにだけCookieを付けるよう指示します
- **HttpOnly属性**: ページ内のJavaScriptからCookieを読めなくします
- **SameSite属性**: 他のサイトを起点とするリクエストにCookieを付けるかどうかを指示します

## RFCを読む: RFC 6265 4.1.2.5節と4.1.2.6節

Secure属性はRFC 6265の4.1.2.5節が定めています。

> The Secure attribute limits the scope of the cookie to "secure" channels (where "secure" is defined by the user agent). When a cookie has the Secure attribute, the user agent will include the cookie in an HTTP request only if the request is transmitted over a secure channel (typically HTTP over Transport Layer Security (TLS) [RFC2818]).

(RFC 6265 4.1.2.5節)

この節は、Secure属性の付いたCookieは、TLSなどの安全な経路で送られるリクエストにだけ
付けられる、と定めています。RFC 6265の8.3節は、Secure属性がない場合の攻撃を説明しています。
利用者が普段HTTPSでしか使わないサイトでも、経路上の攻撃者が別のページの通信に割り込んで
ブラウザを`http://`のURLへ誘導すると、ブラウザはSecure属性のないCookieを平文で送ります。
サーバがHTTPで待ち受けていなくても、リクエストは経路上で読まれます。

4.1.2.5節には続きがあり、Secure属性が保護するのは機密性だけで、HTTPの経路から
Secure属性付きのCookieを上書きされる可能性は残る、と注意しています。これはRFC 6265当時の規定です。
後述の改訂版draft-ietf-httpbis-rfc6265bis(版22)の5.7節は、安全でない経路で受け取ったSet-Cookieについて、
Secure属性の付いたCookieの保存と、同じ名前の既存のSecure属性付きCookieの上書きを、どちらも
無視するよう定めています。これを補う対策(`__Host-`接頭辞など)は[24章](/security/24-browser-native/)で扱います。

> The HttpOnly attribute limits the scope of the cookie to HTTP requests. In particular, the attribute instructs the user agent to omit the cookie when providing access to cookies via "non-HTTP" APIs (such as a web browser API that exposes cookies to scripts).

(RFC 6265 4.1.2.6節)

この節は、HttpOnly属性の付いたCookieは、HTTPのリクエストに付けて送られるだけで、
スクリプトからCookieを読むAPI(ブラウザの`document.cookie`など)には現れない、と定めています。
攻撃者がページに自分のスクリプトを埋め込めた場合でも、セッションIDを読み出して
外部へ送ることはできません。ただし、埋め込まれたスクリプトはそのページから
リクエストを送ることはでき、そのリクエストにはCookieが付きます。HttpOnly属性は
セッションIDの持ち出しを防ぎますが、スクリプトの埋め込みそのものの被害を防ぐものではありません。

SameSite属性は、RFC 6265の改訂版であるdraft-ietf-httpbis-rfc6265bisが定めており、
RFC 6265には含まれていません。この文書は本書執筆時点で版22(2025年12月)が最新で、
RFC Editorでの最終処理の段階にあるInternet-Draftです(2026年10月16日確認)。
値は`Strict`、`Lax`、`None`の3つです。

- `Strict`: 他のサイトを起点とするリクエストには、Cookieを付けません
- `Lax`: 他のサイトからのリンクをたどるような、トップレベルの`GET`での遷移にはCookieを付けますが、
  他のサイトのフォームからの`POST`や、画像などの埋め込みの読み込みには付けません
- `None`: 他のサイトを起点とするリクエストにも付けます。Secure属性と組み合わせる必要があります

SameSite属性が対象にしているのは、RFC 6265の8.2節が「ambient authority」として
説明している問題です。ブラウザは、リクエストを誰が起こしたかに関係なく、
宛先のサーバのCookieを付けて送ります。攻撃者のサイトに置いたフォームから
被害者のブラウザに`POST /transfer`を送らせると、被害者のセッションCookieが付いたリクエストが
届き、サーバは被害者本人の操作と区別できません。この攻撃はCSRFと呼ばれ、
[3章](/web-auth/03-authorization-code/)で認可コードフローの`state`パラメータとともに定義します。
多くのブラウザは、SameSite属性が指定されていないCookieを`Lax`として扱いますが、
挙動はブラウザごとに異なるため、セッションIDのCookieには明示的に指定してください。

## 実験: セッションIDとサーバ側のストア

セッションの仕組みを、1つのプロセスの中で再現します。サーバは**HashMap**(Rust標準ライブラリのハッシュ表で、キーから値を平均して一定時間で検索できます)を
セッションストアとして持ち、ログイン、Cookie付きのリクエスト、ログアウトを
関数として処理します。HTTPのメッセージは文字列として表示します。

<RustPlay snippet="ch01/session" title="セッションIDの発行・照合・削除" />

セッションIDは乱数から作るため、出力は実行ごとに変わります。

出力の1では、ログインに成功したサーバが`Set-Cookie`でセッションIDを返しています。
セッションIDは16バイト(128ビット)の乱数をBase64url(Base64の変種で、5章で扱います)で
22文字にしたものです。2では、ブラウザが同じ値をCookieヘッダで送り、サーバがストアを検索して
`alice`を特定しています。

3と4は、Cookieがない場合と、攻撃者が推測した値を送った場合です。
どちらもストアに該当するIDがないため、ログイン画面へ誘導されます。有効なIDが1件だけなら、
1回の推測が当たる確率は2の128乗分の1です。q回試行しても、当たる確率はおおよそq/2^128にとどまります。
セッションIDを連番や時刻から作ると、この前提が成り立たなくなります(乱数の作り方は
[5章](/web-auth/05-crypto/)で扱います)。

5と6は、ログアウトの効果です。サーバがストアからIDを削除した後は、ブラウザが
古いCookieを送り直しても利用者を特定できません。ログアウトのレスポンスの
`Max-Age=0`は、ブラウザ側のCookieも削除させるための指定です。ただし安全性を
決めているのはサーバ側の削除で、ブラウザ側の削除は補助的な手段です。攻撃者が
事前にセッションIDを写し取っていても、サーバ側で削除されていれば使えません。

## パスワードの保存

セッション方式でも、ログイン時にはパスワードを照合します。照合のためにサーバが
保存しておく値については、RFC 7617の4節が次のように書いています。

> For example, servers ought to avoid storing user passwords in plaintext or as unsalted digests.

(RFC 7617 4節)

この文は、パスワードを平文のまま保存したり、ソルトなしのハッシュ値で保存したりすることを
避けるべきだ、と述べています(小文字の`ought to`で書かれていて、要請語ではありません)。
パスワードの保存では、パスワードから計算した値を保存し、ログイン時に同じ計算をして
結果を比べます。パスワードそのものは保存しません。計算には、元のパスワードを
逆算できず、総当たりで探すのに時間がかかるよう設計された専用の関数を使います。
この関数と、ソルトと呼ばれる値の役割は、[5章](/web-auth/05-crypto/)で実験とともに説明します。

パスワードの保存が漏洩したときの被害は、そのサーバだけにとどまりません。
RFC 7617の4節は、利用者が同じパスワードを複数のサイトで再利用するため、
あるサーバのパスワードの保存が漏れると、他のサイトのアカウントも危険になると指摘しています。
パスワードを持つ場所を減らすという考え方が、次章で説明する委譲の動機です。

## ステートフルとステートレス

HTTPがステートレスであることは変わりませんが、HTTPを使って作る認証の仕組みには、
状態をどこに置くかで2つの方式があります。

セッションCookieの方式は**ステートフル**(stateful)です。サーバ側のストアが
「どのセッションIDが誰のものか」という状態を持ち、リクエストのたびにそれを参照します。
状態がサーバにあるので、ログアウトや強制的な無効化はストアから削除するだけで済みます。
一方で、複数台のサーバで処理を分担する場合はストアを共有する必要があり、
リクエストごとにストアの検索が発生します。

これに対して、必要な情報をすべてリクエストに含める方式はステートレスです。
Basic認証は、毎回のリクエストに資格情報そのものが入っているので、サーバは
パスワードの照合用のデータ以外にリクエストごとの状態を持ちません。
RFC 9110の16.4.2節も、HTTPの認証方式はステートレスであることを前提にし、
認証に必要な情報はすべてリクエストに含めなければならない(MUST)、と書いています。

後の章で扱うトークンにも、この2つの方式があります。サーバが発行した値を
ストアで検索する方式(セッションIDと同じ構造です)と、トークン自体に「誰に、何を、いつまで許可したか」を
書き込み、改ざんできないよう署名しておく方式です。後者はストアの検索が不要になる代わりに、
有効期限前の無効化が難しくなります。この違いは[14章](/oauth-deep/14-token-validation/)で、
署名の仕組みは[5章](/web-auth/05-crypto/)と[7章](/oidc/07-jwt-jose/)で扱います。

| 方式 | 毎回送るもの | サーバ側の状態 | 無効化 |
| --- | --- | --- | --- |
| Basic認証 | ユーザー名とパスワード | なし(照合用の保存値のみ) | パスワードの変更 |
| セッションCookie | セッションID | セッションストア | ストアから削除 |
| 署名付きトークン(7章) | トークン | なし(検証用の鍵のみ) | 有効期限まで困難 |

## まとめ

- HTTPはステートレスで、各リクエストは独立に解釈されます。認証の結果を引き継ぐには、
  リクエストごとに何らかの値を送る必要があります
- RFCはIETFなどが発行する番号付きの仕様です。大文字の要請語(MUST、SHOULD、MAY)は
  BCP 14(RFC 2119/8174)の定義に従って読みます
- Basic認証は、`ユーザー名:パスワード`をBase64にしてAuthorizationヘッダで毎回送ります。
  分割は最初のコロンで行うため、ユーザー名にコロンは使えません
- Base64は符号化であり、暗号化ではありません。パスワードやトークンを送る通信はTLSで保護します
- 401はリクエストに有効な資格情報がないこと、403はサーバがリクエストを理解したうえで実行を拒否したことを表します
- セッションCookieは、ログイン時に推測できないセッションIDを発行し、サーバ側のストアで
  利用者と対応づけます。Cookieには`Secure`、`HttpOnly`、`SameSite`を付けます

ここまでの仕組みは、利用者が自分のアカウントに自分でログインする場面のものでした。
次章では、利用者が別のアプリケーションに「自分のデータへのアクセス」を許可する場面を考え、
パスワードを渡さずに権限だけを渡す委譲という考え方と、OAuth 2.0の全体像を説明します。
