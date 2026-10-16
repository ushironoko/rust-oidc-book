---
title: OAuthからOIDCへ
description: OAuth 2.0 だけでログインを作ると何が起きるか。トークン置換攻撃と、OpenID Connect が足した IDトークン・openid スコープ・UserInfo・標準クレームを、OpenID Connect Core 1.0 の1節・2節・3.1節とともに読む。
sidebar:
  label: 6. OAuthからOIDCへ
---

この章でわかること:

- OAuth 2.0 のアクセストークンだけではログインを安全に作れない理由
- トークン置換攻撃の手順と、IDトークンの `aud` で防げる理由(実験つき)
- OpenID Connect が OAuth 2.0 に足したもの(IDトークン、`openid` スコープ、UserInfo、標準クレーム、Discovery)
- OP・RP・エンドユーザーというロールの呼び名と、OAuth 2.0 のロールとの対応
- 認可コードフローの OpenID Connect 版で流れる HTTP メッセージ

## 「OAuthでログイン」に欠けている情報

[2章](/web-auth/02-delegation/)から[4章](/web-auth/04-tokens/)で見たとおり、OAuth 2.0 は
**認可**の仕様です。リソースオーナーが、クライアントに対して
「このリソースサーバのこの範囲の操作をしてよい」と委譲し、
その結果としてクライアントはアクセストークンを受け取ります。
アクセストークンを受け取って検査するのはリソースサーバであり、クライアントではありません。

RFC 6749 はこの関係を次のように書いています。

> An access token is a string representing an authorization issued to the client. The string is usually opaque to the client.

(RFC 6749 1.4節)

アクセストークンは「クライアントに発行された認可」を表す文字列で、
クライアントにとって中身は通常不透明(opaque)である、という記述です。
クライアントはトークンを読まずにリソースサーバへ送るだけで、
トークンが誰のものか、誰に宛てたものかを確かめる手段を OAuth 2.0 は定めていません。

それでも「Google でログイン」「GitHub でログイン」のような機能を、OAuth 2.0 だけで
作ることはできてしまいます。多くの実装で見られた方法は次のとおりです。

1. クライアントはアクセストークンを得ます
2. そのトークンで、プロフィールを返す API(`/me` のようなもの)を呼びます
3. 返ってきたユーザーIDのユーザーとしてログインさせます

手順1でアクセストークンを得る構成は、次の2通りに分かれます。

- バックチャネルで交換する構成: クライアント自身が認可コードフロー
  ([3章](/web-auth/03-authorization-code/))で認可コードを受け取り、
  トークンエンドポイントで自分のクライアント認証を付けてアクセストークンに交換します。
  アクセストークンは OP からクライアントへ直接届きます
- 外部からアクセストークンを受け入れる構成: クライアントは、アクセストークンそのものを
  外部から受け取ります。インプリシットフローでブラウザ経由で受け取る場合や、
  スマートフォンのアプリが取得したアクセストークンをバックエンドの API に送り、
  バックエンドがそれでログインさせる場合がこれにあたります

どちらの構成も、アクセストークンを持っていることを、ユーザーがその場にいることの証明として
扱っています。ログインに必要な判断は、本来は次の4つの問いに答えることです。

| 問い | ログインで必要な理由 |
| --- | --- |
| 誰が認証されたか | ログインさせるアカウントを決めるため |
| 誰がそう主張しているか | 信頼する発行者の主張だけを受け入れるため |
| 誰に宛てた主張か | 他のアプリ向けの結果を流用されないため |
| いつ、どのログイン操作に対する結果か | 古い結果や別のログイン操作の結果を拒否するため |

アクセストークンは、このうち3つ目と4つ目に答えません。
`/me` の応答は「このトークンを持つ者はユーザー alice のリソースにアクセスできる」ことしか
示しておらず、トークンがどのクライアントに発行されたかは含まれていないからです。
この欠落を突く攻撃が、次に説明するトークン置換攻撃です。
トークン置換攻撃が直接成り立つのは、外部からアクセストークンを受け入れる構成です。
バックチャネルで交換する構成では、攻撃者がアクセストークンを差し込む経路がないため、
攻撃者は代わりに認可コードを差し込みます(この攻撃と対策は[9章](/oidc/09-state-nonce-pkce/)で扱います)。

## トークン置換攻撃

**トークン置換攻撃**(token substitution attack)は、別の文脈で発行されたトークンを
差し替えて提示し、正規のクライアントに受け入れさせる攻撃の総称です。
ここでは、ログインに使われる場面の典型例を扱います。

登場するのは、OP(後述する認証サーバ)の利用者 alice、攻撃者が運営するクイズアプリ、
正規の家計簿アプリの3者です。家計簿アプリは「OAuth でログイン」を外部からアクセストークンを受け入れる構成で実装しており、
スマートフォンのアプリから受け取ったアクセストークンでプロフィール API を呼び、
返ったユーザーとしてログインさせます。家計簿アプリは、トークンエンドポイントでの交換を
自分では行いません。

```mermaid
sequenceDiagram
    participant A as alice
    participant Q as クイズアプリ(攻撃者)
    participant OP as OP
    participant K as 家計簿アプリ
    A->>Q: クイズアプリにOAuthでログイン
    Q->>OP: 認可リクエスト(client_id=quiz-app)
    OP-->>Q: aliceのアクセストークン
    Note over Q: 攻撃者はトークンを保持する
    Q->>K: aliceのアクセストークンを自分のものとして提示
    K->>OP: プロフィールAPIを呼ぶ
    OP-->>K: sub=alice
    Note over K: 攻撃者をaliceとしてログインさせる
```

攻撃者は、alice がクイズアプリに一度ログインしただけで、alice のアクセストークンを
正当な手段で取得しています。そのトークンを家計簿アプリに提示すると、
プロフィール API は正しく alice を返します。トークンは偽造も改ざんもされていないため、
リソースサーバの側では異常を検出できません。

家計簿アプリに欠けているのは、「このトークンは自分(家計簿アプリ)に宛てて発行されたか」
という検査です。この検査に必要な情報は、OAuth 2.0 のアクセストークンからは得られません。

## RFCを読む: RFC 6749 10.16節

RFC 6749 自身も、この問題を Security Considerations の中で扱っています。

> For public clients using implicit flows, this specification does not provide any method for the client to determine what client an access token was issued to.

(RFC 6749 10.16節)

この節は、インプリシットフロー(アクセストークンを認可エンドポイントから直接返すフロー。
[19章](/oidc-deep/19-flows/)で扱います)を使うパブリッククライアントについて、
アクセストークンがどのクライアントに発行されたかを判断する方法を
この仕様は提供していない、と定めています。続けて、攻撃の手口として
フィッシングなどで攻撃者のクライアントにトークンを発行させ、それを正規のクライアントに
提示する手順を挙げています。

> Any public client that makes the assumption that only the resource owner can present it with a valid access token for the resource is vulnerable to this type of attack.

(RFC 6749 10.16節)

「有効なアクセストークンを提示できるのはリソースオーナー本人だけだ」と仮定する
パブリッククライアントは、すべてこの攻撃に対して脆弱である、という記述です。
この仮定は、前節で見た「OAuth でログイン」の実装が前提にしている仮定です。
節の最後は、認可の手続きを認証の代わりに使う仕様に対する要請で終わります。

> Any specification that uses the authorization process as a form of delegated end-user authentication to the client (e.g., third-party sign-in service) MUST NOT use the implicit flow without additional security mechanisms that would enable the client to determine if the access token was issued for its use (e.g., audience-restricting the access token).

(RFC 6749 10.16節)

認可の手続きをエンドユーザー認証の代わりに使う仕様(第三者のサインインサービスなど)は、
アクセストークンが自分のために発行されたかをクライアントが判断できる追加の仕組みなしに、
インプリシットフローを使ってはなりません(MUST NOT)。
括弧内の例は、アクセストークンの宛先(audience)を制限する方法です。
この追加の仕組みを標準として定めたものが、次に説明する OpenID Connect の IDトークンです。

節の本文はインプリシットフローを対象として挙げていますが、問題の原因は
「クライアントがトークンの宛先を確認できない」ことにあります。このため、インプリシットフロー以外でも、
外部からアクセストークンを受け入れる構成は同じ問題を持ちます。
例えばネイティブアプリが受け取ったアクセストークンをバックエンドに送り、
バックエンドがそれでログインさせる構成も、同じ節で
「同様に危険にさらされうる」(may be similarly compromised)と書かれています。

## 実験: トークン置換攻撃を再現する

上の攻撃を1つのプロセスの中で再現します。`op` モジュールが OP を表し、
アクセストークンの発行と、プロフィールを返す UserInfo 相当の関数を持ちます。
家計簿アプリは2通り用意します。1つはアクセストークンで UserInfo を呼んで
ログインさせる実装、もう1つは IDトークン(この後で説明します)の `aud` を
自分の `client_id` と照合する実装です。

IDトークンの改ざんを防ぐ仕組みは本来は署名です。署名は7章と8章で扱うため、
ここでは Rust のモジュールの可視性を使い、`IdToken` のフィールドを非公開にしています。
`op` モジュールの外では `IdToken` を作れず、クレームは `iss()`・`sub()`・`aud()` の
読み取り専用のメソッドでしか参照できません。攻撃者はトークンを持ち出せても、
`aud` を書き換えた IDトークンは作れない、という性質だけを再現しています。

<RustPlay snippet="ch06/token-substitution" title="同じアクセストークンを別のアプリに提示する" />

出力は次のように読みます。

- `[2]` の後の「OAuth だけでログインする家計簿アプリ」は、UserInfo の応答が `sub=alice` で
  あることだけを見て、攻撃者のブラウザを alice としてログインさせています。
  最後の行のセッション表が、攻撃者のブラウザに alice のセッションが作られたことを示しています
- 「OIDC の家計簿アプリ」は、IDトークンの `aud` が `quiz-app` であることを見て拒否しています。
  このIDトークンはクイズアプリ宛てに発行されたものであり、家計簿アプリ宛てではないからです
- alice 本人が家計簿アプリでログインした場合は、`aud=kakeibo` のIDトークンが発行されるため、
  同じ検査を通過します

攻撃者が `aud=kakeibo` の IDトークンを取得するには、alice に家計簿アプリへ
ログインしてもらうしかありません。そのトークンは家計簿アプリに届くため、
攻撃者には届きません。宛先を書いたトークンを発行者が署名する、という構成が
この攻撃を防いでいます。

## OpenID Connectが足したもの

**OpenID Connect**(OIDC)は、OAuth 2.0 を前提にして、ログインに必要な
認証の結果をクライアントへ伝える方法を定めた仕様群です。
策定しているのは **OpenID Foundation**(OIDF)で、OpenID 関連の仕様を
策定する非営利団体です。中心となる仕様は OpenID Connect Core 1.0 で、
本書は2023年12月に発行された errata set 2 を取り込んだ版を参照します
(OpenID 仕様の版と正誤表の関係は[付録 RFCの読み方](/appendix/reading-rfcs/)で説明しています)。

OpenID Connect が OAuth 2.0 に足したものは、主に次の5つです。

- IDトークン: 認証の結果(誰が、いつ、どの発行者によって、どのクライアントのために
  認証されたか)を書いた、署名付きのトークンです。この章の後半と8章で詳しく扱います
- `openid` スコープ: 認可リクエストがOpenID Connectの認証リクエストであることを示す
  スコープ値です
- UserInfo エンドポイント: アクセストークンを受け取り、エンドユーザーの属性を返す
  エンドポイントです
- 標準クレーム: 氏名・メールアドレスなど、エンドユーザーの属性の名前と形式の取り決めです
- Discovery と動的登録: OP の設定値(エンドポイントの URL や公開鍵の場所)を取得する方法と、
  クライアントを登録する方法です。Discovery は[10章](/rust-impl/10-discovery-jwks/)で扱います

OAuth 2.0 の仕組み(認可エンドポイント、トークンエンドポイント、認可コード、
アクセストークン)はそのまま使います。OpenID Connect の認証リクエストは、
`scope` に `openid` を含めた OAuth 2.0 の認可リクエストです。
このため、OAuth 2.0 の認可サーバに機能を追加すれば OpenID Connect のサーバになります。

### ロールの呼び名

OpenID Connect は、OAuth 2.0 のロールに別の名前を付けています。

- **OpenID プロバイダ**(OpenID Provider、OP): エンドユーザーを認証し、
  その結果とエンドユーザーの属性をクレームとして RP に提供できる OAuth 2.0 の認可サーバです
- **リライングパーティ**(Relying Party、RP): エンドユーザーの認証とクレームを
  OP に求める OAuth 2.0 のクライアントです。OP が行った認証の結果に依拠する(rely on)ことが
  名前の由来です
- **エンドユーザー**(End-User): 人間の利用者です。OAuth 2.0 のリソースオーナーのうち、
  人間であるものに相当します

| OAuth 2.0 のロール | OpenID Connect での呼び名 |
| --- | --- |
| 認可サーバ | OP(OpenID プロバイダ) |
| クライアント | RP(リライングパーティ) |
| リソースオーナー | エンドユーザー |
| リソースサーバ | (UserInfo エンドポイントは OP が持つリソースサーバ) |

OpenID Connect 以外の文脈では、認証を担うサーバを **IdP**(Identity Provider、
アイデンティティプロバイダ)と呼ぶことがあります。IdP は SAML などを含む一般的な呼び名で、
OP は OpenID Connect の IdP を指します。

1つの OP に一度ログインすれば、その OP を使う複数の RP に改めてパスワードを
入力せずにログインできる状態を **SSO**(single sign-on、シングルサインオン)と呼びます。
RP は OP のログイン状態を利用するため、2つ目以降の RP では、OP が既存のセッションを
確認して IDトークンを発行するだけで済みます。
また、組織や事業者の境界を越えて、ある組織の IdP による認証結果を
別の組織のサービスが受け入れる関係を **フェデレーション**(federation、
認証連携)と呼びます。OpenID Connect はフェデレーションを実現するプロトコルの1つで、
より大規模な信頼関係の構成は[27章](/practice/27-ecosystem/)の OpenID Federation で扱います。

## 仕様を読む: OpenID Connect Core 1.0 1節

OpenID Connect Core 1.0 は、冒頭で自らの位置づけを次のように述べています。

> OpenID Connect 1.0 is a simple identity layer on top of the OAuth 2.0 [RFC6749] protocol. It enables Clients to verify the identity of the End-User based on the authentication performed by an Authorization Server, as well as to obtain basic profile information about the End-User in an interoperable and REST-like manner.

(OpenID Connect Core 1.0 1節)

この節は、OpenID Connect を OAuth 2.0 プロトコルを前提にしたアイデンティティの層と定め、
2つの機能を挙げています。1つは、認可サーバが行った認証に基づいて、クライアントが
エンドユーザーの身元を検証できることです。もう1つは、エンドユーザーの基本的な
プロフィール情報を相互運用可能な方法で取得できることです。
前者が IDトークン、後者が UserInfo エンドポイントと標準クレームに対応します。

続く段落は、OAuth 2.0 との関係をさらに明確にしています。

> They define mechanisms to obtain and use Access Tokens to access resources but do not define standard methods to provide identity information. Notably, without profiling OAuth 2.0, it is incapable of providing information about the authentication of an End-User.

(OpenID Connect Core 1.0 1節)

OAuth 2.0(RFC 6749)と Bearer トークンの仕様(RFC 6750)は、アクセストークンを
取得して使う仕組みを定めていますが、身元の情報を提供する標準的な方法は定めていません。
特に、OAuth 2.0 をプロファイル(用途に合わせて制約・拡張)しない限り、
エンドユーザーの認証についての情報を提供できない、という記述です。
前節までの「OAuth でログイン」の問題を、仕様の側から確認する文です。

> OpenID Connect implements authentication as an extension to the OAuth 2.0 authorization process. Use of this extension is requested by Clients by including the openid scope value in the Authorization Request. Information about the authentication performed is returned in a JSON Web Token (JWT) [JWT] called an ID Token (see Section 2).

(OpenID Connect Core 1.0 1節)

OpenID Connect は、認証を OAuth 2.0 の認可の手続きの拡張として実装します。
クライアントは認可リクエストに `openid` スコープ値を含めることでこの拡張を要求し、
行われた認証の情報は IDトークンと呼ばれる JWT で返されます。
JWT の構造は[7章](/oidc/07-jwt-jose/)で扱います。

1.2節の用語定義も、本書が使う用語の出典です。OP と RP は次のように定義されています。

> OpenID Provider (OP)
> OAuth 2.0 Authorization Server that is capable of Authenticating the End-User and providing Claims to a Relying Party about the Authentication event and the End-User.

> Relying Party (RP)
> OAuth 2.0 Client application requiring End-User Authentication and Claims from an OpenID Provider.

(OpenID Connect Core 1.0 1.2節)

どちらも OAuth 2.0 の用語(Authorization Server、Client)で定義されています。
OP と RP は OAuth 2.0 の認可サーバとクライアントに役割を足したものであり、
新しい種類の主体ではありません。なお1.2節の用語定義は、仕様の規範的な部分であると明記されています
(IMPORTANT NOTE TO READERS の段落)。仕様中で大文字で始まる語は、この定義に従って読みます。

## IDトークン: 認証の結果を書いたトークン

**IDトークン**(ID Token)は、OP がエンドユーザーを認証した結果を RP に伝えるための
トークンで、JWT 形式で表されます。IDトークンに書かれる1つ1つの情報を
**クレーム**(claim)と呼びます。クレームは「ある主体について主張された情報」で、
JSON オブジェクトの名前と値の組として書かれます。

IDトークンが必ず持つクレームのうち、この章の冒頭で挙げた4つの問いに対応するものを先に挙げます。
各クレームの正確な定義と検証の手順は、7章(JWT の登録済みクレーム)と
8章(IDトークンの検証)で扱います。

| 問い | クレーム | 意味 |
| --- | --- | --- |
| 誰が認証されたか | `sub` | エンドユーザーの識別子 |
| 誰がそう主張しているか | `iss` | IDトークンを発行した OP の識別子(URL) |
| 誰に宛てた主張か | `aud` | IDトークンの宛先。RP の `client_id` を含む |
| いつ、どのログイン操作の結果か | `iat`、`exp`、`nonce` | 発行時刻、有効期限、認証リクエストとの対応づけ |

`sub`(subject)は、OP の中でエンドユーザーを一意に識別する文字列です。
OP の中で一意であり、別のユーザーに再割り当てされない値と定められています。
メールアドレスのように変わりうる値とは異なり、RP がユーザーのアカウントと
対応づけるときのキーには `iss` と `sub` の組を使います
(この設計判断は[18章](/oidc-deep/18-claims-identity/)で扱います)。

`aud` が、トークン置換攻撃を防ぐクレームです。OP は IDトークンを発行するときに、
認証リクエストを送ってきた RP の `client_id` を `aud` に書き、全体に署名します。
RP は `aud` に自分の `client_id` があることを確認します。署名があるため、
攻撃者は `aud` を書き換えられません。

## 仕様を読む: OpenID Connect Core 1.0 2節

2節の冒頭は、IDトークンを OpenID Connect の中心となる拡張と位置づけています。

> The primary extension that OpenID Connect makes to OAuth 2.0 to enable End-Users to be Authenticated is the ID Token data structure. The ID Token is a security token that contains Claims about the Authentication of an End-User by an Authorization Server when using a Client, and potentially other requested Claims. The ID Token is represented as a JSON Web Token (JWT) [JWT].

(OpenID Connect Core 1.0 2節)

この節は、エンドユーザーの認証を可能にするために OpenID Connect が OAuth 2.0 に加えた
主要な拡張を IDトークンというデータ構造と定め、IDトークンを
「クライアントを使う際の、認可サーバによるエンドユーザーの認証についてのクレーム」と
要求された他のクレームを含むセキュリティトークンとしています。
表現形式は JWT です。

同じ節の後半には、IDトークンの保護について次の要請があります。

> ID Tokens MUST be signed using JWS [JWS] and optionally both signed and then encrypted using JWS [JWS] and JWE [JWE] respectively, thereby providing authentication, integrity, non-repudiation, and optionally, confidentiality, per Section 16.14.

(OpenID Connect Core 1.0 2節)

IDトークンは JWS で署名しなければなりません(MUST)。必要なら署名した後に
JWE で暗号化してもかまいません。署名によって発行者の認証、完全性、否認防止が得られ、
暗号化によって機密性が得られる、という記述です。JWS と JWE は7章で扱います。

> ID Tokens MUST NOT use none as the alg value unless the Response Type used returns no ID Token from the Authorization Endpoint (such as when using the Authorization Code Flow) and the Client explicitly requested the use of none at Registration time.

(OpenID Connect Core 1.0 2節)

署名アルゴリズムに `none`(署名なし)を使ってはなりません(MUST NOT)。
例外は、認可エンドポイントから IDトークンを返さないレスポンスタイプ(認可コードフローなど)で、
かつクライアントが登録時に明示的に `none` を要求した場合だけです。
この例外は、トークンエンドポイントとの TLS 通信で発行者を確認できる場合に限った
規定です。本書の RP は、この例外を使わずに常に署名を検証します(8章)。

2節には、各クレームの定義(`iss`、`sub`、`aud`、`exp`、`iat`、`auth_time`、`nonce`、
`acr`、`amr`、`azp`)が続きます。これらは8章で1つずつ読みます。

## 実験: IDトークンの中身を表示する

OpenID Connect Core 1.0 の3.1.3.3節には、トークンレスポンスの例として
実際の IDトークンが記載されています。この IDトークンを `.` で3つに分け、
それぞれを Base64url で復号して表示します(Base64url は[5章](/web-auth/05-crypto/)で扱いました)。

<RustPlay snippet="ch06/peek-id-token" title="仕様の例の IDトークンを3つに分けて読む" />

出力は次のように読みます。

- IDトークンは588文字の文字列で、`.` で区切ると3つの部分になります。
  この形式を JWS コンパクトシリアライゼーションと呼びます(7章)
- 1つ目はヘッダです。`"alg":"RS256"` は署名アルゴリズムが RSA と SHA-256 の組であること、
  `"kid":"1e9gdk7"` は署名に使った鍵の識別子を示します
- 2つ目はペイロードで、前節の表のクレームが JSON で書かれています。
  `aud` は `s6BhdRkqt3` で、仕様の例で使われるクライアントの `client_id` です
- 3つ目は256バイトの署名です。2048ビットの RSA 鍵による署名はこの長さになります

このプログラムは、署名をまったく検証していません。Base64url の復号は誰にでもできるため、
誰でも同じ形式の文字列を作れます。最後の「クレームを取り出した結果(未検証)」に
表示された値を信用してよいのは、署名を検証し、`iss`・`aud`・`exp`・`nonce` などを
照合した後だけです。

この例の `iss` は `http://server.example.com` で、`https` ではありません。
2節は `iss` を `https` スキームの URL と定めているため、この例は仕様自身の規定と
食い違っています。8章の実験では、この IDトークンを検証器に渡し、
`iss` の検査で拒否されることを確かめます。仕様の例も、検証の手順に照らして
読む必要があります。

## UserInfoエンドポイントと標準クレーム

IDトークンは認証の結果を伝えるためのトークンです。エンドユーザーの属性(氏名や
メールアドレス)は、主に **UserInfo エンドポイント**(UserInfo Endpoint)から取得します。
UserInfo エンドポイントは OP が提供する保護されたリソースで、
OpenID Connect の認証で得たアクセストークンを Bearer トークン
([4章](/web-auth/04-tokens/))として受け付け、エンドユーザーのクレームを JSON で返します。

```http
GET /userinfo HTTP/1.1
Host: server.example.com
Authorization: Bearer SlAV32hkKG
```

```http
HTTP/1.1 200 OK
Content-Type: application/json

{
 "sub": "248289761001",
 "name": "Jane Doe",
 "given_name": "Jane",
 "family_name": "Doe",
 "preferred_username": "j.doe",
 "email": "janedoe@example.com",
 "picture": "http://example.com/janedoe/me.jpg"
}
```

(OpenID Connect Core 1.0 5.3.1節と5.3.2節の例)

応答に含まれる `name`、`email` などは、5.1節が定める **標準クレーム**(Standard Claims)です。
標準クレームは、エンドユーザーの属性の名前・型・意味を OP の間で揃えるための取り決めで、
RP は OP ごとに異なる形式を扱わずに済みます。主なものを挙げます。

| クレーム | 型 | 意味 |
| --- | --- | --- |
| `sub` | 文字列 | 発行者の中でのエンドユーザーの識別子 |
| `name` | 文字列 | 表示用の氏名 |
| `given_name` / `family_name` | 文字列 | 名 / 姓 |
| `preferred_username` | 文字列 | エンドユーザーが希望する短い名前 |
| `email` | 文字列 | メールアドレス |
| `email_verified` | 真偽値 | OP がメールアドレスの所有を確認済みか |
| `picture` | 文字列 | プロフィール画像の URL |
| `locale` | 文字列 | 言語と地域 |
| `updated_at` | 数値 | 情報の最終更新時刻 |

どのクレームを要求するかは、スコープ値で指定します。5.4節は `profile`、`email`、
`address`、`phone` の4つのスコープ値を定めており、例えば `email` スコープは
`email` と `email_verified` のクレームを要求します。

UserInfo の応答について、5.3.2節は次の注意を書いています。

> NOTE: Due to the possibility of token substitution attacks (see Section 16.11), the UserInfo Response is not guaranteed to be about the End-User identified by the sub (subject) element of the ID Token. The sub Claim in the UserInfo Response MUST be verified to exactly match the sub Claim in the ID Token; if they do not match, the UserInfo Response values MUST NOT be used.

(OpenID Connect Core 1.0 5.3.2節)

この節は、トークン置換攻撃の可能性があるため、UserInfo の応答が IDトークンの
`sub` のエンドユーザーについてのものとは限らない、と述べています。
RP は UserInfo の応答の `sub` が IDトークンの `sub` と完全に一致することを
検証しなければならず(MUST)、一致しない場合は応答の値を使ってはなりません(MUST NOT)。
UserInfo はアクセストークンで呼ぶため、この章の最初の問題(アクセストークンが
誰のものかを RP が確かめられない)をそのまま持っています。IDトークンを検証して得た `sub` と
照合することで、UserInfo の応答をこのログインの結果と結びつけます。

## 認可コードフローのOpenID Connect版

OpenID Connect は、3つのフローを定めています。認可コードフロー、インプリシットフロー、
ハイブリッドフローで、どれを使うかは `response_type` の値で決まります。
本書の基礎編では、[3章](/web-auth/03-authorization-code/)で扱った認可コードフロー
(`response_type=code`)だけを使います。RFC 9700 2.1.2節によると、クライアントは、認可レスポンスでアクセストークンを
返す `response_type`(インプリシットフローの `token` など)を使うべきではありません(SHOULD NOT)。アクセストークンをトークンレスポンスで返す `response_type` は推奨される側にあり、
ハイブリッドフローの `code id_token` はその例として挙げられています。
フローごとの性質は[19章](/oidc-deep/19-flows/)で扱います。

認可コードフローの OpenID Connect 版の全体を図に示します。

```mermaid
sequenceDiagram
    participant B as ブラウザ
    participant RP as RP
    participant OP as OP
    B->>RP: ログインを開始
    RP->>RP: state と nonce を生成してセッションに保存
    RP-->>B: 302 認証リクエストへリダイレクト
    B->>OP: GET /authorize (scope=openid, nonce)
    OP->>B: ログイン画面と同意画面
    B->>OP: 認証情報と同意
    OP-->>B: 302 redirect_uri へ (code, state)
    B->>RP: GET /cb?code=...&state=...
    RP->>RP: state を照合
    RP->>OP: POST /token (code, クライアント認証)
    OP-->>RP: access_token と id_token
    RP->>RP: IDトークンを検証 (8章)
    RP->>OP: GET /userinfo (Bearer)
    OP-->>RP: クレーム (sub を照合)
    RP-->>B: ログイン済みのセッションを発行
```

図の中で OAuth 2.0 の認可コードフローと異なる点は、次の4つです。

1. 認可リクエストの `scope` に `openid` が入り、`nonce` パラメータが加わります
2. トークンレスポンスに `id_token` が加わります
3. RP は IDトークンを検証し、その `sub` でユーザーを決めます
4. 必要なら UserInfo を呼び、応答の `sub` を IDトークンの `sub` と照合します

それぞれのメッセージを、OpenID Connect Core 1.0 の例で示します(値の途中の改行は表示のためです)。
最初は、RP がブラウザを認可エンドポイントへ送るリダイレクトです
(3.1.2.1節の例に、A.1節と同じ `nonce` を加えています)。

```http
HTTP/1.1 302 Found
Location: https://server.example.com/authorize?
  response_type=code
  &client_id=s6BhdRkqt3
  &redirect_uri=https%3A%2F%2Fclient.example.org%2Fcb
  &scope=openid%20profile%20email
  &nonce=n-0S6_WzA2Mj
  &state=af0ifjsldkj
```

このリダイレクトを受けたブラウザが、認可エンドポイントに認証リクエストを送ります(A.1節)。

```http
GET /authorize?response_type=code&client_id=s6BhdRkqt3
  &redirect_uri=https%3A%2F%2Fclient.example.org%2Fcb
  &scope=openid%20profile%20email&nonce=n-0S6_WzA2Mj&state=af0ifjsldkj HTTP/1.1
Host: server.example.com
```

`nonce` は、RP が認証リクエストごとに生成する推測できない値で、OP はこの値を
そのまま IDトークンの `nonce` クレームに入れて返します。RP は自分のセッションに
保存した値と比較し、この IDトークンが自分の送った認証リクエストへの応答であることを
確かめます。`nonce` の役割と `state` との違いは[9章](/oidc/09-state-nonce-pkce/)で扱います。

OP はエンドユーザーを認証し、同意を得た後、認可コードを付けてブラウザを RP へ戻します(A.1節)。

```http
HTTP/1.1 302 Found
Location: https://client.example.org/cb?
  code=Qcb0Orv1zh30vL1MPRsbm-diHiMwcLyZvn1arpZv-Jxf_11jnpEX3Tgfvk
  &state=af0ifjsldkj
```

RP は `state` を照合した後、バックチャネルでトークンリクエストを送ります(3.1.3.1節)。
`Authorization` ヘッダはクライアント認証です([3章](/web-auth/03-authorization-code/))。

```http
POST /token HTTP/1.1
Host: server.example.com
Content-Type: application/x-www-form-urlencoded
Authorization: Basic czZCaGRSa3F0MzpnWDFmQmF0M2JW

grant_type=authorization_code&code=SplxlOBeZQQYbYS6WxSbIA
  &redirect_uri=https%3A%2F%2Fclient.example.org%2Fcb
```

トークンレスポンスには、OAuth 2.0 のパラメータに加えて `id_token` が入ります(3.1.3.3節)。

```http
HTTP/1.1 200 OK
Content-Type: application/json
Cache-Control: no-store

{
 "access_token": "SlAV32hkKG",
 "token_type": "Bearer",
 "refresh_token": "8xLOxBtZp8",
 "expires_in": 3600,
 "id_token": "eyJhbGciOiJSUzI1NiIsImtpZCI6IjFlOWdkazcifQ.ewogImlzc
   yI6ICJodHRwOi8vc2VydmVyLmV4YW1wbGUuY29tIiwKICJzdWIiOiAiMjQ4Mjg5
   (以下略。先の実験で表示した IDトークン)"
}
```

仕様の例では、認可レスポンスのコード(A.1節)とトークンリクエストのコード(3.1.3.1節)が
異なる値になっています。別々の節の例であるためで、実際のフローでは同じ値を送ります。

## 仕様を読む: OpenID Connect Core 1.0 3.1節

3節はフローの選び方を、`response_type` の値で決まると定めています。

> The flow used is determined by the response_type value contained in the Authorization Request.

(OpenID Connect Core 1.0 3節)

`code` は認可コードフロー、`id_token` と `id_token token` はインプリシットフロー、
`code id_token` など `code` と他の値の組み合わせはハイブリッドフローを選びます。
3.1節が、本書で使う認可コードフローの節です。

> The Authorization Code Flow returns an Authorization Code to the Client, which can then exchange it for an ID Token and an Access Token directly. This provides the benefit of not exposing any tokens to the User Agent and possibly other malicious applications with access to the User Agent. The Authorization Server can also authenticate the Client before exchanging the Authorization Code for an Access Token.

(OpenID Connect Core 1.0 3.1節)

この節は、認可コードフローではクライアントが認可コードを受け取り、それを直接
IDトークンとアクセストークンに交換すると定めています。利点として2つを挙げています。
1つは、トークンがユーザーエージェント(ブラウザ)と、ブラウザにアクセスできる
他の悪意のあるアプリケーションに露出しないことです。もう1つは、認可サーバが
認可コードを交換する前にクライアントを認証できることです。
3章で見た「なぜコードを1度挟むのか」の理由が、OpenID Connect でもそのまま当てはまります。

3.1.1節は、フローを8つの手順に分けています。

> 1. Client prepares an Authentication Request containing the desired request parameters.
> 2. Client sends the request to the Authorization Server.
> 3. Authorization Server Authenticates the End-User.
> 4. Authorization Server obtains End-User Consent/Authorization.
> 5. Authorization Server sends the End-User back to the Client with an Authorization Code.
> 6. Client requests a response using the Authorization Code at the Token Endpoint.
> 7. Client receives a response that contains an ID Token and Access Token in the response body.
> 8. Client validates the ID token and retrieves the End-User's Subject Identifier.

(OpenID Connect Core 1.0 3.1.1節)

手順1〜7は OAuth 2.0 の認可コードフローと同じ構造です。OpenID Connect で増えたのは
手順8の「IDトークンを検証し、エンドユーザーの Subject Identifier(`sub`)を取り出す」です。
ログインの安全性は、この手順8の検証が正しく行われるかによって決まります。

認証リクエストの `scope` について、3.1.2.1節は次のように定めています。

> REQUIRED. OpenID Connect requests MUST contain the openid scope value. If the openid scope value is not present, the behavior is entirely unspecified.

(OpenID Connect Core 1.0 3.1.2.1節)

OpenID Connect のリクエストは `openid` スコープ値を含まなければなりません(MUST)。
含まない場合の動作はまったく規定されていません。`openid` のないリクエストは
OAuth 2.0 のリクエストとしては有効でも、OpenID Connect のリクエストではない、と
3.1.2.2節も書いています。RP が `openid` を付け忘れると、IDトークンが返らないか、
返るかどうかが OP の実装に依存することになります。

`redirect_uri` も、OpenID Connect では必須です(REQUIRED)。OAuth 2.0 では
登録済みのリダイレクト URI が1つなら省略できましたが、OpenID Connect の認証リクエストでは
省略できず、登録済みの値のいずれかと完全一致しなければなりません(MUST)。
完全一致の比較は RFC 3986 6.2.1節の単純な文字列比較で行うと定められています。
前方一致などの緩い比較によって成立する攻撃は[22章](/security/22-threats/)で扱います。

トークンレスポンスについては、3.1.3.3節が `id_token` を必須としています。

> In addition to the response parameters specified by OAuth 2.0, the following parameters MUST be included in the response:
> id_token
> ID Token value associated with the authenticated session.

(OpenID Connect Core 1.0 3.1.3.3節)

OAuth 2.0 が定めるレスポンスパラメータに加えて、`id_token` を含めなければなりません(MUST)。
同じ節は、トークンなどの機密情報を含むレスポンスに `Cache-Control: no-store` を
付けなければならない(MUST)ことも定めています。これは4章で読んだ RFC 6749 5.1節の
要請と同じです。

最後に、RP がトークンレスポンスを受け取った後の検証を、3.1.3.5節が3つにまとめています。
RFC 6749 の検証規則(特に5.1節と10.12節)に従うこと、3.1.3.7節の IDトークン検証規則に
従うこと、3.1.3.8節のアクセストークン検証規則に従うことです。
3.1.3.7節と3.1.3.8節は8章で1項目ずつ読み、Rust で実装します。

## まとめ

- OAuth 2.0 のアクセストークンは、クライアントにとって中身が不透明であり、
  誰に宛てて発行されたかを示しません。このためアクセストークンでログインさせると、
  トークン置換攻撃を受けます
- RFC 6749 10.16節は、認可の手続きを認証に使う仕様に対し、トークンが自分宛てかを
  クライアントが判断できる仕組みを要求しています。OpenID Connect の IDトークンがその仕組みです
- OpenID Connect は OAuth 2.0 を前提にした仕様群で、IDトークン、`openid` スコープ、
  UserInfo エンドポイント、標準クレーム、Discovery を足しています。
  ロールは OP(認可サーバ)、RP(クライアント)、エンドユーザー(リソースオーナー)と呼びます
- IDトークンは `iss`・`sub`・`aud`・`iat`・`exp`・`nonce` などのクレームを持つ署名付きの JWT です。
  `aud` が RP 自身の `client_id` を含むことの検査が、トークン置換攻撃を防ぎます
- 認可コードフローの OpenID Connect 版は、OAuth 2.0 のフローに `scope=openid`、
  `nonce`、トークンレスポンスの `id_token`、RP による IDトークンの検証を加えたものです

IDトークンは JWT であり、署名は JWS で表されます。次章では、IDトークンの3つの部分が
どのような規則で作られているかを、JOSE の仕様群(JWS、JWT、JWK、JWA)で読み、
RFC のテストベクタで署名を再計算します。
