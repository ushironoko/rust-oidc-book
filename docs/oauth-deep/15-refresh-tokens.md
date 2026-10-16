---
title: リフレッシュトークン
description: トークンの寿命の設計、refresh_token グラント、ローテーションと再利用検知、送信者制約との関係、offline_access、スライディング有効期限と絶対有効期限、保存場所。
sidebar:
  label: 15. リフレッシュトークン
---

この章でわかること:

- アクセストークンを短寿命にし、リフレッシュトークンで補う理由
- `refresh_token` グラントの手順と、認可サーバが確認しなければならない事項(RFC 6749 6節)
- リフレッシュトークンローテーションによる再利用検知と、トークンファミリー単位の失効(実験)
- 送信者制約との関係と、FAPI 2.0 がローテーションを原則として禁じている理由
- `offline_access` スコープ、スライディング有効期限と絶対有効期限の組み合わせ(実験)、保存場所
- なぜ体系に必須か: 前章で見たとおり、失効状態を確認せずにローカル検証する JWT アクセストークンは失効させても期限まで使えるため、多くの構成では有効期限を短くして失効の遅れを抑えます。短い有効期限で利用を継続させる仕組みがリフレッシュトークンであり、その保護を誤ると、短い有効期限による保護がすべて無効になります

## 基礎編からの接続

[4章](/web-auth/04-tokens/)では、RFC 6749 の1.5節を読み、リフレッシュトークンを「アクセストークンを取り直すための資格情報で、認可サーバにだけ送られるもの」として紹介し、詳細は15章で扱うとしました。[14章](/oauth-deep/14-token-validation/)では、自己完結型のアクセストークンをローカル検証だけで受け入れる場合、失効がリソースサーバに伝わらないため、有効期限を短くする必要があることを確かめました。

この章では、アクセストークンを短寿命にした分の利用期間をリフレッシュトークンがどう補うかと、そのリフレッシュトークン自体が盗まれたときに何が起きるかを扱います。

## トークンの寿命を設計する

アクセストークンとリフレッシュトークンは、送られる先と検証のされ方が異なります。

| 観点 | アクセストークン | リフレッシュトークン |
| --- | --- | --- |
| 送信先 | 1つ以上のリソースサーバ | 認可サーバのトークンエンドポイントだけ |
| 検証する主体 | リソースサーバ(署名またはイントロスペクション) | 発行した認可サーバ自身 |
| 失効の反映 | JWT をローカル検証だけで受け入れるなら `exp` まで反映されない | 次の使用時に必ず反映される |
| 有効期限の目安 | 数分〜1時間程度 | 数日〜数か月程度 |

この違いが、寿命の設計の根拠です。アクセストークンは多くの場所に送られるため、漏洩の機会が多くなります。漏洩しても失効が伝わりにくいので、有効期限を短くします。リフレッシュトークンは認可サーバにだけ送られ、使われるたびに認可サーバが自分の記録と照合します。このため、長い有効期限を持たせても、問題が発覚した時点で失効させられます。OpenID Connect Core 1.0 の16.18節も、アクセストークンは認可サーバが失効させられない場合があるため、1回限りの使用か非常に短い有効期限にすべきだ(SHOULD)としています。同節は、継続的なアクセスが必要ならリフレッシュトークンを使うよう述べています。

有効期限の具体的な値は仕様では決められておらず、認可サーバの運用者が決めます。表の値は多くの実装で見られる範囲の目安です。

## refresh_token グラント

クライアントは、アクセストークンの期限が切れたとき(またはリソースサーバから `invalid_token` を受け取ったとき)に、リフレッシュトークンをトークンエンドポイントに送って新しいアクセストークンを受け取ります。この手続きを `refresh_token` グラント(grant_type=refresh_token)と呼びます。

```mermaid
sequenceDiagram
    participant C as クライアント
    participant AS as 認可サーバ
    participant RS as リソースサーバ
    C->>RS: GET /orders (期限切れのアクセストークン)
    RS-->>C: 401 WWW-Authenticate: Bearer error="invalid_token"
    C->>AS: POST /token<br/>grant_type=refresh_token&refresh_token=...
    AS->>AS: クライアント認証、トークンの発行先とスコープを確認
    AS-->>C: 新しいアクセストークン (と新しいリフレッシュトークン)
    C->>RS: GET /orders (新しいアクセストークン)
    RS-->>C: 200 OK
```

リクエストと応答は次のようになります(RFC 6749 6節と OpenID Connect Core 1.0 12.2節の例です)。

```http
POST /token HTTP/1.1
Host: server.example.com
Authorization: Basic czZCaGRSa3F0MzpnWDFmQmF0M2JW
Content-Type: application/x-www-form-urlencoded

grant_type=refresh_token&refresh_token=tGzv3JOkF0XG5Qx2TlKWIA
```

```http
HTTP/1.1 200 OK
Content-Type: application/json
Cache-Control: no-store

{
 "access_token": "TlBN45jURg",
 "token_type": "Bearer",
 "refresh_token": "9yNOxJtZa5",
 "expires_in": 3600
}
```

応答に新しい `refresh_token` が含まれる場合、クライアントは古いリフレッシュトークンを破棄して、新しいものに置き換えます。

## RFCを読む: RFC 6749 6節

> Because refresh tokens are typically long-lasting credentials used to request additional access tokens, the refresh token is bound to the client to which it was issued. If the client type is confidential or the client was issued client credentials (or assigned other authentication requirements), the client MUST authenticate with the authorization server as described in Section 3.2.1.

(RFC 6749 6節)

この節は、リフレッシュトークンを使うリクエストを定めています。パラメータは、`refresh_token` に固定された `grant_type`、`refresh_token`、任意の `scope` です。引用した部分は、リフレッシュトークンの束縛を定めています。リフレッシュトークンは通常長期間有効で、追加のアクセストークンを得るための資格情報なので、発行先のクライアントに束縛されます。機密クライアント(または資格情報を発行されたクライアント)は、クライアント認証を行わなければなりません(MUST)。

認可サーバについては、同じ節が次の3つを求めています(MUST)。

1. 機密クライアントと資格情報を発行されたクライアントには、クライアント認証を要求します
2. クライアント認証が含まれていれば認証し、リフレッシュトークンがそのクライアントに発行されたものであることを確認します
3. リフレッシュトークンを検証します

2の確認によって、機密クライアントのリフレッシュトークンは、盗まれてもクライアントの資格情報がなければ使えません。この性質は、後で送信者制約との関係を考えるときに重要になります。

> The requested scope MUST NOT include any scope not originally granted by the resource owner, and if omitted is treated as equal to the scope originally granted by the resource owner.

(RFC 6749 6節、scope パラメータの項)

`scope` パラメータには、リソースオーナーが最初に許可しなかったスコープを含めてはなりません(MUST NOT)。省略した場合は、最初に許可されたスコープと同じものとして扱います。リフレッシュで縮小はできても、拡大はできません。拡大が必要なら、クライアントは利用者を認可エンドポイントに送り、改めて同意を得ます。

> The authorization server MAY issue a new refresh token, in which case the client MUST discard the old refresh token and replace it with the new refresh token. The authorization server MAY revoke the old refresh token after issuing a new refresh token to the client. If a new refresh token is issued, the refresh token scope MUST be identical to that of the refresh token included by the client in the request.

(RFC 6749 6節)

最後の段落は、新しいリフレッシュトークンの発行を定めています。認可サーバは新しいリフレッシュトークンを発行してもかまいません(MAY)。発行された場合、クライアントは古いものを破棄して新しいものに置き換えなければなりません(MUST)。認可サーバは古いリフレッシュトークンを失効させてもかまいません(MAY)。新しいリフレッシュトークンのスコープは、リクエストで提示されたリフレッシュトークンのスコープと同一でなければなりません(MUST)。

RFC 6749 の時点では、新しいリフレッシュトークンの発行も、古いものの失効も任意でした。後述の RFC 9700 は、パブリッククライアントについてこれを強化しています。

OpenID Connect では、リフレッシュの応答に新しい ID トークンを含めることができます。OpenID Connect Core 1.0 の12.2節は、その ID トークンの `iss`、`sub`、`aud` が最初の認証時の ID トークンと同じでなければならない(MUST)と定めています。`auth_time` は最初の認証時刻を表さなければならず、新しい ID トークンの発行時刻にしてはなりません(MUST)。`nonce` は含めるべきではありません(SHOULD NOT)。リフレッシュは利用者の再認証を伴わないため、ID トークンの内容が「改めてログインした」ことを示さないように定められています。

## リフレッシュトークンが盗まれた場合

問題になるのはパブリッククライアントです。機密クライアントのリフレッシュトークンは、盗まれてもクライアント認証がなければ使えません。ブラウザ上のアプリ(SPA)やネイティブアプリはクライアント認証を行えないため、リフレッシュトークンを入手した者は誰でもトークンエンドポイントで新しいアクセストークンを得られます。ブラウザ上のアプリでは、XSS(クロスサイトスクリプティング、[24章](/security/24-browser-native/))で JavaScript からアクセスできる場所のトークンが読み出されることが、典型的な漏洩の経路です。

> Refresh tokens are an attractive target for attackers because they represent the full scope of access granted to a certain client, and they are not further constrained to a specific resource.

(RFC 9700 4.14.1節)

RFC 9700 は、リフレッシュトークンが攻撃の対象になりやすい理由を、クライアントに許可されたすべてのスコープを表し、特定のリソースに限定されていないためと説明しています。アクセストークンは宛先とスコープを限定できますが([14章](/oauth-deep/14-token-validation/)の Resource Indicators)、リフレッシュトークンからは同意の範囲内であれば任意の宛先のアクセストークンを作れます。有効期限も長いため、漏洩したリフレッシュトークンは、アクセストークンよりも長く、広く使われます。

## リフレッシュトークンローテーションと再利用検知

**リフレッシュトークンローテーション**(refresh token rotation)は、認可サーバがリフレッシュのたびに新しいリフレッシュトークンを発行し、使われたリフレッシュトークンを無効にする方式です。RFC 6749 6節で任意とされていた2つの動作(新しいトークンの発行と古いトークンの失効)を、毎回必ず行うものです。

ローテーションの目的は、盗まれたリフレッシュトークンの使用を検知することです。1つの認可から始まり、ローテーションで次々に置き換えられていくリフレッシュトークンの系列を、本書では**トークンファミリー**(token family)と呼びます。各リフレッシュトークンは1回しか使えないため、同じリフレッシュトークンが2回提示されたら、正規のクライアントと攻撃者の両方が同じトークンを持っていることになります。このように、使用済みのリフレッシュトークンが再び提示されたことを検出することを**再利用検知**(reuse detection)と呼びます。

```mermaid
sequenceDiagram
    participant C as クライアント
    participant A as 攻撃者
    participant AS as 認可サーバ
    Note over C,A: RT1 が漏洩し、両者が同じ RT1 を持つ
    C->>AS: refresh_token=RT1
    AS-->>C: AT と RT2 (RT1 は使用済み)
    A->>AS: refresh_token=RT1
    AS->>AS: 使用済みの RT1 を検知、ファミリー全体を失効
    AS-->>A: 400 invalid_grant
    C->>AS: refresh_token=RT2
    AS-->>C: 400 invalid_grant (再ログインが必要)
```

認可サーバは、どちらが攻撃者かを判断できません。そこで、ファミリーに属する有効なリフレッシュトークンをすべて失効させます。正規のクライアントも再ログインが必要になりますが、攻撃者が入手したトークンも使えなくなります。

## RFCを読む: RFC 9700 4.14節

> Refresh tokens for public clients MUST be sender-constrained or use refresh token rotation as described in Section 4.14. [RFC6749] already mandates that refresh tokens for confidential clients can only be used by the client for which they were issued.

(RFC 9700 2.2.2節)

引用は、RFC 9700 の推奨事項を要約した2節の一部です。パブリッククライアントのリフレッシュトークンは、送信者制約を付けるか、リフレッシュトークンローテーションを使わなければなりません(MUST)。機密クライアントについては、RFC 6749 が既に発行先のクライアントだけが使えることを求めている、と補足しています。RFC 9700 は RFC 6749 を更新する BCP なので、RFC 6749 6節で任意だった動作が、パブリッククライアントでは2つの選択肢のどちらかとして必須になりました。

4.14.2節が詳細を定めています。

> If refresh tokens are issued, those refresh tokens MUST be bound to the scope and resource servers as consented by the resource owner. This is to prevent privilege escalation by the legitimate client and reduce the impact of refresh token leakage.

(RFC 9700 4.14.2節)

リフレッシュトークンを発行する場合、そのトークンはリソースオーナーが同意したスコープとリソースサーバに束縛しなければなりません(MUST)。正規のクライアントによる権限の拡大を防ぎ、漏洩の影響を小さくするためです。同じ節の冒頭は、認可サーバはリスク評価に基づいて、あるクライアントにリフレッシュトークンを発行するかどうかを決めなければならない(MUST)とも定めています。リフレッシュトークンを発行しないことも選択肢です。

> *Refresh token rotation:* the authorization server issues a new refresh token with every access token refresh response. The previous refresh token is invalidated, but information about the relationship is retained by the authorization server. If a refresh token is compromised and subsequently used by both the attacker and the legitimate client, one of them will present an invalidated refresh token, which will inform the authorization server of the breach. The authorization server cannot determine which party submitted the invalid refresh token, but it will revoke the active refresh token.

(RFC 9700 4.14.2節)

この部分がローテーションの定義です。認可サーバはリフレッシュの応答ごとに新しいリフレッシュトークンを発行し、前のトークンを無効にします。ただし、トークン同士の関係の情報は保持します。この「関係の保持」が、本書でトークンファミリーと呼んだものです。漏洩したトークンを攻撃者と正規のクライアントの両方が使うと、どちらかが無効化済みのトークンを提示することになります。この提示によって、認可サーバは漏洩を検出します。どちらが提示したかは判断できないため、有効なリフレッシュトークンを失効させます。同節は続けて、これは攻撃を止める代わりに、正規のクライアントに新しい認可の取得を強いるものだと述べています。

同じ箇所の実装上の注記は、リフレッシュトークンの値に所属する認可(ファミリー)の情報を埋め込めば、失効させるべきトークンを効率よく特定できると述べています。その場合、認可サーバは署名などでトークンの値の完全性を保証しなければなりません(MUST)。値を改ざんしてファミリーの情報を書き換えられると、失効の範囲を操作されるためです。

> Refresh tokens SHOULD expire if the client has been inactive for some time, i.e., the refresh token has not been used to obtain fresh access tokens for some time.

(RFC 9700 4.14.2節)

クライアントが一定期間使っていないリフレッシュトークンは、期限切れにすべきです(SHOULD)。この期間は認可サーバが決めます。後で扱うスライディング有効期限がこれに当たります。同じ節は、パスワードの変更や認可サーバでのログアウトのようなセキュリティ上の出来事があれば、リフレッシュトークンを自動的に失効させてもかまわない(MAY)とも述べています。

## 実験: ローテーションと再利用検知

認可サーバのリフレッシュトークンの記録(トークンごとの使用済みフラグと所属ファミリー)と、ファミリーの記録(クライアント、スコープ、失効済みフラグ)を作り、正規のクライアントと攻撃者が同じリフレッシュトークンを持つ状況を再現します。トークンの値は `RT1`、`RT2` のような連番のダミー値で、出力は実行ごとに変わりません。

<RustPlay snippet="ch15/rotation" title="リフレッシュトークンのローテーションと再利用検知" />

[1] はローテーションのない認可サーバです。正規のクライアントと攻撃者が交互に `RT1` を使い、どちらも毎回アクセストークンを得ています。認可サーバから見ると、同じクライアントが何度もリフレッシュしているのと区別できず、漏洩を検出する手段がありません。

[2] は攻撃者が先に使った場合です。攻撃者は `RT1` で `RT2` を得ます。その後、正規のクライアントが `RT1` を提示すると、使用済みのトークンなので再利用として検知され、ファミリー全体が失効します。攻撃者が入手した `RT2` も、次の使用で `invalid_grant` になります。

[3] は正規のクライアントが先に使った場合です。正規のクライアントは `RT1`、`RT2` と順に使い、`RT3` を持っています。攻撃者が盗んでおいた `RT1` を提示すると再利用が検知され、ファミリーが失効します。正規のクライアントの `RT3` も無効になり、利用者は再ログインを求められます。検知された時点で攻撃は止まりますが、正規の利用者にも影響が及びます。

[4] は RFC 6749 6節の他の規定です。元の同意にない `orders:write` を含むスコープの要求は `invalid_scope` になります。別のクライアントが提示した場合は `invalid_grant` になり、同意の範囲内のスコープなら新しいトークンが発行されます。拒否されたリクエストでは `RT1` が使用済みにならないため、3行目の正規の要求は成功します。不正な要求を拒否する前にトークンを使用済みにすると、攻撃者は無効なスコープを付けて正規のクライアントのトークンを消費させられます。

ローテーションには、次の限界があります。

- 検知には、正規のクライアントと攻撃者の両方が使う必要があります。攻撃者が最新のリフレッシュトークンを盗み、正規のクライアントがその後使わなければ(利用者がアプリを閉じたままにすれば)、攻撃者は検知されずにローテーションを続けられます。後述の有効期限と組み合わせる必要があります
- 正規のクライアントが複数のタブやプロセスから同時にリフレッシュすると、2つ目の要求が再利用と判定されます。多くの実装は、使用済みになってから数秒程度は同じトークンの再提示を許す猶予期間を設けています
- 新しいリフレッシュトークンを含む応答が、ネットワークの障害でクライアントに届かなかった場合、クライアントは古いトークンしか持たず、それを再送すると再利用と判定されます

## 送信者制約との関係

ローテーションは、盗まれたリフレッシュトークンを「使われた後で」検知する方式です。もう1つの方式である送信者制約は、盗まれたリフレッシュトークンを「そもそも使えなくする」方式です。リフレッシュトークンを、クライアントだけが持つ秘密鍵に結びつけ、使うたびにその秘密鍵を持つことを証明させます。

[16章](/oauth-deep/16-sender-constrained/)で扱う DPoP(RFC 9449)の5節は、DPoP をサポートする認可サーバが、DPoP の証明を提示したパブリッククライアントにリフレッシュトークンを発行する場合、そのリフレッシュトークンを証明の公開鍵に束縛しなければならない(MUST)と定めています。以降のリフレッシュでは、同じ鍵の証明が必要になります。秘密鍵を取り出せない形で保持すれば、リフレッシュトークンだけを盗んでも使えません。ブラウザでは、暗号 API である **WebCrypto**(Web Cryptography API)で、鍵を抽出不可能として生成できます。

同じ RFC 9449 の5節は、機密クライアントのリフレッシュトークンは DPoP の鍵に束縛しないと述べています。機密クライアントのリフレッシュトークンは、RFC 6749 6節のクライアント認証によって既に送信者制約が付いているためです。同節は、クライアント認証による束縛のほうが、リフレッシュトークンを無効にせずにクライアントの資格情報を更新できる点で柔軟だと説明しています。

この考え方に従うと、機密クライアントと送信者制約を組み合わせた構成では、ローテーションは安全性を高めないことになります。FAPI 2.0 Security Profile([25章](/security/25-high-security/))は、認可サーバの要件として次のように定めています。

> shall not use refresh token rotation except in extraordinary circumstances (see Note 1 below);

(FAPI 2.0 Security Profile 5.3.2.1節)

認可サーバは、例外的な状況を除き、リフレッシュトークンローテーションを使ってはなりません。注記(Note 1)は理由を2つ挙げています。1つは、機密クライアントと送信者制約付きアクセストークンを使う場合、ローテーションは安全上の利点をもたらさないことです。もう1つは、クライアントが新しいリフレッシュトークンの保存や受信に失敗したとき、再試行の手段がなく、利用者の体験の悪化と運用上の問題を引き起こすことです。インフラの移行などでローテーションが必要な場合は、失敗時に古いリフレッシュトークンで再試行できる期限付きの手段をクライアントに提供することを条件に、例外として認めています。

RFC 9700 と FAPI 2.0 の規定は、矛盾しているように見えて、対象が異なります。RFC 9700 のローテーション必須(送信者制約との二択)はパブリッククライアントについての規定であり、FAPI 2.0 は機密クライアントしか認めないプロファイルです。「リフレッシュトークンは常にローテーションすべき」という一般論は、パブリッククライアントの前提で成り立つものであり、クライアントの種類と送信者制約の有無によって結論が変わります。前の実験で見た限界のうち、3つ目(応答の喪失)が FAPI 2.0 の注記の挙げる問題そのものです。

## offline_access

OpenID Connect では、リフレッシュトークンの用途の1つを、スコープの値として明示的に定めています。`offline_access`(offline_access スコープ)は、利用者がその場にいない(ログインしていない)ときにも UserInfo エンドポイントなどにアクセスするための、リフレッシュトークンの発行を要求するスコープです。利用者が寝ている間にカレンダーを同期するアプリのような用途が該当します。

## 仕様を読む: OpenID Connect Core 1.0 11節

> offline_access
> OPTIONAL. This scope value requests that an OAuth 2.0 Refresh Token be issued that can be used to obtain an Access Token that grants access to the End-User's UserInfo Endpoint even when the End-User is not present (not logged in).

(OpenID Connect Core 1.0 11節)

この節は `offline_access` スコープを定めています。このスコープ値は、エンドユーザーがその場にいない(ログインしていない)ときでも UserInfo エンドポイントにアクセスできるアクセストークンを得るための、リフレッシュトークンの発行を要求します。

> When offline access is requested, a prompt parameter value of consent MUST be used unless other conditions for processing the request permitting offline access to the requested resources are in place. The OP MUST always obtain consent to returning a Refresh Token that enables offline access to the requested resources. A previously saved user consent is not always sufficient to grant offline access.

(OpenID Connect Core 1.0 11節)

オフラインアクセスを要求する場合、他に処理を許す条件がない限り、`prompt` パラメータ([18章](/oidc-deep/18-claims-identity/))の値に `consent` を使わなければなりません(MUST)。OP は、オフラインアクセスを可能にするリフレッシュトークンを返すことについて、常に同意を得なければなりません(MUST)。以前に保存した同意では十分でない場合があります。

同じ節は、`offline_access` を受け取った認可サーバについて、次のように定めています。

- `prompt` に `consent` が含まれず、他の条件も満たさない場合は、`offline_access` の要求を無視しなければなりません(MUST)
- 認可コードが返される `response_type` でなければ、`offline_access` の要求を無視しなければなりません(MUST)。リフレッシュトークンはトークンエンドポイントでしか返せないためです
- 登録された `application_type` が `web` の場合は、オフラインアクセスへの同意を明示的に得なければならず(MUST)、`native` の場合は得るべきです(SHOULD)

17.4節は、この規定の理由を、利用者がいないときのクレームへのアクセスは、利用者がいるときよりプライバシー上のリスクが大きいためと説明しています。最後の段落は、リフレッシュトークンの使用は `offline_access` に限定されず、認可サーバはこの仕様の範囲外の状況でリフレッシュトークンを発行してもかまわない(MAY)と述べています。多くの OP は、`offline_access` を要求しなくても、通常のログインでリフレッシュトークンを発行します。`offline_access` は、利用者がいないときの長期的なアクセスについて、明示的な同意を得るための手段と位置づけられます。

## 有効期限: スライディングと絶対

リフレッシュトークンの有効期限の決め方は2種類あります。

**スライディング有効期限**(sliding expiration)は、最後に使われた時刻から一定期間で切れる有効期限です。使われるたびに期限が延びます。RFC 9700 4.14.2節の「一定期間使われていないリフレッシュトークンは期限切れにすべき」は、この方式を指しています。アイドルタイムアウトとも呼ばれます。

**絶対有効期限**(absolute expiration)は、最初の認可(ファミリーの開始)から一定期間で切れる有効期限です。どれだけ頻繁に使っても延びません。

2つの方式を、利用のパターンごとに比べる実験を行います。スライディング14日、絶対90日、その組み合わせ、期限なしの4つの方針について、毎日使う利用者、月に1回使う利用者、盗んだトークンを週に1回使う攻撃者が、何日目に再ログインを求められるかを計算します。

<RustPlay snippet="ch15/expiry" title="スライディング有効期限と絶対有効期限の比較" />

毎日使う利用者は、スライディング14日だけなら120日間使い続けられ、絶対90日があると91日目に再ログインになります。月に1回使う利用者は、スライディング14日では30日目に失効します。前回の使用から14日を超えたためです。

週に1回(7日ごと)使う攻撃者は、スライディング14日の期限を常に満たし、364日目まで使い続けられます。ローテーションをしている場合も、正規のクライアントがその後使わなければ再利用は検知されないため、結果は同じです。スライディング有効期限だけでは、定期的に使い続ける攻撃者を止められません。絶対有効期限を組み合わせると、攻撃者も91日目には使えなくなります。

この結果から、組み合わせの方針は次のように決まります。

- スライディング有効期限は、使われなくなったトークン(端末の紛失や放置)を早く無効にします。短いほど放置されたトークンの危険が減り、たまにしか使わない利用者の再ログインが増えます
- 絶対有効期限は、トークンの悪用が続く期間の上限を決めます。長いほど利用者の再ログインが減り、悪用の期間の上限が長くなります
- どちらも認可サーバの方針で決め、ファミリーの開始時刻と最終使用時刻を記録しておく必要があります

## 保存場所

リフレッシュトークンはクライアントが保持する資格情報の中で最も寿命が長いため、保存場所が漏洩の範囲を決めます。

機密クライアント(サーバ上の Web アプリケーション)は、リフレッシュトークンをサーバ側のデータベースに保存し、ブラウザには渡しません。ブラウザとの対応づけには、セッション Cookie([1章](/web-auth/01-http-auth/))を使います。データベースの漏洩に備えて暗号化して保存し、ログには出力しません([26章](/practice/26-operations/))。

ブラウザ上のアプリケーションでは、`localStorage` のように JavaScript から読める場所に保存すると、XSS で読み出されます。RFC 10017(ブラウザベースアプリケーションの BCP)は、トークンをブラウザに置かずにサーバ側のコンポーネント(BFF)に保持させる構成を含む3つの構成を比較しており、[24章](/security/24-browser-native/)で扱います。ブラウザに保持する場合は、DPoP で送信者制約を付けるか、ローテーションと短い有効期限を組み合わせます。

ネイティブアプリでは、OS が提供する資格情報の保管領域(多くの環境で、アプリごとに分離され、端末の鍵で暗号化される領域)に保存します。

認可サーバ側では、リフレッシュトークンの SHA-256 のハッシュ値だけを保存し、提示されたトークンのハッシュ値と照合すれば足ります。推測できない十分な長さのランダムな値であれば、この方法で照合でき、値そのものを保存する必要はありません。パスワードと異なり、エントロピーが十分あるため、[5章](/web-auth/05-crypto/)のパスワードハッシュのような低速なハッシュ関数は必要ありません。この方法なら、認可サーバのデータベースが漏洩しても、リフレッシュトークンとしては使えません。

## まとめ

- アクセストークンは多くの場所に送られ、失効が伝わりにくいため短寿命にします。利用の継続には、認可サーバにだけ送られて使用のたびに照合されるリフレッシュトークンを使います
- RFC 6749 6節は、リフレッシュトークンを発行先のクライアントに束縛し、機密クライアントには認証を求めています。リフレッシュでスコープは縮小できても、拡大はできません
- RFC 9700 は、パブリッククライアントのリフレッシュトークンに、送信者制約かローテーションのどちらかを必須としています。ローテーションは再利用を検知し、ファミリー全体を失効させます
- 実験では、攻撃者と正規のクライアントのどちらが先に使っても、2回目の提示でファミリーが失効しました。不正な要求でトークンを使用済みにしないことも必要です
- FAPI 2.0 は、機密クライアントと送信者制約の組み合わせではローテーションに安全上の利点がないとして、原則として禁じています。結論は、クライアントの種類と送信者制約の有無で変わります
- `offline_access` は、利用者不在時のアクセスのためのリフレッシュトークンを、明示的な同意のもとで要求するスコープです
- 実験では、スライディング有効期限だけでは週1回使う攻撃者が1年間使い続けられました。絶対有効期限と組み合わせて、悪用の期間に上限を設けます

次章では、リフレッシュトークンの節で触れた送信者制約を詳しく扱います。Bearer トークンの「持っていれば使える」という性質を、DPoP と mTLS がどう変えるかを、DPoP の証明を自分で作って検証することで確かめます。
