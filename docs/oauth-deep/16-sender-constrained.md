---
title: "送信者制約トークン: DPoPとmTLS"
description: Bearer トークンの限界、所有証明による送信者制約、DPoP 証明の構造と RFC 9449 4.3節の検証手順、cnf.jkt による束縛、DPoP-Nonce、mTLS の証明書束縛アクセストークン。
sidebar:
  label: "16. 送信者制約トークン: DPoPとmTLS"
---

この章でわかること:

- Bearer トークンの「持っていれば誰でも使える」という性質の限界と、所有証明による送信者制約の考え方
- DPoP 証明の構造(`typ`、`alg`、`jwk`、`jti`、`htm`、`htu`、`iat`、`ath`)と、RFC 9449 4.3節の検証手順
- アクセストークンの `cnf.jkt` で公開鍵に束縛する仕組みと、RFC 9449 の例の署名・ハッシュ・Thumbprint の一致確認(実験)
- ring で DPoP 証明を作り、盗まれたトークン、再送、メソッドの差し替え、Bearer への格下げを検証で拒否する実験
- なぜ体系に必須か: ここまでの対策はすべて「トークンを漏洩させない」ためのものでした。送信者制約は「漏洩しても使えない」ようにする唯一の層であり、FAPI 2.0 はこれを必須にしています

## 基礎編からの接続

[4章](/web-auth/04-tokens/)の Bearer トークンは、名前のとおり「持参人」が使えるトークンでした。RFC 6750 の定義は、トークンを持つ者は誰でも、他の持つ者と同じようにそれを使え、暗号鍵の所有を証明する必要がない、というものです。[14章](/oauth-deep/14-token-validation/)では宛先の制限によって漏洩したトークンの使い道を狭め、[15章](/oauth-deep/15-refresh-tokens/)ではリフレッシュトークンの漏洩をローテーションで検知しました。どちらも、漏洩したトークンが使えるという前提は変えていません。

この章では、その前提を変えます。必要な技術は基礎編で説明済みです。[5章](/web-auth/05-crypto/)の ECDSA の署名、[7章](/oidc/07-jwt-jose/)の JWS と JWK、JWK Thumbprint(RFC 7638)です。[13章](/oauth-deep/13-client-auth/)で見た mTLS も、ここでは別の用途で使います。

## Bearer トークンの限界

> A security token with the property that any party in possession of the token (a "bearer") can use the token in any way that any other party in possession of it can. Using a bearer token does not require a bearer to prove possession of cryptographic key material (proof-of-possession).

(RFC 6750 1.2節)

この節は、Bearer トークンを定義しています。トークンを持つ者(bearer)は誰でも、他の持つ者と同じ方法でトークンを使えます。使うときに暗号鍵の所有を証明する(proof-of-possession)必要はありません。

この性質のため、Bearer トークンの安全性は、トークンがどこにも漏洩しないことに依存します。実際には、トークンは多くの経路で漏洩します。

- リソースサーバやリバースプロキシのログに `Authorization` ヘッダが記録されます
- 悪意のある、または侵入されたリソースサーバが、受け取ったトークンを別のリソースサーバに送ります
- ブラウザ上のアプリケーションで、XSS によって JavaScript からトークンが読み出されます
- TLS 実装の脆弱性によってメモリの内容が読み出されます

RFC 9449 の2節は、CRIME、BREACH、Heartbleed、Cloudbleed のような、プロトコルやソフトウェアの別の層の脆弱性による予期しない漏洩の例を挙げています。漏洩の経路をすべてなくすことは現実的ではなく、漏洩した場合の影響を小さくする層が必要になります。

> Authorization and resource servers SHOULD use mechanisms for sender-constraining access tokens, such as mutual TLS for OAuth 2.0 [RFC8705] or OAuth 2.0 Demonstrating Proof of Possession (DPoP) [RFC9449] (see Section 4.10.1), to prevent misuse of stolen and leaked access tokens.

(RFC 9700 2.2.1節)

RFC 9700 は、盗まれたり漏洩したりしたアクセストークンの悪用を防ぐために、認可サーバとリソースサーバはアクセストークンに送信者制約を付ける仕組みを使うべきだ(SHOULD)と推奨しています。例として挙げられているのが、この章で扱う mTLS と DPoP です。

## 送信者制約と所有証明

**送信者制約**(sender-constraining)は、アクセストークンを使える送信者を特定のクライアントに限定することです。送信者制約が付いたトークンを**送信者制約トークン**(sender-constrained token)と呼びます。限定の方法は、トークンを鍵に結びつけ、トークンを使うたびにその鍵を持っていることを証明させることです。この証明を**所有証明**(proof of possession、PoP)と呼びます。

RFC 9700 の4.10.1節は、送信者制約の典型的な流れを3段階で説明しています。

1. 認可サーバは、トークンを特定のクライアントに結びつけるデータをトークンに関連づけます。多くの場合、クライアントが持つ鍵(またはそこから導いたデータ)を使います
2. その鍵を何らかの方法で配布します。X.509 証明書のように事前に登録する方法と、TLS の層で接続時に作る方法があります
3. リソースサーバが所有証明を検査します。所有証明そのものが再送されないことも確認する必要があります

トークンと鍵の関連づけは、JWT アクセストークンでは `cnf`(cnf クレーム)に入れます。`cnf` は confirmation(確認)の略で、RFC 7800 が定める「このトークンを提示する者が持っているはずの鍵」を表すクレームです。`cnf` の中身はオブジェクトで、鍵の表し方ごとにメンバー名が決まっています。DPoP は公開鍵の JWK Thumbprint を `jkt` に、mTLS は証明書のハッシュを `x5t#S256` に入れます。不透明トークンの場合は、イントロスペクションの応答の最上位に同じ `cnf` を入れて伝えます。

鍵を持たない攻撃者は、トークンを盗んでも所有証明を作れません。送信者制約は、漏洩したトークンを単独では使えなくする対策であり、漏洩そのものを防ぐ対策ではありません。

## DPoP の全体像

**DPoP**(Demonstrating Proof of Possession、RFC 9449)は、アプリケーション層で所有証明を行う仕組みです。クライアントは自分で鍵ペアを生成し、HTTP リクエストのたびに、そのリクエストの内容を含む JWT を秘密鍵で署名して `DPoP` ヘッダで送ります。この JWT を **DPoP 証明**(DPoP proof)と呼びます。

```mermaid
sequenceDiagram
    participant C as クライアント
    participant AS as 認可サーバ
    participant RS as リソースサーバ
    Note over C: 鍵ペアを生成 (秘密鍵は外に出さない)
    C->>AS: POST /token<br/>DPoP: (htm=POST, htu=トークンエンドポイントの証明)
    AS->>AS: 証明を検証し、公開鍵の jkt を計算
    AS-->>C: access_token (cnf.jkt 付き), token_type=DPoP
    C->>RS: GET /protectedresource<br/>Authorization: DPoP (アクセストークン)<br/>DPoP: (htm=GET, htu, ath の証明)
    RS->>RS: 証明を検証し、証明の鍵の jkt と cnf.jkt を照合
    RS-->>C: 200 OK
```

クライアントは、トークンリクエストに DPoP 証明を付けます。

```http
POST /token HTTP/1.1
Host: server.example.com
Content-Type: application/x-www-form-urlencoded
DPoP: eyJ0eXAiOiJkcG9wK2p3dCIsImFsZyI6IkVTMjU2IiwiandrIjp7Imt0eSI6IkVDIiwieCI6Imw4dEZyaHgtMzR0VjNoUklDUkRZOXpDa0RscEJoRjQyVVFVZldWQVdCRnMiLCJ5IjoiOVZFNGpmX09rX282NHpiVFRsY3VOSmFqSG10NnY5VERWclUwQ2R2R1JEQSIsImNydiI6IlAtMjU2In19.eyJqdGkiOiItQndDM0VTYzZhY2MybFRjIiwiaHRtIjoiUE9TVCIsImh0dSI6Imh0dHBzOi8vc2VydmVyLmV4YW1wbGUuY29tL3Rva2VuIiwiaWF0IjoxNTYyMjYyNjE2fQ.2-GxA6T8lP4vfrg8v-FdWP0A0zdrj8igiMLvqRMUvwnQg4PtFLbdLXiOSsX0x7NVY-FNyJK70nfbV37xRZT3Lg

grant_type=authorization_code&client_id=s6BhdRkqt
&code=SplxlOBeZQQYbYS6WxSbIA
&redirect_uri=https%3A%2F%2Fclient%2Eexample%2Ecom%2Fcb
&code_verifier=bEaL42izcC-o-xBk0K2vuJ6U-y1p9r_wW2dFWIWgjz-
```

認可サーバは、証明の公開鍵にアクセストークンを束縛し、`token_type` を `DPoP` にして返します。

```http
HTTP/1.1 200 OK
Content-Type: application/json
Cache-Control: no-store

{
 "access_token": "Kz~8mXK1EalYznwH-LC-1fBAo.4Ljp~zsPE_NeO.gxU",
 "token_type": "DPoP",
 "expires_in": 2677,
 "refresh_token": "Q..Zkm29lexi8VnWg2zPW1x-tgGad0Ibc3s3EwM_Ni4-g"
}
```

リソースへのリクエストでは、`Authorization` ヘッダのスキームを `DPoP` に変え、そのリクエスト用の新しい DPoP 証明を付けます。

```http
GET /protectedresource HTTP/1.1
Host: resource.example.org
Authorization: DPoP Kz~8mXK1EalYznwH-LC-1fBAo.4Ljp~zsPE_NeO.gxU
DPoP: eyJ0eXAiOiJkcG9wK2p3dCIsImFsZyI6IkVTMjU2IiwiandrIjp7Imt0eSI6IkVDIiwieCI6Imw4dEZyaHgtMzR0VjNoUklDUkRZOXpDa0RscEJoRjQyVVFVZldWQVdCRnMiLCJ5IjoiOVZFNGpmX09rX282NHpiVFRsY3VOSmFqSG10NnY5VERWclUwQ2R2R1JEQSIsImNydiI6IlAtMjU2In19.eyJqdGkiOiJlMWozVl9iS2ljOC1MQUVCIiwiaHRtIjoiR0VUIiwiaHR1IjoiaHR0cHM6Ly9yZXNvdXJjZS5leGFtcGxlLm9yZy9wcm90ZWN0ZWRyZXNvdXJjZSIsImlhdCI6MTU2MjI2MjYxOCwiYXRoIjoiZlVIeU8ycjJaM0RaNTNFc05yV0JiMHhXWG9hTnk1OUlpS0NBcWtzbVFFbyJ9.2oW9RP35yRqzhrtNP86L-Ey71EOptxRimPPToA1plemAgR6pxHF8y6-yqyVnmcw6Fy1dqd-jfxSYoMxhAJpLjA
```

これらはすべて RFC 9449 の例(Figure 5、6、13)で、1つの鍵ペアで一貫して作られています。後の実験で、この例の署名とハッシュを実際に検証します。

RFC 9449 の3節は、DPoP はクライアント認証の方式ではないと明記しています。主な用途は、クライアント認証を行えないパブリッククライアント(SPA やネイティブアプリ)のトークンを保護することです。`private_key_jwt` などのクライアント認証とも組み合わせられます。

## RFCを読む: RFC 9449 4.2節

> The JOSE Header of a DPoP JWT MUST contain at least the following parameters:
>
> typ: A field with the value dpop+jwt, which explicitly types the DPoP proof JWT as recommended in Section 3.11 of [RFC8725].
>
> alg: An identifier for a JWS asymmetric digital signature algorithm from [IANA.JOSE.ALGS]. It MUST NOT be none or an identifier for a symmetric algorithm (Message Authentication Code (MAC)).
>
> jwk: Represents the public key chosen by the client in JSON Web Key (JWK) [RFC7517] format as defined in Section 4.1.3 of [RFC7515]. It MUST NOT contain a private key.

(RFC 9449 4.2節)

この節は、DPoP 証明の構文を定めています。ヘッダには少なくとも次の3つを含めなければなりません(MUST)。

- `typ`: 値は `dpop+jwt` です。RFC 8725(JWT BCP)3.11節が推奨する明示的な型付けで、他の用途の JWT と区別します
- `alg`: 非対称のデジタル署名アルゴリズムです。`none` や、MAC(共通鍵)のアルゴリズムであってはなりません(MUST NOT)。検証に共通鍵を使う方式では、検証者も署名を作れてしまい、所有証明にならないためです
- `jwk`: クライアントが選んだ公開鍵を JWK で表したものです。秘密鍵を含めてはなりません(MUST NOT)

`jwk` ヘッダが署名の検証鍵を含む点が、[8章](/oidc/08-id-token-validation/)の ID トークンや[14章](/oauth-deep/14-token-validation/)の JWT アクセストークンとの大きな違いです。通常の JWT では、ヘッダの鍵を信用して検証すると誰でも署名を作れてしまうため、鍵は信頼できる経路(JWKS)から取得します。DPoP で確認するのは、署名した鍵がアクセストークンに束縛された鍵と同じかどうかであり、どの鍵で署名されたか自体は問いません。この照合を後述の `cnf.jkt` で行います。

ペイロードには、少なくとも次の4つのクレームを含めなければなりません(MUST)。

- `jti`: 証明ごとの一意な識別子です。96ビット以上の乱数を符号化するか、バージョン4の UUID を使います
- `htm`(htm クレーム): 証明を付けた HTTP リクエストのメソッドです
- `htu`(htu クレーム): 証明を付けた HTTP リクエストの対象 URI から、クエリとフラグメントを除いたものです
- `iat`: 証明の作成時刻です

アクセストークンと一緒に使う証明には、さらに `ath`(ath クレーム)が必須です。

> ath: Hash of the access token. The value MUST be the result of a base64url encoding (as defined in Section 2 of [RFC7515]) the SHA-256 [SHS] hash of the ASCII encoding of the associated access token's value.

(RFC 9449 4.2節)

`ath` は、アクセストークンの値を ASCII で符号化し、その SHA-256 ハッシュを Base64url で符号化した値でなければなりません(MUST)。サーバが `DPoP-Nonce` ヘッダで nonce を渡した場合は、証明に `nonce` クレームも必須になります(後述)。

同じ節の最後の段落は、HTTP リクエストのうちメソッドと URI だけを証明に含める理由を、所有の証明として妥当な程度に必要最小限のデータに署名し、HTTP メッセージを正規化することの困難を避けるためだと説明しています。ヘッダや本文はプロキシなどで書き換えられることがあり、署名対象に含めると、正規のリクエストでも検証に失敗する場合が出てきます。

## RFCを読む: RFC 9449 4.3節

> To validate a DPoP proof, the receiving server MUST ensure the following:

(RFC 9449 4.3節)

この節は、DPoP 証明を受け取ったサーバが確認しなければならない(MUST)事項を12項目で定めています。各項目と、それが防ぐ攻撃を表にまとめます。

| 項目 | 確認する内容 | 防ぐもの |
| --- | --- | --- |
| 1 | `DPoP` ヘッダが1つだけである | 複数の証明による検査の取り違え |
| 2 | ヘッダの値が1つの正しい形式の JWT である | 不正な入力 |
| 3 | 4.2節の必須クレームがすべてある | 検査の省略 |
| 4 | `typ` が `dpop+jwt` である | 他の用途の JWT の流用 |
| 5 | `alg` が登録された非対称署名で、`none` でなく、許可されている | 署名の偽造、アルゴリズム混同 |
| 6 | `jwk` ヘッダの公開鍵で署名が検証できる | 証明の改ざん |
| 7 | `jwk` に秘密鍵が含まれない | 秘密鍵の露出を許す実装 |
| 8 | `htm` が現在のリクエストのメソッドと一致する | 別のメソッドへの流用 |
| 9 | `htu` が現在のリクエストの URI(クエリとフラグメントを除く)と一致する | 別のエンドポイントへの流用 |
| 10 | nonce を渡していれば、`nonce` がそれと一致する | 事前生成した証明 |
| 11 | `iat`(または nonce に含めたサーバの時刻)が許容範囲内である | 古い証明の再送 |
| 12 | アクセストークンと一緒なら、`ath` がそのハッシュと一致し、証明の公開鍵がトークンに束縛された鍵と一致する | 盗んだトークンの使用、証明とトークンの組み替え |

同じ節は、偽陰性(正しい証明の拒否)を減らすため、`htu` の比較の前に RFC 3986 の構文に基づく正規化とスキームに基づく正規化を行うべきだ(SHOULD)と定めています。ホスト名の大文字小文字や、`https` の既定のポート番号 `:443` の有無による違いで、正しい証明を拒否しないためです。最後に、これらの検査はどの順序で行ってもよいと述べています。

項目11の許容範囲について、11.1節は、サーバは作成から限られた時間(秒か分の単位の比較的短い期間が望ましい)だけ証明を受け入れなければならない(MUST)と定めています。さらに、その時間内に同じ `jti` の証明を2度受け入れないよう、使用済みの `jti` を記録してもよいとしています。

## RFCを読む: RFC 9449 6節

> jkt: JWK SHA-256 Thumbprint confirmation method. The value of the jkt member MUST be the base64url encoding (as defined in [RFC7515]) of the JWK SHA-256 Thumbprint (according to [RFC7638]) of the DPoP public key (in JWK format) to which the access token is bound.

(RFC 9449 6.1節)

この節は、アクセストークンと公開鍵の束縛の表し方を定めています。JWT のアクセストークンでは、`cnf` クレームの中に `jkt`(jkt 確認メソッド)を入れます。`jkt` の値は、アクセストークンを束縛した DPoP の公開鍵の JWK SHA-256 Thumbprint(RFC 7638)を Base64url で符号化したものでなければなりません(MUST)。RFC 9449 の例(Figure 9)のアクセストークンのペイロードは次のとおりです。

```json
{
  "sub": "someone@example.com",
  "iss": "https://server.example.com",
  "nbf": 1562262611,
  "exp": 1562266216,
  "cnf": {
    "jkt": "0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I"
  }
}
```

`cnf` に公開鍵そのものを入れずに Thumbprint を入れるのは、[7章](/oidc/07-jwt-jose/)で見たように、Thumbprint が鍵の表記の違い(メンバーの順序や空白)に依存しない一意な値だからです。EC 鍵の Thumbprint は、`crv`、`kty`、`x`、`y` の4つだけを辞書順に並べ、空白を含まない JSON にして SHA-256 をとります。

6節の本文は、DPoP をサポートするリソースサーバは、DPoP 証明の公開鍵がアクセストークンに束縛された公開鍵と一致することを確認しなければならない(MUST)と定めています。不透明トークンの場合は、6.2節のとおり、イントロスペクションの応答の最上位に同じ `cnf` を入れて返します。束縛の照合は、応答を受け取ったリソースサーバが自分で行います。リソースサーバはイントロスペクションのリクエストに DPoP 証明を付けず、認可サーバもこの時点では束縛を検証しません。

## 実験: RFC 9449 の例を検証する

RFC 9449 の Figure 2(トークンリクエスト用)と Figure 13(リソースアクセス用)の DPoP 証明について、次の3点を確かめます。

1. `jwk` ヘッダの公開鍵で、両方の証明の ES256 署名を検証します
2. Figure 13 の `ath` が、Figure 6 のアクセストークン `Kz~8mXK1EalYznwH-LC-1fBAo.4Ljp~zsPE_NeO.gxU` の SHA-256 の Base64url と一致するかを確かめます
3. `jwk` ヘッダの公開鍵の JWK Thumbprint が、Figure 9 の `cnf.jkt` と一致するかを確かめます

署名の検証には、`jwk` の `x` と `y` を連結して非圧縮形式の点(`0x04 || x || y`、65バイト)を作り、ring の `ECDSA_P256_SHA256_FIXED` に渡します。JWS の ES256 の署名は `r || s` の64バイトで、DER 形式とは異なるので、`FIXED` の方を使います。

<RustPlay snippet="ch16/dpop-rfc-vector" title="RFC 9449 の例の DPoP 証明を検証し、ath と jkt を再計算する" />

出力のヘッダとペイロードは、serde_json がキーを辞書順に並べて表示したもので、元の JSON の順序とは異なります。署名の検証には元の Base64url の文字列を使っているので、表示の順序は結果に影響しません。

2つの証明の署名は、どちらも `jwk` ヘッダの公開鍵で検証に成功します。`ath` の計算値は `fUHyO2r2Z3DZ53EsNrWBb0xWXoaNy59IiKCAqksmQEo` で、証明の値と一致します。Thumbprint の計算値は `0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I` で、`cnf.jkt` と一致します。RFC の例は、Figure 2 の証明で得たアクセストークンが Figure 9 の `cnf.jkt` でその鍵に束縛され、Figure 13 の証明がそのトークンを `ath` で参照する、という一連の流れとして整合していることがわかります。

## RFCを読む: RFC 9449 7節

> Binding the token value to the proof in this way prevents a proof to be used with multiple different access token values across different requests.

(RFC 9449 7節)

この節は、保護されたリソースへのアクセスを定めています。リソースへのリクエストには、DPoP 証明とアクセストークンの両方が必要で、証明は `ath` を含まなければなりません(MUST)。引用した文は `ath` の目的を述べています。トークンの値を証明に結びつけることで、1つの証明を異なるアクセストークンと組み合わせて使えなくします。同じ節は例として、同じ鍵で2人のリソースオーナーのトークン AT1 と AT2 を持つクライアントを挙げています。`ath` がなければ、AT1 と一緒に送った証明を捕捉した者が、それを AT2 と組み合わせて再送できます。

7.1節は `DPoP` 認証スキームを定めています。DPoP に束縛されたアクセストークンは、`Authorization: DPoP <トークン>` の形で送ります。リソースサーバは、`DPoP` ヘッダの証明を4.3節に従って検査し、証明の公開鍵がトークンに束縛された鍵と一致することを確認しなければなりません(MUST)。すべての検査が成功しない限り、アクセスを許可してはなりません(MUST NOT)。

> Specifically, such a protected resource MUST reject a DPoP-bound access token received as a bearer token per [RFC6750].

(RFC 9449 7.2節)

7.2節は、Bearer と DPoP の両方を受け付けるリソースサーバの注意点を定めています。そのようなリソースサーバは、DPoP に束縛されたアクセストークンが Bearer トークンとして送られてきた場合、拒否しなければなりません(MUST)。この検査がないと、トークンを盗んだ攻撃者は、スキームを `Bearer` にして DPoP の検査そのものを回避できます。このように、より弱い保護の方式を使わせて強い保護を回避する攻撃を**格下げ攻撃**(downgrade attack)と呼びます。同じ節は、DPoP に対応していない Bearer 専用のリソースサーバは、`cnf` を理解できないクレームとして無視し、DPoP 束縛のトークンを Bearer として受け入れてしまうだろうとも述べています。送信者制約は、トークンを受け取るすべてのリソースサーバが DPoP に対応して初めて完全に機能します。

## 実験: DPoP 証明を作って検証する

ring で ES256 の鍵ペアを生成し、DPoP のフロー全体を1つのプロセスで再現します。

- クライアントは、リクエストごとに `jti`(UUID v4)、`htm`、`htu`、`iat`、必要なら `ath` を入れた証明を作ります
- 認可サーバは、トークンリクエストの証明を4.3節に従って検証し、証明の公開鍵の JWK Thumbprint を `cnf.jkt` に入れた JWT アクセストークンを発行します
- リソースサーバは、まず[14章](/oauth-deep/14-token-validation/)と同じ RFC 9068 の検証(`typ`、署名、`iss`、`aud`、`exp`)でアクセストークンを確認します。次に `Authorization` のスキームと `cnf.jkt` の有無を見て、DPoP 証明を4.3節に従って検証し、証明の鍵の Thumbprint を `cnf.jkt` と照合します。最後に、メソッドに応じたスコープ(GET は `orders:read`、それ以外は `orders:write`)を確認します。DPoP の検証はアクセストークンの検証に追加するものであり、アクセストークンの検証を置き換えるものではありません

拒否の理由には、4.3節の項目番号を括弧で付けています。項目6の署名検証の前に、`jwk` の `kty` が `EC`、`crv` が `P-256` で、座標 `x` と `y` がそれぞれ32バイトであることも確かめます。`alg` を ES256 に固定しているため、鍵は P-256 の EC 鍵でなければならず(RFC 7518 3.4節)、座標の長さは曲線の座標の大きさと一致しなければならないからです(RFC 7518 6.2.1.2節、6.2.1.3節)。`crv` を検査しない実装では、同じ座標に別の `crv` を付けた `jwk` から別の Thumbprint が計算されます。現在時刻は固定値、`iat` の許容範囲は前後60秒です。`iat` は送信者が決める値なので、現在時刻との差は `i128` で計算し、桁あふれを防ぎます。鍵、署名、`jti` は乱数を使うので、`jkt` の値は実行ごとに変わります。

<RustPlay snippet="ch16/dpop" title="ring で DPoP 証明を作り、RFC 9449 4.3節の検証と jkt の照合を行う" />

[1] では、認可サーバが発行したアクセストークンの `cnf.jkt` と、クライアントの公開鍵から計算した Thumbprint が一致しています。同じ証明でもう1度トークンリクエストを送ると、`jti` の再利用として拒否されます。

[2] は正規のクライアントのリクエストで、成功します。[3] は、[2] のリクエスト(トークンと証明の組)をそのまま再送した場合です。証明の `jti` が使用済みなので拒否されます。

[4] が送信者制約の中心の検証です。攻撃者はアクセストークンを盗み、自分の鍵ペアで正しい形式の証明を作りました。証明自体は攻撃者の鍵で正しく署名され、`ath` も正しいので、4.3節の項目1〜11はすべて通過します。拒否の理由は、証明の鍵の Thumbprint がトークンの `cnf.jkt` と一致しないことです。トークンを盗んでも、束縛された秘密鍵がなければ使えません。

[5] は、攻撃者が未使用の証明(GET 用)をトークンと一緒に盗み、DELETE に使おうとした場合です。このリクエストは `htm` の不一致で拒否されます。証明はメソッドと URI(クエリとフラグメントを除く)に結びついているため、盗んだ証明を別のメソッドや別の対象 URI に再利用することは防げます。ただし、同じメソッドと同じパスであれば、クエリ、本文、他のヘッダを変えたリクエストに未使用の証明を使えます。RFC 9449 11.7節は、DPoP がリクエストの本文やヘッダの完全性を保証しないことを、意図した設計判断として明記しています。[6] は、盗んだトークンを `Bearer` スキームで送った場合で、7.2節の規定どおり拒否されます。

[7] は `typ` が `JWT` の証明、[8] は `iat` を1時間後にして事前に作った証明、[9] は `ath` を含まない証明、[10] は `DPoP` ヘッダを2つ付けたリクエストで、それぞれ項目4、11、12、1で拒否されます。

[11] は、正規のクライアントの鍵に束縛され、1時間前に期限が切れたアクセストークンです。証明は正しく、`cnf.jkt` も一致しますが、DPoP の検証の前に行う `exp` の検査で `invalid_token` として拒否されます。アクセストークンの署名だけを確認して DPoP の検証に進む実装は、このトークンを受け入れます。[12] は `jwk` の `crv` を `P-384` に書き換えた証明で、署名検証の前に拒否されます。[13] は `iat` に i64 の最小値を入れた証明です。差を i64 で計算すると桁あふれが発生しますが、i128 で計算するため、項目11の許容範囲外として拒否されます。

## RFCを読む: RFC 9449 8節

> Without employing such a mechanism, a malicious party controlling the client (potentially including the end-user) can create DPoP proofs for use arbitrarily far in the future.

(RFC 9449 8節)

この節は、認可サーバが提供する nonce を定めています。引用した文は、その動機を述べています。この仕組みがなければ、クライアントを制御する悪意のある者(エンドユーザー自身を含む)は、任意に先の時刻で使う DPoP 証明を作れます。証明の `iat` はクライアントが自由に決められるためです。

11.2節は、この攻撃を具体的に説明しています。例えば、XSS でブラウザ上のアプリケーションのコードを実行できる攻撃者は、抽出できない秘密鍵であっても、その場で署名させることはできます。攻撃者は、`iat` を未来の時刻にした証明を大量に作らせて外部に持ち出し、後で使えます。このとき証明しているのは証明の所有であり、鍵の所有ではありません。

対策として、サーバは推測できない値を `DPoP-Nonce`(DPoP-Nonce ヘッダ)でクライアントに渡し、次の証明の `nonce` クレームにその値を含めさせます。サーバが nonce を更新すれば、それより前に作られた証明は使えなくなります。

```http
HTTP/1.1 400 Bad Request
DPoP-Nonce: eyJ7S_zG.eyJH0-Z.HX4w-7v

{
 "error": "use_dpop_nonce",
 "error_description": "Authorization server requires nonce in DPoP proof"
}
```

認可サーバは、nonce を含まない証明に `use_dpop_nonce` のエラーと `DPoP-Nonce` ヘッダを返します。nonce の値は推測できないものでなければなりません(MUST)。クライアントは受け取った nonce を含めて証明を作り直し、リクエストを再送します。8.2節は、成功の応答(200)の `DPoP-Nonce` ヘッダで次の nonce を渡せば、往復を増やさずに nonce を更新できると述べています。11.3節は、1度 nonce を渡したクライアントからの、`nonce` クレームのない証明を受け入れてはならない(MUST NOT)と定めています。nonce のない古い形式に戻されると、nonce の効果がなくなるためです。

9節は、リソースサーバも同じ方法で nonce を渡せると定めています。リソースサーバの場合は、401 と `WWW-Authenticate: DPoP error="use_dpop_nonce"` で通知します。nonce は発行したサーバでだけ受け入れられ、OpenID Connect の ID トークンの `nonce`([9章](/oidc/09-state-nonce-pkce/))とは別のものです。

nonce がない場合も、`ath` が証明の悪用を制限します。11.2節によれば、`ath` を含む証明は、まだ存在しないアクセストークンに対しては作れないため、事前に作った証明はそのアクセストークンの有効期限内でしか使えません。nonce を使わない構成では、DPoP 束縛のアクセストークンを長寿命にすべきではない(SHOULD NOT)とされています。

## 認可コードを DPoP の鍵に束縛する

RFC 9449 の10節は、認可リクエストに `dpop_jkt`(dpop_jkt パラメータ)を付けて、発行される認可コードを DPoP の鍵に束縛する方法を定めています。値は、クライアントの DPoP 公開鍵の JWK Thumbprint で、`cnf.jkt` と同じ値です。認可サーバは、トークンリクエストの DPoP 証明の鍵の Thumbprint が `dpop_jkt` と一致することを確認し、一致しなければ拒否しなければなりません(MUST)。

11.9節によれば、この束縛は、認可コードを捕捉した攻撃者が自分の鍵で DPoP 証明を作り、認可コードを交換する攻撃を防ぎます。PKCE([9章](/oidc/09-state-nonce-pkce/))で同じ攻撃を防げるのは `code_verifier` が漏洩していない場合に限られます。XSS で認可コードと `code_verifier` の両方が読み出される場合は、`dpop_jkt` がなければ攻撃者は自分の鍵に束縛したトークンを得られます。次章で扱う PAR と組み合わせる場合は、PAR のリクエストに `DPoP` ヘッダを付ける方法も使えます(10.1節)。

## DPoP が防がないもの

RFC 9449 の11節は、DPoP の限界も明記しています。

- クライアントの実行環境で攻撃者のコードが実行される場合(11.4節)、攻撃者は秘密鍵を取り出せなくても、クライアントがオンラインの間は正しい証明を作らせて使えます。DPoP は XSS の対策にはならず、XSS そのものを防ぐ必要があります
- DPoP 証明はメソッドと URI だけを対象にし、リクエストの本文やヘッダの完全性は保証しません(11.7節)。完全性は TLS に依存します
- `jti` の重複検査は、同じエンドポイントへのリクエストを複数のサーバで処理し、それらが状態を共有していない場合は、厳密には行えません(11.1節)

## mTLS による証明書束縛アクセストークン

送信者制約のもう1つの方式は、[13章](/oauth-deep/13-client-auth/)で見た mTLS を使うものです。クライアントがトークンエンドポイントへの接続で mTLS を使うと、認可サーバは発行するアクセストークンをそのクライアント証明書に結びつけられます。このように証明書に結びつけたアクセストークンを、**証明書束縛アクセストークン**(certificate-bound access token)と呼びます。

結びつけには、証明書の SHA-256 ハッシュを使います。JWT アクセストークンでは、`cnf` の中の `x5t#S256`(x5t#S256 確認メソッド)に入れます。

```json
{
  "iss": "https://server.example.com",
  "sub": "ty.webb@example.com",
  "exp": 1493726400,
  "nbf": 1493722800,
  "cnf": {
    "x5t#S256": "bwcK0esc3ACC3DB2Y5_lESsXE8o9ltc05O89jdN-dg2"
  }
}
```

リソースサーバは、TLS 接続でクライアントが提示した証明書のハッシュを計算し、`x5t#S256` と比べます。所有証明は TLS ハンドシェイクの CertificateVerify で済んでいるため、HTTP のメッセージに証明を追加する必要はありません。

## RFCを読む: RFC 8705 3節

> The protected resource MUST obtain, from its TLS implementation layer, the client certificate used for mutual TLS and MUST verify that the certificate matches the certificate associated with the access token. If they do not match, the resource access attempt MUST be rejected with an error, per [RFC6750], using an HTTP 401 status code and the "invalid_token" error code.

(RFC 8705 3節)

この節は、証明書束縛アクセストークンの使い方を定めています。リソースサーバは、TLS の実装の層から mTLS で使われたクライアント証明書を取得し(MUST)、その証明書がアクセストークンに関連づけられた証明書と一致することを確認しなければなりません(MUST)。一致しない場合は、401 と `invalid_token` で拒否しなければなりません(MUST)。同じ節は、リソースへのリクエストは、トークンエンドポイントで使ったのと同じ証明書による mTLS 接続で行わなければならない(MUST)とも定めています。

> The value of the "x5t#S256" member is a base64url-encoded [RFC4648] SHA-256 [SHS] hash (a.k.a., thumbprint, fingerprint, or digest) of the DER encoding [X690] of the X.509 certificate [RFC5280]. The base64url-encoded value MUST omit all trailing pad '=' characters and MUST NOT include any line breaks, whitespace, or other additional characters.

(RFC 8705 3.1節)

`x5t#S256` の値は、X.509 証明書の DER 符号化の SHA-256 ハッシュを Base64url で符号化したものです。末尾のパディング `=` は省かなければならず(MUST)、改行や空白などを含めてはなりません(MUST NOT)。計算の対象は証明書全体であり、公開鍵だけではありません。このため、同じ鍵で証明書を更新すると、ハッシュが変わり、古い証明書に束縛されたトークンは使えなくなります。

3節には、mTLS 特有の制約も書かれています。TLS では、サーバがクライアント証明書を要求するのはハンドシェイクの最中で、アクセストークンを含む HTTP のデータはハンドシェイクの後に届きます。リソースサーバは、トークンを見てから証明書を要求するかどうかを決めることができず、mTLS を使うかどうかを事前に設定しておく必要があります。同節は、mTLS を使うリソースサーバは、すべてのリソースで mTLS を要求するか、mTLS のリソースを別のホスト名とポートで提供することが多いだろうと述べています。

## DPoP と mTLS の比較

| 観点 | DPoP | mTLS 証明書束縛 |
| --- | --- | --- |
| 所有証明を行う層 | アプリケーション層(HTTP ヘッダの JWT) | TLS 層(ハンドシェイク) |
| 鍵の準備 | クライアントが自由に生成 | 証明書が必要(自己署名も可) |
| ブラウザ上のアプリ | WebCrypto で使える | クライアント証明書の扱いが難しく、多くの場合使えない |
| 証明の再送対策 | `jti`、`iat`、nonce で別途必要 | TLS の機能で行われる |
| TLS 終端のプロキシ | 外部から見た URI を `htu` の照合に使う必要がある | 証明書をアプリケーションに渡す仕組みが必要 |
| パブリッククライアント | 主な用途 | 使えるが証明書の配布が課題 |
| メッセージの完全性 | 対象外(TLS に依存) | TLS の範囲で保証 |

DPoP はアプリケーション層だけで完結するため、ブラウザ上のアプリやネイティブアプリに導入しやすい方式です。ただし、プロキシの構成の影響は受けます。4.3節の項目9は、`htu` を、その JWT を受け取った HTTP リクエストの URI と照合するよう求めています。TLS を終端してアプリケーションサーバへ中継するプロキシが、`https://api.example.com/orders` へのリクエストを `http://10.0.0.5:8080/orders` のような内部の URI に書き換えて転送する構成を考えます。この構成でアプリケーションが内部の URI で照合すると、正しい証明も拒否されます。アプリケーションは、プロキシがヘッダに付けた転送情報(元のホスト名やスキーム)から、クライアントが送った外部の URI を組み立て直して照合します。転送情報を信頼できるのは、プロキシ自身が付けた場合だけです。RFC 9700 4.13節は、TLS を終端するプロキシは外部から届いたリクエストを無害化し、アプリケーションサーバのセキュリティに関わるヘッダの真正性と完全性を確保しなければならない(MUST)と定めています。プロキシが外部から届いた転送ヘッダを除去しなければ、攻撃者は別の URI 向けに作った証明に合わせて転送ヘッダを偽り、`htu` の照合を通過させられます。DPoP では、`jti` の記録や nonce の管理をアプリケーションが行う必要があります。mTLS は再送対策とメッセージの完全性を TLS に任せられますが、証明書の運用と、TLS の終端からアプリケーションまでの証明書の受け渡しが必要です。サーバ間の通信で既に mTLS を運用している組織では mTLS が、ブラウザやモバイルのクライアントでは DPoP が選ばれることが多い、という使い分けになります。

FAPI 2.0 Security Profile は、認可サーバに送信者制約付きのアクセストークンだけを発行することを求め、その方式として mTLS か DPoP のどちらかを使うと定めています([25章](/security/25-high-security/))。

## まとめ

- Bearer トークンは持っていれば誰でも使えるため、漏洩した時点で悪用できます。RFC 9700 は送信者制約を推奨しています
- 送信者制約は、トークンを鍵に結びつけ、使うたびに所有証明を求めます。結びつけはトークンの `cnf` クレームで表します
- DPoP 証明は、`typ=dpop+jwt`、非対称の `alg`、公開鍵の `jwk` をヘッダに持ち、`jti`、`htm`、`htu`、`iat` と、トークンと一緒なら `ath` をペイロードに持つ JWT です。RFC 9449 4.3節の12項目で検証します
- RFC 9449 の例の証明は、`jwk` ヘッダの鍵で署名が検証でき、`ath` と `cnf.jkt` も再計算した値と一致しました
- リソースサーバは、RFC 9068 のアクセストークンの検証を行ったうえで DPoP 証明を検証します。実験では、盗んだトークンを攻撃者の鍵の証明と送ると、証明自体は正しくても `cnf.jkt` との照合で拒否されました。再送、メソッドの差し替え、Bearer への格下げ、事前生成、期限切れのアクセストークンも拒否されました
- DPoP 証明が結びつくのはメソッドと URI だけで、本文やクエリの完全性は保証しません。TLS を終端するプロキシを置く構成では、信頼できる転送情報から外部の URI を組み立て直して `htu` と照合します
- DPoP-Nonce は事前生成した証明を無効にし、`dpop_jkt` は認可コードを鍵に束縛します。DPoP は XSS そのものは防ぎません
- mTLS の証明書束縛アクセストークンは、証明書の SHA-256 を `cnf` の `x5t#S256` に入れ、TLS 層で所有を証明します

次章の主題は、トークンエンドポイントより前の段階にある認可リクエストです。ブラウザを経由する認可リクエストと認可レスポンスの改ざん・漏洩を、PAR、JAR、iss パラメータでどう防ぐかを扱います。
