---
title: さらに学ぶには
description: 本書の先へ進むための仕様、書籍、ツール、Rustのクレートの案内。
sidebar:
  label: さらに学ぶには
---

本書で扱った各分野を深めるための資料を挙げます。仕様そのものは
[RFC・仕様の索引](/appendix/rfc-index/)に一覧があるため、ここでは仕様を
読み進めるための案内と、実装・検証に使う資料を中心に挙げます。

## 仕様の案内

- [**OAuth.net**](https://oauth.net/): OAuth WG の参加者が運営する案内サイトです。
  OAuth 2.0 の関連仕様の一覧と、OAuth 2.1 の現況がまとまっています
- [**OpenID Foundation の仕様一覧**](https://openid.net/developers/specs/):
  OpenID Connect、FAPI、OpenID Federation、OpenID4VC などの最新版と状態
  (Implementer's Draft / Final)を確認できます
- [**IETF Datatracker の OAuth WG**](https://datatracker.ietf.org/wg/oauth/documents/):
  策定中の Internet-Draft の一覧と、各ドラフトの版の履歴を確認できます。
  本書が扱った OAuth 2.1 や JWT BCP の改訂版の進捗はここで追えます
- [**IANA OAuth Parameters**](https://www.iana.org/assignments/oauth-parameters/) /
  [**JOSE**](https://www.iana.org/assignments/jose/) /
  [**JWT**](https://www.iana.org/assignments/jwt/): パラメータ名、エラーコード、
  `alg` 値、クレーム名の公式な一覧です([RFCの読み方](/appendix/reading-rfcs/))

## 書籍

- **OAuth 2 in Action**(Justin Richer、Antonio Sanso、Manning、2017):
  クライアント、認可サーバ、リソースサーバを順に実装しながら OAuth 2.0 を学ぶ書籍です。
  日本語訳は『OAuth徹底入門』(翔泳社)です。本書の Part I と Part III を
  別の言語の実装で復習するのに向いています。発行年が古いため、
  インプリシットグラントの扱いなどは RFC 9700 で更新されている点に注意してください
- **Real-World Cryptography**(David Wong、Manning、2021):
  ハッシュ、MAC、署名、鍵交換を実務の観点で説明する書籍です。
  [5章](/web-auth/05-crypto/)と[23章](/security/23-jwt-attacks/)の暗号の話題を深めるのに向いています

## セキュリティの資料

- [**RFC 9700 OAuth 2.0 Security Best Current Practice**](https://www.rfc-editor.org/rfc/rfc9700):
  [22章](/security/22-threats/)で読解した BCP です。新しい攻撃が報告されたときに
  何が推奨されているかを確認する最初の文書です
- [**OWASP Cheat Sheet Series**](https://cheatsheetseries.owasp.org/):
  OAuth 2.0、JWT、セッション管理、Cookie の実装上の注意点を短くまとめた資料です
- [**PortSwigger Web Security Academy**](https://portswigger.net/web-security):
  OAuth と JWT の脆弱性を、意図的に脆弱にしたサイトで試せる学習教材です。
  [23章](/security/23-jwt-attacks/)のアルゴリズム混同攻撃なども演習として用意されています

## 検証とテスト

- [**OpenID Foundation 適合性テスト**](https://openid.net/certification/):
  OP・RP の実装を OpenID Connect や FAPI 2.0 の仕様に照らして自動で検査する
  テストスイートです([25章](/security/25-high-security/))。
  ソースコードが公開されており、手元で実行することもできます
- **JWT のデコード**: JWT の中身を確認するツールは多数ありますが、
  本番のトークンを外部のWebサイトに貼り付けないでください。
  トークンはそれ自体が認可の証拠であり、貼り付けた時点で第三者に渡ることになります。
  本書の [6章](/oidc/06-oauth-to-oidc/) のスニペットのように、手元でデコードしてください

## Rustのクレート

本書の `examples/` と、実務で検討する主なクレートです。
版は本書の執筆時点(2026年10月)のものです。

| クレート | 用途 | 本書での使用 |
| --- | --- | --- |
| [openidconnect](https://crates.io/crates/openidconnect) | OIDC の RP(クライアント)の実装 | 11章の RP |
| [oauth2](https://crates.io/crates/oauth2) | OAuth 2.0 のクライアントの実装。openidconnect の内部でも使われている | 11章で間接的に使用 |
| [ring](https://crates.io/crates/ring) | ハッシュ、HMAC、ECDSA、RSA、Ed25519 | スニペット全般、12章の OP |
| [jsonwebtoken](https://crates.io/crates/jsonwebtoken) | JWT の生成と検証 | 不使用(仕組みを示すため、本書では JWS を手で組み立てている) |
| [josekit](https://crates.io/crates/josekit) | JWS、JWE、JWK を網羅した JOSE の実装 | 不使用 |
| [axum](https://crates.io/crates/axum) | Web アプリケーションフレームワーク | 11章・12章・14章のサーバ |
| [tower-sessions](https://crates.io/crates/tower-sessions) | axum 向けのセッション管理 | 11章の RP |

実務でトークンの検証を自作する必要はほとんどありません。本書がスニペットで
検証の手順を手で書いているのは、ライブラリが内部で何を確認しているかを理解し、
ライブラリの設定(許可する `alg`、`aud`、時計のずれの許容幅など)を
正しく選べるようにするためです。
