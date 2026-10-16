# RustではじめるOIDC

Webアプリケーション開発者のための、RustでたどるOAuth 2.0とOpenID Connectの教科書。
[ox-content](https://ox-content.void.app/) 製のドキュメントサイトです。

- **基礎編12章 + 応用編16章 + 付録(用語集・RFCの読み方・RFC・仕様の索引)** の全28章構成
- OAuth 2.0 / OpenID Connect の RFC と OpenID 仕様の主要な箇所を、各章の「RFCを読む」「仕様を読む」の節で原文から読み解きます
- 本文中のRustコードの多くは、ブラウザ上から
  [Rust Playground](https://play.rust-lang.org/) で**その場で実行・編集**できます
- 実際にサーバを起動してログインを動かす OP・RP・リソースサーバの実装を `examples/` に置いています

## 読む / 開発する

```sh
bun install
bun run dev      # 開発サーバ (http://localhost:5173)
bun run build    # dist/ へ静的ビルド
bun run preview  # ビルド結果の確認
bun run deploy   # void で Cloudflare Workers へデプロイ

# mermaid図のビルドには headless Chromium が必要です。
# ブラウザが自動検出できない環境では実行ファイルを指定してください:
#   PUPPETEER_EXECUTABLE_PATH=/path/to/chromium bun run build
# mermaid図が1つでもレンダリングされないとビルドは失敗します
# (scripts/verify-build.mjs がビルド後に自動検証)
```

## 目次

**基礎編**: 前提知識ゼロから、OIDC のログインをメッセージ単位で説明し、Rust で実装できる状態を目指します

| Part | 章 |
| --- | --- |
| I Webの認証と認可 | 1 認証はどう動くか / 2 認可と委譲 / 3 認可コードフロー / 4 アクセストークンとスコープ / 5 暗号の基礎 |
| II OpenID Connectを知る | 6 OAuthからOIDCへ / 7 JWTとJOSE / 8 IDトークンを検証する / 9 state・nonce・PKCE |
| III RustでOIDCを動かす | 10 DiscoveryとJWKS / 11 RPを作る / 12 OPを作る |

**応用編**: 体系を完成させるための主題です。関心のある章から独立して読めます

| Part | 章 |
| --- | --- |
| IV OAuth 2.0の深層 | 13 クライアント認証 / 14 リソースサーバとトークンの検証 / 15 リフレッシュトークン / 16 DPoPとmTLS / 17 認可リクエストの保護 |
| V OpenID Connectの深層 | 18 クレームとユーザーの識別 / 19 フローの全体像 / 20 認可コード以外のグラント / 21 ログアウトとセッション管理 |
| VI セキュリティの深層 | 22 脅威と対策の体系 / 23 JWTへの攻撃と防御 / 24 ブラウザアプリとネイティブアプリ / 25 高セキュリティプロファイル |
| VII 運用と周辺技術 | 26 運用 / 27 周辺の標準 / 28 設計判断と知識の一覧 |

## リポジトリ構成

```
docs/                 # 本文 (Markdown)
  web-auth/           #   Part I   Webの認証と認可 (1-5章)
  oidc/               #   Part II  OpenID Connectを知る (6-9章)
  rust-impl/          #   Part III RustでOIDCを動かす (10-12章)
  oauth-deep/         #   Part IV  OAuth 2.0の深層 (13-17章)
  oidc-deep/          #   Part V   OpenID Connectの深層 (18-21章)
  security/           #   Part VI  セキュリティの深層 (22-25章)
  practice/           #   Part VII 運用と周辺技術 (26-28章)
  appendix/           #   用語集・RFCの読み方・RFC・仕様の索引・さらに学ぶには
src/snippets/         # 実行可能なRustコード (表示・実行・検証の単一ソース)
src/theme/            # カスタムCSS / RustPlay出力整形JS / UI日本語化JS
config/sidebar.mjs    # frontmatter からサイドバーを生成
scripts/preprocess-docs.mjs  # <RustPlay> を展開して .ox-docs/ へ出力
scripts/verify-build.mjs     # ビルド後検証 (mermaid / note / play / pager)
scripts/lint-style.mjs       # STYLE.md の機械検査
scripts/check-snippets.sh    # スニペットを Playground と同じクレート版で手元実行
scripts/play.sh              # スニペットを Playground API で実行
examples/             # ローカル実行用Cargoワークスペース (mini-op / rp / resource-server / flow-test)
```

## examples の実行

ネットワーク越しのフローはブラウザ内の Playground では動かないため、
ローカルで実行します。3つのサーバを別々の端末で起動してから flow-test を実行します。

```sh
cd examples
cargo run --release -p mini-op           # OP            http://127.0.0.1:9000
cargo run --release -p resource-server   # リソースサーバ http://127.0.0.1:4000
cargo run --release -p rp                # RP            http://127.0.0.1:3000
cargo run --release -p flow-test         # ログインから API 呼び出しまでを自動実行
```

ブラウザで http://127.0.0.1:3000/ を開くと、手動でログインを試せます
(テストユーザーは11章・12章を参照してください)。

## スニペットの検証

`src/snippets/` のコードは表示・ブラウザ実行・検証の単一ソースです。
使ってよい外部クレートは、Rust Playground に登録済みで `snippet-check/Cargo.toml` に
固定したものに限っています。

```sh
bash scripts/check-snippets.sh               # 全スニペットを手元で実行
bash scripts/check-snippets.sh ch09/pkce     # 1本だけ
bash scripts/play.sh src/snippets/ch09/pkce.rs   # Playground 上で実行
node scripts/lint-style.mjs                  # 文体の機械検査 (ビルド後は dist も検査)
```
