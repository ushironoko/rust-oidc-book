import re,glob
import os
os.chdir(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..'))
P={}
for f in glob.glob('docs/*/[0-9]*.md'):
    n=int(re.search(r'/(\d+)-',f).group(1)); P[n]='/'+f[5:-3]+'/'
def L(s):
    # "3*,9,12" → 読解章を太字に
    out=[]
    for t in s.split(','):
        t=t.strip(); r=t.endswith('*'); n=int(t.rstrip('*'))
        out.append(f'[**{n}章**]({P[n]})' if r else f'[{n}章]({P[n]})')
    return '、'.join(out)
rows=lambda items: '\n'.join(f'| {a} | {b} | {c} | {L(d)} |' for a,b,c,d in items)
H='| 文書 | 発行 | 内容 | 扱う章 |\n| --- | --- | --- | --- |\n'
sec=[]
sec.append(('HTTPと標準化の基礎',[
('RFC 2119 / RFC 8174 (BCP 14)','1997-03 / 2017-05','要請語 MUST・SHOULD・MAY の意味。大文字のときだけ要請語として読む','1'),
('RFC 9110 HTTP Semantics','2022-06','HTTP の意味論。ステートレス性、認証の枠組み、ステータスコード、リダイレクト','1,4,22'),
('RFC 7617 Basic認証','2015-09','user-id とパスワードをコロンで連結し Base64 で送る認証スキーム。charset 引数','1*,13'),
('RFC 6265 Cookie','2011-04','Set-Cookie と Cookie ヘッダ、Secure・HttpOnly 属性。SameSite は改訂版ドラフトで定義','1*,24'),
]))
sec.append(('OAuth 2.0 の中核',[
('RFC 6749 OAuth 2.0 Authorization Framework','2012-10','ロール、認可コードなど4つのグラント、エンドポイント、トークンレスポンス、エラー、セキュリティ上の考慮事項','2*,3*,4*,5*,6*,9*,13*,15*,20*'),
('RFC 6750 Bearer Token Usage','2012-10','アクセストークンを Authorization: Bearer で送る方法と、WWW-Authenticate のエラー','4*,14,16'),
('RFC 6819 Threat Model and Security Considerations','2013-01','OAuth 2.0 の脅威モデルと対策の分析','22*'),
('RFC 9700 OAuth 2.0 Security BCP (BCP 240)','2025-01','RFC 6749/6750/6819 を更新する現在のセキュリティ要件。PKCE、完全一致、インプリシットと ROPC の非推奨・禁止','9*,12*,15*,19*,22*,25'),
]))
sec.append(('JOSE とトークンの形式',[
('RFC 7515 JWS','2015-05','JSON で署名・MAC を表すデータ構造とコンパクトシリアライゼーション','5*,7*,23'),
('RFC 7516 JWE','2015-05','JSON で暗号化を表すデータ構造','7'),
('RFC 7517 JWK','2015-05','暗号鍵を JSON で表す形式と JWK Set','7*,10'),
('RFC 7518 JWA','2015-05','JWS・JWE・JWK で使うアルゴリズム名(HS256、RS256、ES256 など)','5*,7*,23'),
('RFC 7519 JWT','2015-05','クレームの集合を JWS/JWE で表す形式と登録済みクレーム','7*,8,23'),
('RFC 7638 JWK Thumbprint','2015-09','JWK の必須メンバーから鍵の識別子を計算する方法','7*,10,16'),
('RFC 8725 JWT BCP','2020-02','JWT の安全な使い方。alg の検証、明示的型付け、issuer と audience の検証','23*,26*'),
('RFC 9068 JWT Profile for Access Tokens','2021-10','アクセストークンを JWT で発行するときの形式(typ=at+jwt)と検証','14*'),
('RFC 9864 Fully-Specified Algorithms','2025-10','曲線やハッシュまで1つに決まるアルゴリズム識別子。Ed25519 など','23,25'),
('RFC 9901 SD-JWT','2025-11','JWT のクレームを選択的に開示する形式。Disclosure と _sd ダイジェスト','27*'),
]))
sec.append(('OpenID Connect の仕様(OpenID Foundation)',[
('OpenID Connect Core 1.0 (errata set 2)','2023-12','ID トークン、認証リクエスト、ID トークンの検証、UserInfo、クレーム、pairwise 識別子','6*,8*,9*,10*,11*,12*,13*,15*,18*,19*,26*'),
('OpenID Connect Discovery 1.0','2023-12','OP のメタデータを well-known URI で公開する方法と issuer の検証','10*'),
('OpenID Connect RP-Initiated Logout 1.0','2022-09','RP が OP にログアウトを依頼する方法','21*'),
('OpenID Connect Front-Channel Logout 1.0','2022-09','OP が iframe で RP にログアウトを伝える方法','21*'),
('OpenID Connect Back-Channel Logout 1.0 (errata set 1)','2023-12','OP がログアウトトークンを RP に直接送る方法','21*'),
('OpenID Connect Session Management 1.0','2022-09','iframe と postMessage で OP のセッションの変化を検出する方法','21*'),
('OAuth 2.0 Multiple Response Type Encoding Practices','2014-02','response_type の組み合わせと response_mode','19*'),
('OAuth 2.0 Form Post Response Mode','2015-04','認可レスポンスを自動送信のフォームで POST する応答モード','19*'),
('OpenID Connect CIBA Core 1.0','2021-09','利用者の別の端末で認証を行うバックチャネルのフロー','20*'),
('FAPI 2.0 Security Profile / Attacker Model','2025-02','高いセキュリティを要求する API のためのプロファイルと、その前提の攻撃者モデル','25*'),
('FAPI 2.0 Message Signing','2025-09','リクエストとレスポンスの署名による否認防止','25*'),
('OpenID Federation 1.0 / 1.1','2026-02 / 2026-05','トラストチェーンでエンティティ間の信頼を確立する仕組み','27*'),
]))
sec.append(('OAuth 2.0 の拡張',[
('RFC 7009 Token Revocation','2013-08','クライアントがトークンの失効を依頼するエンドポイント','14*,21'),
('RFC 7521 / RFC 7523 Assertion Framework / JWT Profile','2015-05','JWT をクライアント認証(private_key_jwt)と認可グラントに使う方法','13*,20*'),
('RFC 7591 Dynamic Client Registration','2015-07','クライアントを API で登録する方法','13,27'),
('RFC 7636 PKCE','2015-09','code_verifier と code_challenge で認可コードの横取りを防ぐ方法','9*,11,12'),
('RFC 7662 Token Introspection','2015-10','リソースサーバがトークンの状態を認可サーバに問い合わせる方法','14*'),
('RFC 7800 Proof-of-Possession Key Semantics for JWTs','2016-04','JWT に cnf クレームで鍵を結びつける方法','16'),
('RFC 8176 Authentication Method Reference Values','2017-06','amr クレームの値(pwd、otp、hwk など)','18'),
('RFC 8414 Authorization Server Metadata','2018-06','認可サーバのメタデータの形式と取得方法','10*'),
('RFC 8628 Device Authorization Grant','2019-08','入力手段の限られた端末のためのグラント','20*'),
('RFC 8693 Token Exchange','2020-01','トークンを別のトークンに交換する方法。委任となりすまし','20*'),
('RFC 8705 Mutual-TLS','2020-02','mTLS によるクライアント認証と証明書束縛トークン','13*,16*'),
('RFC 8707 Resource Indicators','2020-02','resource パラメータでトークンの宛先を指定する方法','14*,27'),
('RFC 9101 JAR','2021-08','認可リクエストを署名付き JWT で送る方法','17*'),
('RFC 9126 PAR','2021-09','認可リクエストをバックチャネルで事前に送る方法','17*,25'),
('RFC 9207 Issuer Identification','2022-03','認可レスポンスに iss を付けてミックスアップ攻撃を防ぐ方法','17*'),
('RFC 9396 Rich Authorization Requests','2023-05','authorization_details で細かい権限を要求する方法','17*'),
('RFC 9449 DPoP','2023-09','アプリケーション層の所有証明でトークンを送信者に束縛する方法','16*'),
('RFC 9470 Step Up Authentication Challenge','2023-09','リソースサーバがより強い認証を要求する方法','18*'),
('RFC 9701 JWT Response for Token Introspection','2025-01','イントロスペクションの応答を署名付き JWT で返す方法','14'),
('RFC 9728 Protected Resource Metadata','2025-04','リソースサーバのメタデータと、対応する認可サーバの発見','14,27'),
]))
sec.append(('アプリケーションの種類ごとの BCP',[
('RFC 8252 OAuth 2.0 for Native Apps (BCP 212)','2017-10','ネイティブアプリは外部ユーザーエージェントを使う。ループバックと claimed https','24*'),
('RFC 10017 OAuth 2.0 for Browser-Based Applications (BCP 212)','2026-08','ブラウザアプリの脅威と3つのアーキテクチャ(BFF、トークン仲介バックエンド、ブラウザ内クライアント)','11*,24*'),
('RFC 10027 Cross-Device Flows (BCP)','2026-08','別の端末で認可するフローの脅威と対策','20*'),
]))
drafts=[
('draft-ietf-oauth-v2-1-16 OAuth 2.1','2026-09','OAuth 2.0 と後続の BCP を1つの文書に統合する改訂版','25*'),
('draft-ietf-oauth-rfc8725bis-10 JWT BCP 改訂','2026-08','RFC 8725 の改訂版。kid・jku の扱いや明示的型付けを強化','23*'),
('draft-ietf-oauth-client-id-metadata-document-02','2026-07','URL を client_id にしてメタデータを公開する登録方法','13,27'),
('draft-ietf-oauth-sd-jwt-vc','2026','SD-JWT を検証可能クレデンシャルに使う形式','27'),
]
out=['---','title: RFC・仕様の索引','description: 本書で扱ったRFCとOpenID仕様の一覧。要約と、本文で読解している章へのリンクをまとめる。','sidebar:','  label: RFC・仕様の索引','---','',
'本書で扱った RFC と OpenID 仕様の一覧です。「扱う章」のうち**太字**の章は、',
'その文書を「RFCを読む」「仕様を読む」の節で原文から読解している章です。',
'RFC の種別や要請語の読み方は[RFCの読み方](/appendix/reading-rfcs/)にまとめています。',
'発行年月と現況は2026年10月16日に確認したものです。','']
for t,items in sec:
    out+= [f'## {t}','',H+rows(items),'']
out+=['## 策定中の文書(Internet-Draft)','',
'次の文書は策定中で、まだRFCになっていません。版が変わると内容も変わる可能性があります。表の版は2026年10月16日時点の最新版です。','',H+rows(drafts),'',
'## 文書どうしの関係','',
'主要な文書の更新関係と依存関係を図にまとめます。矢印は「左の文書が右の文書を前提にする、または更新する」ことを表します。','',
'```mermaid','flowchart LR','    r6749["RFC 6749<br/>OAuth 2.0"] --> r6750["RFC 6750<br/>Bearer"]','    r9700["RFC 9700<br/>Security BCP"] -->|更新| r6749','    r9700 -->|更新| r6750','    r7636["RFC 7636<br/>PKCE"] --> r6749','    core["OIDC Core 1.0"] --> r6749','    core --> r7519["RFC 7519<br/>JWT"]','    r7519 --> r7515["RFC 7515<br/>JWS"]','    r7515 --> r7518["RFC 7518<br/>JWA"]','    r7515 --> r7517["RFC 7517<br/>JWK"]','    disc["OIDC Discovery"] --> core','    r8414["RFC 8414<br/>AS Metadata"] --> r6749','    v21["OAuth 2.1<br/>(draft-16)"] -.->|統合| r6749','    v21 -.->|統合| r9700','    v21 -.->|統合| r7636','    fapi["FAPI 2.0"] --> r9700','    fapi --> par["RFC 9126<br/>PAR"]','    fapi --> dpop["RFC 9449<br/>DPoP"]','```','',
'この図の中心は RFC 6749 です。OpenID Connect Core 1.0 は RFC 6749 と JWT を前提にした拡張であり、RFC 9700 は RFC 6749 の要件を更新しています。OAuth 2.1 はこれらを1つの文書に統合するドラフトで、FAPI 2.0 は RFC 9700 の推奨に加えて PAR や送信者制約を必須にしたプロファイルです。','']
open('docs/appendix/rfc-index.md','w').write('\n'.join(out))
