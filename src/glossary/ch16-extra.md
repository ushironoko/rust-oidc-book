## 攻撃と防御

- **Heartbleed**: 2014年に公表された OpenSSL の脆弱性(CVE-2014-0160)。サーバのメモリの内容を外部から読み出せたため、通信中のトークンや鍵が漏洩しうる例として挙げられる。[16章](/oauth-deep/16-sender-constrained/)

## 運用と周辺技術

- **UUID**(universally unique identifier): 128ビットの識別子。バージョン4は乱数から作られ、jti のような一意な値に使われる。[16章](/oauth-deep/16-sender-constrained/)
- **CRIME**/**BREACH**: TLS や HTTP の圧縮を利用して、暗号化された通信に含まれる秘密の値(Cookie やトークン)を少しずつ推定する攻撃。[16章](/oauth-deep/16-sender-constrained/)
- **Cloudbleed**: 2017年に公表された、CDN のパーサの誤りにより他の利用者の通信内容がレスポンスに混入した事故。トークンが予期しない経路で漏洩する例。[16章](/oauth-deep/16-sender-constrained/)
