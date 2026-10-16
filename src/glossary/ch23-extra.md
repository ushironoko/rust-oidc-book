## 暗号

- **PEM**: DER で符号化した鍵や証明書を Base64 にし、-----BEGIN ...----- の行で囲んだテキスト形式。[23章](/security/23-jwt-attacks/)
- **ECDH-ES**: 楕円曲線 Diffie-Hellman で使い捨ての鍵を合意し、そこから暗号化の鍵を導く JWE の鍵管理方式。[23章](/security/23-jwt-attacks/)

## 攻撃と防御

- **LDAP インジェクション**(LDAP injection): 外部から受け取った値を LDAP の検索式に組み込むことで、意図しない検索を実行させる攻撃。kid の値をそのまま検索に使う実装で起こりうる。[23章](/security/23-jwt-attacks/)
- **SQL インジェクション**(SQL injection): 外部から受け取った値を SQL 文に組み込むことで、意図しない問い合わせを実行させる攻撃。kid の値をそのまま鍵の検索に使う実装で起こりうる。[23章](/security/23-jwt-attacks/)
