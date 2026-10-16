## トークンとJOSE

- **StringOrURI**: RFC 7519 が定める値の型。任意の文字列で、コロンを含む場合は URI でなければならない。iss・sub・aud の値の型。[7章](/oidc/07-jwt-jose/)
- **Nested JWT**: JWS で署名した JWT を、さらに JWE で暗号化するなど、JWT を入れ子にした形式。[7章](/oidc/07-jwt-jose/)
- **CRLF**: 改行を表す2文字の並び(復帰 CR と改行 LF)。JSON の改行や空白の違いは署名入力のバイト列を変えるため、JWS では意味の同じ JSON でも署名が一致しない。[7章](/oidc/07-jwt-jose/)

## 暗号

- **Ed448**: 448ビットの楕円曲線 Edwards448 を使う EdDSA 署名。Ed25519 より大きな安全性の余裕を持つ。[7章](/oidc/07-jwt-jose/)
