## HTTPとWebの基礎

- **TCP**(Transmission Control Protocol): HTTP/1.1 と HTTP/2 が下位で使う、順序と到達を保証するバイト列の通信の取り決め。[1章](/web-auth/01-http-auth/)
- **HTTP/2**/**HTTP/3**: HTTP の新しい版。メッセージの送り方(バイナリのフレーム、QUIC の利用)が異なるが、ヘッダとステータスコードの意味は HTTP/1.1 と同じ。[1章](/web-auth/01-http-auth/)
- **Unicode**: 世界の文字に番号(符号位置)を割り当てた文字集合。[1章](/web-auth/01-http-auth/)
- **UTF-8**: Unicode の文字を1〜4バイトの列で表す文字符号化方式。ASCII の文字は1バイトのまま表せる。[1章](/web-auth/01-http-auth/)
- **NFC**(Unicode Normalization Form C): 同じ見た目の文字の異なる表現(合成済み文字と結合文字の並び)を、合成済みの形にそろえる Unicode の正規化形式。[1章](/web-auth/01-http-auth/)

## 標準化

- **Rust Playground**: Rust のコードをブラウザから送って、サーバ上でコンパイル・実行できる公式のサービス。本書の RustPlay の実行先。[1章](/web-auth/01-http-auth/)
