`sqlite3mc-aes128.enc` contains generated test data, not account data.

It was encrypted with the independent, MIT-licensed SQLite3 Multiple Ciphers
2.5.1 C implementation (SQLite 3.53.4), using its `EncryptPageAES128Cipher`
function. The known test cipher key is the sixteen bytes `00` through `0f`.
The original SQLite database has a `sample(id INTEGER PRIMARY KEY, body TEXT)`
table: row 1 contains `中文、换行测试 ✅`; row 2 contains 9000 `x` characters.
Page size is 4096 and the database spans four pages.

The small [generator](generate.c) is included for reproduction. It uses the
upstream amalgamation directly; the amalgamation is not vendored here.

Upstream source:
https://github.com/utelle/SQLite3MultipleCiphers/releases/tag/v2.5.1

This verifies cipher interoperability and full SQLite integrity. It does not
prove key capture, a WeCom schema, account login, message access, or sending.
