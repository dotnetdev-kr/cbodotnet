# Public signature fixture

`public-signed.json` and `.asc` are exact public, already released metadata:
[SDK10.0.403 branded archive revision2](https://github.com/dotnetdev-kr/cbodotnet/releases/tag/distribution-archive-sdk-10.0.403-r2).
They retain the original project signature. No private signing material or
generated test credential is present. Tests verify the independent embedded
project key, a long temporary home path and rejection of modified signed bytes.
This sibling distribution manifest is not an installer catalog and cannot pass
the installer's catalog kind/schema/source admission checks.

`catalog-v1.json` and `.asc` are the byte-exact signed installer catalog from
[catalog release 41952285282](https://github.com/dotnetdev-kr/cbodotnet/releases/tag/cbodotnetup-catalog-41952285282).
The catalog SHA-256 is
`506689fc4e5b89a395ddd7b21813723686b387697c002cd5d803d737f226a4c9`.
Tests validate its original schema-1 SDK 10 r2 entries at its issuance time and
verify its real signature, independently of the current online catalog expiry.
It proves that the schema-2 client still reads legacy signed admissions without
adding fields to the historical SDK or receipt shape.
