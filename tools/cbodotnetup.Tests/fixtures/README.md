# Public signature fixture

`public-signed.json` and `.asc` are exact public, already released metadata:
[SDK10.0.403 branded archive revision2](https://github.com/dotnetdev-kr/cbodotnet/releases/tag/distribution-archive-sdk-10.0.403-r2).
They retain the original project signature. No private signing material or
generated test credential is present. Tests verify the independent embedded
project key, a long temporary home path and rejection of modified signed bytes.
This sibling distribution manifest is not an installer catalog and cannot pass
the installer's catalog kind/schema/source admission checks.
