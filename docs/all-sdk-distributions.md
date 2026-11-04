# All SDK distribution rollout

The reviewed source pins cover SDK 10.0.403, 9.0.123, 8.0.133, 7.0.120,
6.0.136, 5.0.214, 3.1.426 and 3.0.103. Source admission permits candidate
builds and native qualification. It does not grant package or container support,
authorize publication, or replace complete signed installation reports.

The original `sdk-*` releases are experimental, unbranded test releases and are
not recommended for installation or direct use. Their titles and bodies carry
this warning. Their tags, original assets, hashes and release flags are retained
because they are immutable canonical inputs for downstream distributions.

The additional SDK preparation matrix records the earlier planning snapshot.
Its zero execution and qualification counts remain historical observations.
Live availability must come from signed distribution receipts and public
installation verification, rather than those planning rows.

All native packages use `/opt/cbodotnet/<major.minor>` and a versioned launcher.
The common `cbodotnet` selector chooses the highest installed SDK series. OCI
images additionally provide `dotnet`. Branded relocatable archives retain the
original SDK under `payload/` and add wrappers outside that payload.

SDK 5 and Core 3 candidates require an independently recorded Rocky Linux 9
compatibility provider outside the SDK payload. Provider source signatures,
checksums, licenses, ABI bounds and native TLS/crypto/globalization checks must
pass before publication. No change to the original SDK bytes is authorized.

AUR publication remains deferred in issue [#10](https://github.com/dotnetdev-kr/cbodotnet/issues/10).
Local recipe generation and native build validation are included in the rollout.
