# SDK5 original MSBuild localization resources

`musl_legacy5_msbuild_resources.py` validates the original
`Microsoft.Build.Localization/16.9.0-preview-21167-03` package as imported
resource data. It keeps the publisher's bytes and version and makes no local
compilation claim. The distinct SDK5 policy pins the actual raw package's
byte count, SHA256 and SHA512, its 56 satellite members, and 93 exact source
files at MSBuild commit `5e4b48a27efce55a613664b58d353ab4c8d1f6c1`.
No SDK6 source policy executes in this contract.

All 56 assemblies are resource-only PE files: one module type, no methods,
fields, exported types or linked files, no managed/native entry point or
ReadyToRun header, and only the standard optional `mscoree.dll` import.
Their embedded source commit, assembly ABI, public key, culture and package
layout must match. The package contains four assemblies in 14 cultures,
including English. The original Chinese XLF language attributes use
`zh-HANS` and `zh-HANT`; the policy preserves those exact source spellings.

The 126 resource streams contain 21,098 intrinsic strings. Every key set must
equal both its original XLF and neutral RESX key sets. Every XLF source value
equals its neutral RESX value exactly. Translated values equal the original
XLF targets, with only the observed CRLF/LF difference permitted: 20,384 exact
values and 714 CRLF-only values. XML entities, duplicate keys, missing or
ambiguous targets, foreign cultures and other text changes reject.

`prepare(package, source, destination)` checks the original Git checkout and
all 84 XLF files, six RESX files, original localization nuspec, MIT license and
third-party notices against their exact Git blobs. It retains the raw NPK,
original package nuspec, all satellite bytes, decoded readable resources and
an explicit imported-data origin record in a separate tree root. That tree
does not claim Git provenance.

`validate(release, manifest, package)` requires an SDK5 source delivery, the
complete original MSBuild Git root and the separate data root. It binds the
source archive and index fingerprints, checks the closed data inventory and
all 93 selected original source bytes and baseline Git blob IDs, then decodes
and compares the resources again. The caller must first perform the full
source packet verification and its normal producer/source admission checks.
The returned products cover precisely the 56 unchanged SDK5 localization
paths; qualification and source admission remain false.

The actual complete source packet passed pack, verify and this leaf:
3,247 files, 56 products. Six focused tests and seven actual mutation controls
passed, including changed raw NPK bytes, a foreign SDK source delivery, fake
Git provenance for the data tree, excluded upstream source, a changed source
index, changed translated text and changed neutral RESX source text.

Private results and controls are in
`.build/sdk5-localization-source-contract-v2/`; the retained complete packet
is at `/var/tmp/cbodotnet-sdk5-localization-source-contract-v2-20261109/release`
in the existing WSL registration. The earlier strict XLF spelling failure and
private control-targeting correction remain documented. These receipts prove
this resource leaf; they do not qualify a complete SDK5 release.
