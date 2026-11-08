# SDK5 original Json.NET publisher sources

`musl_legacy5_newtonsoft_source_inputs.py` covers three SDK5 Json.NET
occurrences: the 9.0.1 netstandard1.0 and net45 members, and the 11.0.1
netstandard2.0 member. Each original NPK DLL is literally equal in byte count,
SHA256 and SHA512 to the matching binary in the publisher's original
`Json90r1.zip` or `Json110r1.zip`. Those original release ZIPs also contain the
complete publisher C# source and build inputs.

The closed SDK5 policy retains both original NPKs, both complete original ZIPs,
all 1,950 publisher source files and the complete pristine Git trees at
`e5ac9a8473dfdefb8fe2cddae433a9aaa94a5b37` (9.0.1) and
`d50b912e9948472e122cfaf24ffeebbf77032806` (11.0.1). The existing unrelated
Newtonsoft source commit `4ab34b0461fb595805d092a46a58f35f66c84d6a` is not used
as 11.0.1 source. Original publisher and source license bytes remain retained.

All functional source matches the original Git source literally or by the
observed publisher CRLF representation. All 216 and 227 production source and
project inputs are present. Five publisher-generated build metadata files are
kept separately from pristine Git: three 9.0.1 AssemblyInfo version outputs,
its project.json version/signing settings, and the 11.0.1 csproj file version
and prerelease suffix. The exact original upstream build recipes remain in
the Git trees. The validator checks these exact changes, including the
original PowerShell output's single final newline; changes to C# code,
frameworks, compiler defines or other project settings reject.

The 2018 publisher ZIP uses original backslash member names. The validator
reads its pinned literal names without extracting that ZIP. Only the closed
source comparison map supplies portable paths for the retained source tree.
Original ZIP bytes and member spelling are preserved.

`prepare(package_paths, distribution_paths, source_paths, destination)` returns
the separate non-Git original-publisher-source tree. `validate(release,
manifest, package_paths, distribution_paths)` checks the SDK5 source delivery,
archive/index fingerprints, both complete original Git trees and every
original package, distribution and source byte. The caller must also perform
the complete source packet verification and normal admission checks.

Returned products include their full SDK5 layout path, original package
SHA256/member, publisher binary member, source data root and separate Git
source root/commit. Publisher source is not misrepresented as pristine Git.
`package_origin` classifies only the two pinned original NPK containers.
No local build, byte-identical compilation or whole SDK qualification is
claimed; no publisher source or product is rewritten.

The actual complete source packet passed pack, verify and this leaf:
4,845 files, all three products, seven focused tests and seven actual mutation
controls. Receipts are in `.build/sdk5-newtonsoft-source-contract-v3/`; the
complete packet is retained at
`/var/tmp/cbodotnet-sdk5-newtonsoft-source-contract-v3-20261109/release`.
The earlier strict final-newline and legacy member-spelling failures, their
used source versions and all original inputs remain preserved.
