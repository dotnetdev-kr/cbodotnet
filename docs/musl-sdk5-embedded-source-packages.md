# SDK5 original packages with per-member source identities

`musl_legacy5_embedded_source_inputs.py` covers 27 actual SDK5 layout
occurrences from 14 original NPK inputs. Its distinct SDK5 policy was derived
from the actual raw packages, literal managed metadata and seven acquired Git
source trees. It executes no SDK6 source policy.

The original nuspecs have no repository element. Their metadata remains
unchanged, and their retained container has a non-Git data role. Each allowed
member separately binds its full embedded Git commit, exact original package
member, byte count, SHA256, SHA512, assembly identity and managed IL metadata.
An unlisted package or member cannot use this as a missing-repository fallback.

System.Drawing's reference assembly names commit
`02b11eeee1fbc5f3ef43a1452fe07efd25fa1715`; its Unix and Windows runtime members
name `0f7f38c4fd323b26da10cce95f857f77f0f09b48`. Those identities remain
separate. All 27 products must use their exact declared package/member pair.
The other sources retain the literal embedded commits for CoreFX and
ASP.NET Common members.

`prepare(packages_by_sha, vstest_source, destination)` retains the complete
14 raw NPKs and the unchanged original upstream .NET Library EULA reference.
The latter comes from the exact SDK5 VSTest source's
`src/package/licenses/LICENSE_NET.txt`; it is the same original license text
referenced by CommandLineUtils' publisher license URL. This establishes no
VSTest consumption claim. Original publisher binary licensing remains separate
from each corresponding source tree's license and notices.

`validate(release, manifest, packages_by_sha)` requires an SDK5 source delivery
and verifies its archive/index fingerprints. It reconstructs all seven
original Git trees from complete baselines, rejects exclusions/deletions,
checks every archived file against its original Git blob and retains every
original source license. The separate original-package data tree must exactly
equal the authenticated raw packages and license reference. The original
VSTest license reference retains its exact full Git source root and blob.
The caller must perform the complete source packet verification and normal
producer/admission checks as well.

The actual packet passed pack, verify and the leaf: 115,679 files and all
27 products. Six focused tests and seven actual mutation controls passed:
changed original NPK bytes, changed managed member bytes, a foreign SDK layout,
a foreign source delivery, excluded original code source, fake Git provenance
for the binary package container and a replaced binary license reference.

Private receipts are in `.build/sdk5-embedded-source-contract-v1/`; its
complete source packet is retained at
`/var/tmp/cbodotnet-sdk5-embedded-source-contract-v1-20261109/release` in the
existing WSL registration. This imported-source evidence makes no local build,
byte-identical compilation or whole SDK qualification claim. Ten additional
SDK5 occurrences without embedded Git commits require their own source chains;
they are outside this closed policy.
