# Explicit SDK5 tooling feed with local AppInsights

`musl-legacy5-tooling.py` keeps its original24-package mode when
`--appinsights-package` is absent. Its package versions, cache-prime restore,
three original product commands and default result fields retain their
existing behavior.

The optional future mode takes one actual package path:

    --appinsights-package /work/inputs/bootstrap-feed/microsoft.applicationinsights.2.0.0-cbodotnet.1.nupkg

The path must be the ordinary canonical file in the supplied feed. The worker
uses the committed App consumption contract's ID, version, package name,
controlled property and closed25-package matrix. IDs remain unique under
NuGet's case-insensitive identity rule. Duplicate IDs, aliases of the App
filename, wrong versions, missing packages, special files and symlinks reject.
The supplied App image is parsed and fingerprinted as the same raw NPK bytes;
its full size/SHA256/SHA512 must remain unchanged through final validation.

The real cache-prime project downloads all25 exact versions. The existing
cache verifier checks every original raw NPK, source metadata and SHA512
content-hash record before and after product construction. No cache metadata
is fabricated by the worker.

Only the three original product restore/build/redist commands receive
`/p:MicrosoftApplicationInsightsPackageVersion=2.0.0-cbodotnet.1`, exactly once
per command. Bootstrap selection and cache priming receive no such override.
Original SDK version files and source TFMs are not changed. The final new-mode
report must pass the existing `validate_tooling` contract against the actual
provided package fingerprints before it is written.

The distinct App feed role and report explicitly require external strong
supplier proof and do not claim that proof has been validated by this worker.
An NPK, its metadata or a descriptor alone cannot establish genuine App source
compilation. The future normal P5 caller must first validate the actual strong
normal App supplier and the separately reviewed finite private-input/export
boundary. Reader/Csc, cache/member consumption, Copy edges, toolset/final
Crossgen binding, complete source/licensing and normal admission remain
independent required gates. Existing private workers and retained packets are
unchanged by this optional interface.

Focused tests use synthetic package/cache/process records only. They do not
produce a genuine25-package SDK consumer or execute restore, MSBuild, a
compiler, Reader, CLR or container. Qualification and source-admission flags
remain false in both modes.
