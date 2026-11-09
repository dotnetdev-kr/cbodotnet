# SDK5 source-disposition integration

`musl_legacy5_source_dispositions.py` is the imported-source portion of A5.
It invokes the eight distinct SDK5 source validators for framework assets,
MSBuild localization, embedded-source packages, Json.NET, Cecil, Unsafe, CSS
and original NuGet translations. Canonical source package and publisher
distribution inputs have closed roles and complete byte fingerprints.
The separate derived-compiler validator binds the actual mutable Roslyn input
container; a diagnostic container hash cannot stand in for that contract.

The module reads actual PE inputs throughout the entire SDK archive, including
shared frameworks and files without a DLL extension. Pre-Crossgen inputs are
read from the actual bound toolset package. A source disposition requires exact
length, SHA-256 and SHA-512 agreement. Package suppliers must retain their raw
managed-package kind and exact package/member relationship. CSS's observed
certificate-appended image and Json.NET's publisher source remain distinct
from canonical package members and pristine Git metadata.

Raw emitter unknowns are preserved verbatim. The derived report references
their original positions and records independent source correspondence and
actual supplier binding separately. A canonical framework correspondence does
not automatically authorize a different publisher container. Missing framework
alias, literal/reference/template, Arcade and AppInsights inputs remain open.

This module does not provide a normal admission route. Full fixed artifact
roles and framework pins, original compiler/source/installer/native/Reader
guards, complete native bootstrap source closure, all remaining source inputs,
consumer checks and normal producer boundaries still need integration. The
producer's collection and seal methods stay closed until those conditions are
implemented and independently reviewed against a complete fresh producer.
