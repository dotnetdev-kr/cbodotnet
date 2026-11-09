# Stronger App5 retained validation

`musl_legacy5_appinsights_validator.py` is the reviewed post-build validation
entry for the genuine local AppInsights package. Its `verify_execution()`,
`validate()` and `package_local()` functions add checks to the immutable v5
worker's checks. The original worker, API decoder, policy, tests and historical
document remain unchanged. Their old entry points alone do not provide this
stronger contract.

The validator authenticates all three actually executed worker/input modules
with complete byte count, SHA-256 and SHA-512 before importing the original
worker. It preserves the original worker/source snapshot binding. Its own
fingerprint is returned separately as post-build validator provenance; it does
not claim to have executed during the v5 build.

The App command must contain exactly the arguments prescribed by the original
PCL adjunct and its recorded Csc task. Defines, language, deterministic mode,
signing, debug, optimization, target, platform, warning, configuration and output
options are closed. References and source arguments also have exact
multiplicities. Extra switches, alternative override forms, and duplicate
switches reject. The original repeated AssemblyInfo source argument is retained
explicitly. The existing controlled PATH and exact ordinary bootstrap host
binding still applies to any bare logged `dotnet` command.

The two generated source names are fixed:

- `/output/obj/AssemblyInfo.g.cs`
- `/output/obj/.NETPortable,Version=v4.5,Profile=Profile7.AssemblyAttributes.cs`

Their entire bytes must equal the known SDK5 generator formatting with assembly
version, file version, target framework and display name derived from the closed
policy. Extra implementation code, even when the retained source fingerprint
is updated, rejects. Unknown generated C# files also reject. All original 112 C#
files and all 65 exact Profile7 references remain subject to the original checks.

The unchanged actual v5 output passes the stronger execution/API/package
roundtrip. The local NPK remains 102,910 bytes, SHA-256
`2dc9113825c520275240606cb29540276e4934bf04d5572f05d3f18aa14b8cb6`.
Strict public/protected API and all 21 contract references remain equal. Thirty
actual retained-record controls reject, including the reviewer's three command
counterexamples and appended internal C# code. Five additional focused tests
pass alongside the original eleven tests.

These checks execute neither Csc nor the binary Reader. The actual Reader calls
remain the original v5 worker's two recorded executions. Total genuine App Csc
calls remain two, v4 and v5. Original v2/v3 evaluation failures, v4 API failure,
v5 output and source packet, and the stopped first control driver are preserved.
The stronger validator and its checks are carried in a separate supplemental
source packet, without editing any original execution record.

This remains isolated component evidence. No SDK dependency version has been
replaced, no SDK consumer has yet been observed consuming this local NPK, and
qualification/source-admission flags remain false. A5 integration must call the
stronger validator and independently bind the later real SDK package/member
consumption and all other admission guards.
