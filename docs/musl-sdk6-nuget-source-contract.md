# SDK6 original NuGet library construction

The SDK6 worker builds NuGet commit
`451e9bc27184dc49d04e975122c9e7189d525872` through the original
`build/build.proj` RestoreXPLAT, BuildXPLAT and PackXPLAT graph. It selects the
original full library matrix explicitly: net40, net45, net472, net6.0 and
netstandard2.0. Nineteen packages retain their genuine `6.0.6-rc.4` identity.
The independent component evidence gate binds all 72 managed package members
to actual successful source-bearing compiler tasks.

The original source-build Pack target documents that it cannot use ILMerge.
Three conditions now honor that existing source-build rule when the complete
library matrix is selected. Only the Pack input selection changes: no C# code,
project framework or package version is retargeted. The retained exact patch
must reverse the archived project to original Git blob
`c94acffd885742b8c71f3e39818ca07ecdd08f4f`.

The separate source leaf requires the complete original NuGet Git tree and
all three original Common, FileSystem and NuGet.Build.Localization Gitlinks.
Every archived original source byte must match its pinned Git baseline except
that one reversible project patch. Only the ten Visual Studio file suffixes
explicitly declared `eol=crlf` by that original parent's `.gitattributes`, plus
Windows command files, can use uniform CRLF checkout encoding when their
canonical bytes recover the exact original blob. The actual source bytes stay
archived unchanged. No such extension policy is inherited by a submodule.
The pinned Common and FileSystem children independently require CRLF for their
own original `Common.sln` and `FileSystem.sln`; only those two child paths get
that same exact-Git-blob check.
No general source normalization or executable input substitution is admitted.

The leaf also binds the original three commands and actual log receipts, the
original build binlog consumed by the compiler replay, every emitted package
and the original complete target framework matrix. The normal worker uses the
explicit `/bootstrap/dotnet` input and `/work/work/nuget` source mount; the
outer producer must independently bind their actual container volumes and
the frozen native builder.

This component and corresponding-source contract does not establish the final
SDK's complete construction closure, archive-only consumers, both native CPUs
or signed public distribution. Those remain independent admission gates.
