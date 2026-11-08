# SDK6 Globbing source and license inputs

SDK6's original source-built VSTest 17.0.3-dev imports
Microsoft.Extensions.FileSystemGlobbing 1.1.1. Its unmodified binary records the
real `CommitHash` 96bf83a6c1ab6f6801130150c27282c49030c8e1. The package has no
repository element and declares the original .NET Library EULA. This single
package therefore requires the closed SDK6 policy rather than a general
missing-repository exception.

The policy retains the complete FileSystem source at that commit and the
complete Common source at fab8d45f6be307ae0b96b1860e516f8a7aa903b0. Their original
project files specify the same shared source package version, 1.1.1; the full
HashCodeCombiner implementation and each source's separate Apache license are
retained. The shared commit is preferred corresponding source. The policy does
not claim that the original binary embeds that Common commit, or that this
Globbing binary was compiled locally or reproduced byte for byte.

The actual SDK6 consumer package, its unchanged `LICENSE_NET.txt`, the identical
original cc7fb0593127e24f55ce016fb3ac85b5b2857fec VSTest license source, the
original Globbing package and its unmodified nuspec are retained as a separate
non-Git data tree. The Apache source licenses do not replace the binary license.
The source-built consumer package's fingerprint must separately match the
completed VSTest compiler and SDK consumption evidence. This leaf alone grants
neither SDK qualification nor complete source admission.

An actual source-pack roundtrip retained 3,182 files across the complete three
Git source roots and this data tree. The full source pack and independent
license/source validation passed. Tests also exercise missing Common source,
changed Git baselines and changed consumed license bytes. Historical SDK7
publisher-package comparisons and its source policy are not used in this route.
