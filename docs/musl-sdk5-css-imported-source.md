# SDK5 CSS imported source contract

This distinct SDK5 leaf checks one exact Razor layout path. It executes no SDK6
or SDK7 component module or policy. The source basis is the original canonical
image plus an exact certificate append and an independently declared publisher
Gitlink/project recipe; SDK5 selection or execution of that Gitlink is not
claimed.

The immutable canonical Microsoft.Css.Parser 1.0.0-20200708.1 NPK has SHA-256
`6eaaee47a12a96138731e9f42b117f62e7978982b3821290f77bd296d2903d0f`.
Its `lib/netstandard2.0/Microsoft.Css.Parser.dll` is 128,512 bytes. The actual
SDK5 Razor NPK member `tools/Microsoft.Css.Parser.dll` is a separate observed
distributor image of 138,640 bytes. The initial strict literal comparison
rejected their difference, and its driver is preserved.

Both complete original files retain their size, SHA-256 and SHA-512. Every
canonical image byte matches the distributor image except the exact PEChecksum
four bytes and SecurityDirectory eight bytes. The latter points to the exact
10,128-byte WIN_CERTIFICATE appended at the canonical EOF, offset 128,512. The
validator checks both independently calculated PE checksums, region bounds,
eight-byte alignment, exact certificate size, revision 0x0200, type 2 and full
certificate fingerprints. No original image or certificate bytes are rewritten.
This proves a bounded image correspondence; signer identity, signature
authenticity and publisher signing execution are not claimed.

The newly produced installer-only v7 archive contains the same signed 138,640
byte distributor image. The signed DLL is not represented as a literal member
of the canonical NPK. Result records distinguish `canonicalPackageMember` from
the actual distributor package/member and `observedDistributorImage`. A normal
producer/admission contract must separately bind its actual container/member
consumption and final layout bytes.

Full pristine original source is required for source-build-externals commit
`522d361e1cd703f1e8e526f5306e4ed18de1da41`, its real CSS Gitlink
`d6d86bcd8c162b1ae22ef00955ff748d028dd0ee`, and SDK5 Razor/ASP.NET Core commit
`02c6de4ba6022025fcda7581415f310f8c73cdc3`. Every archived file is checked against
its original Git blob and mode, and each complete baseline Git tree is rebuilt.
The parent `.gitmodules`/Gitlink, `repos/cssparser.proj`, original CSS project,
pipeline and licenses remain exact.

The parent recipe builds/packs the exact CSS project. It has no literal package
version constant. The original CSS pipeline expression is
`VersionSuffix=$(Build.BuildNumber)`; no actual publisher build number is
observed. The exact 1.0.0-20200708.1 version comes separately from the original
canonical NPK and SDK5 Razor `Versions.props`, while the original `rzc.csproj`
declares its CSS reference. The canonical NPK has no repository element or
embedded license. Its license URL and the separate original CSS MIT source
license retain their different roles.

`prepare(packages_by_sha, sources_by_role, destination)` retains original
package bytes and comparison/recipe records in a non-Git data tree.
`validate(release, manifest, packages_by_sha)` returns the exact full SDK path,
both image origins, source root/commit and independent recipe basis. It does not
claim local rebuilding, observed publisher compilation or SDK qualification.

The actual 26,422-file packet passed source capture, generic source verification
and this leaf in 19.1 seconds. Seven focused tests and nine actual source,
package, code-byte, certificate-directory and certificate-header controls pass.
