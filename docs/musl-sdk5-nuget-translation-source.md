# SDK5 original NuGet translation inputs

`musl_legacy5_translation_inputs.py` validates the distinct SDK 5.0.214
translation extraction policy and the actual imported data. It pins the
original tracked SDK5 extraction worker, NuGet source commit
`d525b0e670f3b6cbd5c73a35f04730a9f658c852`, both original comparison SDK
archives, thirteen cultures and the complete 286-member satellite universe.
It does not select an SDK6 or SDK7 translation policy.

The validator reparses each managed resource-only PE and its literal resource
tables. Actual SDK5 metadata retains assembly/product version 5.9.1.8, the
missing file-version string, uppercase Chinese metadata cultures and the
separate VisualStudio.Contracts strong name. The 637 resources contain
36,231 literal strings; 65 satellites are empty. Readable values, embedded
bytes, the complete data tree, source index and source archive must agree.

The one generated static NuGet schema has SDK5-specific original and generated
hashes. Its three namespace placeholders are compared using ordered qualified
XML names, attributes and non-whitespace text. DTDs and entities are forbidden.
Only indentation whitespace is ignored; the source schema must also equal
the original NuGet Git source bytes. The SDK and NuGet licenses, notices and
original localization package definition are retained and checked.

Every imported product is matched to its exact member in the authenticated
original SDK archive using length, SHA-256 and SHA-512. The full archive
inventory is recomputed. Thirteen Test.Utility resource satellites may be
omitted only when no primary Test.Utility assembly exists anywhere in that
original archive. These are imported original resource data with generated
readable inspection inputs. The validator does not claim a local translation
rebuild or possession of the publisher's original translation authoring files.

The source-only roundtrip and mutation receipts remain separate from whole
producer validation. This leaf does not grant qualification, publication or
normal SDK5 source admission. Original component, worker and full release
guards must still validate their respective boundaries.
