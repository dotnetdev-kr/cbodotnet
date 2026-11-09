# SDK5 publisher-declared Cecil source

`musl_legacy5_cecil_source_inputs.py` covers the three Cecil DLL occurrences
inside the original `Microsoft.NET.ILLink.Tasks/5.0.0-rtm.21519.5` package.
Its source basis is `publisher-declared-repository-gitlink-project-recipe`.
It makes no claim to observe the publisher's compiler process or to rebuild
these imported binaries locally.

The pinned original NPK declares Linker repository commit
`a3cca7a168d83444e833eceac61e721f97d5cfb2`. Its complete original Git tree
declares the `external/cecil` Gitlink at
`75fc419764f239dcdd679657316e6eae31e04dc2`. Both complete pristine Git trees,
their licenses and the actual parent/child Gitlink relation are required.

The original Linker recipe defaults `UseCecilPackage` to false and retains
the original Cecil and Cecil.Pdb project references. Its package targets
remain netcoreapp3.0/net472; the child projects retain netstandard2.0/net40
and the original 0.11.2.0 assembly version source. The original project,
version, Gitmodule and license files are pinned to their exact Git blobs.
The original MSBuild XML namespace is preserved.

Each product closes the full SDK5 layout path, original NPK SHA256/member,
byte count, SHA256, SHA512 and actual managed assembly identity. A different
package, member, source Gitlink or source tree cannot use this contract.
Original publisher package and source licenses remain retained separately.

`prepare(package, linker_source, cecil_source, destination)` returns a
non-Git input tree containing the original NPK and readable declaration
record. `validate(release, manifest, package)` binds the SDK5 source archive
and index, reconstructs both full original Git trees, checks every archived
Git blob/mode, rechecks the original package members and source recipe, and
returns three explicit product dispositions. Each names its full SDK path,
NPK SHA/member, Cecil source root/commit, parent publisher source root/commit
and declared source basis.

The caller must also verify the full source packet and all other normal A5
source, compiler, Reader, native and consumer guards. This leaf grants no
whole SDK admission or qualification.

The actual 2,729-file source packet passed pack, verify and this leaf, with
all three products. Six focused tests and seven actual mutation controls
passed. Receipts are in `.build/sdk5-cecil-declared-source-contract-v2/`;
the complete packet is at
`/var/tmp/cbodotnet-sdk5-cecil-declared-source-contract-v2-20261109/release`.
The first strict original-XML-namespace failure and used source versions
remain preserved.
