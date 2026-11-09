# SDK5 original package byte envelopes

`musl_legacy5_construction_inputs.validate_raw_artifact_roles` composes the
actual raw package validator with the original strict named artifact policy.
It reads each canonical retained NPK and restore report, checks whole hashes
and original nuspec metadata, and preserves missing repository/source fields
and every original unknown observation. All named framework, native, compiler
and constructor roles still use the original strict checks. Artifact paths
must be globally unique across named and package roles.

`validate_raw_byte_inputs` additionally checks the actual complete final SDK
archive, every input archive inventory, compiler toolset binding and one-to-one
layout. The existing strict entry points retain their behavior. The new entries
return source correspondence, producer consumption and admission as false.
Independent source dispositions, original compiler/process boundaries and full
App/generated-data construction remain required by the future aggregate.

These entries do not rewrite raw artifact kinds or add invented Git metadata
to original packages. They do not activate collection, normal SDK production,
the public route or release qualification.
