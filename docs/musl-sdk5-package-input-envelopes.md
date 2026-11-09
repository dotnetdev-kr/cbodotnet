# SDK5 original restored-package envelopes

`musl_legacy5_package_inputs.validate` reads each retained original NPK, checks
all three fingerprints and its root nuspec, and compares the literal repository
metadata with the raw restore observation and construction artifact. The closed
`package-<sha256>` role always remains `managed-package`; repository absence is
preserved. Source-built NuGet/VSTest package roles must also match the independently
validated component compiler package fingerprints and original source commits.

Every raw `unmapped-package-source` record remains present, including original
package ID/version and missing repository data. Imported source validators may
derive a separate explanation without rewriting those records or inventing Git
metadata. This guard does not establish restore/Copy execution, source-packet
validation, or whole producer admission. SDK5 normal routes remain closed.
