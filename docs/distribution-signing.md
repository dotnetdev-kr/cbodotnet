# Distribution signing identity

Community Build of .NET (built by .NET Dev) uses a dedicated Ed25519 distribution
key. Its full primary fingerprint is:

```text
D7D1 54B4 B33C 19A8 2B95 B136 8813 5410 ACD9 C0EA
```

Use the ungrouped fingerprint for machine comparison:
`D7D154B4B33C19A82B95B13688135410ACD9C0EA`.
The [public key](../releases/downstream-signing-key.asc) expires on
2028-11-03 at 02:38:19 UTC. Confirm this fingerprint through a trusted .NET Dev
project-owner channel before trusting a downloaded key. A key and its adjacent
fingerprint from the same unverified server are not independent authentication.

The project owner approved creating this key for signed installation evidence,
distribution publication manifests and APT repository metadata. Private key
material and a separate emergency revocation certificate are encrypted GitHub
Environment secrets in `downstream-release`. That environment permits only the
`main` branch. Only the trusted distribution publishing job references the
signing secret; general packaging, PR tests and Pages jobs have no private key.

The primary key is deliberately separate from contributor identities and SDK
producer commits. It attests to downstream distribution and cannot change the
qualified source/SDK hashes. Image digests and signed manifests connect OCI
publication back to those hashes; this is not a Microsoft signature or a promise
of upstream security maintenance.

Inspect a downloaded public key with:

```bash
gpg --show-keys --with-colons distribution-signing-key.asc
```

Compare its `fpr` value exactly with the trusted fingerprint above, then dearmor
it into a dedicated APT `signed-by` keyring. Never disable repository signature
checking or import it as a blanket trust key for unrelated repositories.

For rotation, create a successor key with its own explicit owner approval,
publish its full fingerprint and validity window through existing trust
channels, add an overlapping active policy entry, and test signed installation
before retiring the predecessor. Preserve old public keys and immutable records
so historic downloads remain auditable. The tests exercise independent signature
verification, trust windows, wrong fingerprints, revoked policy and tampering.

For compromise, stop the publishing environment, mark the signer revoked in
`releases/downstream-status.json`, remove its active keyring entry, and recover
the encrypted revocation certificate through repository-owner administration.
Publish the certificate, affected artifact/digest list and successor trust
bootstrap through the established project channels. Keep immutable artifacts
and their history; do not hide a revocation by replacing their bytes.
