# Contributing

Thanks for helping improve cbodotnet. This repository builds and distributes
community SDKs; changes to source selection, qualification, signing and public
availability can affect users' trust, so keep claims tied to reproducible
evidence.

## Start Here

- Search existing issues before starting substantial work. Open an issue for
  behavior changes, new targets, workflow changes or release-policy updates.
- Small first task: choose a published target from the
  [distribution matrix](docs/all-sdk-distributions.md), verify its links against
  the signed status/receipt and scorecard, then report a discrepancy or add a
  focused regression test.
- Use Linux or WSL with Git and Python 3 for the standard local checks. Builds
  run in GitHub Actions; local SDK compilation is not a substitute for the
  native release gates.
- Keep documentation in English. Preserve immutable release bytes, signatures,
  source pins and historical evidence. Do not commit credentials, private keys,
  recovery data, generated artifacts or unreviewed downloaded inputs.

## Pull Requests and Validation

Use a pull request for contributions. Describe the user-visible change, exact
files or release cells affected, assumptions, and any migration or recovery
impact. Link the issue, include focused test results, and update relevant
documentation and machine-readable records together. Do not claim a target or
SDK is supported merely because a build or unit test passes.

Run the repository checks from its root:

```bash
python3 scripts/check-repository.py
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests -p '*_test.py' -v
```

The first command checks syntax, pinned inputs, repository policy and local
links. The second matches the CI test-discovery rule. Some native/package/release
gates additionally require their documented Linux tools, protected GitHub
environment and native runners; consult the owning runbook and do not simulate
their results.

## Review and Release-Critical Changes

Do not approve your own pull request. Routine documentation, test and isolated
bug-fix changes require one independent maintainer review and passing CI.
Changes to source pins, native qualification, release or Pages workflows,
signing policies/keys, package or OCI promotion, signed status feeds, or
installer admission require two independent maintainer reviews, including a
reviewer authorized for the affected release boundary. Key creation, rotation,
revocation and external repository settings also require explicit repository
owner approval. A missing reviewer or evidence gate is a reason to defer, not
to reduce the checks.

As reviewed on 2026-11-10, `main` has no GitHub branch-protection rule. These are
the project review expectations, not a claim that GitHub currently enforces
them. Until required pull-request reviews and status checks are enabled,
maintainers must treat direct pushes as an operational exception that needs
explicit owner authorization and post-push CI verification. Release secrets
remain confined to their protected GitHub environments; ordinary test and
packaging jobs must not receive them.

## Decisions and Continuity

Maintainers record proposals, evidence, decisions and unresolved risks in the
issue or pull request. Routine changes need an independent review; release
trust changes follow the two-review/owner-approval rule above. When evidence or
maintainer availability is insufficient, pause the change and state what
decision or additional review is needed rather than implying consensus.

Maintainers are responsible for issue triage, review capacity, documentation
accuracy, release-gate integrity, incident communication and scheduled access
review. Review repository administrator access, protected environments and
workflow permissions at least twice each year and after maintainer departures.
Keep at least two active maintainers familiar with release operations and key
recovery; never solve a continuity gap by sharing a personal account or secret.

The current public repository metadata lists 10 admin collaborators, but does
not establish who is actively maintaining the project or who can independently
recover protected credentials. The signing environment has no required-reviewer
rule and `main` is unprotected. Repository owners should designate a primary
and deputy release custodian, configure enforceable reviews for `main` and the
signing environment, and periodically rehearse recovery with disposable test
credentials. Until that work is verified, record the single-maintainer risk in
release decisions and defer key- or availability-changing actions when an
independent reviewer is unavailable.

For project behavior or release questions, use a public issue without posting
security-sensitive details. For vulnerability reports, use the
[private reporting policy](SECURITY.md). For conduct concerns, follow the
[Code of Conduct](CODE_OF_CONDUCT.md).