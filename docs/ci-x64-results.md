# Native Linux x64 CI qualification records

Implementation, architecture rejection fixtures and workflow linting are complete. The profiles below require actual hosted product builds and independent verification of their downloaded SDK/source deliveries. A pending row is not a qualified x64 SDK.

| Profile | SDK | Hosted run | Downloaded delivery |
| --- | --- | --- | --- |
| .NET 10 | 10.0.403 | [41295429028](https://github.com/dotnetdev-kr/cbodotnet/actions/runs/41295429028), in progress | Pending |
| .NET 9 | 9.0.123 | [41295430879](https://github.com/dotnetdev-kr/cbodotnet/actions/runs/41295430879), in progress | Pending |
| .NET 8 | 8.0.133 | [41295751388](https://github.com/dotnetdev-kr/cbodotnet/actions/runs/41295751388), in progress | Pending |
| .NET 7 | 7.0.120 | [41295753622](https://github.com/dotnetdev-kr/cbodotnet/actions/runs/41295753622), failed preparation | Pending replacement |
| .NET 6 | 6.0.136 | [41295755838](https://github.com/dotnetdev-kr/cbodotnet/actions/runs/41295755838), failed preparation | Pending replacement |
| .NET 5 | 5.0.214 | [41295758152](https://github.com/dotnetdev-kr/cbodotnet/actions/runs/41295758152), failed preparation | Pending replacement |
| .NET Core 3.1 | 3.1.426 | [41295433032](https://github.com/dotnetdev-kr/cbodotnet/actions/runs/41295433032), failed preparation | Pending replacement |
| .NET Core 3.0 | 3.0.103 | [41295434962](https://github.com/dotnetdev-kr/cbodotnet/actions/runs/41295434962), failed preparation | Pending replacement |

The [x64 guide](ci-x64.md) describes the native workers, version-specific construction, source delivery and trusted portable verifier. Qualification must bind each artifact to its exact orchestration commit, source revision, run and attempt. Original ARM64 records remain separately available in the [ARM64 results](ci-matrix-results.md).

## Preserved initial failures

The initial .NET 5/Core 3.x runs authenticated the Ubuntu archive but stopped before product compilation because Xenial's initial CA bundle could not verify its current HTTPS certificate. The replacement producer retains and fingerprints the working container CA bundle and requires explicit peer/hostname verification and unchanged package signature verification.

The initial .NET 6 generator silently selected its default ARM target for an unsupported x64 argument. The .NET 7 generator selected amd64 but lacked the requested x64 Xenial source list. Their replacements use an explicit native amd64 producer with the exact pinned upstream package set, authenticated archive, recorded source-list transport adaptation and complete inventories. These failed runs remain failed; replacement runs must independently qualify.
