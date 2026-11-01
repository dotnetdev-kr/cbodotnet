# Native Linux x64 CI qualification records

Implementation, architecture rejection fixtures and workflow linting are complete. The profiles below require actual hosted product builds and independent verification of their downloaded SDK/source deliveries. A pending row is not a qualified x64 SDK.

| Profile | SDK | Hosted run | Downloaded delivery |
| --- | --- | --- | --- |
| .NET 10 | 10.0.403 | Pending | Pending |
| .NET 9 | 9.0.123 | Pending | Pending |
| .NET 8 | 8.0.133 | Pending | Pending |
| .NET 7 | 7.0.120 | Pending | Pending |
| .NET 6 | 6.0.136 | Pending | Pending |
| .NET 5 | 5.0.214 | Pending | Pending |
| .NET Core 3.1 | 3.1.426 | Pending | Pending |
| .NET Core 3.0 | 3.0.103 | Pending | Pending |

The [x64 guide](ci-x64.md) describes the native workers, version-specific construction, source delivery and trusted portable verifier. Qualification must bind each artifact to its exact orchestration commit, source revision, run and attempt. Original ARM64 records remain separately available in the [ARM64 results](ci-matrix-results.md).
