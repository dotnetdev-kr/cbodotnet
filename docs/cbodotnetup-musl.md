# Native Alpine cbodotnetup

The 0.5 tool line adds separate NativeAOT executables for `linux-musl-x64`
and `linux-musl-arm64`. Admission is limited to Alpine **3.24.4** and
Community Build SDK **10.0.403 r1**, the inputs qualified in [#24](alpine-musl.md).
Other SDK series and Alpine versions require their own native evidence.
The active [signed availability record](../releases/cbodotnetup-status.json)
determines whether this feed is available.

## Bootstrap on an SDK-free host

Install the prerequisites from the signed Alpine repositories:

```sh
apk add --no-cache python3 ca-certificates gpg gpgv coreutils
```

Python **3.10 or newer**, GnuPG 2, GNU coreutils (for ownership checks), system CA certificates and a writable
regular user's home are required. A .NET SDK is not required. Run the
bootstrap and manager as that regular user. Review the downloaded script
and independently verify the [project signing identity](distribution-signing.md)
before using it:

```sh
curl -fLO https://dotnetdev.kr/cbodotnet/cbodotnetup/get-cbodotnetup.py
python3 get-cbodotnetup.py
~/.local/bin/cbodotnetup list --available
~/.local/bin/cbodotnetup install --channel 10.0
~/.local/bin/cbodotnetup doctor
~/.local/bin/cbodotnetup run 10.0.403-r1 -- --info
```

The script can also be downloaded with Python's `urllib.request` or a browser;
`curl` is only needed for the example download command. The manager checks the
SDK's declared native dependencies before admitting it. Install these stock
Alpine runtime packages before SDK use:

```sh
apk add --no-cache ca-certificates icu-libs icu-data-full libgcc libstdc++ \
  libssl3 libcrypto3 zlib tzdata krb5-libs brotli-libs lttng-ust
```

`gcompat`, `libc6-compat` and glibc installations do not qualify as native
musl hosts. The running executable's ELF interpreter, CPU, Alpine identity
and exact branch patch level must agree. Downloaded tools and SDK hosts
are checked before activation. A glibc binary with a musl file name is refused.

## Catalog and state isolation

The default bootstrap chooses the libc-specific endpoint. Alpine uses
[`v4/catalog.json`](https://dotnetdev.kr/cbodotnet/cbodotnetup/v4/catalog.json)
and its adjacent detached OpenPGP signature. Schema4 adds only the root
`libc: "musl"` field; SDK, target and tool records retain their existing shapes.
It contains only the two qualified musl SDK records. No legacy compatibility
providers are admitted.

The existing schema1, schema2 and schema3 feeds retain their glibc-only record
shapes and original 0.1.0 upgrade path. The new glibc executable continues to
use schema3. Alpine normally stores state in `~/.local/share/cbodotnetup-musl`.
Its `cache/v4`, `toolchains-v4`, `selection-v4.json`, `bin-v4` and `staging-v4`
namespaces also prevent collisions when an explicit shared state root is used.
The bootstrap refuses to overwrite an unrelated or other-libc executable.

Use a separate `--install-dir` if a different libc's managed executable already
occupies `~/.local/bin/cbodotnetup`. Shell files, official `dotnet` installations,
APK-managed SDKs and glibc toolchains are preserved. Add the chosen executable
directory to `PATH` explicitly when desired; [command and recovery instructions](cbodotnetup.md)
apply to the owned musl namespaces.

SDK commands retain their usual user-profile behavior. SDK10 can create a
development certificate and MSBuild shared-memory state under
`~/.dotnet/corefx`. Qualification requires every preexisting profile entry to
retain its bytes, permissions and link target, and records only the narrowly
classified new runtime paths as metadata. Other retained user/glibc roots and
the complete official and APK-managed SDK payloads must remain identical.

System certificate stores can load roots during the first TLS handshake.
The bootstrap requires certificate and hostname verification and keeps normal
verified HTTPS downloads; it accepts a secure context whose CA statistics are
initially empty. This supports Fedora45's stock lazy trust store and signed
offline bootstrap inputs. Python documents the [lazy loading of capath
certificates](https://docs.python.org/3.14/library/ssl.html#ssl.SSLContext.get_ca_certs).

## Build and promotion contract

The [musl admission policy](../releases/cbodotnetup-musl-policy.json) independently
pins the archive, canonical producer manifest and final signed native SDK
verification. The tool is compiled on the matching CPU in the reviewed Alpine
image using the authenticated Community SDK, pinned clang/lld/APK inputs and
NativeAOT runtime/compiler **10.0.14**. Build records retain actual NuGet package
hashes, lock data, source inputs, compiler/package inventories, notices and
ELF dependency closure. NativeAOT applies to the manager; the SDK payload is
preserved with its original licenses and full ICU behavior.

The protected distribution workflow freezes and signs the candidate, requires
both native Alpine lifecycle reports plus the existing eight glibc targets,
publishes immutable assets, then repeats qualification from anonymous public
downloads before activating the feed. Hosted default bootstrap verification
also runs on both libc families and CPUs.

The initial musl self-update test uses separately compiled real 0.5.0 and
0.5.1 executables from the same reviewed source. The retained 0.5.0 release
is a qualification baseline; use the default signed feed to choose the current
tool. SDK admission initially contains one revision: tracked update verifies
that r1 is current, and SDK rollback restores activation of the retained r1
installation. It does not claim an upgrade to an unqualified SDK revision.

Additional musl SDKs remain tracked in #32–#35. Workloads and NativeAOT
compilation of user applications need separate qualification.
