# SDK5 explicit bootstrap byte validation

`musl_legacy5_bootstrap_byte_inputs.py` independently rehashes all ordinary
members of the three original pinned archives: SDK 5.0.401, matching runtime
5.0.17 and the separate SDK 6.0.135 VSTest/Reader inspection bootstrap. It
compares file modes, lengths, SHA-256 and SHA-512 against the actual composed
receipts. The exact original CLR, JIT and debugger files remain original
imported build inputs. Only the two explicitly declared source-native support
libraries replace their original matching framework counterparts.

Both replacements require their actual worker identities, logs and products,
the exact original generate/configure/compile/inspection command sequences,
and the original native load or X509 ABI smoke result. The original SDK5
worker and declared OpenSSL port patch are fixed inputs. This validator
executes neither a compiler nor native code. When supplied the actual readonly
bootstrap directories, it compares every file, permission and fingerprint to
the reconstructed complete trees and rejects additional inputs.
The actual directories permit regular files and directories only; FIFOs,
devices, links and permission bits for setuid, setgid or sticky behavior are
rejected. Original archives also reject those special permission bits before
normal permissions are inventoried.

This is an archive-backed byte-construction leaf. It does not establish the
complete native compiler source closure, a normal worker mount boundary, or
whole producer source admission. Those require the independent native source,
worker and final release guards. Imported compilers remain explicitly imported;
the derived tree is not described as an unmodified publisher SDK. The source
and qualification routes remain separate and closed until their complete
independent checks pass.
