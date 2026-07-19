# Compatibility matrix

This matrix distinguishes implemented adapters from configurations that have release
evidence. A dynamic adapter is never treated as available merely because its code exists;
`skill-doctor readiness --deep --json` must attest every capability on the actual host.

| Area | Windows | macOS | Linux |
| --- | --- | --- | --- |
| Static analysis and local reports | Python 3.12; CI matrix | Python 3.12; CI matrix | Python 3.12; CI matrix |
| Standalone release architecture | amd64 | arm64 | amd64 |
| Credential protection | DPAPI | Keychain | Secret Service |
| Dynamic containment | Windows Sandbox trusted runner | Virtualization.framework trusted runner | Rootless/user-namespaced Podman or Docker |
| Default networking | Disabled | Disabled | Disabled |
| Approved networking | Backend-attested proxy only | Exact attested proxy only | Named isolated network plus exact proxy |
| Unsupported backend state | Static-only, explicit coverage gap | Static-only, explicit coverage gap | Static-only, explicit coverage gap |

Codex and Claude Code runtime adapters preserve the selected runtime version string, model,
configuration document, permission mode, sandbox mode, and proxy authorization. The exact
runtime executable is invoked inside the sandbox. If the historical runtime/model is absent,
the run is indeterminate unless the user explicitly approves a recorded substitution. There
is no direct-host fallback.

Runtime CLI versions are not declared universally compatible. Each stable benchmark report
records the actual runtime/model dimensions exercised by its dynamic evidence, and releases
must publish those versions alongside this matrix. The current `0.1.0.dev0` result is static
and synthetic-runtime validation only; it certifies no production Codex or Claude CLI
version.

Known limitations:

- Windows directory-symlink test creation may require Developer Mode or elevation; lack of
  that privilege is reported as a test skip and does not weaken sandbox canary requirements.
- Linux requires a digest-pinned image and an independent rootless/user-namespace
  attestation. Merely finding Docker or Podman is insufficient.
- Windows/macOS runner binaries and images are deployment-controlled trusted computing base
  components and must match their signed bootstrap receipts.
- Rust and other unrecognized script languages are snapshotted but script semantics are
  explicitly unsupported.
- Cold/warm load time, CPU, peak memory, network bytes, and retries remain unsupported
  performance metrics.

Development evidence includes a disposable WSL2 x86_64 run on CPython 3.12.13 with the exact
dependency locks, public benchmark gate, standalone smoke/readiness, SBOM and manifest generation,
and two byte-identical clean builds. This validates an additional Linux development configuration;
it does not replace the exact-commit GitHub-hosted Linux artifact required for release.
