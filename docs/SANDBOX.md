# Sandbox capability and operator contract

Agent Skill Doctor treats skill content, eval prompts, runtime output, and
dependency metadata as untrusted. Actual-runtime tests are permitted only when
the selected backend reports all eight capabilities: filesystem, process,
network, and identity isolation; resource limits; trace capture; forced
teardown; and attestation.

Run the non-mutating capability report before planning dynamic tests:

```console
skill-doctor readiness --deep --json
```

The command exits with status 2 when only static analysis is available. It
does not enable Windows Sandbox, install a container engine, create a VM,
change privilege settings, or schedule a reboot.

## Backend requirements

Linux requires `podman` or `docker` and
`SKILL_DOCTOR_LINUX_IMAGE=name@sha256:<digest>`. The deployment must separately
attest rootless or user-namespace isolation and set
`SKILL_DOCTOR_CONTAINER_ISOLATION_ATTESTED=1`. The launch is read-only,
capability-free, non-root, PID/memory/CPU bounded, `no-new-privileges`, and
networkless by default. `SKILL_DOCTOR_NETWORK_NAME` is required for an
approved allowlist proxy. `SKILL_DOCTOR_PROXY_URL` pins the proxy endpoint used
by an approved job. The engine is always asked to remove the named
container after completion or forced teardown.

Windows requires the Windows Sandbox feature and these configured assets:

- `SKILL_DOCTOR_WINDOWS_SANDBOX_RUNNER`
- `SKILL_DOCTOR_WINDOWS_RUNNER_SHA256`
- `SKILL_DOCTOR_WINDOWS_RUNTIME_BUNDLE`
- `SKILL_DOCTOR_WINDOWS_RUNTIME_MANIFEST`
- `SKILL_DOCTOR_WINDOWS_RUNTIME_MANIFEST_SHA256`

The runner receives a bounded JSON specification. It must verify the runtime
manifest, map the snapshot read-only, create a disposable writable workspace,
translate canonical guest paths, enforce job limits, propagate stdin, capture
bounded stdout/stderr, destroy the sandbox, and reject networking. Environment
values arrive in the runner process environment; the JSON and process argument
list contain keys only.

macOS requires `SKILL_DOCTOR_MACOS_VM_RUNNER`,
`SKILL_DOCTOR_MACOS_RUNNER_SHA256`, and a digest-pinned
`SKILL_DOCTOR_MACOS_VM_IMAGE`. Networked jobs additionally require the exact
`SKILL_DOCTOR_MACOS_PROXY_URL`. The runner has the same structured contract and
may enable networking only through the approved metadata-only allowlist proxy.

Windows and macOS runners are deployment-controlled trusted computing base
components. A missing or hash-mismatched component is a coverage gap, never a
reason to execute on the host.

## Per-job containment

The skill snapshot is reconstructed from bytes captured before testing and is
mounted read-only. The writable workspace is unique to one trial. Prompts use
stdin so they do not appear in host or guest process arguments. Sensitive
ephemeral proxy values are passed through a scrubbed process environment, and
host credential stores and files are not mounted.

Every trial receives synthetic credential, private-file, and controlled-sink
canaries. Canary values in output or writes to the sink are marked as a
containment exposure. Output readers continuously drain both streams while
retaining at most 10 MB per stream. Cancellation and timeout kill the process
tree; Linux additionally performs daemon-side orphan cleanup.

Networking defaults to disabled. Approved networking supplies both a domain
allowlist and an attested proxy. The sandbox records destination metadata only;
payload capture is outside the contract.

Dependencies are optional and declared. Python packages require exact `==`
pins and SHA-256 hashes. npm packages require `package-lock.json`, non-linked
entries, and SHA-512 integrity. Installation runs inside the sandbox through
an approved registry proxy, with dependency scripts disabled and command and
output hashes recorded.
