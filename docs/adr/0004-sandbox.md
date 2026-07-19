# ADR 0004: fail-closed platform sandbox backends

Status: accepted for engineering preview.

Dynamic skill evaluation runs only through the common capability contract in
`skill_doctor.sandbox`. Linux uses a digest-pinned hardened container. Windows
uses Windows Sandbox plus a hash-pinned runner and runtime-bundle manifest.
macOS uses a hash-pinned Virtualization Framework runner plus a digest-pinned
VM image. The adapters must attest filesystem, process, network, identity,
resource, trace, teardown, and artifact controls before execution.

The runtime receives an immutable materialization of captured snapshot bytes,
a disposable writable workspace, a scrubbed environment, and prompt text over
stdin. Network is disabled unless an attested allowlist proxy is part of the
approved plan. Host credential files, sockets, and agent state are never
mounted.

Missing, incomplete, or unverifiable controls produce explicit coverage gaps
and a static-only result. There is no direct-host execution fallback. Enabling
virtualization, installing privileged components, or rebooting remains an
operator action outside the normal diagnostic flow.
