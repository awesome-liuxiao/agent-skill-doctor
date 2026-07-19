# Local policy foundation

Configuration precedence, highest first: managed policy, explicit CLI option,
project configuration, user configuration, built-in default. Managed policy
may tighten limits or disable capabilities but may not silently enable network,
execution, collection, telemetry, or longer retention.

Job metadata, reports, manifests, and snapshot blobs are stored under an explicit or
per-user local state directory. Snapshot artifacts remain until the user deletes that state
directory; the doctor does not silently shorten evidence retention. Raw artifacts are AES-GCM encrypted with a
master key protected by the host credential facility. Reports omit file
contents and redact obvious credential-shaped values from messages. Session
diagnosis reads a bounded trace in place and persists only minimized metadata,
selector signals, categorized errors, and aggregate timings. The optional
flight recorder is off by default, encrypted, retained for no more than 24
hours, capped at 50 MB, and immediately purgeable. Telemetry is off by default.
The only opt-in telemetry schema contains a fixed event, outcome, duration bucket,
host family, schema version, and tool version; it cannot represent a skill,
prompt, trace, path, finding, or generated test. No data leaves the host until a
credential-free HTTPS endpoint receives an exact two-step approval token.

Consent records are versioned. Explicit invocation consents to bounded reads of
the supplied directory and local artifact persistence, not execution, network,
platform trace collection, or mutation.

External rule packs and sandbox bootstrap assets are disabled until their signed
plan is reviewed and approved. Rule feeds require separate endpoint-bound network
consent. Verified content may be pinned or rolled back; unsigned, expired,
revoked, checksum-mismatched, or corrupt content never runs in the normal flow.
