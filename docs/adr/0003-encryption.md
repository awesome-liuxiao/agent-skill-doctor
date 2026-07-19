# ADR 0003: Encryption at rest

Status: accepted for Milestone 1.

Raw snapshots and future traces use AES-256-GCM envelope encryption. Every
content-addressed blob receives a fresh 96-bit nonce and authenticates its
plaintext SHA-256 identifier as associated data. Reports, findings, cache
records, and job metadata are sanitized data and are not treated as raw
artifacts.

The random 256-bit state master key is protected by the host credential
facility: DPAPI with UI disabled on Windows, the default Keychain on macOS, and
the Secret Service collection on Linux. IPC authentication material is derived
from the master key with domain-separated HMAC-SHA-256. There is no plaintext
key-file or plaintext-artifact fallback. If the credential facility is missing
or locked, readiness fails explicitly and analysis does not persist raw data.

The envelope format is versioned. Changing the algorithm, nonce construction,
associated data, key protection, or rotation lifecycle requires a new ADR and
migration tests.
