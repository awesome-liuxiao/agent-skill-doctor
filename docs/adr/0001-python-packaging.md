# ADR 0001: Python packaging

Status: accepted for Milestone 1.

Use a `src` layout, Python 3.12 only, and PEP 621 metadata. Development and
runtime dependencies are exactly pinned. Milestone 1 adds `cryptography` for
AES-GCM and conditional `SecretStorage` support on Linux; macOS and Windows key
protection use native system APIs. Standalone signed bundles remain Milestone 9.
