# Security policy

## Supported versions

The latest public-preview minor release receives security fixes. A superseded minor release is
supported for 90 days after its replacement. Development snapshots are unsupported. Release
artifacts, rule packs, sandbox bootstrap manifests, and their signatures remain available so an
operator can pin or roll back while a supported fix is prepared.

## Private disclosure

Do not open a public issue for a suspected sandbox escape, credential exposure, signature bypass,
malicious rule-pack acceptance, or report-content execution. Use the repository's GitHub private
vulnerability reporting form. Include the affected version, host platform, containment/readiness
output, minimal reproduction, and whether a synthetic canary was exposed. Do not include real
credentials, private prompts, or customer traces.

The project will acknowledge a report within three business days, provide an initial severity
assessment within seven, and coordinate remediation and disclosure with the reporter. Critical
signature or containment defects block new releases and trigger key/image revocation as needed.

## Signing and verification

Standalone release files are signed with a Sigstore GitHub Actions identity and receive GitHub
artifact attestations. The installer verifies the artifact attestation before copying or executing
the binary. Release manifests contain SHA-256 checksums; releases also include CycloneDX SBOMs and
provenance attestations.

Declarative rule packs and sandbox bootstrap manifests use the embedded Ed25519 release key. The
normal flow verifies the exact key ID, revocation list, signature, expiry, size, and asset checksum
before activation. An active rule pack is reverified before every job. Unverified or corrupt active
content makes analysis incomplete and cannot silently fall back to executing that content.

## Signing-key revocation

On suspected signing-key compromise:

1. Stop publishing and disable the affected update feed.
2. Add the key ID to the embedded `trust/revoked-keys.json` list and issue an emergency release
   signed through the independent release identity.
3. Publish the revoked key ID, affected release/rule ranges, and verified rollback instructions.
4. Reject the revoked key even for otherwise valid historical envelopes in the normal update and
   bootstrap flows.
5. Rotate the release key, audit all artifacts since the last trusted signing event, and publish
   fresh checksums, SBOMs, and provenance.

Operators should disable automatic rule updates and pin the last verified version until the
revocation release is installed. A revoked binary release is removed from the supported-version
set but retained as evidence where the hosting platform permits.
