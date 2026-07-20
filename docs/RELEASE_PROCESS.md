# Release and validation process

## Promotion stages

1. Internal developer preview: core schemas and static behavior may change.
2. Static alpha: discovery and session evidence are exercised with design partners.
3. Private design-partner alpha: approved partners run real failing sessions and sandboxed
   reproductions under the private-disclosure policy.
4. Remediation period: every confirmed high-severity false positive, containment issue,
   privacy leak, and release blocker is fixed or explicitly blocks promotion. Benchmark
   expectations are reviewed independently of rule authors.
5. Public preview: all public candidate gates pass on the three-OS CI matrix; limitations
   and compatibility remain explicit.
6. Stable v1: every quantitative gate passes on an attested rotating held-out corpus and
   all three platform validation artifacts, with no unresolved critical sandbox escape.

## Public static-analysis alpha

The separate `signed-public-preview` workflow may publish a PEP 440 alpha, beta, or release
candidate tag such as `v0.1.0a1`. It runs the complete public candidate gate on GitHub-hosted
Windows, macOS, and Linux runners, then publishes only an attested wheel and source distribution as
a GitHub prerelease. It does not publish standalone executables, claim stable readiness, or bypass
any protected stable-release evidence gate.

Dispatch the workflow from the exact existing preview tag and provide the same value for
`release_ref` and `release_tag`. Source commit, checked-out `HEAD`, workflow source SHA, tag, and
package version must agree. Preview release notes must enumerate every missing external gate.

Design-partner evidence is kept outside the repository because it may contain private
session material. The release owner records only aggregate participant count, tested
platform/runtime combinations, issue IDs, remediation status, and sign-off in the protected
`stable-release` environment. Raw prompts, traces, paths, findings, and customer skills are
not release artifacts. A reviewer must reject promotion when this evidence or the remediation
period is incomplete.

## Stable workflow

Stable release is manual and environment-protected. First run
`.github/workflows/held-out-evaluation.yml` with the exact release ref, release version, and a
new rotation ID. Independently run `.github/workflows/design-partner-signoff.yml` after the
alpha, remediation period, and public preview. Then run `.github/workflows/release.yml` with
both protected run IDs. Every protected workflow must be dispatched from the same exact source
commit it checks out; stable release must be dispatched from an existing `vMAJOR.MINOR.PATCH`
tag and use that same value for `release_ref` and `release_tag`. A guard fails before dependency
installation when `GITHUB_SHA`, checked-out `HEAD`, and the requested source do not match.

The stable workflow:

- checks out the same exact ref on Windows, macOS, and Linux;
- runs formatting, lint, strict typing, the full tests, public benchmarks, fault injection,
  functional contracts, containment, and secret canaries;
- creates standalone bundles, CycloneDX SBOMs, checksummed manifests, verified supplemental
  Sigstore signature bundles, and GitHub build-provenance attestations;
- verifies the held-out result against the protected signer workflow and exact source digest;
- enforces 95% highlighted precision, at most 2% benign false positives, 90% causal accuracy,
  90% reproduction consistency, 99.5% supported completion, 100% containment, 100% fault
  injection, 100% public functional checks, three-platform evidence, and no unresolved
  critical escape;
- attests and publishes the aggregate benchmark report only after every gate succeeds; and
- publishes nothing when any gate, artifact, signature, or environment review is missing.

`security/known-sandbox-escapes.json` is the reviewable release register. Removing an entry
is not remediation: fixed entries remain with disclosure references. An open or accepted
critical entry blocks stable promotion.

## Release evidence checklist

- Threat model, security policy, limitations, compatibility matrix, public benchmark, and
  current results reviewed.
- Design-partner aggregate evidence and remediation sign-off recorded in the protected
  environment.
- Held-out rotation is licensed, disjoint, independently reviewed, and attested.
- Windows, macOS, and Linux validation artifacts are from the exact release ref.
- SBOM, checksums, signatures, provenance, and installer verification are present.
- Rule-pack and bootstrap signing keys are not revoked; rollback assets remain available.
- Stable benchmark report says `stable_v1_ready: true`. No human override may replace it.
