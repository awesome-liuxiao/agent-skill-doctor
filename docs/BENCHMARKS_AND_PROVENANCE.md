# Benchmarks, provenance, and release gates

The public corpus is `benchmarks/public/v1` and has corpus version `1.0.0`. It is
Apache-2.0 project content except for two unmodified, separately licensed upstream
fixtures. Every case records its stratum, languages, origin, license path, modification
history, exact expected rule IDs, and expected coverage. The strict manifest schema is
`schemas/benchmark.schema.json`.

## Public corpus

The static corpus currently contains 16 cases:

- Six benign cases: three project-authored multilingual skills, the minimal seed, and
  exact pinned copies of the OpenAI and Anthropic `skill-creator` skills.
- Seven mutated static defects covering broken and unsafe references, credential shapes,
  unsafe commands, dynamic evaluation, broad suppression, and name mismatch.
- One intentionally invalid-frontmatter input with explicitly expected incomplete
  frontmatter coverage.
- One controlled hostile prompt-injection/exfiltration instruction and one
  unsupported-Rust case.

The separately versioned functional manifest executes broken references, dependency
preflight failure, skill collisions, explicit context-budget bloat, trigger failure,
portability defects, a repeatable performance regression, and an authored evaluation
contract. The causal corpus contains trusted and untrusted contracts, successful and
failed controls, shared-runtime failures, unrelated failures, and nondeterministic trials.

The two upstream fixtures are vendored for offline reproducibility at these immutable
Git objects:

| Fixture | Commit | Tree | License |
| --- | --- | --- | --- |
| `openai/skills` `skills/.system/skill-creator` | `49f948faa9258a0c61caceaf225e179651397431` | `8bfb6b8774d223eea3e788cfdfa1e4209e5e2ae9` | Apache-2.0 |
| `anthropics/skills` `skills/skill-creator` | `9d2f1ae187231d8199c64b5b762e1bdf2244733d` | `3cf9a8db32597ba3e24b584a3d696f4e11c7d7b6` | Apache-2.0 |

The manifest pins each license SHA-256 and the doctor’s deterministic snapshot SHA-256.
The benchmark refuses to run if a vendored tree, commit mapping, or license differs.
Unknown or incompatible licenses are excluded.

## Metric definitions

- Highlighted precision counts only high-confidence findings shown as highlights.
- Expected-finding recall counts findings at every confidence level against exact case
  expectations.
- Benign false-positive rate counts benign skills with any finding, divided by benign
  skills.
- Supported static completion excludes only cases whose manifest explicitly expects a
  failed coverage component.
- Root-cause accuracy compares confirmed versus non-confirmed causal outcomes.
- Reproduction consistency measures agreement between repeated treatment trials.
- Containment, fault-injection, and public-functional pass rates are extracted from
  platform JUnit, with skipped cases not counted as passes.
- Runtime is measured with a monotonic wall clock and reports total, median, p95, and
  throughput. It is descriptive because host and filesystem noise are not controlled.

Run a platform’s public candidate gate with:

```console
pytest -q --junitxml=validation-linux.xml
python scripts/run_benchmark.py \
  --manifest benchmarks/public/v1/manifest.json \
  --causal benchmarks/public/v1/causal.json \
  --known-escapes security/known-sandbox-escapes.json \
  --junit validation-linux.xml --platform linux \
  --public-gate --output public-benchmark-linux.json
```

CI runs this independently on Windows, macOS, and Linux. A public candidate failure is a
hard CI failure, even though stable promotion additionally requires all three platform
artifacts and the protected held-out result.

## Rotating held-out evaluation

Held-out cases never enter this repository. The protected workflow accepts a bounded
archive from the `stable-release-held-out` environment, rejects unsafe archive entries,
requires case IDs disjoint from the public corpus, and emits metrics plus a commitment to
the private case IDs. It does not publish prompts, skills, findings, or case identities.

The result is signed with GitHub artifact provenance. Stable promotion retrieves it by
workflow run ID and verifies repository, signer workflow, exact evaluator source commit,
and non-self-hosted execution before setting the attestation gate. A result for another
release version or commit is rejected. See `benchmarks/held-out/README.md` and
`docs/RELEASE_PROCESS.md`.

## Current development result

`benchmarks/results/0.1.0.dev0-windows.json` is the current Windows development snapshot.
It is a public-preview candidate result, not stable-v1 evidence: it lacks independent
macOS/Linux artifacts and an attested rotating held-out result. The report itself lists
every satisfied gate and every remaining limitation. Stable release reports are generated
and attested by `.github/workflows/release.yml` and attached to the release.
