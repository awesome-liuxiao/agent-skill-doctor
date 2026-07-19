# Agent Skill Doctor

Agent Skill Doctor is an advisory-only, local-first diagnostic tool for agent
skills. This repository contains the specification and local static core,
platform discovery, targeted session diagnosis, fail-closed actual-runtime
testing, causal diagnosis, remediation guidance, and performance diagnostics.

It never edits a checked skill or applies patches. Static checks never execute
skill content. Approved dynamic tests invoke the selected runtime only inside
an attested disposable sandbox; there is no direct-host fallback. Findings are
evidence-linked observations, not claims that a skill is universally safe.

## Development preview

Requirements: Python 3.12.

```console
python -m venv .venv
.venv/Scripts/python -m pip install -r requirements-dev.lock
.venv/Scripts/python -m pip install -e .
skill-doctor check path/to/skill --state-dir .doctor
skill-doctor check deploy --platform codex
skill-doctor check --all --platform claude --cwd path/to/repository
skill-doctor diagnose --platform codex
skill-doctor diagnose --platform claude --transcript path/to/transcript.jsonl
skill-doctor purge --flight-recorder
skill-doctor readiness --deep --json
skill-doctor check path/to/skill --dynamic --runtime-version "VERSION" --json
```

On POSIX systems use `.venv/bin/python`. The command starts an authenticated
per-user worker on demand, writes persisted progress as JSONL to stderr, prints
a terminal summary to stdout, and stores a versioned JSON report under the local
state directory. Use `--json` to print the report to stdout. The worker exits
after five idle minutes.

Current-session diagnosis emits its collection manifest before reading the
bounded local trace, selects only skills evidenced by that session, and ranks
non-causal quick hypotheses. The optional flight recorder is disabled by
default; `--flight-recorder` stores only minimized encrypted signals for at
most 24 hours and 50 MB.

Dynamic testing is a two-invocation flow. The first invocation returns a plan,
capability report, cost/runtime estimate, consent scopes, and SHA-256 approval
token without starting a runtime. Repeating the unchanged command with
`--approve-dynamic PLAN_TOKEN` permits sandboxed execution. See
`docs/SANDBOX.md` and `docs/DYNAMIC_TESTING.md` for backend setup, authored eval
contracts, substitutions, proxied authentication, dependency locking, and
static-only fallback behavior. See `docs/PERFORMANCE.md` for explicit budgets,
controlled measurement, strictly keyed baselines, and unsupported metrics.
See `docs/REPORTING.md` for offline HTML, SARIF, JUnit, CI thresholds, expiring
suppressions, local feedback, and two-step sanitized export.
See `docs/INSTALLATION.md`, `docs/REPRODUCIBLE_BUILDS.md`, and `SECURITY.md` for
no-Python standalone installation, attestations, signed rule packs, sandbox
bootstrap, SBOM/provenance, rollback, and key revocation.
See `docs/BENCHMARKS_AND_PROVENANCE.md`, `docs/COMPATIBILITY.md`, and
`docs/RELEASE_PROCESS.md` for the public and held-out corpora, measured gates,
platform/runtime support, design-partner remediation, and stable promotion.

```console
skill-doctor jobs
skill-doctor status JOB_ID
skill-doctor cancel JOB_ID
skill-doctor resume JOB_ID
skill-doctor status JOB_ID --verbose
skill-doctor feedback JOB_ID FINDING_ID --disposition unresolved
skill-doctor export JOB_ID --json
```

Raw snapshot artifacts are AES-256-GCM encrypted. The master key is protected
by Windows DPAPI, macOS Keychain, or Linux Secret Service. If that facility is
unavailable or locked, analysis fails readiness instead of storing plaintext.

## Current scope

The checker can snapshot an explicitly supplied directory or resolve Codex and
Claude Code repository, user, managed, system, command, added-directory, and
plugin copies. Named checks use platform-effective resolution; all-skills
checks preserve inactive and shadowed inventory entries and deduplicate static
analysis by content hash. Bounded Agent Skills metadata, references, secrets,
commands, fallbacks, and five first-class script families are checked without
executing content. Durable jobs use encrypted immutable artifacts, stale-input
checks, cancellation, resumption, and strict versioned caches. See
`docs/DISCOVERY.md` for the documented platform behavior and limitations.
