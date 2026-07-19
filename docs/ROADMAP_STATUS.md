# Roadmap implementation status

This file maps the roadmap to current authoritative implementation evidence. “Implemented”
means the code, schema, documentation, and local tests exist. It does not replace a release
gate: stable v1 remains false until independently produced external evidence is verified.

| Milestone | Status | Primary evidence |
| --- | --- | --- |
| 0 — specification/security foundation | Implemented | `docs/PRODUCT.md`, `docs/THREAT_MODEL.md`, `docs/DIAGNOSTIC_MODEL.md`, `docs/POLICIES.md`, `docs/adr`, versioned schemas |
| 1 — local static core | Implemented and locally verified | `snapshot.py`, `analysis.py`, `store.py`, `ipc.py`, `worker.py`, `engine.py`, static/hostile/cache/encryption tests |
| 2 — platform discovery | Implemented and locally verified | `discovery.py`, named/all-skill engine paths, Codex/Claude discovery fixtures and resolution tests |
| 3 — session evidence | Implemented and locally verified | `session.py`, current-session diagnosis, minimized flight recorder, trigger and missing-evidence tests |
| 4 — sandbox capability layer | Implemented; release matrix required | `sandbox.py`, `docs/SANDBOX.md`, all three fail-closed adapters, readiness/canary/cancellation tests |
| 5 — real-runtime testing | Implemented; production runtime matrix required | `runtime.py`, `dynamic_orchestration.py`, `evals.py`, two-step approval, exact-context/substitution/control/repetition tests |
| 6 — causal diagnosis | Implemented and locally verified | `causal.py`, `semantic_judge.py`, corroboration/counterfactual/injection-boundary/remediation tests |
| 7 — performance/reliability | Implemented and locally verified | `performance.py`, explicit budgets, non-overlap, strict baselines, measured/unsupported limitation tests |
| 8 — reports/UX/integration | Implemented and locally verified | offline HTML/SARIF/JUnit, stable IDs, suppressions, feedback, export, locale handling, wrapper skills |
| 9 — install/update/supply chain | Implemented and locally verified | signed rule packs/bootstrap, telemetry allow-schema, installers, release bundles/SBOM/provenance workflows, security policy |
| 10 — benchmark/hardening/release | Implementation complete; external promotion evidence pending | public/licensed/functional/causal corpora, fault suite, current result, held-out/design-partner workflows, three-OS stable gate |

The current local quality gate is:

```text
ruff format --check: pass
ruff check: pass
mypy --strict: pass
pytest: 138 passed, 3 skipped (Windows symlink privilege only)
pip check: pass
Windows public candidate gate: pass
wheel content check: pass
Windows standalone smoke/readiness: pass (static-only readiness exit 2 as expected)
two clean standalone builds: byte-identical SHA-256
WSL2 Linux/Python 3.12 quality and public candidate gate: pass (local, not attested)
WSL2 Linux standalone smoke/readiness/SBOM/manifest: pass
two clean Linux standalone builds: byte-identical SHA-256
Darwin-targeted strict mypy pass: pass (typing only, not macOS execution)
```

The checked-in Windows development report records 100% highlighted precision, 0% benign
false positives, 100% expected-finding recall, 100% supported static completion, 100% causal
classification accuracy, 90% reproduction consistency, 100% containment/runtime checks,
100% fault injection, and 100% public functional checks on the versioned public corpus.
The separately named `0.1.0.dev0-linux-wsl.json` records the same public candidate gate from
a disposable WSL2 CPython 3.12.13 environment. Its 134 passed and 7 skipped tests reflect the
unavailable desktop Secret Service and non-Windows credential integration. It is useful local
cross-platform evidence but is deliberately not accepted as the required GitHub-hosted Linux
release artifact.

Stable v1 is intentionally not asserted by local evidence. The remaining requirements are
external outcomes, and the normal release path fails closed until all are supplied:

- independent Windows, macOS, and Linux validation artifacts from the exact release commit;
- an independently reviewed rotating held-out corpus result from the protected workflow;
- a completed private design-partner alpha, remediation period, and public preview recorded
  by the protected sign-off workflow; and
- successful GitHub provenance verification for both protected evidence artifacts.

Publishing the development repository does not satisfy those protected release workflows. They
still require an exact tagged release ref plus independently produced and verified evidence; no
synthetic local result is substituted for them.
