# Actual-runtime dynamic testing

Dynamic tests use the originating platform only. Codex runs through `codex
exec --json --ephemeral`; Claude Code runs through print mode with stream JSON,
no session persistence, and bare configuration. Both receive prompts over
stdin. The doctor verifies the exact expected `--version` output inside the
sandbox before any model call.

## Plan, review, approve

Planning never starts a runtime. Supply every material context value during
planning so the returned token covers the intended snapshot, platform,
runtime, model, permission mode, sandbox mode, configuration hash, network,
dependency proxy, substitutions, test depth, and consent scopes.

```console
skill-doctor check path/to/skill --dynamic --depth quick \
  --platform codex \
  --runtime-version "codex-cli 1.2.3" \
  --model MODEL_ID \
  --permission-mode never \
  --sandbox-mode workspace-write \
  --runtime-config path/to/captured-config.toml
```

Review `dynamic_test_plan`, `sandbox_readiness`, time, runtime uses, and consent
scopes. Then repeat the same command with the returned token:

```console
skill-doctor check path/to/skill --dynamic --depth quick \
  --platform codex \
  --runtime-version "codex-cli 1.2.3" \
  --model MODEL_ID \
  --permission-mode never \
  --sandbox-mode workspace-write \
  --runtime-config path/to/captured-config.toml \
  --approve-dynamic PLAN_SHA256
```

Any material change produces a different token and prevents execution. Quick,
standard, and deep are independently approved scopes. Quick runs one targeted
case once. Standard selects up to three cases, repeats each three times, and
adds no-skill controls. Deep selects all cases, repeats each five times, and
adds controls. Dynamic sandboxes are serialized by default.

Model prices change independently of the doctor. Pass an operator-reviewed
`--estimated-cost-per-run USD` during both invocations to include a model-cost
estimate in the immutable plan; otherwise the cost remains explicitly unknown.

If an exact configuration is unavailable, omit `--runtime-config` and add
`--approve-substitution`; the plan discloses
`clean_configuration_substitution`. Historical runtime or model replacements
use `--substitute-runtime` or `--substitute-model` and the same explicit
substitution approval. Reports preserve both originating and substituted
identifiers.

Cloud authentication must use an attested proxy. Put a short-lived token in
the form `asd-job-UNIX_EXPIRY-RANDOM` in `SKILL_DOCTOR_EPHEMERAL_TOKEN`; the
expiry must be no more than 15 minutes away. Never put the token on the command
line. Use `--runtime-proxy` and one or more
`--allow-domain` values. The token value is neither stored in job options nor
written to the report. A long-running worker that did not inherit the token
reports missing authentication rather than using host credentials.

## Contracts and evidence

Authored contracts live at `evals/evals.json` and conform to
`schemas/evals.schema.json`. Version 1 supports bounded prompts, timeouts,
tags, exit-code assertions, output fragments and bounded regular expressions,
and workspace file presence or absence. `x-*` extensions are retained as
metadata and never executed.

Without authored evals, the doctor derives one provisional purpose test from
the skill description. Inferred contracts are untrusted. They can be promoted
for one job with `--promote-inferred`, but an unpromoted inferred contract can
never confirm functional correctness.

Reports identify runtime, model, permission mode, configuration hash,
substitutions, sandbox backend and image/runner attestations, dependency lock
and setup hashes, rule-pack version, repetition, control status, and assertion
results. Raw stdout and stderr are not embedded in reports; their hashes refer
to AES-256-GCM encrypted local artifacts. No-skill controls keep the dependency
source available at `/opt/skill` while withholding the skill from platform
discovery.

If secure execution is unavailable, the report includes the exact sandbox
coverage gaps and remains static-only. It never invokes the runtime directly on
the host.
