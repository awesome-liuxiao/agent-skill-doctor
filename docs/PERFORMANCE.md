# Performance and reliability diagnostics

Performance analysis does not impose a universal definition of a fast or cheap skill. The
doctor creates a finding only for an explicit user or project budget, a repeated regression
against a strictly compatible baseline, an approved trial timeout, or attested resource
exhaustion. Other values remain observations.

## Controlled measurement

Add `--measure-performance` to both invocations of an approved dynamic plan. The immutable
approval token then includes the `controlled_load_measurement` consent scope. Actual-runtime
sandboxes share a process-wide execution lock, so these measurements never overlap another
dynamic sandbox in the worker.

Quick runs expose measurements but do not establish a historical baseline. A baseline requires
at least three successful, non-cancelled treatment trials, so use standard or deep depth:

```console
skill-doctor check path/to/skill --dynamic --depth standard \
  --measure-performance --runtime-version "EXACT VERSION" \
  --model MODEL_ID --permission-mode never --sandbox-mode workspace-write --json
```

The report labels each metric as `measured`, `estimated`, `budgeted`, or
`baseline-relative`. Measured values include setup and execution latency, tool and model calls,
reported tokens and cost when the runtime supplies them, workspace disk growth, failure rate,
and output variance. Instruction and initial-catalog context sizes are bounded byte-based token
estimates and disclose that limitation.

Cold/warm load time, process CPU time, peak memory, network bytes, and retry count are currently
reported as unsupported coverage. Host, runtime, model, and service noise is also disclosed;
unsupported metrics are never filled with invented precision.

## Explicit budgets

The user file is `~/.skill-doctor/performance-budgets.json`. The nearest ancestor project file
is `.skill-doctor/performance-budgets.json`; project values override user values. Both are strict
version 1 JSON documents:

```json
{
  "version": 1,
  "default": {
    "max_latency_ms": 10000,
    "max_failure_rate": 0.05
  },
  "skills": {
    "deploy": {
      "max_instruction_tokens": 3000,
      "max_tool_calls": 8,
      "max_cost_usd": 0.25
    }
  }
}
```

Supported limits are documented by `schemas/performance-budgets.schema.json`. Every source is
hashed into the baseline key. Baselines are additionally keyed by skill, platform, runtime,
model, permission mode, configuration, sandbox backend, and rule set. A changed skill snapshot
may compare with the latest otherwise-compatible snapshot; incompatible contexts never share a
baseline.
