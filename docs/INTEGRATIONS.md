# Integrations

## GitHub Actions

The repository root contains a reusable composite action. The action installs the checked-out
Agent Skill Doctor source into an isolated runner environment, performs a static check, preserves
the native exit code, and copies the generated SARIF report to a predictable path.

```yaml
name: skill-doctor

on:
  pull_request:
  push:
    branches: [main]

permissions:
  contents: read
  security-events: write

jobs:
  check-skill:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v7
      - id: doctor
        uses: awesome-liuxiao/agent-skill-doctor@v0.1.0a1
        with:
          path: path/to/skill
          platform: codex
          fail-on-findings: true
          sarif: ${{ runner.temp }}/skill-doctor.sarif.json
      - uses: github/codeql-action/upload-sarif@v4
        if: always() && steps.doctor.outputs.sarif != ''
        with:
          sarif_file: ${{ steps.doctor.outputs.sarif }}
```

During the development preview, pin the action to an exact commit when reproducibility matters.
The `main` example favors evaluation convenience and may change.

The action's outputs are:

| Output | Meaning |
| --- | --- |
| `exit-code` | Native audited exit code: 0 clean, 1 blocking finding, 2 incomplete, 3 internal failure, 4 cancelled |
| `sarif` | Absolute path to the generated SARIF report when available |

Set `fail-on-findings: false` to collect SARIF without failing the workflow for exit code 1.
Incomplete analysis and internal failures always fail the action.

After the workflow is active, repositories may display a small attribution badge:

```markdown
[![Checked by Agent Skill Doctor](https://img.shields.io/badge/checked%20by-Agent%20Skill%20Doctor-315FE8)](https://github.com/awesome-liuxiao/agent-skill-doctor)
```

[![Checked by Agent Skill Doctor](https://img.shields.io/badge/checked%20by-Agent%20Skill%20Doctor-315FE8)](https://github.com/awesome-liuxiao/agent-skill-doctor)

## Codex wrapper

The explicit-invocation wrapper is in `wrappers/codex/skill-doctor`. Install that directory through
your Codex skill-install flow, then invoke `$skill-doctor`. The wrapper never downloads or executes
a backend by itself.

## Claude Code wrapper

The explicit-invocation wrapper is in `wrappers/claude/skill-doctor`. Install that directory through
your Claude Code skill flow, then invoke `/skill-doctor`.

Both wrappers preserve the same advisory-only, consent-before-execution contract as the CLI.
