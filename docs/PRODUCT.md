# Product requirements and non-goals

Status: frozen for schema version 1 / Milestone 1 local core.

Agent Skill Doctor explains why an agent skill may have failed, the causal role
it may have played, and the local evidence supporting that conclusion. Version
1 is advisory-only and local-first. Milestone 1 accepts one explicit local
skill directory and performs bounded static analysis through an authenticated,
durable local worker.

## Required behavior

- Preserve input bytes in immutable, encrypted, content-addressed snapshots.
- Never follow symlinks or allow a referenced path to escape the skill root.
- Link every finding and result claim to evidence or identify missing coverage.
- Keep severity, confidence, coverage, causal role, and result state separate.
- Produce deterministic terminal and versioned JSON reports.
- Persist durable jobs and JSONL events with cancellation and resumption.
- Authenticate local IPC and shut the worker down after five idle minutes.
- Treat malformed and hostile content as data and fail closed within limits.

## Non-goals for Milestone 1

No skill edits, patches, agent-runtime execution, model calls, network access,
platform discovery, session diagnosis, portability comparison, HTML/SARIF/JUnit
output, or safety certification. Later milestones add those capabilities only
behind their own evidence, consent, and containment gates.
