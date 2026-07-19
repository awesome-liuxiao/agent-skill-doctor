---
name: skill-doctor
description: Use only when the user explicitly invokes /skill-doctor to diagnose an agent skill.
---

# Agent Skill Doctor for Claude Code

This wrapper is explicit-invocation-only. Do not activate it from description similarity, an
ordinary error, or a general request for debugging.

When explicitly invoked, explain that the doctor is advisory-only and local-first, then run:

```console
skill-doctor diagnose --platform claude
```

Show the concise conclusion and every local artifact path. If the report proposes dynamic
execution or export, show the plan or preview first and wait for the user's exact approval token.
Never edit the diagnosed skill, execute skill content directly, bypass a sandbox readiness gap,
or describe an `indeterminate` result as safe or healthy.
