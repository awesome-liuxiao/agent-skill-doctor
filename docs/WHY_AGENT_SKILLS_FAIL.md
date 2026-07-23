# Why agent skills fail in surprising ways

An agent skill can fail loudly while leaving almost no trustworthy evidence about why it failed.
The command may be wrong. A referenced file may have moved. The skill may never have triggered. The
runtime may lack a dependency. Or the skill may be innocent while a nearby configuration change is
the real cause.

That ambiguity is why “the agent behaved badly” is a symptom, not a diagnosis.

Agent Skill Doctor is an experiment in making this debugging process more disciplined. Its public
alpha checks Codex and Claude Code skills locally, records exactly which checks ran, and links each
finding back to evidence. It is deliberately advisory: static analysis never executes the skill or
rewrites its files.

## A skill document is code-adjacent input

A skill often mixes prose, metadata, links, scripts, shell fragments, and instructions that cause
an agent to use other tools. Reviewing it only as documentation misses important failure modes;
treating it exactly like conventional source code misses the role of language and runtime context.

A safer starting point is to treat every skill as untrusted data. Agent Skill Doctor first creates
a bounded, content-addressed snapshot. Static rules inspect that snapshot without following
symlinks outside the skill root, fetching remote content, or obeying instructions embedded in the
document.

That boundary matters. A diagnostic tool should not become a second execution path for the thing it
is inspecting.

## Four ideas that should not collapse into one score

Developer tools often reduce a result to red, yellow, or green. That is convenient, but it can hide
the most useful parts of a diagnosis. Agent Skill Doctor keeps four dimensions separate:

- **Severity** describes the potential impact of an observation.
- **Confidence** describes how strongly the evidence supports that observation.
- **Coverage** records which checks completed, failed, were skipped, or are unsupported.
- **Causal role** distinguishes a correlation from a reproduced cause.

A high-confidence broken link is still not automatically the cause of an unrelated runtime
failure. Likewise, a clean static run does not prove that a skill is safe. It means only that the
completed checks did not establish a blocking issue. The report carries missing coverage beside the
result so downstream automation cannot quietly erase that uncertainty.

## Two tiny examples

Consider a skill containing this reference:

```markdown
Read [the deployment checklist](references/deployment-checklist.md).
```

If the target does not exist, a deterministic rule can identify the exact source line. That is a
strong observation and a useful repair lead. It is not yet proof that the missing file caused the
user's reported symptom.

Now consider:

```sh
curl https://example.invalid/install | sh
```

Pipe-to-shell installation deserves review because it joins network retrieval and execution with
no integrity check. A static analyzer can flag the pattern without making the request or running
the command. The owner can then decide whether to pin, verify, replace, or remove it.

Both examples are included in the repository's deliberately broken demo skill. They make the first
run reproducible without asking anyone to upload a private skill.

## Why reproduction needs a consent boundary

Static evidence has limits. Trigger behavior, runtime compatibility, permissions, and environment
interactions may require an actual agent run. But automatic reproduction can spend money, touch the
network, invoke tools, and expose sensitive inputs.

For that reason, Agent Skill Doctor's dynamic path is two-step. The first request creates a plan
that describes the runtime, permissions, sandbox, cases, and estimated cost. It does not execute the
plan. Execution requires the caller to repeat the unchanged request with the plan's approval token.
Any material change invalidates that token.

If the required sandbox or attestation is unavailable, the operation fails closed. There is no
silent fallback to direct host execution.

## What the alpha evidence says

The checked-in public benchmark currently exercises static detection, benign fixtures, causal
classification, containment, fault injection, and functional flows. The repository publishes the
fixture counts, gate definitions, and limitations in the
[public benchmark snapshot](STATE_OF_AGENT_SKILLS.md).

Those results are development evidence, not an ecosystem survey and not a stable-v1 claim. The
project still needs independent held-out evaluation, cross-platform evidence, and sanitized results
from maintainers of real skills. Publishing that gap is more useful than hiding it behind a badge.

## An invitation to skill maintainers

If you maintain Codex or Claude Code skills, the most valuable feedback is not a star. It is a
sanitized answer to one of these questions:

- Which finding was genuinely useful?
- Which warning was noise?
- Which important problem went undetected?
- Where did installation or interpretation become confusing?
- Did the report make its uncertainty obvious?

The alpha runs locally and does not require sharing raw prompts, credentials, customer data, or the
skill itself. The [design-partner guide](DESIGN_PARTNERS.md) explains how to share only a minimal,
sanitized outcome.

The goal is not to make every agent failure look certain. It is to make the boundary between what we
observed, what we inferred, and what we still need to test impossible to miss.
