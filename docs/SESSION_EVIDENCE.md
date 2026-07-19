# Current-session evidence contract

Milestone 3 adds targeted current-session triage without continuous
monitoring. `skill-doctor diagnose` uses the originating platform only. It
does not invoke Codex or Claude Code, execute a skill, or send trace content to
another service.

## Source selection

For Codex, an exact `CODEX_THREAD_ID` match under `~/.codex/sessions` is
high-confidence native evidence. For Claude Code, an exact
`CLAUDE_SESSION_ID` match under `~/.claude/projects` is high-confidence native
evidence. Without an exact ID match, the newest local transcript is explicitly
labeled reduced confidence. `--transcript PATH` accepts a visible transcript as
an explicit reduced-confidence reconstruction source.

The source contract follows the official platform documentation current on
2026-07-16:

- Codex retains session transcripts under `~/.codex/sessions`; the hook
  `transcript_path` format is convenient but not a stable interface.
- Claude Code retains local session transcripts under `~/.claude/projects` and
  exposes `session_id` plus `transcript_path` to hooks; the file can lag the
  in-memory turn while it is being written.

Primary references:

- <https://learn.chatgpt.com/docs/customization/hooks>
- <https://learn.chatgpt.com/docs/config-file/basic-config>
- <https://code.claude.com/docs/en/hooks>
- <https://code.claude.com/docs/en/data-usage>

## Collection and minimization

Before reading a trace, the worker emits a collection event containing only
the source kind, path, byte count, confidence, and reason. Trace reads are
bounded to 50 MB, 100,000 lines, and 2 MB per line. The report never includes
prompt or response bodies. It retains only:

- session, runtime, model, working-directory, and permission metadata;
- tool names and aggregate timing statistics;
- selector or `SKILL.md` access signals;
- categorized error counts; and
- parse/change coverage limitations.

Missing evidence is a failed coverage dimension and an `analysis incomplete`
result. A trace that contains no target is evidence of absence only within the
collected coverage; it does not cause all installed skills to be analyzed.

## Targeting and quick hypotheses

Exact invocation and manifest-access signals are resolved through the
originating platform inventory. Only effective resolved targets receive static
analysis. Genuine ambiguity is reported and never guessed.

When no invocation signal exists, deterministic word overlap may identify up
to three active repository/project trigger candidates. Candidates require at
least two shared description terms. They are reported as low- or
medium-confidence leads and are not statically analyzed merely because they
are installed.

Quick hypotheses rank permission, dependency, configuration, runtime, static
skill, and trigger explanations. They are explicitly non-causal: confirmation
requires the later reproduction and counterfactual milestones.

## Optional flight recorder

The flight recorder is off by default and enabled per diagnosis with
`--flight-recorder`. It records only the minimized selector list, error-category
counts, session/runtime identifiers, confidence, and snapshot hashes. Each
record is AES-256-GCM encrypted using the same OS-protected master-key boundary
as snapshots.

The recorder is a 50 MB ring with a hard 24-hour expiry. Oldest records are
evicted first. `skill-doctor purge --flight-recorder` deletes indexed records
and any remaining encrypted recorder files immediately.
