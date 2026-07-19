# Platform discovery contract

This document records the behavior implemented by the Milestone 2 adapters. It
was reviewed against the official Codex manual and Claude Code documentation on
2026-07-16. The supported-runtime compatibility window is the preceding 90
days; fixture changes require a source review and an explicit compatibility
note.

Discovery is read-only. Every lexical copy remains in the inventory even when
it is disabled, shadowed, deduplicated through a symlink target, malformed, or
unresolved. Analysis snapshots the resolved target but reports both the lexical
origin and resolved path.

## Codex

The adapter scans `.agents/skills` from the working directory through the
repository root, `$HOME/.agents/skills`, `/etc/codex/skills` (with an
OS-appropriate configurable admin root), bundled system skills, the legacy
`$CODEX_HOME/skills` location used by current desktop installations, and
installed plugin cache copies at
`$CODEX_HOME/plugins/cache/<marketplace>/<plugin>/<version>/skills`.

`[[skills.config]]` entries whose exact `SKILL.md` path has `enabled = false`
remain visible as inactive. Plugin state is read from
`[plugins."<plugin>@<marketplace>"].enabled`; installed copies lacking an
explicit off switch are treated as enabled. Codex documents that same-name
skills are not merged or silently precedence-selected, so multiple active
selectors are reported as genuinely ambiguous and a named check refuses to
guess. Directory symlinks are followed, while aliases resolving to the same
target are loaded and analyzed once.

Primary references:

- <https://learn.chatgpt.com/docs/customization/skills.md>
- <https://learn.chatgpt.com/docs/plugins>

## Claude Code

The adapter scans enterprise managed-policy skills, personal
`~/.claude/skills`, `.claude/skills` in the start directory and every parent to
the repository root, nested skill roots activated by files being worked on,
`.claude/skills` under explicit `--add-dir` locations, legacy personal/project
`.claude/commands/*.md`, and installed plugin cache copies.

Effective unqualified precedence is enterprise, personal, then project. A
skill beats a same-name legacy command. Nested same-name variants remain
available under a working-directory-relative selector such as
`apps/web:deploy`, while a unique nested skill remains unqualified. Plugin
skills use `<plugin>:<skill>` selectors and therefore do not collide with
ordinary skills. Resolved settings apply `skillOverrides`, `enabledPlugins`,
and managed `strictPluginOnlyCustomization`; policy-blocked sources stay in the
inventory as inactive. `permissions.additionalDirectories` is deliberately not
treated as skill discovery because Claude Code only gives that exception to
`--add-dir` and `/add-dir`.

Legacy command files receive the same bounded content snapshot, suspicious
pattern, secret, and path-hazard checks as directory skills. Optional command
frontmatter is parsed, but Agent Skills-required `name` and `description`
fields are not invented. Project-relative reference existence remains an
explicit coverage limitation when only the command file is snapshotted.

Primary references:

- <https://code.claude.com/docs/en/skills>
- <https://code.claude.com/docs/en/settings>
- <https://code.claude.com/docs/en/plugins-reference>

## Report semantics

Statuses are independent of analysis results:

- `active`: the platform can select this copy.
- `inactive`: configuration, policy, or plugin enablement disables it.
- `shadowed`: another copy wins precedence, or the same resolved target was
  already inventoried.
- `ambiguous`: Codex exposes more than one active copy under one selector.
- `unresolved`: the entrypoint or symlink target cannot be read safely.

`check <selector>` analyzes only the effective active copy and fails with the
candidate locations when selection is genuinely ambiguous. `check --all`
keeps and attempts bounded static analysis of every resolvable copy, including
inactive and shadowed copies. Identical snapshots are analyzed once per job and
the report maps the shared content hash back to every copy. The report also
includes a quick dynamic-test estimate before any runtime use is approved;
model cost remains explicitly unknown until a runtime, model, and billing mode
are selected.
