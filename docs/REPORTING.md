# Reports, CI, suppressions, and export

Every completed diagnosis writes four local artifacts with the same stable finding and evidence
identifiers:

- versioned JSON for lossless machine processing;
- offline HTML with collapsible evidence, dynamic-trial timeline, causal edges, and local paths;
- SARIF 2.1.0 for code-scanning integrations;
- JUnit XML for test-result integrations.

The HTML has no scripts or external resources. All untrusted content is HTML-escaped and a CSP
denies scripts, connections, frames, objects, images, media, fonts, forms, and base-URL changes.
The terminal shows a concise conclusion, high-confidence highlighting, the smallest next
experiment, one remediation lead, and every artifact path. `status JOB_ID --verbose` is the
terminal fallback for structured event details. Long worker stages emit a path-free, evidence-free
heartbeat every 30 seconds.

Reports do not use `safe` or `healthy` as an unconditional conclusion. A lack of highlighted
findings means only that completed checks did not establish a blocking issue.

## CI exit policy

- `0`: no unsuppressed high-severity, high-confidence finding;
- `1`: at least one unsuppressed high-severity, high-confidence finding;
- `2`: incomplete analysis or readiness failure;
- `3`: internal failure;
- `4`: cancellation.

Lower-severity and lower-confidence observations remain visible but do not block by default.
`blocking_finding_ids` and `suppressed_finding_ids` make the decision auditable in every format.

## Expiring suppressions

Use `~/.skill-doctor/suppressions.json` or the nearest ancestor project file at
`.skill-doctor/suppressions.json`. Project entries replace user entries with the same suppression
ID. Every entry requires a reason, expiry, exact snapshot hash, and rule-set version:

```json
{
  "version": 1,
  "suppressions": [
    {
      "id": "accepted-fixture-risk",
      "rule_id": "ASD900",
      "finding_id": "finding-id-from-report",
      "reason": "Owner reviewed the bounded fixture.",
      "created_at": "2026-07-16T00:00:00Z",
      "expires_at": "2026-08-16T00:00:00Z",
      "snapshot_hash": "64-lowercase-hex-characters",
      "ruleset_version": "ruleset-from-report"
    }
  ]
}
```

Expired entries stop applying. A content or rule-set change marks an entry stale instead of
silently carrying it forward. Active, stale, expired, and unmatched entries remain in the report
audit. The strict document shape is published in `schemas/suppressions.schema.json`.

## Local feedback

Record the owner's disposition without changing the skill:

```console
skill-doctor feedback JOB_ID FINDING_ID --disposition confirmed
skill-doctor feedback JOB_ID FINDING_ID --disposition rejected --reason "Verified false positive"
skill-doctor feedback JOB_ID FINDING_ID --disposition unresolved
```

The disposition is locally indexed against the report snapshot and rules. The optional reason is
stored as an encrypted artifact rather than plaintext in SQLite.

## Sanitized export

Export is a two-step local operation. The first command creates no bundle; it previews file sizes,
hashes, exclusions, redactions, and an immutable approval token:

```console
skill-doctor export JOB_ID --json
skill-doctor export JOB_ID --approve PREVIEW_TOKEN --json
```

The resulting ZIP excludes raw prompts, raw traces, credentials, and encrypted local artifacts.
It removes absolute paths, artifact hashes, full inventory/configuration paths, collection paths,
and suppression reasons/source paths. A material report change invalidates the preview token.

## Language

Session reports record the normalized session locale in `report_language`. Commands, paths,
identifiers, and original evidence are never translated. This preview currently has complete
English report strings; a non-English locale is disclosed as a translation fallback in the
diagnostic summary instead of claiming unavailable localization.

The thin Codex and Claude Code wrappers under `wrappers/` are explicit-invocation-only and point
the agent to the concise conclusion and all local artifacts.
