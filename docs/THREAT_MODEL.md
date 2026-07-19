# Threat and data-flow model

The skill directory is untrusted. File names, Markdown, frontmatter, scripts,
links, and symlinks may be malicious. Reports are also treated as untrusted data
by future renderers. The invoking user, installed package, and local state root
are trusted for this increment; compromise of those boundaries is out of scope.

```text
CLI -> authenticated local IPC -> durable worker -> bounded reader
                                                |-> encrypted immutable artifacts
                                                |-> deterministic rules -> findings
trusted job configuration ---------------------|                    |-> reports
```

Controls: lexical and resolved containment checks, no symlink traversal,
regular-files-only reads, per-file and aggregate byte limits, bounded file
count, no execution, no network, escaped terminal text, authenticated and
length-bounded JSON IPC, AES-GCM artifact encryption with OS-protected keys,
atomic writes, and database parameterization. Files that race or change while
read cause an incomplete analysis rather than a confident conclusion.

Fallback behavior is static-only and explicit. Unsupported file types reduce
coverage. Failure to read required evidence yields `analysis_incomplete` or
`indeterminate`; it is never reworded as absence of issues.
