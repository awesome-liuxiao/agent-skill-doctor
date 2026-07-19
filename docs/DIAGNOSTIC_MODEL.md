# Diagnostic and claim model

Causal roles are `caused`, `contributed`, `exposed`, `unrelated`, and
`indeterminate`. This static increment emits only `indeterminate`; stronger
roles require later reproduction and counterfactual evidence.

Result states are `confirmed_issues`, `no_confirmed_issues`, `indeterminate`,
`analysis_incomplete`, `cancelled`, and `internal_error`. Static rule matches do
not alone confirm a root cause. A clean bounded scan is `no_confirmed_issues`
only with an explicit coverage statement and never means “safe” or “healthy.”

Severity (`info`, `low`, `medium`, `high`, `critical`) describes potential
impact. Confidence (`low`, `medium`, `high`) describes evidential support.
Coverage records completed, skipped, unsupported, and failed checks. These
dimensions must not be collapsed into a single score.

Every user-visible finding requires: a stable rule identifier, message,
location when available, at least one evidence identifier, severity,
confidence, and causal role. Result-state claims require the finding set,
coverage record, and job input hash. Missing evidence must be stated.

