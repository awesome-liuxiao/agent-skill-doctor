from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Literal, cast

SCHEMA_VERSION = "1.0.0"
Severity = Literal["info", "low", "medium", "high", "critical"]
Confidence = Literal["low", "medium", "high"]
CausalRole = Literal["caused", "contributed", "exposed", "unrelated", "indeterminate"]
ResultState = Literal[
    "confirmed_issues",
    "no_confirmed_issues",
    "indeterminate",
    "analysis_incomplete",
    "cancelled",
    "internal_error",
]
JobStatus = Literal["queued", "running", "complete", "failed", "cancelled"]
ReportScope = Literal["explicit", "named", "all", "session"]


@dataclass(frozen=True, slots=True)
class Evidence:
    id: str
    kind: str
    description: str
    artifact_hash: str | None = None
    path: str | None = None
    line: int | None = None


@dataclass(frozen=True, slots=True)
class Finding:
    id: str
    rule_id: str
    title: str
    message: str
    severity: Severity
    confidence: Confidence
    causal_role: CausalRole
    evidence_ids: tuple[str, ...]
    path: str | None = None
    line: int | None = None


@dataclass(frozen=True, slots=True)
class Event:
    schema_version: str
    job_id: str
    sequence: int
    timestamp: str
    stage: str
    summary: str
    detail: str | None = None


@dataclass(frozen=True, slots=True)
class JobRecord:
    schema_version: str
    id: str
    created_at: str
    updated_at: str
    status: JobStatus
    operation: str
    input_path: str
    options: dict[str, Any]
    attempt: int
    cancel_requested: bool
    snapshot_hash: str | None = None
    report_path: str | None = None
    result_state: ResultState | None = None
    error: str | None = None


@dataclass(frozen=True, slots=True)
class Consent:
    schema_version: str
    job_id: str
    granted_at: str
    scopes: tuple[str, ...]
    denied_scopes: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class Coverage:
    completed: tuple[str, ...] = ()
    skipped: tuple[str, ...] = ()
    unsupported: tuple[str, ...] = ()
    failed: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class AnalyzedCopy:
    copy_ids: tuple[str, ...]
    selectors: tuple[str, ...]
    snapshot_hash: str | None
    analyzed: bool
    reused_by_content_hash: bool
    reason: str | None = None


@dataclass(frozen=True, slots=True)
class DynamicTestPlan:
    depth: str
    skill_count: int
    test_count: int
    estimated_seconds: int
    runtime_uses: int
    estimated_model_cost_usd: float | None
    requires_approval: bool = True
    authored_test_count: int = 0
    inferred_test_count: int = 0
    repetitions: int = 1
    control_runs: int = 0
    required_consent_scopes: tuple[str, ...] = ()
    approval_token: str | None = None


@dataclass(frozen=True, slots=True)
class CollectionRecord:
    kind: str
    path: str | None
    bytes: int | None
    collected: bool
    confidence: str
    reason: str | None = None


@dataclass(frozen=True, slots=True)
class SessionTarget:
    selector: str
    copy_id: str | None
    reason: str
    confidence: Confidence
    analyzed: bool


@dataclass(frozen=True, slots=True)
class TriggerCandidate:
    selector: str
    copy_id: str
    shared_term_count: int
    confidence: Confidence


@dataclass(frozen=True, slots=True)
class Hypothesis:
    id: str
    category: str
    summary: str
    confidence: Confidence
    rank: int
    evidence_ids: tuple[str, ...] = ()


@dataclass(slots=True)
class StaticAnalysis:
    findings: list[Finding] = field(default_factory=list)
    evidence: list[Evidence] = field(default_factory=list)
    coverage: Coverage = field(default_factory=Coverage)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> StaticAnalysis:
        try:
            raw_findings = cast(list[dict[str, Any]], payload["findings"])
            raw_evidence = cast(list[dict[str, Any]], payload["evidence"])
            raw_coverage = cast(dict[str, list[str]], payload["coverage"])
            findings = [
                Finding(
                    id=str(item["id"]),
                    rule_id=str(item["rule_id"]),
                    title=str(item["title"]),
                    message=str(item["message"]),
                    severity=cast(Severity, item["severity"]),
                    confidence=cast(Confidence, item["confidence"]),
                    causal_role=cast(CausalRole, item["causal_role"]),
                    evidence_ids=tuple(str(value) for value in item["evidence_ids"]),
                    path=None if item.get("path") is None else str(item["path"]),
                    line=None if item.get("line") is None else int(item["line"]),
                )
                for item in raw_findings
            ]
            evidence = [
                Evidence(
                    id=str(item["id"]),
                    kind=str(item["kind"]),
                    description=str(item["description"]),
                    artifact_hash=(
                        None if item.get("artifact_hash") is None else str(item["artifact_hash"])
                    ),
                    path=None if item.get("path") is None else str(item["path"]),
                    line=None if item.get("line") is None else int(item["line"]),
                )
                for item in raw_evidence
            ]
            coverage = Coverage(
                completed=tuple(str(value) for value in raw_coverage["completed"]),
                skipped=tuple(str(value) for value in raw_coverage["skipped"]),
                unsupported=tuple(str(value) for value in raw_coverage["unsupported"]),
                failed=tuple(str(value) for value in raw_coverage["failed"]),
            )
        except (KeyError, TypeError, ValueError) as error:
            raise ValueError("invalid cached static analysis") from error
        return cls(findings, evidence, coverage)


@dataclass(slots=True)
class Report:
    schema_version: str
    job_id: str
    created_at: str
    tool_version: str
    ruleset_version: str
    result_state: ResultState
    input_path: str
    snapshot_hash: str
    findings: list[Finding] = field(default_factory=list)
    evidence: list[Evidence] = field(default_factory=list)
    coverage: Coverage = field(default_factory=Coverage)
    limitations: list[str] = field(default_factory=list)
    scope: ReportScope = "explicit"
    platform: str | None = None
    inventory: dict[str, Any] | None = None
    analyzed_copies: list[AnalyzedCopy] = field(default_factory=list)
    dynamic_test_plan: DynamicTestPlan | None = None
    session_id: str | None = None
    collection_manifest: list[CollectionRecord] = field(default_factory=list)
    session_environment: dict[str, Any] | None = None
    session_targets: list[SessionTarget] = field(default_factory=list)
    trigger_candidates: list[TriggerCandidate] = field(default_factory=list)
    hypotheses: list[Hypothesis] = field(default_factory=list)
    sandbox_readiness: dict[str, Any] | None = None
    dynamic_results: list[dict[str, Any]] = field(default_factory=list)
    causal_graph: dict[str, Any] | None = None
    remediations: list[dict[str, Any]] = field(default_factory=list)
    diagnostic_summary: dict[str, Any] | None = None
    performance: dict[str, Any] | None = None
    artifacts: dict[str, Any] | None = None
    suppression_audit: dict[str, Any] | None = None
    suppressed_finding_ids: list[str] = field(default_factory=list)
    blocking_finding_ids: list[str] = field(default_factory=list)
    report_language: str = "en"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> Report:
        analysis = StaticAnalysis.from_dict(
            {
                "findings": payload["findings"],
                "evidence": payload["evidence"],
                "coverage": payload["coverage"],
            }
        )
        limitations = payload["limitations"]
        if not isinstance(limitations, list) or not all(
            isinstance(value, str) for value in limitations
        ):
            raise ValueError("invalid report limitations")
        return cls(
            schema_version=str(payload["schema_version"]),
            job_id=str(payload["job_id"]),
            created_at=str(payload["created_at"]),
            tool_version=str(payload["tool_version"]),
            ruleset_version=str(payload["ruleset_version"]),
            result_state=cast(ResultState, payload["result_state"]),
            input_path=str(payload["input_path"]),
            snapshot_hash=str(payload["snapshot_hash"]),
            findings=analysis.findings,
            evidence=analysis.evidence,
            coverage=analysis.coverage,
            limitations=limitations,
            scope=cast(ReportScope, payload.get("scope", "explicit")),
            platform=(None if payload.get("platform") is None else str(payload["platform"])),
            inventory=_optional_dict(payload.get("inventory"), "report inventory"),
            analyzed_copies=_analyzed_copies(payload.get("analyzed_copies", [])),
            dynamic_test_plan=_dynamic_test_plan(payload.get("dynamic_test_plan")),
            session_id=(None if payload.get("session_id") is None else str(payload["session_id"])),
            collection_manifest=_collection_records(payload.get("collection_manifest", [])),
            session_environment=_optional_dict(
                payload.get("session_environment"), "session environment"
            ),
            session_targets=_session_targets(payload.get("session_targets", [])),
            trigger_candidates=_trigger_candidates(payload.get("trigger_candidates", [])),
            hypotheses=_hypotheses(payload.get("hypotheses", [])),
            sandbox_readiness=_optional_dict(payload.get("sandbox_readiness"), "sandbox readiness"),
            dynamic_results=_object_list(payload.get("dynamic_results", []), "dynamic results"),
            causal_graph=_optional_dict(payload.get("causal_graph"), "causal graph"),
            remediations=_object_list(payload.get("remediations", []), "remediations"),
            diagnostic_summary=_optional_dict(
                payload.get("diagnostic_summary"), "diagnostic summary"
            ),
            performance=_optional_dict(payload.get("performance"), "performance report"),
            artifacts=_optional_dict(payload.get("artifacts"), "report artifacts"),
            suppression_audit=_optional_dict(payload.get("suppression_audit"), "suppression audit"),
            suppressed_finding_ids=_string_list(
                payload.get("suppressed_finding_ids", []), "suppressed finding identifiers"
            ),
            blocking_finding_ids=_string_list(
                payload.get("blocking_finding_ids", []), "blocking finding identifiers"
            ),
            report_language=str(payload.get("report_language", "en")),
        )


def _optional_dict(value: object, label: str) -> dict[str, Any] | None:
    if value is None:
        return None
    if not isinstance(value, dict):
        raise ValueError(f"invalid {label}")
    return cast(dict[str, Any], value)


def _analyzed_copies(value: object) -> list[AnalyzedCopy]:
    if not isinstance(value, list):
        raise ValueError("invalid analyzed copies")
    result: list[AnalyzedCopy] = []
    try:
        for raw in value:
            if not isinstance(raw, dict):
                raise ValueError("invalid analyzed copy")
            item = cast(dict[str, Any], raw)
            result.append(
                AnalyzedCopy(
                    copy_ids=tuple(str(entry) for entry in item["copy_ids"]),
                    selectors=tuple(str(entry) for entry in item["selectors"]),
                    snapshot_hash=(
                        None if item.get("snapshot_hash") is None else str(item["snapshot_hash"])
                    ),
                    analyzed=bool(item["analyzed"]),
                    reused_by_content_hash=bool(item["reused_by_content_hash"]),
                    reason=None if item.get("reason") is None else str(item["reason"]),
                )
            )
    except (KeyError, TypeError) as error:
        raise ValueError("invalid analyzed copies") from error
    return result


def _dynamic_test_plan(value: object) -> DynamicTestPlan | None:
    if value is None:
        return None
    if not isinstance(value, dict):
        raise ValueError("invalid dynamic test plan")
    item = cast(dict[str, Any], value)
    try:
        raw_cost = item.get("estimated_model_cost_usd")
        return DynamicTestPlan(
            depth=str(item["depth"]),
            skill_count=int(item["skill_count"]),
            test_count=int(item["test_count"]),
            estimated_seconds=int(item["estimated_seconds"]),
            runtime_uses=int(item["runtime_uses"]),
            estimated_model_cost_usd=None if raw_cost is None else float(raw_cost),
            requires_approval=bool(item["requires_approval"]),
            authored_test_count=int(item.get("authored_test_count", 0)),
            inferred_test_count=int(item.get("inferred_test_count", 0)),
            repetitions=int(item.get("repetitions", 1)),
            control_runs=int(item.get("control_runs", 0)),
            required_consent_scopes=tuple(
                str(scope) for scope in item.get("required_consent_scopes", [])
            ),
            approval_token=(
                None if item.get("approval_token") is None else str(item["approval_token"])
            ),
        )
    except (KeyError, TypeError, ValueError) as error:
        raise ValueError("invalid dynamic test plan") from error


def _object_list(value: object, label: str) -> list[dict[str, Any]]:
    if not isinstance(value, list) or not all(isinstance(item, dict) for item in value):
        raise ValueError(f"invalid {label}")
    return cast(list[dict[str, Any]], value)


def _string_list(value: object, label: str) -> list[str]:
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise ValueError(f"invalid {label}")
    return cast(list[str], value)


def _collection_records(value: object) -> list[CollectionRecord]:
    try:
        return [
            CollectionRecord(
                kind=str(item["kind"]),
                path=None if item.get("path") is None else str(item["path"]),
                bytes=None if item.get("bytes") is None else int(item["bytes"]),
                collected=bool(item["collected"]),
                confidence=str(item["confidence"]),
                reason=None if item.get("reason") is None else str(item["reason"]),
            )
            for item in _object_list(value, "collection manifest")
        ]
    except (KeyError, TypeError, ValueError) as error:
        raise ValueError("invalid collection manifest") from error


def _session_targets(value: object) -> list[SessionTarget]:
    try:
        return [
            SessionTarget(
                selector=str(item["selector"]),
                copy_id=None if item.get("copy_id") is None else str(item["copy_id"]),
                reason=str(item["reason"]),
                confidence=cast(Confidence, item["confidence"]),
                analyzed=bool(item["analyzed"]),
            )
            for item in _object_list(value, "session targets")
        ]
    except (KeyError, TypeError, ValueError) as error:
        raise ValueError("invalid session targets") from error


def _trigger_candidates(value: object) -> list[TriggerCandidate]:
    try:
        return [
            TriggerCandidate(
                selector=str(item["selector"]),
                copy_id=str(item["copy_id"]),
                shared_term_count=int(item["shared_term_count"]),
                confidence=cast(Confidence, item["confidence"]),
            )
            for item in _object_list(value, "trigger candidates")
        ]
    except (KeyError, TypeError, ValueError) as error:
        raise ValueError("invalid trigger candidates") from error


def _hypotheses(value: object) -> list[Hypothesis]:
    try:
        return [
            Hypothesis(
                id=str(item["id"]),
                category=str(item["category"]),
                summary=str(item["summary"]),
                confidence=cast(Confidence, item["confidence"]),
                rank=int(item["rank"]),
                evidence_ids=tuple(str(entry) for entry in item["evidence_ids"]),
            )
            for item in _object_list(value, "hypotheses")
        ]
    except (KeyError, TypeError, ValueError) as error:
        raise ValueError("invalid hypotheses") from error
