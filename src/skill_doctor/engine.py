from __future__ import annotations

import hashlib
import json
import os
import platform
import re
import shutil
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any, Literal, cast

from skill_doctor import __version__
from skill_doctor.analysis import RULESET_VERSION, analyze
from skill_doctor.causal import CausalOutcome, assess_causality
from skill_doctor.discovery import (
    AmbiguousSkill,
    DiscoveredSkill,
    DiscoveryContext,
    DiscoveryError,
    Inventory,
    Platform,
    SkillNotFound,
    discover,
)
from skill_doctor.dynamic_orchestration import (
    DynamicOutcome,
    DynamicRequest,
    DynamicTarget,
    orchestrate_dynamic,
)
from skill_doctor.errors import OperationCancelled
from skill_doctor.frontmatter import FrontmatterError, parse_skill_document
from skill_doctor.models import (
    SCHEMA_VERSION,
    AnalyzedCopy,
    CollectionRecord,
    Confidence,
    Coverage,
    DynamicTestPlan,
    Evidence,
    Finding,
    Hypothesis,
    Report,
    ResultState,
    SessionTarget,
    StaticAnalysis,
    TriggerCandidate,
)
from skill_doctor.performance import PerformanceOutcome, analyze_performance
from skill_doctor.session import (
    MAX_SIGNAL_TEXT_CHARS,
    CollectionItem,
    SessionEvidence,
    SessionEvidenceError,
    collect_session_evidence,
    locate_session_source,
)
from skill_doctor.snapshot import (
    SNAPSHOT_FORMAT_VERSION,
    Snapshot,
    SnapshotError,
    create_legacy_command_snapshot,
    create_snapshot,
    verify_snapshot,
)
from skill_doctor.store import LocalStore, StoreError
from skill_doctor.supply_chain import (
    RulePackManager,
    VerifiedRulePack,
    analyze_declarative_rules,
)
from skill_doctor.suppressions import SuppressionOutcome, resolve_suppressions

Emit = Callable[[str, str, str | None], None]
Cancelled = Callable[[], bool]


@dataclass(frozen=True, slots=True)
class ExecutionResult:
    exit_code: int
    report: Report | None = None
    target: Path | None = None


@dataclass(frozen=True, slots=True)
class EffectiveRuleSet:
    version: str
    external_pack: VerifiedRulePack | None = None


def _effective_ruleset(store: LocalStore) -> EffectiveRuleSet:
    manager = RulePackManager(store.root)
    manager.maybe_auto_update()
    pack = manager.load_active()
    if pack is None:
        return EffectiveRuleSet(RULESET_VERSION)
    return EffectiveRuleSet(f"{RULESET_VERSION}+signed.{pack.effective_version}", pack)


def _cache_key(snapshot: Snapshot, ruleset_version: str) -> str:
    dimensions = {
        "python": platform.python_version(),
        "ruleset": ruleset_version,
        "schema": SCHEMA_VERSION,
        "skill_directory_name": snapshot.root.name,
        "snapshot": snapshot.digest,
        "snapshot_format": SNAPSHOT_FORMAT_VERSION,
        "tool": __version__,
    }
    payload = json.dumps(dimensions, separators=(",", ":"), sort_keys=True).encode()
    return hashlib.sha256(payload).hexdigest()


def _coverage(analysis: StaticAnalysis) -> Coverage:
    return Coverage(
        completed=("bounded_snapshot", *analysis.coverage.completed, "stale_input_check"),
        skipped=analysis.coverage.skipped,
        unsupported=analysis.coverage.unsupported,
        failed=analysis.coverage.failed,
    )


def _merge_dynamic_coverage(coverage: Coverage, outcome: DynamicOutcome) -> Coverage:
    return Coverage(
        completed=tuple(dict.fromkeys((*coverage.completed, *outcome.completed))),
        skipped=tuple(dict.fromkeys((*coverage.skipped, *outcome.skipped))),
        unsupported=tuple(dict.fromkeys((*coverage.unsupported, *outcome.unsupported))),
        failed=tuple(dict.fromkeys((*coverage.failed, *outcome.failed))),
    )


def _causal_outcome(
    findings: list[Finding],
    evidence: list[Evidence],
    dynamic_results: list[dict[str, Any]],
    hypotheses: list[Hypothesis] | None = None,
) -> CausalOutcome:
    return assess_causality(
        existing_findings=findings,
        existing_evidence=evidence,
        dynamic_results=dynamic_results,
        hypotheses=hypotheses,
    )


def _performance_outcome(
    *,
    targets: tuple[tuple[Snapshot, str], ...],
    dynamic: DynamicOutcome | None,
    store: LocalStore,
    emit: Emit,
    ruleset_version: str,
    home: Path | None = None,
) -> PerformanceOutcome:
    emit("performance", "Evaluating explicit budgets and compatible baselines", None)
    dynamic_results = [] if dynamic is None else list(dynamic.results)
    controlled_load = (
        bool(dynamic_results)
        and dynamic is not None
        and ("controlled_load_measurement" in dynamic.plan.required_consent_scopes)
    )
    return analyze_performance(
        targets=targets,
        dynamic_results=dynamic_results,
        ruleset_version=ruleset_version,
        store=store,
        controlled_load=controlled_load,
        home=home,
    )


def _merge_performance_coverage(
    coverage: Coverage,
    performance: PerformanceOutcome,
) -> Coverage:
    raw_limitations = performance.report.get("limitations", [])
    unsupported_metrics = tuple(
        f"performance:{item.removeprefix('unsupported_metric:')}"
        for item in raw_limitations
        if isinstance(item, str) and item.startswith("unsupported_metric:")
    )
    completed = ["performance_context_accounting", "performance_budget_resolution"]
    if performance.report.get("controlled_load"):
        completed.append("non_overlapping_controlled_load_measurement")
    return Coverage(
        completed=tuple(dict.fromkeys((*coverage.completed, *completed))),
        skipped=coverage.skipped,
        unsupported=tuple(dict.fromkeys((*coverage.unsupported, *unsupported_metrics))),
        failed=coverage.failed,
    )


def _report_controls(
    *,
    findings: list[Finding],
    root: Path,
    snapshot_hash: str,
    ruleset_version: str,
    flagged_finding_ids: set[str],
    home: Path | None = None,
) -> SuppressionOutcome:
    return resolve_suppressions(
        findings=findings,
        root=root,
        snapshot_hash=snapshot_hash,
        ruleset_version=ruleset_version,
        flagged_finding_ids=flagged_finding_ids,
        home=home,
    )


def _artifact_paths(store: LocalStore, job_id: str) -> dict[str, str]:
    return {name: str(path) for name, path in store.report_artifact_paths(job_id).items()}


def _session_language(environment: Mapping[str, str] | None) -> str:
    values = os.environ if environment is None else environment
    raw = values.get("LC_ALL") or values.get("LC_MESSAGES") or values.get("LANG") or "en"
    tag = raw.split(".", 1)[0].replace("_", "-").strip()
    return tag[:32] if 2 <= len(tag) <= 32 else "en"


def _result_state(analysis: StaticAnalysis) -> ResultState:
    if analysis.coverage.failed:
        return "analysis_incomplete"
    if analysis.findings:
        return "indeterminate"
    return "no_confirmed_issues"


def _ensure_not_cancelled(cancelled: Cancelled) -> None:
    if cancelled():
        raise OperationCancelled("job cancelled")


def _safe_emit(emit: Emit, stage: str, summary: str, detail: str | None) -> None:
    try:
        emit(stage, summary, detail)
    except Exception:
        return


def _analyze_snapshot(
    snapshot: Snapshot,
    *,
    ruleset: EffectiveRuleSet,
    created_at: str,
    store: LocalStore,
    emit: Emit,
    cancelled: Cancelled,
) -> tuple[StaticAnalysis, bool]:
    key = _cache_key(snapshot, ruleset.version)
    cached = store.load_cached_analysis(key)
    analysis: StaticAnalysis | None = None
    if cached is not None:
        try:
            analysis = StaticAnalysis.from_dict(cached)
        except ValueError:
            analysis = None
    if analysis is None:
        emit("analysis", "Running deterministic static rules", str(snapshot.root))
        analysis = analyze(snapshot, cancelled=cancelled)
        if ruleset.external_pack is not None:
            supplemental = analyze_declarative_rules(snapshot, ruleset.external_pack)
            analysis = StaticAnalysis(
                [*analysis.findings, *supplemental.findings],
                [*analysis.evidence, *supplemental.evidence],
                Coverage(
                    completed=tuple(
                        dict.fromkeys(
                            (*analysis.coverage.completed, *supplemental.coverage.completed)
                        )
                    ),
                    skipped=tuple(
                        dict.fromkeys((*analysis.coverage.skipped, *supplemental.coverage.skipped))
                    ),
                    unsupported=tuple(
                        dict.fromkeys(
                            (*analysis.coverage.unsupported, *supplemental.coverage.unsupported)
                        )
                    ),
                    failed=tuple(
                        dict.fromkeys((*analysis.coverage.failed, *supplemental.coverage.failed))
                    ),
                ),
            )
        _ensure_not_cancelled(cancelled)
        store.cache_analysis(key, snapshot.digest, created_at, analysis.to_dict())
        return analysis, False
    emit("analysis", "Reusing strictly keyed deterministic analysis", str(snapshot.root))
    return analysis, True


def execute_check(
    *,
    job_id: str,
    created_at: str,
    path: Path,
    store: LocalStore,
    emit: Emit,
    cancelled: Cancelled,
    platform_name: Platform = "codex",
    dynamic_request: DynamicRequest | None = None,
) -> ExecutionResult:
    try:
        _ensure_not_cancelled(cancelled)
        emit("snapshot", "Reading bounded local skill snapshot", None)
        snapshot = create_snapshot(path, cancelled=cancelled)
        _ensure_not_cancelled(cancelled)
        store.persist_snapshot(snapshot)
        ruleset = _effective_ruleset(store)

        analysis, _ = _analyze_snapshot(
            snapshot,
            ruleset=ruleset,
            created_at=created_at,
            store=store,
            emit=emit,
            cancelled=cancelled,
        )

        verify_snapshot(snapshot, cancelled=cancelled)
        _ensure_not_cancelled(cancelled)
        outcome: DynamicOutcome | None = None
        if dynamic_request is not None and dynamic_request.enabled:
            outcome = orchestrate_dynamic(
                targets=(DynamicTarget(snapshot, platform_name, snapshot.root.name),),
                request=dynamic_request,
                store=store,
                emit=emit,
                cancelled=cancelled,
                ruleset_version=ruleset.version,
            )
        coverage = _coverage(analysis)
        limitations = ["Static observations cannot establish a causal role or universal safety."]
        result_state = _result_state(analysis)
        if outcome is not None:
            coverage = _merge_dynamic_coverage(coverage, outcome)
            limitations.extend(outcome.limitations)
            result_state = _result_state(
                StaticAnalysis(analysis.findings, analysis.evidence, coverage)
            )
            if outcome.indeterminate and result_state == "no_confirmed_issues":
                result_state = "indeterminate"
        dynamic_results = [] if outcome is None else list(outcome.results)
        performance = _performance_outcome(
            targets=((snapshot, snapshot.root.name),),
            dynamic=outcome,
            store=store,
            emit=emit,
            ruleset_version=ruleset.version,
        )
        coverage = _merge_performance_coverage(coverage, performance)
        limitations.extend(cast(list[str], performance.report["limitations"]))
        base_findings = [*analysis.findings, *performance.findings]
        base_evidence = [*analysis.evidence, *performance.evidence]
        causal = _causal_outcome(base_findings, base_evidence, dynamic_results)
        report_findings = [*base_findings, *causal.findings]
        report_evidence = [*base_evidence, *causal.evidence]
        if performance.findings and result_state == "no_confirmed_issues":
            result_state = "indeterminate"
        if causal.confirmed and not coverage.failed:
            result_state = "confirmed_issues"
        elif causal.indeterminate and result_state == "no_confirmed_issues":
            result_state = "indeterminate"
        controls = _report_controls(
            findings=report_findings,
            root=snapshot.root,
            snapshot_hash=snapshot.digest,
            ruleset_version=ruleset.version,
            flagged_finding_ids=set(causal.summary["flagged_issue_ids"]),
        )
        report = Report(
            schema_version=SCHEMA_VERSION,
            job_id=job_id,
            created_at=created_at,
            tool_version=__version__,
            ruleset_version=ruleset.version,
            result_state=result_state,
            input_path=str(snapshot.root),
            snapshot_hash=snapshot.digest,
            findings=report_findings,
            evidence=report_evidence,
            coverage=coverage,
            limitations=limitations,
            platform=platform_name,
            dynamic_test_plan=None if outcome is None else outcome.plan,
            sandbox_readiness=None if outcome is None else outcome.readiness,
            dynamic_results=dynamic_results,
            causal_graph=causal.graph,
            remediations=list(causal.remediations),
            diagnostic_summary=causal.summary,
            performance=performance.report,
            artifacts=_artifact_paths(store, job_id),
            suppression_audit=controls.audit,
            suppressed_finding_ids=list(controls.suppressed_finding_ids),
            blocking_finding_ids=list(controls.blocking_finding_ids),
        )
        target = store.write_report(job_id, report.to_dict())
        emit("report", "Local report written", str(target))
        store.complete_job(job_id, snapshot.digest, target, report.result_state)
    except OperationCancelled as error:
        store.mark_cancelled(job_id)
        _safe_emit(emit, "cancelled", "Analysis cancelled", str(error))
        return ExecutionResult(4)
    except (OSError, SnapshotError, StoreError, ValueError) as error:
        store.fail_job(job_id, str(error))
        _safe_emit(emit, "error", "Analysis incomplete", str(error))
        return ExecutionResult(2)
    except Exception as error:
        error_name = type(error).__name__
        store.fail_job(job_id, error_name, result_state="internal_error")
        _safe_emit(emit, "error", "Internal error", error_name)
        return ExecutionResult(3)

    if report.result_state == "analysis_incomplete":
        return ExecutionResult(2, report, target)
    return ExecutionResult(1 if report.blocking_finding_ids else 0, report, target)


def _namespace_analysis(
    analysis: StaticAnalysis,
    digest: str,
) -> tuple[list[Finding], list[Evidence]]:
    prefix = digest[:16]
    evidence_ids = {item.id: f"{prefix}-{item.id}" for item in analysis.evidence}
    evidence = [replace(item, id=evidence_ids[item.id]) for item in analysis.evidence]
    findings = [
        replace(
            item,
            id=f"{prefix}-{item.id}",
            evidence_ids=tuple(
                evidence_ids.get(value, f"{prefix}-{value}") for value in item.evidence_ids
            ),
        )
        for item in analysis.findings
    ]
    return findings, evidence


def _state_overlaps(path: Path, state_root: Path) -> bool:
    root = path.resolve(strict=False)
    state = state_root.resolve(strict=False)
    return state == root or state.is_relative_to(root)


def _dynamic_plan(skill_count: int, depth: str = "quick") -> DynamicTestPlan:
    repetitions = {"quick": 1, "standard": 3, "deep": 5}.get(depth, 1)
    test_count = skill_count * repetitions
    return DynamicTestPlan(
        depth=depth,
        skill_count=skill_count,
        test_count=test_count,
        estimated_seconds=test_count * 60,
        runtime_uses=test_count,
        estimated_model_cost_usd=None,
    )


def _copy_not_analyzed(copy: DiscoveredSkill, reason: str) -> AnalyzedCopy:
    return AnalyzedCopy((copy.copy_id,), (copy.selector,), None, False, False, reason)


@dataclass(slots=True)
class _InventoryAnalysis:
    findings: list[Finding]
    evidence: list[Evidence]
    coverage: Coverage
    analyzed_copies: list[AnalyzedCopy]
    snapshot_hashes: tuple[str, ...]
    snapshot_entries: tuple[tuple[Snapshot, DiscoveredSkill], ...]


def _analyze_inventory_copies(
    copies: Sequence[DiscoveredSkill],
    *,
    created_at: str,
    store: LocalStore,
    emit: Emit,
    cancelled: Cancelled,
    ruleset: EffectiveRuleSet,
) -> _InventoryAnalysis:
    snapshots: dict[str, list[tuple[Snapshot, DiscoveredSkill]]] = {}
    analyzed_copies: list[AnalyzedCopy] = []
    failed: list[str] = []
    skipped: list[str] = []
    unsupported: list[str] = []
    for copy in copies:
        _ensure_not_cancelled(cancelled)
        if copy.status == "unresolved" or copy.resolved_path is None:
            reason = copy.status_reason or "skill copy is unresolved"
            analyzed_copies.append(_copy_not_analyzed(copy, reason))
            failed.append(f"unresolved:{copy.copy_id}")
            continue
        is_legacy_command = copy.manifest_path.name != "SKILL.md"
        if not is_legacy_command and _state_overlaps(copy.resolved_path, store.root):
            reason = "state directory is inside the discovered skill"
            analyzed_copies.append(_copy_not_analyzed(copy, reason))
            failed.append(f"state-overlap:{copy.copy_id}")
            continue
        try:
            emit("snapshot", "Reading bounded discovered skill snapshot", str(copy.skill_path))
            snapshot = (
                create_legacy_command_snapshot(copy.resolved_path, cancelled=cancelled)
                if is_legacy_command
                else create_snapshot(copy.resolved_path, cancelled=cancelled)
            )
            store.persist_snapshot(snapshot)
            snapshots.setdefault(snapshot.digest, []).append((snapshot, copy))
        except (OSError, SnapshotError, StoreError, ValueError) as error:
            analyzed_copies.append(_copy_not_analyzed(copy, str(error)))
            failed.append(f"snapshot:{copy.copy_id}")

    findings: list[Finding] = []
    evidence: list[Evidence] = []
    completed: list[str] = ["platform_discovery", "effective_copy_resolution"]
    for digest, group in snapshots.items():
        _ensure_not_cancelled(cancelled)
        canonical = group[0][0]
        analysis, cache_reused = _analyze_snapshot(
            canonical,
            ruleset=ruleset,
            created_at=created_at,
            store=store,
            emit=emit,
            cancelled=cancelled,
        )
        namespaced_findings, namespaced_evidence = _namespace_analysis(analysis, digest)
        findings.extend(namespaced_findings)
        evidence.extend(namespaced_evidence)
        completed.extend(analysis.coverage.completed)
        skipped.extend(analysis.coverage.skipped)
        failed.extend(analysis.coverage.failed)
        unsupported.extend(
            item for item in analysis.coverage.unsupported if item != "platform_resolution"
        )
        for snapshot, _copy in group:
            verify_snapshot(snapshot, cancelled=cancelled)
        analyzed_copies.append(
            AnalyzedCopy(
                copy_ids=tuple(copy.copy_id for _, copy in group),
                selectors=tuple(sorted({copy.selector for _, copy in group})),
                snapshot_hash=digest,
                analyzed=True,
                reused_by_content_hash=cache_reused or len(group) > 1,
            )
        )

    coverage = Coverage(
        completed=tuple(dict.fromkeys((*completed, "stale_input_check"))),
        skipped=tuple(dict.fromkeys(skipped)),
        unsupported=tuple(dict.fromkeys(unsupported)),
        failed=tuple(dict.fromkeys(failed)),
    )
    return _InventoryAnalysis(
        findings,
        evidence,
        coverage,
        analyzed_copies,
        tuple(sorted(snapshots)),
        tuple(entry for group in snapshots.values() for entry in group),
    )


def execute_discovered_check(
    *,
    job_id: str,
    created_at: str,
    platform_name: Platform,
    cwd: Path,
    selector: str | None,
    scope: Literal["named", "all"],
    store: LocalStore,
    emit: Emit,
    cancelled: Cancelled,
    added_directories: tuple[Path, ...] = (),
    active_paths: tuple[Path, ...] = (),
    context: DiscoveryContext | None = None,
    dynamic_request: DynamicRequest | None = None,
) -> ExecutionResult:
    try:
        _ensure_not_cancelled(cancelled)
        ruleset = _effective_ruleset(store)
        emit("discovery", f"Discovering {platform_name} skill copies", str(cwd))
        discovery_context = context or DiscoveryContext(
            cwd=cwd,
            added_directories=added_directories,
            active_paths=active_paths,
        )
        inventory = discover(platform_name, discovery_context)
        if scope == "named":
            if not selector:
                raise ValueError("a named check requires a skill selector")
            selected = [inventory.resolve(selector)]
        else:
            selected = list(inventory.copies)

        static = _analyze_inventory_copies(
            selected,
            created_at=created_at,
            store=store,
            emit=emit,
            cancelled=cancelled,
            ruleset=ruleset,
        )
        analysis_for_state = StaticAnalysis(static.findings, static.evidence, static.coverage)
        inventory_payload = inventory.to_dict()
        aggregate_payload = json.dumps(
            {
                "inventory": inventory_payload,
                "snapshots": static.snapshot_hashes,
            },
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
        aggregate_hash = hashlib.sha256(aggregate_payload).hexdigest()
        outcome: DynamicOutcome | None = None
        if dynamic_request is not None and dynamic_request.enabled:
            outcome = orchestrate_dynamic(
                targets=tuple(
                    DynamicTarget(snapshot, platform_name, copy.name)
                    for snapshot, copy in static.snapshot_entries
                ),
                request=dynamic_request,
                store=store,
                emit=emit,
                cancelled=cancelled,
                ruleset_version=ruleset.version,
            )
        coverage = static.coverage
        limitations = [
            "Static observations cannot establish a causal role or universal safety.",
            "Dynamic estimates exclude model price because no runtime/model was approved.",
        ]
        result_state = _result_state(analysis_for_state)
        if outcome is not None:
            coverage = _merge_dynamic_coverage(coverage, outcome)
            limitations.extend(outcome.limitations)
            result_state = _result_state(StaticAnalysis(static.findings, static.evidence, coverage))
            if outcome.indeterminate and result_state == "no_confirmed_issues":
                result_state = "indeterminate"
        dynamic_results = [] if outcome is None else list(outcome.results)
        performance = _performance_outcome(
            targets=tuple((snapshot, copy.name) for snapshot, copy in static.snapshot_entries),
            dynamic=outcome,
            store=store,
            emit=emit,
            ruleset_version=ruleset.version,
        )
        coverage = _merge_performance_coverage(coverage, performance)
        limitations.extend(cast(list[str], performance.report["limitations"]))
        base_findings = [*static.findings, *performance.findings]
        base_evidence = [*static.evidence, *performance.evidence]
        causal = _causal_outcome(base_findings, base_evidence, dynamic_results)
        report_findings = [*base_findings, *causal.findings]
        report_evidence = [*base_evidence, *causal.evidence]
        if performance.findings and result_state == "no_confirmed_issues":
            result_state = "indeterminate"
        if causal.confirmed and not coverage.failed:
            result_state = "confirmed_issues"
        elif causal.indeterminate and result_state == "no_confirmed_issues":
            result_state = "indeterminate"
        controls = _report_controls(
            findings=report_findings,
            root=inventory.cwd,
            snapshot_hash=aggregate_hash,
            ruleset_version=ruleset.version,
            flagged_finding_ids=set(causal.summary["flagged_issue_ids"]),
        )
        report = Report(
            schema_version=SCHEMA_VERSION,
            job_id=job_id,
            created_at=created_at,
            tool_version=__version__,
            ruleset_version=ruleset.version,
            result_state=result_state,
            input_path=str(inventory.cwd),
            snapshot_hash=aggregate_hash,
            findings=report_findings,
            evidence=report_evidence,
            coverage=coverage,
            limitations=limitations,
            scope=scope,
            platform=platform_name,
            inventory=inventory_payload,
            analyzed_copies=static.analyzed_copies,
            dynamic_test_plan=(
                _dynamic_plan(len(static.snapshot_hashes)) if outcome is None else outcome.plan
            ),
            sandbox_readiness=None if outcome is None else outcome.readiness,
            dynamic_results=dynamic_results,
            causal_graph=causal.graph,
            remediations=list(causal.remediations),
            diagnostic_summary=causal.summary,
            performance=performance.report,
            artifacts=_artifact_paths(store, job_id),
            suppression_audit=controls.audit,
            suppressed_finding_ids=list(controls.suppressed_finding_ids),
            blocking_finding_ids=list(controls.blocking_finding_ids),
        )
        target = store.write_report(job_id, report.to_dict())
        emit("report", "Discovery-aware local report written", str(target))
        store.complete_job(job_id, aggregate_hash, target, report.result_state)
    except OperationCancelled as error:
        store.mark_cancelled(job_id)
        _safe_emit(emit, "cancelled", "Analysis cancelled", str(error))
        return ExecutionResult(4)
    except (
        AmbiguousSkill,
        DiscoveryError,
        OSError,
        SkillNotFound,
        SnapshotError,
        StoreError,
        ValueError,
    ) as error:
        store.fail_job(job_id, str(error))
        _safe_emit(emit, "error", "Analysis incomplete", str(error))
        return ExecutionResult(2)
    except Exception as error:
        error_name = type(error).__name__
        store.fail_job(job_id, error_name, result_state="internal_error")
        _safe_emit(emit, "error", "Internal error", error_name)
        return ExecutionResult(3)

    if report.result_state == "analysis_incomplete":
        return ExecutionResult(2, report, target)
    return ExecutionResult(1 if report.blocking_finding_ids else 0, report, target)


DESCRIPTION_TOKEN = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{2,}")
DESCRIPTION_STOPWORDS = frozenset(
    {"and", "are", "for", "from", "that", "the", "this", "use", "using", "with", "your"}
)


def _description_terms(copy: DiscoveredSkill) -> set[str]:
    if copy.manifest_path.name != "SKILL.md":
        return set()
    try:
        text = copy.manifest_path.read_text(encoding="utf-8")[:MAX_SIGNAL_TEXT_CHARS]
        document = parse_skill_document(text)
    except (OSError, UnicodeError, FrontmatterError):
        return set()
    description = document.metadata.get("description")
    if not isinstance(description, str):
        return set()
    return {
        token.casefold()
        for token in DESCRIPTION_TOKEN.findall(description)
        if token.casefold() not in DESCRIPTION_STOPWORDS
    }


def _select_session_targets(
    inventory: Inventory,
    session: SessionEvidence,
) -> tuple[list[DiscoveredSkill], list[SessionTarget]]:
    invoked = {value.casefold() for value in session.invoked_selectors}
    accessed = {value.casefold() for value in session.accessed_skill_directories}
    signals = invoked | accessed
    selected: list[DiscoveredSkill] = []
    targets: list[SessionTarget] = []
    selected_ids: set[str] = set()
    for selector in sorted(signals):
        matches = [
            copy
            for copy in inventory.copies
            if copy.status in {"active", "ambiguous"}
            and (copy.selector.casefold() == selector or copy.name.casefold() == selector)
        ]
        active = [copy for copy in matches if copy.status == "active"]
        reason_parts = []
        if selector in invoked:
            reason_parts.append("explicit invocation signal")
        if selector in accessed:
            reason_parts.append("SKILL.md access signal")
        reason = " and ".join(reason_parts)
        confidence: Confidence = (
            "high" if session.confidence == "high" and selector in invoked else "medium"
        )
        if len(active) == 1 and len(matches) == 1:
            copy = active[0]
            if copy.copy_id not in selected_ids:
                selected.append(copy)
                selected_ids.add(copy.copy_id)
            targets.append(SessionTarget(selector, copy.copy_id, reason, confidence, True))
        elif matches:
            targets.append(
                SessionTarget(
                    selector,
                    None,
                    f"{reason}; platform resolution is ambiguous",
                    "low",
                    False,
                )
            )
        else:
            if selector not in session.explicit_invocations and selector not in accessed:
                continue
            targets.append(
                SessionTarget(
                    selector,
                    None,
                    f"{reason}; no active discovered copy matches",
                    "low",
                    False,
                )
            )
    return selected, targets


def _trigger_candidates(inventory: Inventory, session: SessionEvidence) -> list[TriggerCandidate]:
    allowed_sources = {"repository", "project", "nested", "added-directory"}
    scored: list[tuple[int, str, DiscoveredSkill]] = []
    for copy in inventory.copies:
        if copy.status != "active" or copy.source not in allowed_sources:
            continue
        overlap = session.prompt_terms & _description_terms(copy)
        if len(overlap) >= 2:
            scored.append((len(overlap), copy.selector, copy))
    scored.sort(key=lambda item: (-item[0], item[1], item[2].copy_id))
    return [
        TriggerCandidate(
            selector=copy.selector,
            copy_id=copy.copy_id,
            shared_term_count=score,
            confidence="low" if score == 2 else "medium",
        )
        for score, _, copy in scored[:3]
    ]


def _session_observations(
    session: SessionEvidence, targets: Sequence[SessionTarget]
) -> list[Evidence]:
    observations: list[Evidence] = []
    selectors = {target.selector for target in targets}
    for selector in sorted(selectors):
        identifier = hashlib.sha256(f"session-target:{selector}".encode()).hexdigest()[:16]
        observations.append(
            Evidence(
                f"session-target-{identifier}",
                "session_target_signal",
                f"The minimized session trace referenced skill selector {selector!r}.",
                path=str(session.source_path),
            )
        )
    for category, count in sorted(session.error_categories.items()):
        observations.append(
            Evidence(
                f"session-error-{category}",
                "session_error_category",
                f"The minimized session trace contained {count} {category} error signal(s).",
                path=str(session.source_path),
            )
        )
    return observations


def _quick_hypotheses(
    session: SessionEvidence | None,
    static: _InventoryAnalysis,
    targets: Sequence[SessionTarget],
    candidates: Sequence[TriggerCandidate],
    collection_error: str | None,
) -> list[Hypothesis]:
    hypotheses: list[Hypothesis] = []
    if collection_error is not None:
        hypotheses.append(
            Hypothesis(
                "hypothesis-missing-session-evidence",
                "missing_evidence",
                "Current-session evidence is unavailable; no causal conclusion is possible.",
                "high",
                1,
            )
        )
        return hypotheses

    if session is not None:
        labels = {
            "permission": "A permission or approval boundary may have blocked the workflow.",
            "dependency": "A missing runtime dependency may have prevented skill execution.",
            "configuration": "Resolved configuration may not match the skill's assumptions.",
            "runtime": "A runtime or tool failure may have interrupted the workflow.",
        }
        for category in ("permission", "dependency", "configuration", "runtime"):
            if not session.error_categories.get(category):
                continue
            hypotheses.append(
                Hypothesis(
                    f"hypothesis-{category}",
                    category,
                    labels[category],
                    "medium" if session.confidence == "high" else "low",
                    len(hypotheses) + 1,
                    (f"session-error-{category}",),
                )
            )
    if static.findings:
        evidence_ids = tuple(
            dict.fromkeys(
                identifier for finding in static.findings for identifier in finding.evidence_ids
            )
        )
        hypotheses.append(
            Hypothesis(
                "hypothesis-skill-static",
                "skill",
                "Static skill observations may have contributed, but the session provides no "
                "controlled reproduction or counterfactual.",
                "low",
                len(hypotheses) + 1,
                evidence_ids,
            )
        )
    unresolved_targets = [target for target in targets if target.copy_id is None]
    if unresolved_targets:
        hypotheses.append(
            Hypothesis(
                "hypothesis-target-resolution",
                "configuration",
                "One or more session skill signals could not be mapped to an effective copy.",
                "low",
                len(hypotheses) + 1,
            )
        )
    if not targets and candidates:
        hypotheses.append(
            Hypothesis(
                "hypothesis-trigger",
                "trigger",
                "A project skill has deterministic description overlap with the latest prompt, "
                "but the trace contains no invocation signal.",
                "low",
                len(hypotheses) + 1,
            )
        )
    if not hypotheses and targets:
        hypotheses.append(
            Hypothesis(
                "hypothesis-indeterminate",
                "indeterminate",
                "The trace identifies a skill target but contains no ranked failure signal.",
                "low",
                1,
            )
        )
    if not hypotheses:
        hypotheses.append(
            Hypothesis(
                "hypothesis-no-target",
                "missing_evidence",
                "The trace contains no skill invocation or sufficiently specific "
                "trigger candidate.",
                "low",
                1,
            )
        )
    return hypotheses


def _collection_record(item: CollectionItem) -> CollectionRecord:
    return CollectionRecord(
        item.kind,
        item.path,
        item.bytes,
        item.collected,
        item.confidence,
        item.reason,
    )


def execute_session_diagnosis(
    *,
    job_id: str,
    created_at: str,
    platform_name: Platform,
    cwd: Path,
    store: LocalStore,
    emit: Emit,
    cancelled: Cancelled,
    supplied_transcript: Path | None = None,
    flight_recorder: bool = False,
    added_directories: tuple[Path, ...] = (),
    active_paths: tuple[Path, ...] = (),
    context: DiscoveryContext | None = None,
    home: Path | None = None,
    environment: Mapping[str, str] | None = None,
    dynamic_request: DynamicRequest | None = None,
) -> ExecutionResult:
    try:
        _ensure_not_cancelled(cancelled)
        ruleset = _effective_ruleset(store)
        source = locate_session_source(
            platform_name,
            supplied_transcript=supplied_transcript,
            home=home,
            environment=environment,
        )
        collection_item = source.collection_item()
        emit(
            "collection",
            "Current-session collection manifest",
            json.dumps(collection_item.to_dict(), separators=(",", ":"), sort_keys=True),
        )
        session: SessionEvidence | None = None
        collection_error: str | None = None
        if collection_item.collected:
            try:
                session = collect_session_evidence(source)
            except SessionEvidenceError as error:
                collection_error = str(error)
        else:
            collection_error = collection_item.reason or "session trace is unavailable"

        session_cwd = cwd if session is None or session.cwd is None else session.cwd
        emit(
            "discovery",
            f"Discovering {platform_name} skills for session targeting",
            str(session_cwd),
        )
        discovery_context = context or DiscoveryContext(
            cwd=session_cwd,
            added_directories=added_directories,
            active_paths=active_paths,
        )
        inventory = discover(platform_name, discovery_context)
        selected: list[DiscoveredSkill] = []
        session_targets: list[SessionTarget] = []
        trigger_candidates: list[TriggerCandidate] = []
        if session is not None:
            selected, session_targets = _select_session_targets(inventory, session)
            if not session_targets:
                trigger_candidates = _trigger_candidates(inventory, session)

        static = _analyze_inventory_copies(
            selected,
            created_at=created_at,
            store=store,
            emit=emit,
            cancelled=cancelled,
            ruleset=ruleset,
        )
        session_evidence = (
            [] if session is None else _session_observations(session, session_targets)
        )
        combined_evidence = [*static.evidence, *session_evidence]

        completed = list(static.coverage.completed)
        skipped = list(static.coverage.skipped)
        unsupported = list(static.coverage.unsupported)
        failed = list(static.coverage.failed)
        completed.extend(("collection_manifest", "session_target_selection", "quick_hypotheses"))
        if session is not None:
            completed.extend(("current_session_collection", "environment_capture"))
            if session.changed_during_collection:
                skipped.append("session_trace_tail_changed_during_collection")
            if session.parse_errors:
                skipped.append(f"session_trace_parse_errors:{session.parse_errors}")
            if session.confidence == "reduced":
                unsupported.append("exact_native_current_session_match")
        if collection_error is not None:
            failed.append("current_session_evidence")
        unsupported.extend(("causal_confirmation", "controlled_counterfactual"))
        coverage = Coverage(
            completed=tuple(dict.fromkeys(completed)),
            skipped=tuple(dict.fromkeys(skipped)),
            unsupported=tuple(dict.fromkeys(unsupported)),
            failed=tuple(dict.fromkeys(failed)),
        )
        hypotheses = _quick_hypotheses(
            session,
            static,
            session_targets,
            trigger_candidates,
            collection_error,
        )
        if coverage.failed:
            result_state: ResultState = "analysis_incomplete"
        elif (
            static.findings
            or (session is not None and session.error_categories)
            or trigger_candidates
        ):
            result_state = "indeterminate"
        else:
            result_state = "no_confirmed_issues"

        inventory_payload = inventory.to_dict()
        environment_payload: dict[str, Any] = (
            {
                "platform": platform_name,
                "session_id": source.session_id,
                "trace_confidence": source.confidence,
            }
            if session is None
            else session.environment_dict()
        )
        environment_payload["configuration_sources"] = list(inventory.configuration_sources)
        environment_payload["tool_availability"] = {
            name: shutil.which(name) is not None
            for name in ("bash", "claude", "codex", "node", "pwsh", "python")
        }
        aggregate_payload = json.dumps(
            {
                "collection": collection_item.to_dict(),
                "environment": environment_payload,
                "inventory": inventory_payload,
                "snapshots": static.snapshot_hashes,
                "targets": [target.selector for target in session_targets],
            },
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
        aggregate_hash = hashlib.sha256(aggregate_payload).hexdigest()
        outcome: DynamicOutcome | None = None
        if dynamic_request is not None and dynamic_request.enabled:
            if session is not None:
                dynamic_request = replace(
                    dynamic_request,
                    runtime_version=dynamic_request.runtime_version or session.runtime_version,
                    model=dynamic_request.model or session.model,
                    permission_mode=(dynamic_request.permission_mode or session.permission_mode),
                    sandbox_mode=dynamic_request.sandbox_mode or session.sandbox_mode,
                )
            outcome = orchestrate_dynamic(
                targets=tuple(
                    DynamicTarget(snapshot, platform_name, copy.name)
                    for snapshot, copy in static.snapshot_entries
                ),
                request=dynamic_request,
                store=store,
                emit=emit,
                cancelled=cancelled,
                ruleset_version=ruleset.version,
            )
            coverage = _merge_dynamic_coverage(coverage, outcome)
            if coverage.failed:
                result_state = "analysis_incomplete"
            elif outcome.indeterminate and result_state == "no_confirmed_issues":
                result_state = "indeterminate"
        if flight_recorder:
            store.append_flight_record(
                {
                    "created_at": created_at,
                    "error_categories": ({} if session is None else dict(session.error_categories)),
                    "platform": platform_name,
                    "session_id": None if session is None else session.session_id,
                    "snapshot_hashes": static.snapshot_hashes,
                    "target_selectors": [target.selector for target in session_targets],
                    "trace_confidence": source.confidence,
                }
            )
            coverage = replace(
                coverage,
                completed=tuple(dict.fromkeys((*coverage.completed, "opt_in_flight_recorder"))),
            )

        dynamic_results = [] if outcome is None else list(outcome.results)
        performance = _performance_outcome(
            targets=tuple((snapshot, copy.name) for snapshot, copy in static.snapshot_entries),
            dynamic=outcome,
            store=store,
            emit=emit,
            ruleset_version=ruleset.version,
            home=home,
        )
        coverage = _merge_performance_coverage(coverage, performance)
        base_findings = [*static.findings, *performance.findings]
        base_evidence = [*combined_evidence, *performance.evidence]
        causal = _causal_outcome(
            base_findings,
            base_evidence,
            dynamic_results,
            hypotheses,
        )
        report_findings = [*base_findings, *causal.findings]
        report_evidence = [*base_evidence, *causal.evidence]
        if performance.findings and result_state == "no_confirmed_issues":
            result_state = "indeterminate"
        if causal.confirmed and not coverage.failed:
            result_state = "confirmed_issues"
        elif causal.indeterminate and result_state == "no_confirmed_issues":
            result_state = "indeterminate"

        report_language = _session_language(environment)
        causal.summary["report_language"] = report_language
        if not report_language.casefold().startswith("en"):
            causal.summary["translation_fallback_used"] = True
        controls = _report_controls(
            findings=report_findings,
            root=session_cwd,
            snapshot_hash=aggregate_hash,
            ruleset_version=ruleset.version,
            flagged_finding_ids=set(causal.summary["flagged_issue_ids"]),
            home=home,
        )

        report = Report(
            schema_version=SCHEMA_VERSION,
            job_id=job_id,
            created_at=created_at,
            tool_version=__version__,
            ruleset_version=ruleset.version,
            result_state=result_state,
            input_path=str(session_cwd),
            snapshot_hash=aggregate_hash,
            findings=report_findings,
            evidence=report_evidence,
            coverage=coverage,
            limitations=[
                "Quick session hypotheses are ranked triage leads, not causal conclusions.",
                "Static observations cannot establish a causal role or universal safety.",
                "No unrelated installed skill is statically analyzed without a session target.",
                *cast(list[str], performance.report["limitations"]),
                *([] if outcome is None else outcome.limitations),
            ],
            scope="session",
            platform=platform_name,
            inventory=inventory_payload,
            analyzed_copies=static.analyzed_copies,
            dynamic_test_plan=(
                _dynamic_plan(len(static.snapshot_hashes)) if outcome is None else outcome.plan
            ),
            session_id=None if session is None else session.session_id,
            collection_manifest=[_collection_record(collection_item)],
            session_environment=environment_payload,
            session_targets=session_targets,
            trigger_candidates=trigger_candidates,
            hypotheses=hypotheses,
            sandbox_readiness=None if outcome is None else outcome.readiness,
            dynamic_results=dynamic_results,
            causal_graph=causal.graph,
            remediations=list(causal.remediations),
            diagnostic_summary=causal.summary,
            performance=performance.report,
            artifacts=_artifact_paths(store, job_id),
            suppression_audit=controls.audit,
            suppressed_finding_ids=list(controls.suppressed_finding_ids),
            blocking_finding_ids=list(controls.blocking_finding_ids),
            report_language=report_language,
        )
        target = store.write_report(job_id, report.to_dict())
        emit("report", "Current-session diagnostic report written", str(target))
        store.complete_job(job_id, aggregate_hash, target, report.result_state)
    except OperationCancelled as error:
        store.mark_cancelled(job_id)
        _safe_emit(emit, "cancelled", "Analysis cancelled", str(error))
        return ExecutionResult(4)
    except (
        DiscoveryError,
        OSError,
        SessionEvidenceError,
        SnapshotError,
        StoreError,
        ValueError,
    ) as error:
        store.fail_job(job_id, str(error))
        _safe_emit(emit, "error", "Analysis incomplete", str(error))
        return ExecutionResult(2)
    except Exception as error:
        error_name = type(error).__name__
        store.fail_job(job_id, error_name, result_state="internal_error")
        _safe_emit(emit, "error", "Internal error", error_name)
        return ExecutionResult(3)

    if report.result_state == "analysis_incomplete":
        return ExecutionResult(2, report, target)
    return ExecutionResult(1 if report.blocking_finding_ids else 0, report, target)
