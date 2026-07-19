from __future__ import annotations

import hashlib
import json
import statistics
from dataclasses import asdict, dataclass, fields
from pathlib import Path
from typing import Any, Literal, cast

from skill_doctor.frontmatter import FrontmatterError, parse_skill_document
from skill_doctor.models import Evidence, Finding
from skill_doctor.snapshot import Snapshot
from skill_doctor.store import LocalStore

MetricBasis = Literal["measured", "estimated", "budgeted", "baseline-relative"]
MAX_BUDGET_BYTES = 1024 * 1024


class PerformanceBudgetError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class PerformanceBudget:
    max_instruction_tokens: int | None = None
    max_catalog_tokens: int | None = None
    max_latency_ms: int | None = None
    max_setup_ms: int | None = None
    max_failure_rate: float | None = None
    max_tool_calls: int | None = None
    max_model_turns: int | None = None
    max_cost_usd: float | None = None
    max_workspace_bytes: int | None = None
    max_output_variants: int | None = None


@dataclass(frozen=True, slots=True)
class Metric:
    name: str
    value: int | float
    unit: str
    basis: MetricBasis
    skill_name: str
    detail: str | None = None


@dataclass(frozen=True, slots=True)
class PerformanceOutcome:
    findings: tuple[Finding, ...]
    evidence: tuple[Evidence, ...]
    report: dict[str, Any]


def _paired_evidence(
    evidence: list[Evidence],
    identifier: str,
    first_kind: str,
    first_detail: str,
    second_kind: str,
    second_detail: str,
) -> tuple[str, str]:
    first_id = f"performance-{identifier}-measurement"
    second_id = f"performance-{identifier}-basis"
    evidence.extend(
        (
            Evidence(first_id, first_kind, first_detail),
            Evidence(second_id, second_kind, second_detail),
        )
    )
    return first_id, second_id


def _bounded_document(path: Path) -> tuple[dict[str, Any], str]:
    try:
        data = path.read_bytes()
    except OSError as error:
        raise PerformanceBudgetError(f"cannot read performance budget: {error}") from error
    if len(data) > MAX_BUDGET_BYTES:
        raise PerformanceBudgetError("performance budget exceeds the 1 MB limit")
    try:
        payload = json.loads(data)
    except (UnicodeError, json.JSONDecodeError) as error:
        raise PerformanceBudgetError(f"invalid performance budget JSON: {error}") from error
    if not isinstance(payload, dict) or payload.get("version") != 1:
        raise PerformanceBudgetError("performance budget must be a version 1 object")
    unknown = set(payload) - {"version", "default", "skills"}
    if unknown:
        raise PerformanceBudgetError("unknown performance budget field")
    return cast(dict[str, Any], payload), hashlib.sha256(data).hexdigest()


def _budget_values(value: object) -> dict[str, int | float | None]:
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise PerformanceBudgetError("performance budget entry must be an object")
    raw = cast(dict[str, Any], value)
    allowed = {item.name for item in fields(PerformanceBudget)}
    if set(raw) - allowed:
        raise PerformanceBudgetError("unknown performance budget limit")
    result: dict[str, int | float | None] = {}
    for key, value in raw.items():
        if value is None:
            result[key] = None
            continue
        if isinstance(value, bool) or not isinstance(value, int | float) or value < 0:
            raise PerformanceBudgetError(f"performance budget {key} must be non-negative")
        if key == "max_failure_rate" and float(value) > 1:
            raise PerformanceBudgetError("max_failure_rate must be between 0 and 1")
        if key == "max_cost_usd":
            result[key] = float(value)
        elif key == "max_failure_rate":
            result[key] = float(value)
        else:
            if int(value) != value or value > 10**12:
                raise PerformanceBudgetError(f"performance budget {key} must be a bounded integer")
            result[key] = int(value)
    return result


def _project_budget_path(skill_root: Path) -> Path | None:
    current = skill_root.resolve(strict=False)
    for candidate_root in (current, *current.parents):
        candidate = candidate_root / ".skill-doctor" / "performance-budgets.json"
        if candidate.is_file():
            return candidate
    return None


def load_performance_budget(
    skill_name: str,
    skill_root: Path,
    *,
    home: Path | None = None,
) -> tuple[PerformanceBudget, tuple[dict[str, str], ...]]:
    sources: list[dict[str, str]] = []
    merged: dict[str, int | float | None] = {}
    user_path = (
        (Path.home() if home is None else home) / ".skill-doctor" / "performance-budgets.json"
    )
    project_path = _project_budget_path(skill_root)
    for path, scope in ((user_path, "user"), (project_path, "project")):
        if path is None or not path.is_file():
            continue
        payload, digest = _bounded_document(path)
        merged.update(_budget_values(payload.get("default")))
        skills = payload.get("skills", {})
        if not isinstance(skills, dict):
            raise PerformanceBudgetError("performance budget skills must be an object")
        skill_budget = skills.get(skill_name)
        merged.update(_budget_values(skill_budget))
        sources.append({"scope": scope, "path": str(path), "sha256": digest})
    return PerformanceBudget(**cast(Any, merged)), tuple(sources)


def _context_metrics(snapshot: Snapshot, skill_name: str) -> tuple[list[Metric], list[str]]:
    metrics: list[Metric] = []
    limitations: list[str] = []
    document = next((item for item in snapshot.files if item.relative_path == "SKILL.md"), None)
    if document is None:
        limitations.append(f"{skill_name}:instruction_context_unavailable")
        return metrics, limitations
    metrics.append(
        Metric(
            "instruction_context_tokens",
            (len(document.data) + 3) // 4,
            "estimated_tokens",
            "estimated",
            skill_name,
            "UTF-8 bytes divided by four; tokenizer-specific measurement is unavailable.",
        )
    )
    try:
        parsed = parse_skill_document(document.data.decode("utf-8"))
        catalog = json.dumps(
            {
                "name": parsed.metadata.get("name"),
                "description": parsed.metadata.get("description"),
            },
            ensure_ascii=False,
            separators=(",", ":"),
        ).encode("utf-8")
        metrics.append(
            Metric(
                "initial_catalog_context_tokens",
                (len(catalog) + 3) // 4,
                "estimated_tokens",
                "estimated",
                skill_name,
                "Bounded name/description catalog projection; tokenizer-specific measurement "
                "is unavailable.",
            )
        )
    except (UnicodeError, FrontmatterError):
        limitations.append(f"{skill_name}:catalog_context_unavailable")
    return metrics, limitations


def _number(metric: dict[str, Any], name: str) -> float | None:
    value = metric.get(name)
    if isinstance(value, bool) or not isinstance(value, int | float):
        return None
    return float(value)


def _percentile_95(values: list[float]) -> float:
    ordered = sorted(values)
    index = max(0, min(len(ordered) - 1, int((len(ordered) - 1) * 0.95)))
    return ordered[index]


def _baseline_key(result: dict[str, Any], ruleset_version: str, budget_hashes: list[str]) -> str:
    raw_context = result.get("context")
    raw_readiness = result.get("readiness")
    context = cast(dict[str, Any], raw_context) if isinstance(raw_context, dict) else {}
    readiness = cast(dict[str, Any], raw_readiness) if isinstance(raw_readiness, dict) else {}
    payload = {
        "skill_name": result.get("skill_name"),
        "platform": context.get("platform"),
        "runtime_version": context.get("runtime_version"),
        "model": context.get("model"),
        "permission_mode": context.get("permission_mode"),
        "config_hash": context.get("config_hash"),
        "backend": readiness.get("backend"),
        "ruleset_version": ruleset_version,
        "budget_hashes": budget_hashes,
    }
    return hashlib.sha256(
        json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
    ).hexdigest()


def analyze_performance(
    *,
    targets: tuple[tuple[Snapshot, str], ...],
    dynamic_results: list[dict[str, Any]],
    ruleset_version: str,
    store: LocalStore,
    controlled_load: bool,
    home: Path | None = None,
) -> PerformanceOutcome:
    metrics: list[Metric] = []
    limitations: list[str] = []
    budgets: dict[str, PerformanceBudget] = {}
    budget_sources: dict[str, tuple[dict[str, str], ...]] = {}
    for snapshot, skill_name in targets:
        context_metrics, context_limitations = _context_metrics(snapshot, skill_name)
        metrics.extend(context_metrics)
        limitations.extend(context_limitations)
        budget, sources = load_performance_budget(skill_name, snapshot.root, home=home)
        budgets[skill_name] = budget
        budget_sources[skill_name] = sources

    findings: list[Finding] = []
    evidence: list[Evidence] = []
    baselines: list[dict[str, Any]] = []
    budget_map = {
        "instruction_context_tokens": "max_instruction_tokens",
        "initial_catalog_context_tokens": "max_catalog_tokens",
    }

    for result in dynamic_results:
        skill_name = str(result.get("skill_name", "skill"))
        raw_trials = result.get("trials", [])
        if not isinstance(raw_trials, list):
            continue
        trials = [cast(dict[str, Any], item) for item in raw_trials if isinstance(item, dict)]
        treatments = [item for item in trials if not item.get("control")]
        controls = [item for item in trials if item.get("control")]
        latencies = [
            value
            for item in treatments
            if isinstance(item.get("runtime_metrics"), dict)
            and (value := _number(cast(dict[str, Any], item["runtime_metrics"]), "wall_latency_ms"))
            is not None
        ]
        if not treatments:
            continue
        failures = sum(1 for item in treatments if not item.get("passed"))
        output_variants = len(
            {
                item.get("final_output_sha256")
                for item in treatments
                if isinstance(item.get("final_output_sha256"), str)
            }
        )
        aggregate: dict[str, int | float] = {
            "sample_count": len(treatments),
            "failure_rate": failures / len(treatments),
            "output_variants": output_variants,
        }
        if latencies:
            aggregate.update(
                {
                    "latency_median_ms": statistics.median(latencies),
                    "latency_p95_ms": _percentile_95(latencies),
                    "latency_max_ms": max(latencies),
                }
            )
        metric_specs = {
            "failure_rate": (aggregate["failure_rate"], "ratio"),
            "output_variants": (output_variants, "count"),
        }
        if latencies:
            metric_specs.update(
                {
                    "execution_latency_median": (aggregate["latency_median_ms"], "ms"),
                    "execution_latency_p95": (aggregate["latency_p95_ms"], "ms"),
                }
            )
        for name, (value, unit) in metric_specs.items():
            metrics.append(Metric(name, value, unit, "measured", skill_name))

        for runtime_name, report_name, unit in (
            ("dependency_setup_ms", "setup_time", "ms"),
            ("tool_calls", "tool_calls", "count"),
            ("model_turns", "model_calls", "count"),
            ("input_tokens", "input_tokens", "tokens"),
            ("output_tokens", "output_tokens", "tokens"),
            ("cost_usd", "model_cost", "USD"),
            ("workspace_bytes", "workspace_disk", "bytes"),
        ):
            values = [
                value
                for item in treatments
                if isinstance(item.get("runtime_metrics"), dict)
                and (value := _number(cast(dict[str, Any], item["runtime_metrics"]), runtime_name))
                is not None
            ]
            if values:
                aggregate[runtime_name] = statistics.median(values)
                metrics.append(
                    Metric(report_name, statistics.median(values), unit, "measured", skill_name)
                )

        control_latencies = [
            value
            for item in controls
            if isinstance(item.get("runtime_metrics"), dict)
            and (value := _number(cast(dict[str, Any], item["runtime_metrics"]), "wall_latency_ms"))
            is not None
        ]
        if latencies and control_latencies:
            delta = statistics.median(latencies) - statistics.median(control_latencies)
            aggregate["with_skill_control_delta_ms"] = delta
            metrics.append(
                Metric(
                    "with_skill_vs_no_skill_latency",
                    delta,
                    "ms",
                    "measured",
                    skill_name,
                )
            )

        budget = budgets.get(skill_name, PerformanceBudget())
        comparisons = {
            "latency_median_ms": budget.max_latency_ms,
            "dependency_setup_ms": budget.max_setup_ms,
            "failure_rate": budget.max_failure_rate,
            "tool_calls": budget.max_tool_calls,
            "model_turns": budget.max_model_turns,
            "cost_usd": budget.max_cost_usd,
            "workspace_bytes": budget.max_workspace_bytes,
            "output_variants": budget.max_output_variants,
        }
        for metric_name, limit in comparisons.items():
            value = aggregate.get(metric_name)
            if limit is None or value is None or float(value) <= float(limit):
                continue
            identifier = hashlib.sha256(
                f"{skill_name}:{metric_name}:{value}:{limit}".encode()
            ).hexdigest()[:20]
            evidence_ids = _paired_evidence(
                evidence,
                identifier,
                "performance_measurement",
                f"Controlled trials measured {metric_name}={value}.",
                "explicit_performance_budget",
                f"The effective explicit {metric_name} budget is {limit}.",
            )
            findings.append(
                Finding(
                    f"performance-{identifier}",
                    "ASD700",
                    "Explicit performance budget exceeded",
                    f"{skill_name} exceeded its configured {metric_name} budget.",
                    "medium",
                    "high" if len(treatments) >= 3 else "medium",
                    "indeterminate",
                    evidence_ids,
                )
            )

        if any(item.get("timed_out") for item in treatments):
            identifier = hashlib.sha256(f"{skill_name}:timeout".encode()).hexdigest()[:20]
            evidence_ids = _paired_evidence(
                evidence,
                identifier,
                "runtime_timeout",
                "A controlled runtime trial timed out.",
                "sandbox_resource_limit",
                "The sandbox attestation records the approved finite trial time limit.",
            )
            findings.append(
                Finding(
                    f"performance-{identifier}",
                    "ASD702",
                    "Controlled runtime timeout",
                    f"{skill_name} exhausted the approved trial time limit.",
                    "high",
                    "high",
                    "indeterminate",
                    evidence_ids,
                )
            )

        hashes = [source["sha256"] for source in budget_sources.get(skill_name, ())]
        series_key = _baseline_key(result, ruleset_version, hashes)
        snapshot_hash = str(result.get("snapshot_hash", ""))
        if len(snapshot_hash) == 64:
            baseline = store.latest_performance_baseline(
                series_key,
                exclude_snapshot=snapshot_hash,
            )
            if baseline is not None:
                baselines.append(
                    {"series_key": series_key, "basis": "baseline-relative", **baseline}
                )
                prior = baseline["metrics"]
                previous_latency = prior.get("latency_median_ms")
                current_latency = aggregate.get("latency_median_ms")
                if (
                    controlled_load
                    and len(treatments) >= 3
                    and baseline["sample_count"] >= 3
                    and isinstance(previous_latency, int | float)
                    and isinstance(current_latency, int | float)
                    and current_latency > previous_latency * 1.2
                    and current_latency - previous_latency >= 500
                ):
                    identifier = hashlib.sha256(
                        f"{series_key}:{snapshot_hash}:regression".encode()
                    ).hexdigest()[:20]
                    evidence_ids = _paired_evidence(
                        evidence,
                        identifier,
                        "controlled_performance_measurement",
                        "At least three non-overlapping controlled trials produced the current "
                        "median latency.",
                        "strict_performance_baseline",
                        "The latest compatible baseline also contains at least three controlled "
                        "samples under the same runtime dimensions.",
                    )
                    findings.append(
                        Finding(
                            f"performance-{identifier}",
                            "ASD701",
                            "Reproducible performance regression",
                            f"{skill_name} median latency increased by more than 20% and 500 ms.",
                            "medium",
                            "high",
                            "indeterminate",
                            evidence_ids,
                        )
                    )
            if (
                controlled_load
                and len(treatments) >= 3
                and not any(item.get("timed_out") or item.get("cancelled") for item in treatments)
            ):
                store.record_performance_baseline(
                    series_key=series_key,
                    snapshot_hash=snapshot_hash,
                    sample_count=len(treatments),
                    metrics=aggregate,
                )

    for metric in list(metrics):
        budget_field = budget_map.get(metric.name)
        budget = budgets.get(metric.skill_name, PerformanceBudget())
        limit = None if budget_field is None else getattr(budget, budget_field)
        if limit is not None and metric.value > limit:
            identifier = hashlib.sha256(
                f"{metric.skill_name}:{metric.name}:{metric.value}:{limit}".encode()
            ).hexdigest()[:20]
            evidence_ids = _paired_evidence(
                evidence,
                identifier,
                "estimated_context_measurement",
                f"The bounded context estimate is {metric.name}={metric.value}.",
                "explicit_performance_budget",
                f"The effective explicit {metric.name} budget is {limit}.",
            )
            findings.append(
                Finding(
                    f"performance-{identifier}",
                    "ASD700",
                    "Explicit context budget exceeded",
                    f"{metric.skill_name} exceeded its configured {metric.name} budget.",
                    "low",
                    "medium",
                    "indeterminate",
                    evidence_ids,
                )
            )

    unsupported = [
        "cold_load_time",
        "warm_load_time",
        "process_cpu_time",
        "peak_memory",
        "network_bytes",
        "retry_count",
    ]
    limitations.extend(f"unsupported_metric:{name}" for name in unsupported)
    limitations.append(
        "Performance measurements include runtime, host, model, and service noise; only "
        "controlled repeated comparisons are eligible for historical regression findings."
    )
    report = {
        "controlled_load": controlled_load,
        "metrics": [asdict(metric) for metric in metrics],
        "budgets": {
            name: {
                "basis": "budgeted",
                "limits": asdict(budget),
                "sources": list(budget_sources.get(name, ())),
            }
            for name, budget in budgets.items()
        },
        "baselines": baselines,
        "limitations": sorted(set(limitations)),
        "policy": (
            "Only explicit budget violations, controlled reproducible regressions, timeouts, "
            "or attested resource exhaustion create findings."
        ),
    }
    return PerformanceOutcome(tuple(findings), tuple(evidence), report)
