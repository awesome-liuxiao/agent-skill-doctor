from __future__ import annotations

import hashlib
import json
import math
import re
import time
import xml.etree.ElementTree as ET
from dataclasses import asdict, dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, cast

from skill_doctor import __version__
from skill_doctor.analysis import RULESET_VERSION, analyze
from skill_doctor.causal import assess_causality
from skill_doctor.snapshot import SnapshotError, create_snapshot


class BenchmarkError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class RatioMetric:
    numerator: int
    denominator: int
    value: float | None
    available: bool


def _ratio(numerator: int, denominator: int) -> RatioMetric:
    return RatioMetric(
        numerator,
        denominator,
        None if denominator == 0 else numerator / denominator,
        denominator > 0,
    )


def _manifest(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_bytes())
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise BenchmarkError(f"cannot read benchmark manifest: {error}") from error
    if not isinstance(payload, dict):
        raise BenchmarkError("benchmark manifest must be an object")
    if (
        payload.get("schema_version") != "1.0.0"
        or not isinstance(payload.get("cases"), list)
        or not payload["cases"]
    ):
        raise BenchmarkError("benchmark manifest version or cases are invalid")
    return cast(dict[str, Any], payload)


def _repository_root(manifest: Path) -> Path:
    for candidate in (manifest.parent, *manifest.parents):
        if (candidate / "pyproject.toml").is_file():
            return candidate.resolve(strict=True)
    raise BenchmarkError("benchmark manifest is not inside the repository")


def run_static_benchmark(manifest_path: Path) -> dict[str, Any]:
    manifest_path = manifest_path.resolve(strict=True)
    manifest = _manifest(manifest_path)
    repository = _repository_root(manifest_path)
    raw_cases = manifest["cases"]
    raw_sources = manifest.get("licensed_upstream_sources")
    if not isinstance(raw_sources, list) or not all(isinstance(item, dict) for item in raw_sources):
        raise BenchmarkError("licensed upstream sources are invalid")
    sources: dict[str, dict[str, Any]] = {}
    for raw_source in raw_sources:
        source = cast(dict[str, Any], raw_source)
        required_source = {
            "id",
            "repository",
            "commit",
            "git_tree",
            "path",
            "license",
            "license_path",
            "license_sha256",
            "vendored_snapshot_sha256",
            "ingestion",
        }
        identifier = source.get("id")
        if (
            set(source) != required_source
            or not isinstance(identifier, str)
            or identifier in sources
            or not isinstance(source.get("repository"), str)
            or not str(source["repository"]).startswith("https://")
            or not isinstance(source.get("path"), str)
            or not source["path"]
            or source.get("license")
            not in {
                "Apache-2.0",
                "MIT",
                "BSD-2-Clause",
                "BSD-3-Clause",
                "CC0-1.0",
            }
            or not isinstance(source.get("license_path"), str)
            or not source["license_path"]
            or not isinstance(source.get("ingestion"), str)
            or not source["ingestion"]
            or re.fullmatch(r"[0-9a-f]{40}", str(source.get("commit"))) is None
            or re.fullmatch(r"[0-9a-f]{40}", str(source.get("git_tree"))) is None
            or re.fullmatch(r"[0-9a-f]{64}", str(source.get("license_sha256"))) is None
            or re.fullmatch(r"[0-9a-f]{64}", str(source.get("vendored_snapshot_sha256"))) is None
        ):
            raise BenchmarkError("licensed upstream source is invalid")
        sources[identifier] = source
    case_results: list[dict[str, Any]] = []
    highlighted_true_positive = 0
    highlighted_false_positive = 0
    expected_matched = 0
    expected_total = 0
    benign_cases = 0
    benign_false_positive = 0
    completed = 0
    supported_cases = 0
    durations_ms: list[float] = []
    case_ids: set[str] = set()
    used_sources: set[str] = set()
    for raw in raw_cases:
        if not isinstance(raw, dict):
            raise BenchmarkError("benchmark case must be an object")
        case = cast(dict[str, Any], raw)
        required = {
            "id",
            "path",
            "stratum",
            "languages",
            "origin",
            "license",
            "modification_history",
            "expected_rule_ids",
            "expected_coverage",
        }
        if set(case) != required:
            raise BenchmarkError("benchmark case has missing or unknown fields")
        identifier = case.get("id")
        relative = case.get("path")
        expected = case.get("expected_rule_ids")
        if (
            not isinstance(identifier, str)
            or not identifier
            or identifier in case_ids
            or not isinstance(relative, str)
            or not relative
            or not isinstance(expected, list)
            or not all(isinstance(item, str) for item in expected)
            or len(set(cast(list[str], expected))) != len(expected)
            or not all(re.fullmatch(r"ASD[0-9]{3}", item) for item in expected)
            or not isinstance(case.get("stratum"), str)
            or not case["stratum"]
            or not isinstance(case.get("languages"), list)
            or not case["languages"]
            or not all(isinstance(item, str) and item for item in case["languages"])
            or not isinstance(case.get("modification_history"), list)
            or not case["modification_history"]
            or not all(isinstance(item, str) and item for item in case["modification_history"])
        ):
            raise BenchmarkError("benchmark case identity, path, or expectations are invalid")
        case_ids.add(identifier)
        path = (manifest_path.parent / relative).resolve(strict=True)
        if not path.is_relative_to(repository):
            raise BenchmarkError("benchmark case escaped the repository")
        license_record = case.get("license")
        if not isinstance(license_record, dict) or license_record.get("spdx") not in {
            "Apache-2.0",
            "MIT",
            "BSD-2-Clause",
            "BSD-3-Clause",
            "CC0-1.0",
        }:
            raise BenchmarkError("benchmark case license is missing or unsupported")
        license_path = license_record.get("path")
        if not isinstance(license_path, str):
            raise BenchmarkError("benchmark case license path is invalid")
        resolved_license = (manifest_path.parent / license_path).resolve(strict=True)
        if not resolved_license.is_relative_to(repository) or not resolved_license.is_file():
            raise BenchmarkError("benchmark license escaped the repository")
        analysis_failed = False
        snapshot_digest: str | None = None
        started = time.perf_counter_ns()
        try:
            snapshot = create_snapshot(path)
            snapshot_digest = snapshot.digest
            analysis = analyze(snapshot)
        except (OSError, SnapshotError, ValueError):
            analysis_failed = True
            predicted: set[str] = set()
            highlighted: set[str] = set()
            coverage_failed = ["benchmark_analysis"]
            coverage_skipped: list[str] = []
            coverage_unsupported: list[str] = []
        else:
            predicted = {finding.rule_id for finding in analysis.findings}
            highlighted = {
                finding.rule_id for finding in analysis.findings if finding.confidence == "high"
            }
            coverage_failed = list(analysis.coverage.failed)
            coverage_skipped = list(analysis.coverage.skipped)
            coverage_unsupported = list(analysis.coverage.unsupported)
        duration_ms = (time.perf_counter_ns() - started) / 1_000_000
        durations_ms.append(duration_ms)
        origin = case.get("origin")
        if (
            not isinstance(origin, dict)
            or set(origin) != {"type", "url", "commit"}
            or origin.get("type")
            not in {
                "synthetic",
                "licensed-upstream",
            }
            or (
                origin.get("type") == "synthetic"
                and (origin.get("url") is not None or origin.get("commit") is not None)
            )
        ):
            raise BenchmarkError("benchmark case origin is invalid")
        if origin.get("type") == "licensed-upstream":
            used_sources.add(identifier)
            pinned_source = sources.get(identifier)
            if (
                pinned_source is None
                or origin.get("url") != pinned_source.get("repository")
                or origin.get("commit") != pinned_source.get("commit")
                or analysis_failed
                or snapshot_digest != pinned_source.get("vendored_snapshot_sha256")
                or hashlib.sha256(resolved_license.read_bytes()).hexdigest()
                != pinned_source.get("license_sha256")
            ):
                raise BenchmarkError("vendored upstream source does not match pinned provenance")
        expected_set = set(cast(list[str], expected))
        matched = predicted & expected_set
        unexpected = predicted - expected_set
        missed = expected_set - predicted
        highlighted_true_positive += len(highlighted & expected_set)
        highlighted_false_positive += len(highlighted - expected_set)
        expected_matched += len(matched)
        expected_total += len(expected_set)
        stratum = str(case.get("stratum"))
        if "benign" in stratum:
            benign_cases += 1
            benign_false_positive += bool(predicted)
        expected_coverage = case.get("expected_coverage")
        if not isinstance(expected_coverage, dict) or set(expected_coverage) != {
            "failed",
            "unsupported_contains",
        }:
            raise BenchmarkError("benchmark case coverage expectation is invalid")
        expected_failed = expected_coverage.get("failed")
        expected_unsupported = expected_coverage.get("unsupported_contains")
        if (
            not isinstance(expected_failed, list)
            or not all(isinstance(item, str) for item in expected_failed)
            or not isinstance(expected_unsupported, list)
            or not all(isinstance(item, str) for item in expected_unsupported)
        ):
            raise BenchmarkError("benchmark case coverage expectation values are invalid")
        expected_failed_set = set(cast(list[str], expected_failed))
        unsupported_expectations = cast(list[str], expected_unsupported)
        coverage_matches = set(coverage_failed) == expected_failed_set and all(
            any(fragment in actual for actual in coverage_unsupported)
            for fragment in unsupported_expectations
        )
        supported_case = not expected_failed_set
        supported_cases += supported_case
        if supported_case and not analysis_failed and not coverage_failed:
            completed += 1
        case_results.append(
            {
                "id": identifier,
                "stratum": stratum,
                "languages": case.get("languages"),
                "duration_ms": round(duration_ms, 3),
                "predicted_rule_ids": sorted(predicted),
                "highlighted_rule_ids": sorted(highlighted),
                "expected_rule_ids": sorted(expected_set),
                "matched_rule_ids": sorted(matched),
                "unexpected_rule_ids": sorted(unexpected),
                "missed_rule_ids": sorted(missed),
                "coverage_failed": coverage_failed,
                "coverage_skipped": coverage_skipped,
                "coverage_unsupported": coverage_unsupported,
                "expected_coverage": expected_coverage,
                "passed": not unexpected and not missed and coverage_matches,
            }
        )
    if used_sources != set(sources):
        raise BenchmarkError("licensed upstream sources and vendored cases do not match")
    ordered_durations = sorted(durations_ms)
    total_duration_ms = sum(durations_ms)
    return {
        "schema_version": "1.0.0",
        "tool_version": __version__,
        "corpus_version": manifest.get("corpus_version"),
        "ruleset_version": RULESET_VERSION,
        "manifest": manifest_path.relative_to(repository).as_posix(),
        "case_count": len(case_results),
        "cases": case_results,
        "metrics": {
            "highlighted_precision": asdict(
                _ratio(
                    highlighted_true_positive,
                    highlighted_true_positive + highlighted_false_positive,
                )
            ),
            "expected_finding_recall": asdict(_ratio(expected_matched, expected_total)),
            "benign_false_positive_rate": asdict(_ratio(benign_false_positive, benign_cases)),
            "static_completion_rate": asdict(_ratio(completed, supported_cases)),
        },
        "runtime": {
            "basis": "measured_monotonic_wall_clock",
            "total_duration_ms": round(total_duration_ms, 3),
            "median_case_duration_ms": round(ordered_durations[len(ordered_durations) // 2], 3),
            "p95_case_duration_ms": round(
                ordered_durations[max(0, math.ceil(len(ordered_durations) * 0.95) - 1)], 3
            ),
            "cases_per_second": (
                None
                if total_duration_ms == 0
                else round(len(case_results) / (total_duration_ms / 1000), 3)
            ),
        },
        "licensed_upstream_sources": manifest.get("licensed_upstream_sources", []),
    }


def run_causal_benchmark(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_bytes())
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise BenchmarkError(f"cannot read causal benchmark: {error}") from error
    if not isinstance(payload, dict) or payload.get("schema_version") != "1.0.0":
        raise BenchmarkError("causal benchmark is invalid")
    scenarios = payload.get("scenarios")
    if not isinstance(scenarios, list):
        raise BenchmarkError("causal benchmark scenarios are invalid")
    correct = 0
    outcomes: list[dict[str, Any]] = []
    consistent = 0
    consistency_total = 0
    for raw in scenarios:
        if not isinstance(raw, dict) or set(raw) != {
            "id",
            "expected_confirmed",
            "dynamic_results",
            "license",
        }:
            raise BenchmarkError("causal benchmark scenario is invalid")
        scenario = cast(dict[str, Any], raw)
        results = scenario.get("dynamic_results")
        if not isinstance(results, list) or not all(isinstance(item, dict) for item in results):
            raise BenchmarkError("causal benchmark dynamic results are invalid")
        outcome = assess_causality(
            existing_findings=[],
            existing_evidence=[],
            dynamic_results=cast(list[dict[str, Any]], results),
        )
        expected = scenario.get("expected_confirmed")
        if not isinstance(expected, bool):
            raise BenchmarkError("causal benchmark expectation is invalid")
        correct += outcome.confirmed == expected
        for result in cast(list[dict[str, Any]], results):
            trials = result.get("trials")
            if not isinstance(trials, list):
                continue
            treatments = [
                item for item in trials if isinstance(item, dict) and not item.get("control")
            ]
            if len(treatments) >= 2:
                consistency_total += 1
                consistent += len({bool(item.get("passed")) for item in treatments}) == 1
        outcomes.append(
            {
                "id": scenario.get("id"),
                "expected_confirmed": expected,
                "observed_confirmed": outcome.confirmed,
                "passed": outcome.confirmed == expected,
            }
        )
    return {
        "schema_version": "1.0.0",
        "scenario_count": len(outcomes),
        "scenarios": outcomes,
        "metrics": {
            "root_cause_accuracy": asdict(_ratio(correct, len(outcomes))),
            "reproduction_consistency": asdict(_ratio(consistent, consistency_total)),
        },
    }


def unresolved_critical_escapes(path: Path) -> int:
    try:
        payload = json.loads(path.read_bytes())
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise BenchmarkError(f"cannot read sandbox escape register: {error}") from error
    if not isinstance(payload, dict) or set(payload) != {
        "schema_version",
        "reviewed_at",
        "entries",
    }:
        raise BenchmarkError("sandbox escape register is invalid")
    reviewed_at = payload.get("reviewed_at")
    if payload.get("schema_version") != "1.0.0" or not isinstance(reviewed_at, str):
        raise BenchmarkError("sandbox escape register metadata is invalid")
    try:
        reviewed = datetime.fromisoformat(reviewed_at.replace("Z", "+00:00"))
    except ValueError as error:
        raise BenchmarkError("sandbox escape register timestamp is invalid") from error
    if reviewed.tzinfo is None or reviewed.utcoffset() is None:
        raise BenchmarkError("sandbox escape register timestamp must include an offset")
    entries = payload.get("entries")
    if not isinstance(entries, list):
        raise BenchmarkError("sandbox escape register entries are invalid")
    unresolved = 0
    identifiers: set[str] = set()
    for raw in entries:
        if not isinstance(raw, dict) or set(raw) != {
            "id",
            "severity",
            "status",
            "platforms",
            "disclosure",
        }:
            raise BenchmarkError("sandbox escape register entry is invalid")
        entry = cast(dict[str, Any], raw)
        identifier = entry.get("id")
        platforms = entry.get("platforms")
        if (
            not isinstance(identifier, str)
            or not identifier
            or identifier in identifiers
            or entry.get("severity") not in {"low", "medium", "high", "critical"}
            or entry.get("status") not in {"open", "fixed", "accepted"}
            or not isinstance(platforms, list)
            or not platforms
            or not all(item in {"windows", "macos", "linux"} for item in platforms)
            or not isinstance(entry.get("disclosure"), str)
            or not entry["disclosure"]
        ):
            raise BenchmarkError("sandbox escape register entry values are invalid")
        identifiers.add(identifier)
        unresolved += entry["severity"] == "critical" and entry["status"] != "fixed"
    return unresolved


def validation_from_junit(
    path: Path,
    *,
    platform_name: str,
    known_critical_sandbox_escapes: int | None = None,
) -> dict[str, Any]:
    try:
        root = ET.fromstring(path.read_bytes())  # noqa: S314 - locally generated pytest XML
    except (OSError, ET.ParseError) as error:
        raise BenchmarkError(f"cannot read validation JUnit: {error}") from error
    cases = root.findall(".//testcase")
    containment = [
        item
        for item in cases
        if "test_sandbox" in item.get("classname", "")
        or "test_runtime" in item.get("classname", "")
    ]
    faults = [item for item in cases if "test_fault_injection" in item.get("classname", "")]
    functional = [
        item for item in cases if "test_public_functional_benchmark" in item.get("classname", "")
    ]

    def passed(items: list[ET.Element]) -> int:
        return sum(
            item.find("failure") is None
            and item.find("error") is None
            and item.find("skipped") is None
            for item in items
        )

    return {
        "platform": platform_name,
        "containment": asdict(_ratio(passed(containment), len(containment))),
        "fault_injection": asdict(_ratio(passed(faults), len(faults))),
        "public_functional": asdict(_ratio(passed(functional), len(functional))),
        "known_critical_sandbox_escapes": known_critical_sandbox_escapes,
    }


def validate_held_out_result(value: object) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise BenchmarkError("held-out result must be an object")
    result = cast(dict[str, Any], value)
    if set(result) != {
        "schema_version",
        "corpus_version",
        "release_version",
        "rotation_id",
        "rotating",
        "evaluated_at",
        "evaluator_commit",
        "case_count",
        "disjoint_from_public_sha256",
        "metrics",
    }:
        raise BenchmarkError("held-out result has missing or unknown fields")
    if (
        result.get("schema_version") != "1.0.0"
        or not isinstance(result.get("corpus_version"), str)
        or not str(result["corpus_version"]).startswith("held-out-")
        or not isinstance(result.get("release_version"), str)
        or not result["release_version"]
        or not isinstance(result.get("rotation_id"), str)
        or not result["rotation_id"]
        or result.get("rotating") is not True
        or not isinstance(result.get("case_count"), int)
        or isinstance(result.get("case_count"), bool)
        or int(result["case_count"]) < 1
        or re.fullmatch(r"[0-9a-f]{40}", str(result.get("evaluator_commit"))) is None
        or re.fullmatch(r"[0-9a-f]{64}", str(result.get("disjoint_from_public_sha256"))) is None
    ):
        raise BenchmarkError("held-out result identity or rotation metadata is invalid")
    evaluated_at = result.get("evaluated_at")
    if not isinstance(evaluated_at, str):
        raise BenchmarkError("held-out result timestamp is invalid")
    try:
        timestamp = datetime.fromisoformat(evaluated_at.replace("Z", "+00:00"))
    except ValueError as error:
        raise BenchmarkError("held-out result timestamp is invalid") from error
    if timestamp.tzinfo is None or timestamp.utcoffset() is None:
        raise BenchmarkError("held-out result timestamp must include an offset")
    metrics = result.get("metrics")
    required_metrics = {
        "highlighted_precision",
        "expected_finding_recall",
        "benign_false_positive_rate",
        "static_completion_rate",
    }
    if not isinstance(metrics, dict) or set(metrics) != required_metrics:
        raise BenchmarkError("held-out result metrics are invalid")
    for name, raw_metric in metrics.items():
        if not isinstance(raw_metric, dict) or set(raw_metric) != {
            "numerator",
            "denominator",
            "value",
            "available",
        }:
            raise BenchmarkError(f"held-out metric {name} is invalid")
        metric = cast(dict[str, Any], raw_metric)
        numerator = metric.get("numerator")
        denominator = metric.get("denominator")
        measured = metric.get("value")
        if (
            metric.get("available") is not True
            or not isinstance(numerator, int)
            or isinstance(numerator, bool)
            or not isinstance(denominator, int)
            or isinstance(denominator, bool)
            or denominator <= 0
            or not 0 <= numerator <= denominator
            or not isinstance(measured, int | float)
            or isinstance(measured, bool)
            or abs(float(measured) - numerator / denominator) > 1e-12
        ):
            raise BenchmarkError(f"held-out metric {name} ratio is invalid")
    return result


def validate_release_evidence(value: object) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise BenchmarkError("release evidence must be an object")
    evidence = cast(dict[str, Any], value)
    if set(evidence) != {
        "schema_version",
        "release_version",
        "evaluator_commit",
        "recorded_at",
        "participant_count",
        "platforms",
        "runtime_contexts",
        "issue_count",
        "remediated_issue_count",
        "open_release_blockers",
        "remediation_started_at",
        "remediation_completed_at",
        "public_preview_completed",
        "signoff",
    }:
        raise BenchmarkError("release evidence has missing or unknown fields")

    def timestamp(name: str) -> datetime:
        raw = evidence.get(name)
        if not isinstance(raw, str):
            raise BenchmarkError(f"release evidence {name} is invalid")
        try:
            parsed = datetime.fromisoformat(raw.replace("Z", "+00:00"))
        except ValueError as error:
            raise BenchmarkError(f"release evidence {name} is invalid") from error
        if parsed.tzinfo is None or parsed.utcoffset() is None:
            raise BenchmarkError(f"release evidence {name} must include an offset")
        return parsed

    recorded = timestamp("recorded_at")
    started = timestamp("remediation_started_at")
    completed = timestamp("remediation_completed_at")
    del recorded
    participants = evidence.get("participant_count")
    issues = evidence.get("issue_count")
    remediated = evidence.get("remediated_issue_count")
    blockers = evidence.get("open_release_blockers")
    platforms = evidence.get("platforms")
    contexts = evidence.get("runtime_contexts")
    integers = (participants, issues, remediated, blockers)
    if (
        evidence.get("schema_version") != "1.0.0"
        or not isinstance(evidence.get("release_version"), str)
        or not evidence["release_version"]
        or re.fullmatch(r"[0-9a-f]{40}", str(evidence.get("evaluator_commit"))) is None
        or any(not isinstance(item, int) or isinstance(item, bool) for item in integers)
    ):
        raise BenchmarkError("release evidence values are invalid")
    participant_count, issue_count, remediated_count, blocker_count = cast(
        tuple[int, int, int, int], integers
    )
    if (
        participant_count < 1
        or issue_count < 0
        or remediated_count < 0
        or remediated_count > issue_count
        or blocker_count < 0
        or not isinstance(platforms, list)
        or not platforms
        or not all(
            isinstance(item, str) and item in {"windows", "macos", "linux"} for item in platforms
        )
        or len(set(cast(list[str], platforms))) != len(platforms)
        or not isinstance(contexts, list)
        or not contexts
        or evidence.get("public_preview_completed") is not True
        or evidence.get("signoff") is not True
        or completed < started
    ):
        raise BenchmarkError("release evidence values are invalid")
    for context in cast(list[object], contexts):
        if not isinstance(context, dict) or set(context) != {
            "platform",
            "runtime_version",
            "model",
        }:
            raise BenchmarkError("release runtime context is invalid")
        if (
            context.get("platform") not in {"codex", "claude"}
            or not isinstance(context.get("runtime_version"), str)
            or not context["runtime_version"]
            or not isinstance(context.get("model"), str)
            or not context["model"]
        ):
            raise BenchmarkError("release runtime context values are invalid")
    return evidence


def release_gate_report(
    *,
    static: dict[str, Any],
    causal: dict[str, Any],
    validations: list[dict[str, Any]],
    held_out: dict[str, Any] | None = None,
    held_out_attested: bool = False,
    release_evidence: dict[str, Any] | None = None,
    release_evidence_attested: bool = False,
) -> dict[str, Any]:
    validated_held_out = None if held_out is None else validate_held_out_result(held_out)
    validated_release_evidence = (
        None if release_evidence is None else validate_release_evidence(release_evidence)
    )
    source = static if validated_held_out is None else validated_held_out
    static_metrics = cast(dict[str, dict[str, Any]], source["metrics"])
    causal_metrics = cast(dict[str, dict[str, Any]], causal["metrics"])
    platforms = {str(item.get("platform")) for item in validations}
    containment_numerator = sum(
        int(cast(dict[str, Any], item.get("containment", {})).get("numerator", 0))
        for item in validations
    )
    containment_denominator = sum(
        int(cast(dict[str, Any], item.get("containment", {})).get("denominator", 0))
        for item in validations
    )
    containment = asdict(_ratio(containment_numerator, containment_denominator))
    fault_numerator = sum(
        int(cast(dict[str, Any], item.get("fault_injection", {})).get("numerator", 0))
        for item in validations
    )
    fault_denominator = sum(
        int(cast(dict[str, Any], item.get("fault_injection", {})).get("denominator", 0))
        for item in validations
    )
    fault_injection = asdict(_ratio(fault_numerator, fault_denominator))
    functional_numerator = sum(
        int(cast(dict[str, Any], item.get("public_functional", {})).get("numerator", 0))
        for item in validations
    )
    functional_denominator = sum(
        int(cast(dict[str, Any], item.get("public_functional", {})).get("denominator", 0))
        for item in validations
    )
    public_functional = asdict(_ratio(functional_numerator, functional_denominator))
    values = {
        "highlighted_precision": static_metrics["highlighted_precision"],
        "benign_false_positive_rate": static_metrics["benign_false_positive_rate"],
        "root_cause_accuracy": causal_metrics["root_cause_accuracy"],
        "reproduction_consistency": causal_metrics["reproduction_consistency"],
        "static_completion_rate": static_metrics["static_completion_rate"],
        "containment_canary_pass_rate": containment,
        "fault_injection_pass_rate": fault_injection,
        "public_functional_pass_rate": public_functional,
    }

    def at_least(name: str, threshold: float) -> bool:
        metric = values[name]
        return metric.get("available") is True and float(metric["value"]) >= threshold

    def at_most(name: str, threshold: float) -> bool:
        metric = values[name]
        return metric.get("available") is True and float(metric["value"]) <= threshold

    gates = {
        "precision_at_least_95_percent": at_least("highlighted_precision", 0.95),
        "benign_false_positive_at_most_2_percent": at_most("benign_false_positive_rate", 0.02),
        "root_cause_accuracy_at_least_90_percent": at_least("root_cause_accuracy", 0.9),
        "reproduction_consistency_at_least_90_percent": at_least("reproduction_consistency", 0.9),
        "static_completion_at_least_99_5_percent": at_least("static_completion_rate", 0.995),
        "containment_and_canary_100_percent": at_least("containment_canary_pass_rate", 1.0),
        "fault_injection_100_percent": at_least("fault_injection_pass_rate", 1.0),
        "public_functional_100_percent": at_least("public_functional_pass_rate", 1.0),
        "three_platform_validation": platforms >= {"windows", "macos", "linux"},
        "rotating_held_out_corpus": validated_held_out is not None,
        "held_out_attestation_verified": validated_held_out is not None and held_out_attested,
        "private_design_partner_alpha": validated_release_evidence is not None,
        "remediation_period_complete": (
            validated_release_evidence is not None
            and validated_release_evidence["open_release_blockers"] == 0
            and validated_release_evidence["remediated_issue_count"]
            == validated_release_evidence["issue_count"]
        ),
        "public_preview_completed": (
            validated_release_evidence is not None
            and validated_release_evidence["public_preview_completed"] is True
        ),
        "release_evidence_attestation_verified": (
            validated_release_evidence is not None and release_evidence_attested
        ),
        "no_known_critical_sandbox_escape": all(
            item.get("known_critical_sandbox_escapes") == 0 for item in validations
        ),
    }
    stable = all(gates.values())
    return {
        "schema_version": "1.0.0",
        "metrics": values,
        "gates": gates,
        "stable_v1_ready": stable,
        "maximum_release_stage": "stable_v1" if stable else "public_preview_candidate",
        "limitations": [name for name, passed in gates.items() if not passed],
    }
