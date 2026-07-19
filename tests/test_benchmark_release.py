import json
from pathlib import Path
from typing import Any, cast

from jsonschema import Draft202012Validator

from skill_doctor.benchmark import (
    release_gate_report,
    run_causal_benchmark,
    run_static_benchmark,
    unresolved_critical_escapes,
)

ROOT = Path(__file__).parents[1]
PUBLIC = ROOT / "benchmarks" / "public" / "v1"


def _ratio(value: float) -> dict[str, Any]:
    return {"numerator": int(value * 100), "denominator": 100, "value": value, "available": True}


def _validation(platform: str) -> dict[str, Any]:
    return {
        "platform": platform,
        "containment": _ratio(1.0),
        "fault_injection": _ratio(1.0),
        "public_functional": _ratio(1.0),
        "known_critical_sandbox_escapes": 0,
    }


def test_public_versioned_corpus_meets_static_and_causal_quality_gates() -> None:
    static = run_static_benchmark(PUBLIC / "manifest.json")
    causal = run_causal_benchmark(PUBLIC / "causal.json")
    assert all(case["passed"] for case in static["cases"])
    assert static["metrics"]["highlighted_precision"]["value"] >= 0.95
    assert static["metrics"]["expected_finding_recall"]["value"] == 1.0
    assert static["metrics"]["benign_false_positive_rate"]["value"] <= 0.02
    assert static["metrics"]["static_completion_rate"]["value"] >= 0.995
    assert causal["metrics"]["root_cause_accuracy"]["value"] >= 0.9
    assert causal["metrics"]["reproduction_consistency"]["value"] >= 0.9


def test_public_corpus_records_license_provenance_and_exact_upstream_revisions() -> None:
    manifest = cast(
        dict[str, Any], json.loads((PUBLIC / "manifest.json").read_text(encoding="utf-8"))
    )
    for case in cast(list[dict[str, Any]], manifest["cases"]):
        assert case["origin"]
        assert case["license"]["spdx"]
        assert case["modification_history"]
    sources = cast(list[dict[str, Any]], manifest["licensed_upstream_sources"])
    assert {source["id"] for source in sources} == {
        "openai-skill-creator",
        "anthropic-skill-creator",
    }
    for source in sources:
        assert len(str(source["commit"])) == 40
        assert len(str(source["git_tree"])) == 40
        assert len(str(source["license_sha256"])) == 64
        assert len(str(source["vendored_snapshot_sha256"])) == 64


def test_benchmark_manifests_match_published_schemas_and_escape_register_is_clear() -> None:
    mappings = {
        "benchmark.schema.json": PUBLIC / "manifest.json",
        "functional-benchmark.schema.json": PUBLIC / "functional.json",
    }
    for schema_name, document_path in mappings.items():
        schema = json.loads((ROOT / "schemas" / schema_name).read_text(encoding="utf-8"))
        document = json.loads(document_path.read_text(encoding="utf-8"))
        Draft202012Validator(schema).validate(document)
    assert unresolved_critical_escapes(ROOT / "security" / "known-sandbox-escapes.json") == 0


def test_stable_release_gate_requires_held_out_and_all_platform_evidence() -> None:
    static = run_static_benchmark(PUBLIC / "manifest.json")
    causal = run_causal_benchmark(PUBLIC / "causal.json")
    validations = [_validation(name) for name in ("windows", "macos", "linux")]
    held_out = {
        "schema_version": "1.0.0",
        "corpus_version": "held-out-2026-07-a",
        "release_version": "v1.0.0",
        "rotation_id": "2026-07-a",
        "rotating": True,
        "evaluated_at": "2026-07-16T00:00:00Z",
        "evaluator_commit": "a" * 40,
        "case_count": static["case_count"],
        "disjoint_from_public_sha256": "b" * 64,
        "metrics": static["metrics"],
    }
    release_evidence = {
        "schema_version": "1.0.0",
        "release_version": "v1.0.0",
        "evaluator_commit": "a" * 40,
        "recorded_at": "2026-07-16T00:00:00Z",
        "participant_count": 2,
        "platforms": ["windows", "macos", "linux"],
        "runtime_contexts": [{"platform": "codex", "runtime_version": "1.0", "model": "model"}],
        "issue_count": 1,
        "remediated_issue_count": 1,
        "open_release_blockers": 0,
        "remediation_started_at": "2026-07-01T00:00:00Z",
        "remediation_completed_at": "2026-07-15T00:00:00Z",
        "public_preview_completed": True,
        "signoff": True,
    }
    passed = release_gate_report(
        static=static,
        causal=causal,
        validations=validations,
        held_out=held_out,
        held_out_attested=True,
        release_evidence=release_evidence,
        release_evidence_attested=True,
    )
    assert passed["stable_v1_ready"] is True
    assert all(passed["gates"].values())

    no_held_out = release_gate_report(
        static=static,
        causal=causal,
        validations=validations,
    )
    assert no_held_out["stable_v1_ready"] is False
    assert no_held_out["gates"]["rotating_held_out_corpus"] is False

    failed_fault = [*validations]
    failed_fault[0] = {**failed_fault[0], "fault_injection": _ratio(0.99)}
    failed = release_gate_report(
        static=static,
        causal=causal,
        validations=failed_fault,
        held_out=held_out,
        held_out_attested=True,
        release_evidence=release_evidence,
        release_evidence_attested=True,
    )
    assert failed["gates"]["fault_injection_100_percent"] is False
