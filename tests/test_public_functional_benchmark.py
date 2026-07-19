import json
import os
from pathlib import Path

import pytest

from skill_doctor.analysis import analyze
from skill_doctor.dependencies import DependencyPlanError, build_dependency_plan
from skill_doctor.discovery import DiscoveryContext, discover_codex
from skill_doctor.engine import execute_session_diagnosis
from skill_doctor.evals import RuntimeObservation, evaluate_assertions, load_authored_contract
from skill_doctor.performance import analyze_performance
from skill_doctor.security import ArtifactCipher
from skill_doctor.snapshot import create_snapshot
from skill_doctor.store import LocalStore

ROOT = Path(__file__).parents[1]
PUBLIC = ROOT / "benchmarks" / "public" / "v1"
FUNCTIONAL = PUBLIC / "functional"
CREATED = "2026-07-16T00:00:00Z"


def _store(root: Path) -> LocalStore:
    return LocalStore(root, cipher=ArtifactCipher(os.urandom(32)))


def test_public_functional_manifest_has_every_required_mutation_stratum() -> None:
    payload = json.loads((PUBLIC / "functional.json").read_text(encoding="utf-8"))
    categories = {scenario["category"] for scenario in payload["scenarios"]}
    assert categories >= {
        "broken_references",
        "missing_dependencies",
        "collisions",
        "context_bloat",
        "trigger_failures",
        "portability_defects",
        "performance_regressions",
        "functional_evaluation_contracts",
    }
    assert all(scenario["pytest_node_id"] for scenario in payload["scenarios"])


def test_public_functional_broken_reference() -> None:
    result = analyze(create_snapshot(PUBLIC / "fixtures" / "broken-reference"))
    assert {finding.rule_id for finding in result.findings} == {"ASD005"}


def test_public_functional_missing_dependency() -> None:
    with pytest.raises(DependencyPlanError, match="pin a version"):
        build_dependency_plan(FUNCTIONAL / "missing-dependency")


def test_public_functional_collision() -> None:
    fixture = FUNCTIONAL / "collision"
    repo = fixture / "repo"
    context = DiscoveryContext(
        cwd=repo,
        repository_root=repo,
        home=fixture / "home",
        codex_home=fixture / "codex-home",
        claude_home=fixture / "claude-home",
        codex_admin_skills=fixture / "admin",
        claude_managed_root=fixture / "managed",
    )
    inventory = discover_codex(context)
    copies = [copy for copy in inventory.copies if copy.name == "deploy"]
    assert len(copies) == 2
    assert {copy.status for copy in copies} == {"ambiguous"}
    assert any(item.code == "CODEX_DUPLICATE_NAME" for item in inventory.diagnostics)


def test_public_functional_context_bloat(tmp_path: Path) -> None:
    skill = FUNCTIONAL / "context-bloat" / "repo" / ".agents" / "skills" / "context-bloat"
    outcome = analyze_performance(
        targets=((create_snapshot(skill), "context-bloat"),),
        dynamic_results=[],
        ruleset_version="public-benchmark",
        store=_store(tmp_path / "state"),
        controlled_load=False,
        home=tmp_path / "empty-home",
    )
    assert {finding.rule_id for finding in outcome.findings} == {"ASD700"}


def test_public_functional_trigger_failure(tmp_path: Path) -> None:
    repo = FUNCTIONAL / "trigger-failure" / "repo"
    session_id = "public-trigger"
    trace = tmp_path / ".codex" / "sessions" / f"rollout-{session_id}.jsonl"
    trace.parent.mkdir(parents=True)
    records = [
        {"type": "session_meta", "payload": {"id": session_id, "cwd": str(repo)}},
        {
            "type": "event_msg",
            "payload": {
                "type": "user_message",
                "message": "Validate production release artifacts before deployment",
            },
        },
    ]
    trace.write_text("".join(json.dumps(item) + "\n" for item in records), encoding="utf-8")
    store = _store(tmp_path / "state")
    store.start_job("public-trigger", CREATED, str(repo))
    context = DiscoveryContext(
        cwd=repo,
        repository_root=repo,
        home=tmp_path,
        codex_home=tmp_path / ".codex",
        claude_home=tmp_path / ".claude",
        codex_admin_skills=tmp_path / "admin",
        claude_managed_root=tmp_path / "managed",
    )
    result = execute_session_diagnosis(
        job_id="public-trigger",
        created_at=CREATED,
        platform_name="codex",
        cwd=repo,
        store=store,
        emit=lambda _stage, _summary, _detail: None,
        cancelled=lambda: False,
        context=context,
        home=tmp_path,
        environment={"CODEX_THREAD_ID": session_id},
    )
    assert result.report is not None
    assert result.report.session_targets == []
    assert [item.selector for item in result.report.trigger_candidates] == ["release-helper"]
    assert result.report.hypotheses[0].category == "trigger"


def test_public_functional_portability_defect() -> None:
    result = analyze(create_snapshot(PUBLIC / "fixtures" / "unsafe-command"))
    assert {finding.rule_id for finding in result.findings} == {"ASD007"}


def _performance_result(snapshot_hash: str, latency: int) -> dict[str, object]:
    return {
        "skill_name": "fixture",
        "snapshot_hash": snapshot_hash,
        "context": {
            "platform": "codex",
            "runtime_version": "public-benchmark-runtime",
            "model": "public-benchmark-model",
            "permission_mode": "never",
            "config_hash": "a" * 64,
        },
        "readiness": {"backend": "public-benchmark"},
        "trials": [
            {
                "case_id": "latency",
                "control": False,
                "passed": True,
                "timed_out": False,
                "cancelled": False,
                "final_output_sha256": str(index) * 64,
                "runtime_metrics": {"wall_latency_ms": latency + index},
            }
            for index in range(1, 4)
        ],
    }


def test_public_functional_performance_regression(tmp_path: Path) -> None:
    root = FUNCTIONAL / "performance-regression"
    baseline = create_snapshot(root / "baseline" / "fixture")
    mutated = create_snapshot(root / "mutated" / "fixture")
    store = _store(tmp_path / "state")
    analyze_performance(
        targets=((baseline, "fixture"),),
        dynamic_results=[_performance_result(baseline.digest, 1_000)],
        ruleset_version="public-benchmark",
        store=store,
        controlled_load=True,
        home=tmp_path / "empty-home",
    )
    outcome = analyze_performance(
        targets=((mutated, "fixture"),),
        dynamic_results=[_performance_result(mutated.digest, 2_000)],
        ruleset_version="public-benchmark",
        store=store,
        controlled_load=True,
        home=tmp_path / "empty-home",
    )
    assert "ASD701" in {finding.rule_id for finding in outcome.findings}


def test_public_functional_authored_eval_contract() -> None:
    skill = FUNCTIONAL / "eval-contract" / "fixture"
    contract = load_authored_contract(skill)
    assert contract is not None
    assert contract.source == "authored"
    observation = RuntimeObservation(0, "complete", frozenset({"result.txt"}))
    assertions = evaluate_assertions(contract.cases[0], observation)
    assert assertions
    assert all(assertion.passed for assertion in assertions)
