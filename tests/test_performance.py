import json
from pathlib import Path

import pytest

from skill_doctor.performance import analyze_performance, load_performance_budget
from skill_doctor.snapshot import create_snapshot
from skill_doctor.store import LocalStore


def _skill(tmp_path: Path) -> Path:
    skill = tmp_path / "repo" / ".agents" / "skills" / "fixture"
    skill.mkdir(parents=True)
    (skill / "SKILL.md").write_text(
        "---\nname: fixture\ndescription: Performance fixture.\n---\n",
        encoding="utf-8",
    )
    return skill


def test_project_budget_overrides_user_budget(tmp_path: Path) -> None:
    skill = _skill(tmp_path)
    user = tmp_path / "home" / ".skill-doctor"
    user.mkdir(parents=True)
    (user / "performance-budgets.json").write_text(
        json.dumps({"version": 1, "default": {"max_latency_ms": 5000}}),
        encoding="utf-8",
    )
    project = tmp_path / "repo" / ".skill-doctor"
    project.mkdir()
    (project / "performance-budgets.json").write_text(
        json.dumps(
            {
                "version": 1,
                "skills": {"fixture": {"max_latency_ms": 1000, "max_failure_rate": 0.1}},
            }
        ),
        encoding="utf-8",
    )
    budget, sources = load_performance_budget("fixture", skill, home=tmp_path / "home")
    assert budget.max_latency_ms == 1000
    assert budget.max_failure_rate == 0.1
    assert [source["scope"] for source in sources] == ["user", "project"]


def test_only_budgeted_measurement_creates_performance_finding(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    skill = _skill(tmp_path)
    project = tmp_path / "repo" / ".skill-doctor"
    project.mkdir()
    (project / "performance-budgets.json").write_text(
        json.dumps({"version": 1, "default": {"max_latency_ms": 100}}),
        encoding="utf-8",
    )
    snapshot = create_snapshot(skill)
    monkeypatch.setattr(
        "skill_doctor.security.load_or_create_master_key",
        lambda root: b"p" * 32,
    )
    store = LocalStore(tmp_path / "state")
    trials = [
        {
            "case_id": "case-1",
            "control": False,
            "passed": True,
            "timed_out": False,
            "cancelled": False,
            "final_output_sha256": str(index) * 64,
            "runtime_metrics": {
                "wall_latency_ms": 1000 + index,
                "tool_calls": 1,
                "model_turns": 1,
                "dependency_setup_ms": 0,
                "workspace_bytes": 0,
            },
        }
        for index in range(1, 4)
    ]
    result = {
        "skill_name": "fixture",
        "snapshot_hash": snapshot.digest,
        "context": {
            "platform": "codex",
            "runtime_version": "1.0",
            "model": "model",
            "permission_mode": "never",
            "config_hash": "a" * 64,
        },
        "readiness": {"backend": "fixture"},
        "trials": trials,
    }
    outcome = analyze_performance(
        targets=((snapshot, "fixture"),),
        dynamic_results=[result],
        ruleset_version="rules",
        store=store,
        controlled_load=True,
        home=tmp_path / "empty-home",
    )
    assert {finding.rule_id for finding in outcome.findings} == {"ASD700"}
    latency = next(
        metric
        for metric in outcome.report["metrics"]
        if metric["name"] == "execution_latency_median"
    )
    assert latency["basis"] == "measured"
    assert outcome.report["controlled_load"] is True
    assert "unsupported_metric:peak_memory" in outcome.report["limitations"]
    assert len(outcome.findings[0].evidence_ids) == 2
    assert {item.kind for item in outcome.evidence} >= {
        "performance_measurement",
        "explicit_performance_budget",
    }


def test_strict_controlled_baseline_detects_reproducible_regression(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    skill = _skill(tmp_path)
    monkeypatch.setattr(
        "skill_doctor.security.load_or_create_master_key",
        lambda root: b"b" * 32,
    )
    store = LocalStore(tmp_path / "state")

    def result(snapshot_hash: str, latency: int) -> dict[str, object]:
        return {
            "skill_name": "fixture",
            "snapshot_hash": snapshot_hash,
            "context": {
                "platform": "codex",
                "runtime_version": "1.0",
                "model": "model",
                "permission_mode": "never",
                "config_hash": "a" * 64,
            },
            "readiness": {"backend": "fixture"},
            "trials": [
                {
                    "case_id": "case-1",
                    "control": False,
                    "passed": True,
                    "timed_out": False,
                    "cancelled": False,
                    "final_output_sha256": f"{index}" * 64,
                    "runtime_metrics": {"wall_latency_ms": latency + index},
                }
                for index in range(1, 4)
            ],
        }

    first_snapshot = create_snapshot(skill)
    analyze_performance(
        targets=((first_snapshot, "fixture"),),
        dynamic_results=[result(first_snapshot.digest, 1000)],
        ruleset_version="rules",
        store=store,
        controlled_load=True,
        home=tmp_path / "empty-home",
    )
    (skill / "SKILL.md").write_text(
        "---\nname: fixture\ndescription: Performance fixture.\n---\n\nUpdated.\n",
        encoding="utf-8",
    )
    second_snapshot = create_snapshot(skill)
    outcome = analyze_performance(
        targets=((second_snapshot, "fixture"),),
        dynamic_results=[result(second_snapshot.digest, 2000)],
        ruleset_version="rules",
        store=store,
        controlled_load=True,
        home=tmp_path / "empty-home",
    )
    regression = next(item for item in outcome.findings if item.rule_id == "ASD701")
    assert len(regression.evidence_ids) == 2
    assert outcome.report["baselines"][0]["basis"] == "baseline-relative"
