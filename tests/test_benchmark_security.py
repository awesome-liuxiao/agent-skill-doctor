import io
import json
import sys
import tarfile
from pathlib import Path

import pytest

from scripts.extract_held_out import main as extract_held_out
from skill_doctor.benchmark import (
    BenchmarkError,
    unresolved_critical_escapes,
    validate_held_out_result,
    validate_release_evidence,
)


def _ratio(numerator: int, denominator: int) -> dict[str, object]:
    return {
        "numerator": numerator,
        "denominator": denominator,
        "value": numerator / denominator,
        "available": True,
    }


def _held_out() -> dict[str, object]:
    return {
        "schema_version": "1.0.0",
        "corpus_version": "held-out-rotation",
        "release_version": "v1.0.0",
        "rotation_id": "rotation",
        "rotating": True,
        "evaluated_at": "2026-07-16T00:00:00Z",
        "evaluator_commit": "a" * 40,
        "case_count": 20,
        "disjoint_from_public_sha256": "b" * 64,
        "metrics": {
            "highlighted_precision": _ratio(19, 20),
            "expected_finding_recall": _ratio(20, 20),
            "benign_false_positive_rate": _ratio(0, 20),
            "static_completion_rate": _ratio(20, 20),
        },
    }


def test_held_out_ratios_are_recomputed_not_trusted() -> None:
    held_out = _held_out()
    metrics = held_out["metrics"]
    assert isinstance(metrics, dict)
    precision = metrics["highlighted_precision"]
    assert isinstance(precision, dict)
    precision["value"] = 1.0
    with pytest.raises(BenchmarkError, match="ratio is invalid"):
        validate_held_out_result(held_out)


def test_release_evidence_requires_completed_remediation_signoff() -> None:
    evidence = {
        "schema_version": "1.0.0",
        "release_version": "v1.0.0",
        "evaluator_commit": "a" * 40,
        "recorded_at": "2026-07-16T00:00:00Z",
        "participant_count": 1,
        "platforms": ["linux"],
        "runtime_contexts": [{"platform": "claude", "runtime_version": "1", "model": "model"}],
        "issue_count": 1,
        "remediated_issue_count": 1,
        "open_release_blockers": 0,
        "remediation_started_at": "2026-07-01T00:00:00Z",
        "remediation_completed_at": "2026-07-15T00:00:00Z",
        "public_preview_completed": True,
        "signoff": False,
    }
    with pytest.raises(BenchmarkError, match="values are invalid"):
        validate_release_evidence(evidence)


def test_held_out_archive_rejects_path_traversal(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    archive = tmp_path / "unsafe.tar.gz"
    with tarfile.open(archive, "w:gz") as stream:
        member = tarfile.TarInfo("../escaped.txt")
        data = b"escape"
        member.size = len(data)
        stream.addfile(member, io.BytesIO(data))
    destination = tmp_path / "destination"
    monkeypatch.setattr(
        sys,
        "argv",
        ["extract_held_out.py", str(archive), str(destination)],
    )
    with pytest.raises(SystemExit, match="unsafe entry"):
        extract_held_out()
    assert not (tmp_path / "escaped.txt").exists()


def test_open_critical_escape_is_counted(tmp_path: Path) -> None:
    register = tmp_path / "escapes.json"
    register.write_text(
        json.dumps(
            {
                "schema_version": "1.0.0",
                "reviewed_at": "2026-07-16T00:00:00Z",
                "entries": [
                    {
                        "id": "escape-1",
                        "severity": "critical",
                        "status": "open",
                        "platforms": ["linux"],
                        "disclosure": "Private advisory ASD-1",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    assert unresolved_critical_escapes(register) == 1
