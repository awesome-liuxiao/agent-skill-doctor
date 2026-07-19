import json
import zipfile
from pathlib import Path

import pytest

from skill_doctor.exporting import ExportError, plan_export, write_export


def test_sanitized_export_requires_exact_preview_token(tmp_path: Path) -> None:
    report = {
        "job_id": "job",
        "input_path": "C:\\private\\project\\skill",
        "snapshot_hash": "a" * 64,
        "ruleset_version": "rules",
        "tool_version": "tool",
        "result_state": "indeterminate",
        "findings": [],
        "evidence": [],
        "limitations": ["Private path C:\\private\\project\\skill"],
        "dynamic_results": [
            {
                "skill_name": "fixture",
                "snapshot_hash": "a" * 64,
                "trials": [
                    {
                        "case_id": "case",
                        "passed": True,
                        "stdout_sha256": "secret-artifact-hash",
                    }
                ],
            }
        ],
        "causal_graph": None,
        "suppressed_finding_ids": [],
        "blocking_finding_ids": [],
        "artifacts": {"json": "C:\\private\\state\\report.json"},
    }
    plan = plan_export(report)
    combined = b"\n".join(plan.files.values())
    assert b"C:\\private" not in combined
    assert b"secret-artifact-hash" not in combined
    assert plan.preview["requires_explicit_consent"] is True
    with pytest.raises(ExportError, match="approval token"):
        write_export(plan, "0" * 64, tmp_path / "bundle.zip")
    target = write_export(plan, plan.approval_token, tmp_path / "bundle.zip")
    with zipfile.ZipFile(target) as archive:
        assert set(archive.namelist()) == {
            "manifest.json",
            "report.html",
            "report.json",
            "report.junit.xml",
            "report.sarif.json",
        }
        exported = json.loads(archive.read("report.json"))
    assert exported["input_path"] == "<redacted-path>"
