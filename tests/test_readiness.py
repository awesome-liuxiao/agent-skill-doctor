from pathlib import Path

import pytest

from skill_doctor.readiness import readiness_report


def test_readiness_reports_static_fallback_without_claiming_host_execution(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "skill_doctor.readiness.platform_encryption_readiness",
        lambda root: {"ready": True, "detail": str(root)},
    )
    report = readiness_report(tmp_path)
    assert report["schema_version"] == "1.0.0"
    assert report["dynamic_execution_policy"] in {"sandbox_only", "static_only"}
    assert report["credentials"]["host_credential_files_mounted"] is False
    assert set(report["runtimes"]) == {"codex", "claude"}
