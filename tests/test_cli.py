import hashlib
import json
import os
import sqlite3
import time
from pathlib import Path

import pytest

from skill_doctor.cli import main
from skill_doctor.ipc import IPCError
from skill_doctor.security import platform_encryption_readiness
from skill_doctor.worker_client import try_worker_request


@pytest.fixture(autouse=True)
def _ephemeral_direct_state_key(
    monkeypatch: pytest.MonkeyPatch,
    request: pytest.FixtureRequest,
) -> None:
    if request.node.get_closest_marker("os_credential_store") is not None:
        return
    key = os.urandom(32)
    monkeypatch.setattr(
        "skill_doctor.security.load_or_create_master_key",
        lambda _root: key,
    )


def test_check_persists_job_and_report(tmp_path: Path, capsys: object) -> None:
    fixture = Path(__file__).parent / "fixtures" / "valid-skill"
    assert main(["check", str(fixture), "--state-dir", str(tmp_path), "--json", "--direct"]) == 0
    captured = capsys.readouterr()  # type: ignore[attr-defined]
    report = json.loads(captured.out)
    events = [json.loads(line) for line in captured.err.splitlines()]
    assert report["schema_version"] == "1.0.0"
    assert report["ruleset_version"]
    assert report["result_state"] == "no_confirmed_issues"
    assert [event["sequence"] for event in events] == [1, 2, 3, 4]
    assert (tmp_path / "jobs.sqlite3").is_file()
    report_files = {path.suffix for path in (tmp_path / "reports").iterdir()}
    assert report_files == {".json", ".html", ".xml"}
    assert len(list((tmp_path / "reports").iterdir())) == 4
    artifacts = [path for path in (tmp_path / "artifacts" / "sha256").rglob("*") if path.is_file()]
    assert artifacts
    from skill_doctor.store import LocalStore

    store = LocalStore(tmp_path)
    for artifact in artifacts:
        stored_digest = artifact.parent.name + artifact.name
        assert hashlib.sha256(store.get_bytes(stored_digest)).hexdigest() == stored_digest
        assert hashlib.sha256(artifact.read_bytes()).hexdigest() != stored_digest


def test_identical_check_reuses_strict_cache(tmp_path: Path, capsys: object) -> None:
    fixture = Path(__file__).parent / "fixtures" / "valid-skill"
    assert main(["check", str(fixture), "--state-dir", str(tmp_path), "--json", "--direct"]) == 0
    capsys.readouterr()  # type: ignore[attr-defined]
    assert main(["check", str(fixture), "--state-dir", str(tmp_path), "--json", "--direct"]) == 0
    captured = capsys.readouterr()  # type: ignore[attr-defined]
    events = [json.loads(line) for line in captured.err.splitlines()]
    assert events[1]["summary"] == "Reusing strictly keyed deterministic analysis"
    with sqlite3.connect(tmp_path / "jobs.sqlite3") as connection:
        assert connection.execute("SELECT COUNT(*) FROM static_cache").fetchone() == (1,)


def test_missing_skill_is_an_incomplete_report(tmp_path: Path, capsys: object) -> None:
    skill = tmp_path / "missing-skill"
    skill.mkdir()
    state = tmp_path / "state"
    assert main(["check", str(skill), "--state-dir", str(state), "--json", "--direct"]) == 2
    captured = capsys.readouterr()  # type: ignore[attr-defined]
    report = json.loads(captured.out)
    assert report["result_state"] == "analysis_incomplete"
    assert "skill_document" in report["coverage"]["failed"]


def test_rejects_state_directory_inside_skill(tmp_path: Path, capsys: object) -> None:
    skill = tmp_path / "nested-state"
    skill.mkdir()
    state = skill / ".doctor"
    assert main(["check", str(skill), "--state-dir", str(state), "--direct"]) == 2
    captured = capsys.readouterr()  # type: ignore[attr-defined]
    assert "must not be inside" in captured.err
    assert not state.exists()


def test_cache_key_includes_directory_name(tmp_path: Path, capsys: object) -> None:
    state = tmp_path / "state"
    first = tmp_path / "first-name"
    second = tmp_path / "second-name"
    first.mkdir()
    second.mkdir()
    content = "---\nname: first-name\ndescription: Cache dimension fixture.\n---"
    (first / "SKILL.md").write_text(content, encoding="utf-8")
    (second / "SKILL.md").write_text(content, encoding="utf-8")
    assert main(["check", str(first), "--state-dir", str(state), "--json", "--direct"]) == 0
    capsys.readouterr()  # type: ignore[attr-defined]
    assert main(["check", str(second), "--state-dir", str(state), "--json", "--direct"]) == 0
    captured = capsys.readouterr()  # type: ignore[attr-defined]
    report = json.loads(captured.out)
    events = [json.loads(line) for line in captured.err.splitlines()]
    assert events[1]["summary"] == "Running deterministic static rules"
    assert {finding["rule_id"] for finding in report["findings"]} == {"ASD011"}
    with sqlite3.connect(state / "jobs.sqlite3") as connection:
        assert connection.execute("SELECT COUNT(*) FROM static_cache").fetchone() == (2,)


def test_feedback_and_two_step_sanitized_export_commands(
    tmp_path: Path,
    capsys: object,
) -> None:
    skill = tmp_path / "actual-name"
    skill.mkdir()
    (skill / "SKILL.md").write_text(
        "---\nname: different-name\ndescription: Feedback fixture.\n---\n",
        encoding="utf-8",
    )
    state = tmp_path / "state"
    assert main(["check", str(skill), "--state-dir", str(state), "--json", "--direct"]) == 0
    report = json.loads(capsys.readouterr().out)  # type: ignore[attr-defined]
    job_id = report["job_id"]
    finding_id = report["findings"][0]["id"]

    assert (
        main(
            [
                "feedback",
                job_id,
                finding_id,
                "--disposition",
                "unresolved",
                "--state-dir",
                str(state),
                "--json",
            ]
        )
        == 0
    )
    feedback = json.loads(capsys.readouterr().out)  # type: ignore[attr-defined]
    assert feedback["disposition"] == "unresolved"

    assert main(["export", job_id, "--state-dir", str(state), "--json"]) == 0
    preview = json.loads(capsys.readouterr().out)  # type: ignore[attr-defined]
    assert preview["requires_explicit_consent"] is True
    assert not list((state / "exports").glob("*.zip"))
    assert (
        main(
            [
                "export",
                job_id,
                "--approve",
                preview["approval_token"],
                "--state-dir",
                str(state),
                "--json",
            ]
        )
        == 0
    )
    exported = json.loads(capsys.readouterr().out)  # type: ignore[attr-defined]
    assert Path(exported["export_path"]).is_file()


def test_named_and_all_discovery_scopes_route_through_cli(
    tmp_path: Path,
    capsys: object,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo = tmp_path / "repo"
    skill = repo / ".agents" / "skills" / "discover-me"
    skill.mkdir(parents=True)
    (skill / "SKILL.md").write_text(
        "---\nname: discover-me\ndescription: CLI discovery fixture.\n---\n",
        encoding="utf-8",
    )
    home = tmp_path / "isolated-home"
    monkeypatch.setattr(Path, "home", lambda: home)

    named_state = tmp_path / "named-state"
    assert (
        main(
            [
                "check",
                "discover-me",
                "--platform",
                "codex",
                "--cwd",
                str(repo),
                "--state-dir",
                str(named_state),
                "--json",
                "--direct",
            ]
        )
        == 0
    )
    named = json.loads(capsys.readouterr().out)  # type: ignore[attr-defined]
    assert named["scope"] == "named"
    assert named["platform"] == "codex"
    assert named["inventory"]["copies"][0]["selector"] == "discover-me"

    all_state = tmp_path / "all-state"
    assert (
        main(
            [
                "check",
                "--all",
                "--platform",
                "codex",
                "--cwd",
                str(repo),
                "--state-dir",
                str(all_state),
                "--json",
                "--direct",
            ]
        )
        == 0
    )
    aggregate = json.loads(capsys.readouterr().out)  # type: ignore[attr-defined]
    assert aggregate["scope"] == "all"
    assert aggregate["dynamic_test_plan"]["skill_count"] == 1


def test_diagnose_uses_supplied_transcript_and_shows_collection_first(
    tmp_path: Path,
    capsys: object,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo = tmp_path / "repo"
    skill = repo / ".agents" / "skills" / "session-helper"
    skill.mkdir(parents=True)
    (skill / "SKILL.md").write_text(
        "---\nname: session-helper\ndescription: Diagnose a session fixture.\n---\n",
        encoding="utf-8",
    )
    transcript = tmp_path / "visible-transcript.txt"
    transcript.write_text("Please /session-helper diagnose this.\n", encoding="utf-8")
    monkeypatch.setattr(Path, "home", lambda: tmp_path / "home")

    assert (
        main(
            [
                "diagnose",
                "--platform",
                "codex",
                "--cwd",
                str(repo),
                "--transcript",
                str(transcript),
                "--state-dir",
                str(tmp_path / "state"),
                "--json",
                "--direct",
            ]
        )
        == 0
    )
    captured = capsys.readouterr()  # type: ignore[attr-defined]
    report = json.loads(captured.out)
    events = [json.loads(line) for line in captured.err.splitlines()]
    assert events[0]["stage"] == "collection"
    assert report["scope"] == "session"
    assert report["session_targets"][0]["selector"] == "session-helper"
    assert report["session_environment"]["trace_confidence"] == "reduced"


@pytest.mark.os_credential_store
def test_default_check_uses_worker_and_management_commands(
    tmp_path: Path,
    capsys: object,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = Path(__file__).parent / "fixtures" / "valid-skill"
    state = tmp_path / "state"
    readiness = platform_encryption_readiness(state)
    if not readiness["ready"]:
        pytest.skip(str(readiness["detail"]))
    monkeypatch.setenv("SKILL_DOCTOR_IDLE_TIMEOUT", "30")
    try:
        assert main(["check", str(fixture), "--state-dir", str(state), "--json"]) == 0
        captured = capsys.readouterr()  # type: ignore[attr-defined]
        report = json.loads(captured.out)
        events = [json.loads(line) for line in captured.err.splitlines()]
        assert [event["stage"] for event in events] == [
            "queue",
            "snapshot",
            "analysis",
            "performance",
            "report",
        ]
        job_id = report["job_id"]

        assert main(["jobs", "--state-dir", str(state), "--json"]) == 0
        jobs = json.loads(capsys.readouterr().out)  # type: ignore[attr-defined]
        assert jobs["jobs"][0]["id"] == job_id

        assert main(["status", job_id, "--state-dir", str(state), "--json"]) == 0
        status = json.loads(capsys.readouterr().out)  # type: ignore[attr-defined]
        assert status["job"]["status"] == "complete"
        assert len(status["events"]) == 5
    finally:
        try:
            try_worker_request(state, "shutdown")
        except IPCError:
            pass
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            try:
                try_worker_request(state, "ping", timeout=0.1)
            except IPCError:
                break
            time.sleep(0.02)
