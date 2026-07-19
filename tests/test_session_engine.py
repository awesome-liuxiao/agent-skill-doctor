import json
import os
from pathlib import Path

from skill_doctor.discovery import DiscoveryContext
from skill_doctor.engine import execute_session_diagnosis
from skill_doctor.security import ArtifactCipher
from skill_doctor.store import LocalStore


def _skill(root: Path, name: str, description: str) -> Path:
    target = root / name
    target.mkdir(parents=True)
    (target / "SKILL.md").write_text(
        f"---\nname: {name}\ndescription: {description}\n---\n",
        encoding="utf-8",
    )
    return target


def _trace(path: Path, records: list[dict[str, object]]) -> None:
    path.parent.mkdir(parents=True)
    path.write_text(
        "".join(json.dumps(record) + "\n" for record in records),
        encoding="utf-8",
    )


def _store(root: Path, job_id: str) -> LocalStore:
    store = LocalStore(root, cipher=ArtifactCipher(os.urandom(32)))
    store.start_job(job_id, "2026-07-16T00:00:00Z", str(root.parent))
    return store


def _context(tmp_path: Path, repo: Path) -> DiscoveryContext:
    return DiscoveryContext(
        cwd=repo,
        repository_root=repo,
        home=tmp_path,
        codex_home=tmp_path / ".codex",
        claude_home=tmp_path / ".claude",
        codex_admin_skills=tmp_path / "admin",
        claude_managed_root=tmp_path / "managed",
    )


def _codex_trace(tmp_path: Path, repo: Path, session_id: str, prompt: str) -> Path:
    path = tmp_path / ".codex" / "sessions" / f"rollout-{session_id}.jsonl"
    _trace(
        path,
        [
            {
                "type": "session_meta",
                "payload": {"id": session_id, "cwd": str(repo), "cli_version": "1.0"},
            },
            {
                "type": "turn_context",
                "payload": {"cwd": str(repo), "model": "gpt-fixture"},
            },
            {
                "type": "event_msg",
                "payload": {"type": "user_message", "message": prompt},
            },
        ],
    )
    return path


def test_session_diagnosis_analyzes_only_trace_selected_skill(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    _skill(repo / ".agents" / "skills", "deploy-helper", "Deploy release artifacts safely.")
    _skill(repo / ".agents" / "skills", "unrelated", "Translate prose into another language.")
    session_id = "session-targeted"
    trace = _codex_trace(
        tmp_path,
        repo,
        session_id,
        "Use $deploy-helper for this release. The command failed.",
    )
    store = _store(tmp_path / "state", "session-job")
    events: list[tuple[str, str | None]] = []

    result = execute_session_diagnosis(
        job_id="session-job",
        created_at="2026-07-16T00:00:00Z",
        platform_name="codex",
        cwd=repo,
        store=store,
        emit=lambda stage, _summary, detail: events.append((stage, detail)),
        cancelled=lambda: False,
        context=_context(tmp_path, repo),
        home=tmp_path,
        environment={"CODEX_THREAD_ID": session_id, "LANG": "ko_KR.UTF-8"},
    )

    assert result.exit_code == 0
    assert result.report is not None
    report = result.report
    assert events[0][0] == "collection"
    manifest_event = json.loads(events[0][1] or "{}")
    assert manifest_event["path"] == str(trace)
    assert report.scope == "session"
    assert report.session_id == session_id
    assert [target.selector for target in report.session_targets] == ["deploy-helper"]
    assert report.session_targets[0].analyzed
    assert len(report.analyzed_copies) == 1
    analyzed_ids = set(report.analyzed_copies[0].copy_ids)
    inventory = report.inventory["copies"] if report.inventory else []
    unrelated = next(copy for copy in inventory if copy["selector"] == "unrelated")
    assert unrelated["copy_id"] not in analyzed_ids
    assert report.session_environment is not None
    assert report.session_environment["error_categories"] == {"runtime": 1}
    assert report.report_language == "ko-KR"
    assert report.diagnostic_summary is not None
    assert report.diagnostic_summary["translation_fallback_used"] is True
    assert any(hypothesis.category == "runtime" for hypothesis in report.hypotheses)


def test_trigger_candidates_are_reported_but_not_statically_analyzed(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    _skill(
        repo / ".agents" / "skills",
        "release-helper",
        "Deploy production release artifacts with validation.",
    )
    _skill(repo / ".agents" / "skills", "other", "Format source code consistently.")
    session_id = "session-trigger"
    _codex_trace(
        tmp_path,
        repo,
        session_id,
        "Validate production release artifacts before deployment",
    )
    store = _store(tmp_path / "state", "trigger-job")

    result = execute_session_diagnosis(
        job_id="trigger-job",
        created_at="2026-07-16T00:00:00Z",
        platform_name="codex",
        cwd=repo,
        store=store,
        emit=lambda _stage, _summary, _detail: None,
        cancelled=lambda: False,
        context=_context(tmp_path, repo),
        home=tmp_path,
        environment={"CODEX_THREAD_ID": session_id},
    )

    assert result.report is not None
    assert result.report.session_targets == []
    assert [candidate.selector for candidate in result.report.trigger_candidates] == [
        "release-helper"
    ]
    assert result.report.analyzed_copies == []
    assert result.report.dynamic_test_plan is not None
    assert result.report.dynamic_test_plan.skill_count == 0
    assert result.report.hypotheses[0].category == "trigger"


def test_missing_session_evidence_is_distinct_from_evidence_of_absence(
    tmp_path: Path,
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    _skill(repo / ".agents" / "skills", "never-analyze", "Run an unrelated workflow.")
    store = _store(tmp_path / "state", "missing-job")

    result = execute_session_diagnosis(
        job_id="missing-job",
        created_at="2026-07-16T00:00:00Z",
        platform_name="codex",
        cwd=repo,
        store=store,
        emit=lambda _stage, _summary, _detail: None,
        cancelled=lambda: False,
        context=_context(tmp_path, repo),
        home=tmp_path,
        environment={"CODEX_THREAD_ID": "missing"},
    )

    assert result.exit_code == 2
    assert result.report is not None
    assert result.report.result_state == "analysis_incomplete"
    assert result.report.collection_manifest[0].collected is False
    assert "current_session_evidence" in result.report.coverage.failed
    assert result.report.analyzed_copies == []
    assert result.report.hypotheses[0].category == "missing_evidence"


def test_flight_recorder_is_opt_in_and_contains_only_minimized_signals(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    _skill(repo / ".agents" / "skills", "recorded", "Record release workflows.")
    session_id = "session-recorded"
    _codex_trace(tmp_path, repo, session_id, "Use $recorded and keep PRIVATE-CONTENT out")
    store = _store(tmp_path / "state", "flight-job")

    result = execute_session_diagnosis(
        job_id="flight-job",
        created_at="2026-07-16T00:00:00Z",
        platform_name="codex",
        cwd=repo,
        store=store,
        emit=lambda _stage, _summary, _detail: None,
        cancelled=lambda: False,
        context=_context(tmp_path, repo),
        home=tmp_path,
        environment={"CODEX_THREAD_ID": session_id},
        flight_recorder=True,
    )

    assert result.report is not None
    assert "opt_in_flight_recorder" in result.report.coverage.completed
    assert store.flight_recorder_status()["records"] == 1
    encrypted = next(store.flight_recorder.glob("*.enc")).read_bytes()
    assert b"PRIVATE-CONTENT" not in encrypted
