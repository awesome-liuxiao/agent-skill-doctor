import json
import os
import time
from multiprocessing.connection import Connection
from pathlib import Path
from typing import Any, cast

import pytest

from skill_doctor import worker_client
from skill_doctor.ipc import IPCError, make_request, request
from skill_doctor.security import ArtifactCipher, platform_encryption_readiness
from skill_doctor.store import LocalStore
from skill_doctor.worker import Incoming, JobCoordinator, Worker
from skill_doctor.worker_client import ensure_worker, try_worker_request


def test_long_worker_stage_emits_evidence_safe_heartbeats(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = LocalStore(tmp_path, cipher=ArtifactCipher(os.urandom(32)))
    store.create_job("heartbeat-job", "2026-07-16T00:00:00Z", str(tmp_path / "skill"))
    monkeypatch.setenv("SKILL_DOCTOR_HEARTBEAT_SECONDS", "0.05")

    def slow_check(**kwargs: Any) -> None:
        time.sleep(0.16)
        cast(LocalStore, kwargs["store"]).fail_job("heartbeat-job", "fixture complete")

    monkeypatch.setattr("skill_doctor.worker.execute_check", slow_check)
    coordinator = JobCoordinator(store)
    deadline = time.monotonic() + 2
    while time.monotonic() < deadline:
        job = store.get_job("heartbeat-job")
        if job is not None and job.status == "failed":
            break
        time.sleep(0.01)
    coordinator.stop()
    heartbeats = [
        event for event in store.events_since("heartbeat-job") if event.stage == "heartbeat"
    ]
    assert len(heartbeats) >= 2
    assert all(event.detail is None for event in heartbeats)
    assert all(event.summary == "Diagnostic job is still running" for event in heartbeats)


def _wait_for_terminal(state: Path, job_id: str, timeout: float = 10) -> dict[str, Any]:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        result = try_worker_request(state, "status", {"job_id": job_id, "since": 0})
        job = cast(dict[str, Any], result["job"])
        if job["status"] in {"complete", "failed", "cancelled"}:
            return result
        time.sleep(0.02)
    raise AssertionError("worker job did not reach a terminal state")


def _shutdown(state: Path) -> None:
    try:
        try_worker_request(state, "shutdown")
    except IPCError:
        return
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        try:
            try_worker_request(state, "ping", timeout=0.1)
        except IPCError:
            return
        time.sleep(0.02)
    raise AssertionError("worker did not shut down")


def test_authenticated_worker_persists_job_events_and_report(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state = tmp_path / "state"
    readiness = platform_encryption_readiness(state)
    if not readiness["ready"]:
        pytest.skip(str(readiness["detail"]))
    fixture = Path(__file__).parent / "fixtures" / "valid-skill"
    monkeypatch.setenv("SKILL_DOCTOR_IDLE_TIMEOUT", "30")
    ensure_worker(state)
    try:
        ping = try_worker_request(state, "ping")
        assert ping["protocol_version"] == "1.0.0"
        auth_key = ArtifactCipher.for_state(state).ipc_auth_key
        with pytest.raises(IPCError, match="authenticated local worker"):
            request(state, os.urandom(len(auth_key)), "ping", timeout=0.2)

        submitted = try_worker_request(
            state,
            "submit",
            {"path": str(fixture.resolve()), "options": {"depth": "quick"}},
        )
        job_id = str(cast(dict[str, Any], submitted["job"])["id"])
        result = _wait_for_terminal(state, job_id)
        job = cast(dict[str, Any], result["job"])
        events = cast(list[dict[str, Any]], result["events"])
        assert job["status"] == "complete"
        assert job["result_state"] == "no_confirmed_issues"
        assert Path(str(job["report_path"])).is_file()
        assert [event["sequence"] for event in events] == list(range(1, len(events) + 1))
        assert [event["stage"] for event in events] == [
            "queue",
            "snapshot",
            "analysis",
            "performance",
            "report",
        ]
        jobs = try_worker_request(state, "jobs")
        assert len(cast(list[dict[str, Any]], jobs["jobs"])) == 1
    finally:
        _shutdown(state)


def test_worker_idle_shutdown(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state = tmp_path / "state"
    readiness = platform_encryption_readiness(state)
    if not readiness["ready"]:
        pytest.skip(str(readiness["detail"]))
    monkeypatch.setenv("SKILL_DOCTOR_IDLE_TIMEOUT", "0.3")
    ensure_worker(state)
    assert try_worker_request(state, "ping")["idle_timeout"] == 0.3
    time.sleep(1)
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        try:
            try_worker_request(state, "ping", timeout=0.1)
        except IPCError:
            return
        time.sleep(0.1)
    _shutdown(state)
    raise AssertionError("idle worker did not shut down")


def test_disconnected_startup_probe_does_not_terminate_worker(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state = tmp_path / "state"
    readiness = platform_encryption_readiness(state)
    if not readiness["ready"]:
        pytest.skip(str(readiness["detail"]))

    class DisconnectedClient:
        closed = False

        @staticmethod
        def send_bytes(_payload: bytes) -> None:
            raise BrokenPipeError

        def close(self) -> None:
            self.closed = True

    worker = Worker(state, idle_timeout=0.1)
    monkeypatch.setattr(worker, "_accept", lambda: None)
    client = DisconnectedClient()
    worker.incoming.put(
        Incoming(
            cast(Connection, client),
            make_request("shutdown"),
        )
    )
    assert worker.run() == 0
    assert client.closed is True
    assert worker.received_request is False


def test_worker_start_retries_transient_early_process_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    requests = 0
    launches: list[int] = []

    def probe(*_args: object, **_kwargs: object) -> dict[str, Any]:
        nonlocal requests
        requests += 1
        if requests < 5:
            raise IPCError("not ready")
        return {"protocol_version": "1.0.0"}

    class Process:
        def __init__(self, status: int | None) -> None:
            self.status = status

        def poll(self) -> int | None:
            return self.status

    def launch(*_args: object, **_kwargs: object) -> Process:
        launches.append(len(launches) + 1)
        return Process(3221225794 if len(launches) == 1 else None)

    monkeypatch.setattr(worker_client, "try_worker_request", probe)
    monkeypatch.setattr("skill_doctor.worker_client.subprocess.Popen", launch)
    monkeypatch.setattr("skill_doctor.worker_client.time.sleep", lambda _seconds: None)
    worker_client.ensure_worker(tmp_path / "state")
    assert launches == [1, 2]


def test_worker_runs_discovery_aware_all_skills_job(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state = tmp_path / "state"
    readiness = platform_encryption_readiness(state)
    if not readiness["ready"]:
        pytest.skip(str(readiness["detail"]))
    repo = tmp_path / "repo"
    skill = repo / ".agents" / "skills" / "worker-discovery"
    skill.mkdir(parents=True)
    (skill / "SKILL.md").write_text(
        "---\nname: worker-discovery\ndescription: Worker discovery fixture.\n---\n",
        encoding="utf-8",
    )
    isolated_home = tmp_path / "home"
    isolated_home.mkdir()
    monkeypatch.setenv("USERPROFILE", str(isolated_home))
    monkeypatch.setenv("HOME", str(isolated_home))
    monkeypatch.setenv("SKILL_DOCTOR_IDLE_TIMEOUT", "30")
    ensure_worker(state)
    try:
        submitted = try_worker_request(
            state,
            "submit",
            {
                "path": str(repo),
                "options": {
                    "scope": "all",
                    "platform": "codex",
                    "added_directories": [],
                    "active_paths": [],
                },
            },
        )
        job_id = str(cast(dict[str, Any], submitted["job"])["id"])
        result = _wait_for_terminal(state, job_id)
        job = cast(dict[str, Any], result["job"])
        assert job["status"] == "complete"
        report_path = Path(str(job["report_path"]))
        report = json.loads(report_path.read_text(encoding="utf-8"))
        assert report["scope"] == "all"
        assert report["inventory"]["copies"][0]["selector"] == "worker-discovery"
    finally:
        _shutdown(state)


def test_worker_runs_current_session_diagnosis_from_supplied_transcript(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state = tmp_path / "state"
    readiness = platform_encryption_readiness(state)
    if not readiness["ready"]:
        pytest.skip(str(readiness["detail"]))
    repo = tmp_path / "repo"
    skill = repo / ".agents" / "skills" / "session-worker"
    skill.mkdir(parents=True)
    (skill / "SKILL.md").write_text(
        "---\nname: session-worker\ndescription: Diagnose worker sessions.\n---\n",
        encoding="utf-8",
    )
    transcript = tmp_path / "visible.txt"
    transcript.write_text("Use /session-worker for this request.\n", encoding="utf-8")
    isolated_home = tmp_path / "home"
    isolated_home.mkdir()
    monkeypatch.setenv("USERPROFILE", str(isolated_home))
    monkeypatch.setenv("HOME", str(isolated_home))
    monkeypatch.setenv("SKILL_DOCTOR_IDLE_TIMEOUT", "30")
    ensure_worker(state)
    try:
        submitted = try_worker_request(
            state,
            "submit",
            {
                "path": str(repo),
                "options": {
                    "scope": "session",
                    "platform": "codex",
                    "transcript": str(transcript),
                    "flight_recorder": True,
                    "added_directories": [],
                    "active_paths": [],
                },
            },
        )
        job_id = str(cast(dict[str, Any], submitted["job"])["id"])
        result = _wait_for_terminal(state, job_id)
        job = cast(dict[str, Any], result["job"])
        assert job["status"] == "complete"
        report = json.loads(Path(str(job["report_path"])).read_text(encoding="utf-8"))
        assert report["scope"] == "session"
        assert report["session_targets"][0]["selector"] == "session-worker"
        events = cast(list[dict[str, Any]], result["events"])
        assert events[1]["stage"] == "collection"
        assert list((state / "flight-recorder").glob("*.enc"))
        purged = try_worker_request(state, "purge_flight_recorder")
        assert purged["deleted_records"] == 1
        assert not list((state / "flight-recorder").glob("*.enc"))
    finally:
        _shutdown(state)
