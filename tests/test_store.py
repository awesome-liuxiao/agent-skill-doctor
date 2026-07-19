import os
import sqlite3
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from skill_doctor.models import SCHEMA_VERSION, Event
from skill_doctor.security import ArtifactCipher
from skill_doctor.store import LocalStore


def _store(root: Path) -> LocalStore:
    return LocalStore(root, cipher=ArtifactCipher(os.urandom(32)))


def test_durable_job_lifecycle_events_cancellation_and_resume(tmp_path: Path) -> None:
    store = _store(tmp_path)
    created = "2026-07-16T00:00:00Z"
    store.create_job("job-1", created, "/skill", {"depth": "quick"})
    queued = store.get_job("job-1")
    assert queued is not None
    assert queued.status == "queued"
    assert queued.attempt == 0
    assert queued.options == {"depth": "quick"}

    assert store.mark_running("job-1")
    running = store.get_job("job-1")
    assert running is not None
    assert running.status == "running"
    assert running.attempt == 1

    event = Event(SCHEMA_VERSION, "job-1", 1, created, "snapshot", "Snapshot started")
    store.append_event(event)
    assert store.next_event_sequence("job-1") == 2
    assert store.events_since("job-1") == [event]

    assert store.request_cancel("job-1")
    assert store.cancellation_requested("job-1")
    store.mark_cancelled("job-1")
    cancelled = store.get_job("job-1")
    assert cancelled is not None
    assert cancelled.status == "cancelled"
    assert cancelled.result_state == "cancelled"

    assert store.resume_job("job-1")
    assert store.mark_running("job-1")
    resumed = store.get_job("job-1")
    assert resumed is not None
    assert resumed.attempt == 2
    assert not resumed.cancel_requested
    store.fail_job("job-1", "fixture failure")
    failed = store.get_job("job-1")
    assert failed is not None
    assert failed.status == "failed"
    assert failed.error == "fixture failure"


def test_worker_recovery_marks_running_jobs_resumable(tmp_path: Path) -> None:
    store = _store(tmp_path)
    store.start_job("job-1", "2026-07-16T00:00:00Z", "/skill")
    assert store.recover_interrupted_jobs() == 1
    recovered = store.get_job("job-1")
    assert recovered is not None
    assert recovered.status == "failed"
    assert recovered.error == "worker interrupted"
    assert store.resume_job("job-1")


def test_flight_recorder_is_encrypted_bounded_expiring_and_purgeable(
    tmp_path: Path,
) -> None:
    store = _store(tmp_path)
    identifier = store.append_flight_record({"session_id": "fixture", "signals": {"runtime": 1}})
    with sqlite3.connect(store.database) as connection:
        path_value, digest = connection.execute(
            "SELECT path, digest FROM flight_records WHERE id = ?", (identifier,)
        ).fetchone()
    path = Path(path_value)
    encrypted = path.read_bytes()
    assert b"session_id" not in encrypted
    assert b"fixture" not in encrypted
    plaintext = store.cipher.decrypt(str(digest), encrypted)
    assert b'"session_id":"fixture"' in plaintext
    assert store.flight_recorder_status()["records"] == 1

    assert store.purge_flight_recorder() == 1
    assert not path.exists()
    assert store.flight_recorder_status()["records"] == 0

    old = datetime.now(UTC) - timedelta(hours=25)
    store.append_flight_record({"expired": True}, recorded_at=old)
    assert store.flight_recorder_status()["records"] == 0


def test_flight_recorder_evicts_oldest_records_to_capacity(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = _store(tmp_path)
    monkeypatch.setattr("skill_doctor.store.FLIGHT_MAX_BYTES", 70)
    store.append_flight_record({"sequence": 1, "padding": "x" * 20})
    store.append_flight_record({"sequence": 2, "padding": "y" * 20})
    status = store.flight_recorder_status()
    assert status["records"] == 1
    assert status["plaintext_bytes"] <= 70


def test_local_finding_feedback_is_validated_and_encrypted(tmp_path: Path) -> None:
    store = _store(tmp_path)
    report = {
        "snapshot_hash": "a" * 64,
        "ruleset_version": "rules",
        "result_state": "indeterminate",
        "findings": [{"id": "finding-1"}],
    }
    store.write_report("feedback-job", report)
    record = store.record_finding_feedback(
        job_id="feedback-job",
        finding_id="finding-1",
        disposition="rejected",
        reason="Verified false positive",
    )
    assert record["disposition"] == "rejected"
    assert store.finding_feedback("feedback-job")[0]["reason"] == "Verified false positive"
    with sqlite3.connect(store.database) as connection:
        digest = connection.execute(
            "SELECT payload_digest FROM finding_feedback WHERE job_id = 'feedback-job'"
        ).fetchone()[0]
    encrypted_path = store.artifacts / digest[:2] / digest[2:]
    assert b"Verified false positive" not in encrypted_path.read_bytes()
