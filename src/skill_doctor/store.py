from __future__ import annotations

import hashlib
import json
import os
import re
import sqlite3
import tempfile
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, cast

from skill_doctor.models import (
    SCHEMA_VERSION,
    Event,
    JobRecord,
    JobStatus,
    ResultState,
)
from skill_doctor.security import ArtifactCipher, IntegrityError
from skill_doctor.snapshot import Snapshot

DIGEST = re.compile(r"^[0-9a-f]{64}$")
REPORT_ID = re.compile(r"^[A-Za-z0-9_.-]{1,128}$")
FLIGHT_RETENTION = timedelta(hours=24)
FLIGHT_MAX_BYTES = 50 * 1024 * 1024


class StoreError(RuntimeError):
    pass


class LocalStore:
    def __init__(self, root: Path, *, cipher: ArtifactCipher | None = None) -> None:
        self.root = root.expanduser().absolute()
        self.cipher = cipher or ArtifactCipher.for_state(self.root)
        self.artifacts = self.root / "artifacts" / "sha256"
        self.reports = self.root / "reports"
        self.flight_recorder = self.root / "flight-recorder"
        self.artifacts.mkdir(parents=True, exist_ok=True)
        self.reports.mkdir(parents=True, exist_ok=True)
        self.flight_recorder.mkdir(parents=True, exist_ok=True)
        self.database = self.root / "jobs.sqlite3"
        with self._connect() as connection:
            connection.execute(
                """CREATE TABLE IF NOT EXISTS jobs (
                id TEXT PRIMARY KEY, schema_version TEXT NOT NULL,
                created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
                status TEXT NOT NULL, operation TEXT NOT NULL,
                input_path TEXT NOT NULL, options TEXT NOT NULL,
                attempt INTEGER NOT NULL, cancel_requested INTEGER NOT NULL,
                snapshot_hash TEXT, report_path TEXT, result_state TEXT, error TEXT)"""
            )
            self._migrate_jobs(connection)
            connection.execute(
                """CREATE TABLE IF NOT EXISTS events (
                job_id TEXT NOT NULL, sequence INTEGER NOT NULL,
                schema_version TEXT NOT NULL, timestamp TEXT NOT NULL,
                stage TEXT NOT NULL, summary TEXT NOT NULL, detail TEXT,
                PRIMARY KEY(job_id, sequence),
                FOREIGN KEY(job_id) REFERENCES jobs(id))"""
            )
            connection.execute(
                """CREATE TABLE IF NOT EXISTS static_cache (
                cache_key TEXT PRIMARY KEY, snapshot_hash TEXT NOT NULL,
                created_at TEXT NOT NULL, payload TEXT NOT NULL)"""
            )
            connection.execute(
                """CREATE TABLE IF NOT EXISTS flight_records (
                id TEXT PRIMARY KEY, recorded_at TEXT NOT NULL,
                expires_at TEXT NOT NULL, path TEXT NOT NULL,
                digest TEXT NOT NULL, plaintext_bytes INTEGER NOT NULL)"""
            )
            connection.execute(
                """CREATE TABLE IF NOT EXISTS performance_baselines (
                id TEXT PRIMARY KEY, series_key TEXT NOT NULL,
                snapshot_hash TEXT NOT NULL, created_at TEXT NOT NULL,
                sample_count INTEGER NOT NULL, payload TEXT NOT NULL)"""
            )
            connection.execute(
                """CREATE INDEX IF NOT EXISTS performance_baselines_series
                ON performance_baselines(series_key, created_at DESC)"""
            )
            connection.execute(
                """CREATE TABLE IF NOT EXISTS finding_feedback (
                id TEXT PRIMARY KEY, job_id TEXT NOT NULL, finding_id TEXT NOT NULL,
                disposition TEXT NOT NULL, recorded_at TEXT NOT NULL,
                snapshot_hash TEXT NOT NULL, ruleset_version TEXT NOT NULL,
                payload_digest TEXT NOT NULL)"""
            )

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.database)
        connection.row_factory = sqlite3.Row
        return connection

    @staticmethod
    def _now() -> str:
        return datetime.now(UTC).isoformat().replace("+00:00", "Z")

    def _migrate_jobs(self, connection: sqlite3.Connection) -> None:
        columns = {str(row[1]) for row in connection.execute("PRAGMA table_info(jobs)").fetchall()}
        migrations = {
            "schema_version": "TEXT",
            "updated_at": "TEXT",
            "operation": "TEXT NOT NULL DEFAULT 'check'",
            "options": "TEXT NOT NULL DEFAULT '{}'",
            "attempt": "INTEGER NOT NULL DEFAULT 1",
            "cancel_requested": "INTEGER NOT NULL DEFAULT 0",
            "result_state": "TEXT",
            "error": "TEXT",
        }
        for column, declaration in migrations.items():
            if column not in columns:
                connection.execute(f"ALTER TABLE jobs ADD COLUMN {column} {declaration}")
        connection.execute(
            "UPDATE jobs SET schema_version = ? WHERE schema_version IS NULL",
            (SCHEMA_VERSION,),
        )
        connection.execute("UPDATE jobs SET updated_at = created_at WHERE updated_at IS NULL")

    def start_job(
        self,
        job_id: str,
        created_at: str,
        input_path: str,
        options: dict[str, Any] | None = None,
    ) -> None:
        serialized = json.dumps(options or {}, separators=(",", ":"), sort_keys=True)
        with self._connect() as connection:
            connection.execute(
                """INSERT INTO jobs(
                id, schema_version, created_at, updated_at, status, operation,
                input_path, options, attempt, cancel_requested
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    job_id,
                    SCHEMA_VERSION,
                    created_at,
                    created_at,
                    "running",
                    "check",
                    input_path,
                    serialized,
                    1,
                    0,
                ),
            )

    def create_job(
        self,
        job_id: str,
        created_at: str,
        input_path: str,
        options: dict[str, Any] | None = None,
    ) -> None:
        serialized = json.dumps(options or {}, separators=(",", ":"), sort_keys=True)
        with self._connect() as connection:
            connection.execute(
                """INSERT INTO jobs(
                id, schema_version, created_at, updated_at, status, operation,
                input_path, options, attempt, cancel_requested
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    job_id,
                    SCHEMA_VERSION,
                    created_at,
                    created_at,
                    "queued",
                    "check",
                    input_path,
                    serialized,
                    0,
                    0,
                ),
            )

    def mark_running(self, job_id: str) -> bool:
        with self._connect() as connection:
            cursor = connection.execute(
                """UPDATE jobs SET status = 'running', updated_at = ?,
                attempt = attempt + 1, cancel_requested = 0, error = NULL
                WHERE id = ? AND status = 'queued'""",
                (self._now(), job_id),
            )
        return cursor.rowcount == 1

    def append_event(self, event: Event) -> None:
        with self._connect() as connection:
            connection.execute(
                """INSERT INTO events(
                job_id, sequence, schema_version, timestamp, stage, summary, detail
                ) VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (
                    event.job_id,
                    event.sequence,
                    event.schema_version,
                    event.timestamp,
                    event.stage,
                    event.summary,
                    event.detail,
                ),
            )
            connection.execute(
                "UPDATE jobs SET updated_at = ? WHERE id = ?",
                (event.timestamp, event.job_id),
            )

    def next_event_sequence(self, job_id: str) -> int:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT COALESCE(MAX(sequence), 0) + 1 FROM events WHERE job_id = ?",
                (job_id,),
            ).fetchone()
        return int(row[0]) if row is not None else 1

    def events_since(self, job_id: str, sequence: int = 0) -> list[Event]:
        with self._connect() as connection:
            rows = connection.execute(
                """SELECT schema_version, job_id, sequence, timestamp, stage, summary, detail
                FROM events WHERE job_id = ? AND sequence > ? ORDER BY sequence""",
                (job_id, sequence),
            ).fetchall()
        return [
            Event(
                schema_version=str(row["schema_version"]),
                job_id=str(row["job_id"]),
                sequence=int(row["sequence"]),
                timestamp=str(row["timestamp"]),
                stage=str(row["stage"]),
                summary=str(row["summary"]),
                detail=None if row["detail"] is None else str(row["detail"]),
            )
            for row in rows
        ]

    @staticmethod
    def _job_from_row(row: sqlite3.Row) -> JobRecord:
        options = json.loads(str(row["options"]))
        if not isinstance(options, dict):
            raise StoreError("job options are corrupt")
        return JobRecord(
            schema_version=str(row["schema_version"]),
            id=str(row["id"]),
            created_at=str(row["created_at"]),
            updated_at=str(row["updated_at"]),
            status=cast(JobStatus, row["status"]),
            operation=str(row["operation"]),
            input_path=str(row["input_path"]),
            options=cast(dict[str, Any], options),
            attempt=int(row["attempt"]),
            cancel_requested=bool(row["cancel_requested"]),
            snapshot_hash=(None if row["snapshot_hash"] is None else str(row["snapshot_hash"])),
            report_path=None if row["report_path"] is None else str(row["report_path"]),
            result_state=(
                None if row["result_state"] is None else cast(ResultState, row["result_state"])
            ),
            error=None if row["error"] is None else str(row["error"]),
        )

    def get_job(self, job_id: str) -> JobRecord | None:
        with self._connect() as connection:
            row = connection.execute("SELECT * FROM jobs WHERE id = ?", (job_id,)).fetchone()
        return None if row is None else self._job_from_row(row)

    def list_jobs(self, limit: int = 100) -> list[JobRecord]:
        bounded = max(1, min(limit, 1_000))
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT * FROM jobs ORDER BY created_at DESC LIMIT ?", (bounded,)
            ).fetchall()
        return [self._job_from_row(row) for row in rows]

    def request_cancel(self, job_id: str) -> bool:
        with self._connect() as connection:
            cursor = connection.execute(
                """UPDATE jobs SET cancel_requested = 1, updated_at = ?
                WHERE id = ? AND status IN ('queued', 'running')""",
                (self._now(), job_id),
            )
        return cursor.rowcount == 1

    def cancellation_requested(self, job_id: str) -> bool:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT cancel_requested FROM jobs WHERE id = ?", (job_id,)
            ).fetchone()
        return bool(row[0]) if row is not None else False

    def mark_cancelled(self, job_id: str) -> None:
        with self._connect() as connection:
            connection.execute(
                """UPDATE jobs SET status = 'cancelled', result_state = 'cancelled',
                updated_at = ? WHERE id = ?""",
                (self._now(), job_id),
            )

    def resume_job(self, job_id: str) -> bool:
        with self._connect() as connection:
            cursor = connection.execute(
                """UPDATE jobs SET status = 'queued', cancel_requested = 0,
                result_state = NULL, error = NULL, updated_at = ?
                WHERE id = ? AND status IN ('failed', 'cancelled')""",
                (self._now(), job_id),
            )
        return cursor.rowcount == 1

    def recover_interrupted_jobs(self) -> int:
        with self._connect() as connection:
            cursor = connection.execute(
                """UPDATE jobs SET status = 'failed', result_state = 'analysis_incomplete',
                error = 'worker interrupted', updated_at = ? WHERE status = 'running'""",
                (self._now(),),
            )
        return cursor.rowcount

    def put_bytes(self, digest: str, data: bytes) -> Path:
        actual = hashlib.sha256(data).hexdigest()
        if not DIGEST.fullmatch(digest) or actual != digest:
            raise StoreError("artifact digest does not match its content")
        target = self.artifacts / digest[:2] / digest[2:]
        if target.exists():
            try:
                existing = self.cipher.decrypt(digest, target.read_bytes())
                existing_digest = hashlib.sha256(existing).hexdigest()
            except (OSError, IntegrityError) as error:
                raise StoreError(f"cannot verify existing artifact: {digest}") from error
            if existing_digest != digest:
                raise StoreError(f"content-addressed artifact is corrupt: {digest}")
            return target
        target.parent.mkdir(parents=True, exist_ok=True)
        self._atomic_write(target, self.cipher.encrypt(digest, data))
        return target

    def get_bytes(self, digest: str) -> bytes:
        if not DIGEST.fullmatch(digest):
            raise StoreError("invalid artifact digest")
        target = self.artifacts / digest[:2] / digest[2:]
        try:
            plaintext = self.cipher.decrypt(digest, target.read_bytes())
        except (OSError, IntegrityError) as error:
            raise StoreError(f"cannot read encrypted artifact: {digest}") from error
        if hashlib.sha256(plaintext).hexdigest() != digest:
            raise StoreError(f"decrypted artifact digest mismatch: {digest}")
        return plaintext

    def persist_snapshot(self, snapshot: Snapshot) -> None:
        for item in snapshot.files:
            self.put_bytes(item.digest, item.data)
        self.put_bytes(snapshot.digest, snapshot.manifest_bytes())

    def load_cached_analysis(self, cache_key: str) -> dict[str, Any] | None:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT payload FROM static_cache WHERE cache_key = ?",
                (cache_key,),
            ).fetchone()
        if row is None:
            return None
        try:
            payload = json.loads(str(row[0]))
        except (json.JSONDecodeError, TypeError):
            return None
        return cast(dict[str, Any], payload) if isinstance(payload, dict) else None

    def cache_analysis(
        self,
        cache_key: str,
        snapshot_hash: str,
        created_at: str,
        payload: dict[str, Any],
    ) -> None:
        serialized = json.dumps(payload, ensure_ascii=True, separators=(",", ":"), sort_keys=True)
        with self._connect() as connection:
            connection.execute(
                """INSERT OR IGNORE INTO static_cache(
                cache_key, snapshot_hash, created_at, payload
                ) VALUES (?, ?, ?, ?)""",
                (cache_key, snapshot_hash, created_at, serialized),
            )

    def latest_performance_baseline(
        self,
        series_key: str,
        *,
        exclude_snapshot: str,
    ) -> dict[str, Any] | None:
        if not DIGEST.fullmatch(series_key) or not DIGEST.fullmatch(exclude_snapshot):
            raise StoreError("invalid performance baseline key")
        with self._connect() as connection:
            row = connection.execute(
                """SELECT snapshot_hash, created_at, sample_count, payload
                FROM performance_baselines
                WHERE series_key = ? AND snapshot_hash != ?
                ORDER BY created_at DESC LIMIT 1""",
                (series_key, exclude_snapshot),
            ).fetchone()
        if row is None:
            return None
        try:
            payload = json.loads(str(row["payload"]))
        except (json.JSONDecodeError, TypeError) as error:
            raise StoreError("performance baseline is corrupt") from error
        if not isinstance(payload, dict):
            raise StoreError("performance baseline payload is corrupt")
        return {
            "snapshot_hash": str(row["snapshot_hash"]),
            "created_at": str(row["created_at"]),
            "sample_count": int(row["sample_count"]),
            "metrics": cast(dict[str, Any], payload),
        }

    def record_performance_baseline(
        self,
        *,
        series_key: str,
        snapshot_hash: str,
        sample_count: int,
        metrics: dict[str, Any],
    ) -> None:
        if not DIGEST.fullmatch(series_key) or not DIGEST.fullmatch(snapshot_hash):
            raise StoreError("invalid performance baseline key")
        if not 1 <= sample_count <= 10_000:
            raise StoreError("invalid performance baseline sample count")
        serialized = json.dumps(metrics, ensure_ascii=True, separators=(",", ":"), sort_keys=True)
        if len(serialized.encode("utf-8")) > 1024 * 1024:
            raise StoreError("performance baseline exceeds its byte limit")
        with self._connect() as connection:
            connection.execute(
                """INSERT INTO performance_baselines(
                id, series_key, snapshot_hash, created_at, sample_count, payload
                ) VALUES (?, ?, ?, ?, ?, ?)""",
                (
                    str(uuid.uuid4()),
                    series_key,
                    snapshot_hash,
                    self._now(),
                    sample_count,
                    serialized,
                ),
            )

    def _atomic_write(self, target: Path, data: bytes) -> None:
        handle, temporary = tempfile.mkstemp(dir=target.parent)
        try:
            with os.fdopen(handle, "wb") as stream:
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, target)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)

    def write_report(self, job_id: str, report: dict[str, Any]) -> Path:
        from skill_doctor.reporting import (
            render_html_report,
            render_junit_report,
            render_sarif_report,
        )

        paths = self.report_artifact_paths(job_id)
        target = paths["json"]
        payload = (json.dumps(report, indent=2, sort_keys=True) + "\n").encode("utf-8")
        self._atomic_write(target, payload)
        self._atomic_write(paths["html"], render_html_report(report))
        self._atomic_write(paths["sarif"], render_sarif_report(report))
        self._atomic_write(paths["junit"], render_junit_report(report))
        return target

    def report_artifact_paths(self, job_id: str) -> dict[str, Path]:
        if REPORT_ID.fullmatch(job_id) is None:
            raise StoreError("invalid report job identifier")
        return {
            "json": self.reports / f"{job_id}.json",
            "html": self.reports / f"{job_id}.html",
            "sarif": self.reports / f"{job_id}.sarif.json",
            "junit": self.reports / f"{job_id}.junit.xml",
        }

    def record_finding_feedback(
        self,
        *,
        job_id: str,
        finding_id: str,
        disposition: str,
        reason: str | None = None,
    ) -> dict[str, Any]:
        if disposition not in {"confirmed", "rejected", "unresolved"}:
            raise StoreError("invalid finding feedback disposition")
        if not finding_id or len(finding_id) > 256:
            raise StoreError("invalid finding feedback identifier")
        if reason is not None and len(reason.encode("utf-8")) > 16 * 1024:
            raise StoreError("finding feedback reason exceeds 16 KB")
        path = self.report_artifact_paths(job_id)["json"]
        try:
            report = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as error:
            raise StoreError("cannot read completed report for feedback") from error
        if not isinstance(report, dict):
            raise StoreError("completed report is invalid")
        findings = report.get("findings")
        if not isinstance(findings, list) or not any(
            isinstance(item, dict) and item.get("id") == finding_id for item in findings
        ):
            raise StoreError("feedback finding does not exist in the completed report")
        payload = json.dumps({"reason": reason}, separators=(",", ":"), sort_keys=True).encode(
            "utf-8"
        )
        digest = hashlib.sha256(payload).hexdigest()
        self.put_bytes(digest, payload)
        record = {
            "id": str(uuid.uuid4()),
            "job_id": job_id,
            "finding_id": finding_id,
            "disposition": disposition,
            "recorded_at": self._now(),
            "snapshot_hash": str(report.get("snapshot_hash", "")),
            "ruleset_version": str(report.get("ruleset_version", "")),
            "payload_digest": digest,
        }
        with self._connect() as connection:
            connection.execute(
                """INSERT INTO finding_feedback(
                id, job_id, finding_id, disposition, recorded_at, snapshot_hash,
                ruleset_version, payload_digest) VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                tuple(record.values()),
            )
        return {**record, "reason": reason}

    def finding_feedback(self, job_id: str) -> list[dict[str, Any]]:
        with self._connect() as connection:
            rows = connection.execute(
                """SELECT id, job_id, finding_id, disposition, recorded_at,
                snapshot_hash, ruleset_version, payload_digest
                FROM finding_feedback WHERE job_id = ? ORDER BY recorded_at, id""",
                (job_id,),
            ).fetchall()
        records: list[dict[str, Any]] = []
        for row in rows:
            digest = str(row["payload_digest"])
            try:
                payload = json.loads(self.get_bytes(digest))
            except (StoreError, UnicodeError, json.JSONDecodeError) as error:
                raise StoreError("finding feedback payload is unavailable") from error
            records.append(
                {
                    "id": str(row["id"]),
                    "job_id": str(row["job_id"]),
                    "finding_id": str(row["finding_id"]),
                    "disposition": str(row["disposition"]),
                    "recorded_at": str(row["recorded_at"]),
                    "snapshot_hash": str(row["snapshot_hash"]),
                    "ruleset_version": str(row["ruleset_version"]),
                    "reason": payload.get("reason") if isinstance(payload, dict) else None,
                }
            )
        return records

    def complete_job(
        self,
        job_id: str,
        snapshot_hash: str,
        target: Path,
        result_state: ResultState,
    ) -> None:
        with self._connect() as connection:
            connection.execute(
                """UPDATE jobs SET status = ?, snapshot_hash = ?, report_path = ?,
                result_state = ?, updated_at = ?, cancel_requested = 0, error = NULL
                WHERE id = ?""",
                (
                    "complete",
                    snapshot_hash,
                    str(target),
                    result_state,
                    self._now(),
                    job_id,
                ),
            )

    def finish_job(self, job_id: str, snapshot_hash: str, report: dict[str, Any]) -> Path:
        target = self.write_report(job_id, report)
        self.complete_job(
            job_id,
            snapshot_hash,
            target,
            cast(ResultState, report["result_state"]),
        )
        return target

    def fail_job(
        self,
        job_id: str,
        error: str | None = None,
        *,
        result_state: ResultState = "analysis_incomplete",
    ) -> None:
        with self._connect() as connection:
            connection.execute(
                """UPDATE jobs SET status = 'failed', result_state = ?,
                error = ?, updated_at = ? WHERE id = ?""",
                (result_state, error, self._now(), job_id),
            )

    def _delete_flight_paths(self, paths: list[str]) -> int:
        root = self.flight_recorder.resolve(strict=True)
        deleted = 0
        for raw_path in paths:
            try:
                path = Path(raw_path).resolve(strict=False)
                if path.is_relative_to(root) and path.parent == root and path.suffix == ".enc":
                    path.unlink(missing_ok=True)
                    deleted += 1
            except OSError:
                continue
        return deleted

    def _evict_flight_records(self, now: datetime) -> None:
        timestamp = now.astimezone(UTC).isoformat().replace("+00:00", "Z")
        with self._connect() as connection:
            expired = connection.execute(
                "SELECT id, path FROM flight_records WHERE expires_at <= ? ORDER BY recorded_at",
                (timestamp,),
            ).fetchall()
            expired_ids = [str(row["id"]) for row in expired]
            self._delete_flight_paths([str(row["path"]) for row in expired])
            if expired_ids:
                connection.executemany(
                    "DELETE FROM flight_records WHERE id = ?",
                    ((identifier,) for identifier in expired_ids),
                )

            rows = connection.execute(
                "SELECT id, path, plaintext_bytes FROM flight_records ORDER BY recorded_at, id"
            ).fetchall()
            total = sum(int(row["plaintext_bytes"]) for row in rows)
            remove: list[sqlite3.Row] = []
            for row in rows:
                if total <= FLIGHT_MAX_BYTES:
                    break
                total -= int(row["plaintext_bytes"])
                remove.append(row)
            self._delete_flight_paths([str(row["path"]) for row in remove])
            if remove:
                connection.executemany(
                    "DELETE FROM flight_records WHERE id = ?",
                    ((str(row["id"]),) for row in remove),
                )

    def append_flight_record(
        self,
        payload: dict[str, Any],
        *,
        recorded_at: datetime | None = None,
    ) -> str:
        now = (recorded_at or datetime.now(UTC)).astimezone(UTC)
        serialized = json.dumps(
            payload,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
        if len(serialized) > FLIGHT_MAX_BYTES:
            raise StoreError("flight recorder event exceeds the 50 MB ring capacity")
        digest = hashlib.sha256(serialized).hexdigest()
        identifier = str(uuid.uuid4())
        target = self.flight_recorder / f"{identifier}.enc"
        self._atomic_write(target, self.cipher.encrypt(digest, serialized))
        recorded = now.isoformat().replace("+00:00", "Z")
        expires = (now + FLIGHT_RETENTION).isoformat().replace("+00:00", "Z")
        try:
            with self._connect() as connection:
                connection.execute(
                    """INSERT INTO flight_records(
                    id, recorded_at, expires_at, path, digest, plaintext_bytes
                    ) VALUES (?, ?, ?, ?, ?, ?)""",
                    (identifier, recorded, expires, str(target), digest, len(serialized)),
                )
            self._evict_flight_records(now)
        except sqlite3.Error:
            target.unlink(missing_ok=True)
            raise
        return identifier

    def flight_recorder_status(self) -> dict[str, int]:
        self._evict_flight_records(datetime.now(UTC))
        with self._connect() as connection:
            row = connection.execute(
                "SELECT COUNT(*) AS count, COALESCE(SUM(plaintext_bytes), 0) AS bytes "
                "FROM flight_records"
            ).fetchone()
        return {
            "records": 0 if row is None else int(row["count"]),
            "plaintext_bytes": 0 if row is None else int(row["bytes"]),
            "max_bytes": FLIGHT_MAX_BYTES,
            "retention_hours": int(FLIGHT_RETENTION.total_seconds() // 3600),
        }

    def purge_flight_recorder(self) -> int:
        with self._connect() as connection:
            rows = connection.execute("SELECT path FROM flight_records").fetchall()
            connection.execute("DELETE FROM flight_records")
        self._delete_flight_paths([str(row["path"]) for row in rows])
        try:
            for path in self.flight_recorder.glob("*.enc"):
                path.unlink(missing_ok=True)
        except OSError as error:
            raise StoreError(f"cannot purge flight recorder: {error}") from error
        return len(rows)
