from __future__ import annotations

import argparse
import json
import os
import queue
import sys
import threading
import time
import uuid
from collections.abc import Sequence
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from multiprocessing.connection import Connection
from pathlib import Path
from typing import Any, BinaryIO, cast

from skill_doctor.discovery import Platform
from skill_doctor.dynamic_orchestration import dynamic_request_from_options
from skill_doctor.engine import execute_check, execute_discovered_check, execute_session_diagnosis
from skill_doctor.ipc import PROTOCOL_VERSION, IPCError, IPCServer
from skill_doctor.models import SCHEMA_VERSION, Event, JobRecord
from skill_doctor.platform_support import module_attribute, module_int
from skill_doctor.store import LocalStore, StoreError

DEFAULT_IDLE_TIMEOUT = 300.0
STARTUP_GRACE_SECONDS = 15.0


class WorkerAlreadyRunning(RuntimeError):
    pass


def _now() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def _database_safe(value: Path) -> str:
    return str(value).encode("utf-8", errors="backslashreplace").decode("utf-8")


def _state_overlaps_skill(path: Path, state_dir: Path) -> bool:
    skill = path.expanduser().absolute().resolve(strict=False)
    state = state_dir.expanduser().absolute().resolve(strict=False)
    return state == skill or state.is_relative_to(skill)


class StateLock:
    def __init__(self, state_dir: Path) -> None:
        state_dir.mkdir(parents=True, exist_ok=True)
        self.path = state_dir / "worker.lock"
        self.stream: BinaryIO | None = None

    def __enter__(self) -> StateLock:
        stream = self.path.open("a+b")
        if stream.seek(0, os.SEEK_END) == 0:
            stream.write(b"\0")
            stream.flush()
        stream.seek(0)
        try:
            if os.name == "nt":
                import msvcrt

                locking = module_attribute(msvcrt, "locking")
                locking(stream.fileno(), module_int(msvcrt, "LK_NBLCK"), 1)
            else:
                import fcntl

                flock = module_attribute(fcntl, "flock")
                flock(
                    stream.fileno(),
                    module_int(fcntl, "LOCK_EX") | module_int(fcntl, "LOCK_NB"),
                )
        except OSError:
            stream.close()
            raise WorkerAlreadyRunning from None
        self.stream = stream
        return self

    def __exit__(self, *_: object) -> None:
        if self.stream is None:
            return
        self.stream.seek(0)
        try:
            if os.name == "nt":
                import msvcrt

                locking = module_attribute(msvcrt, "locking")
                locking(self.stream.fileno(), module_int(msvcrt, "LK_UNLCK"), 1)
            else:
                import fcntl

                flock = module_attribute(fcntl, "flock")
                flock(
                    self.stream.fileno(),
                    module_int(fcntl, "LOCK_UN"),
                )
        finally:
            self.stream.close()


class DurableEmitter:
    def __init__(self, store: LocalStore, job_id: str) -> None:
        self.store = store
        self.job_id = job_id
        self.sequence = store.next_event_sequence(job_id) - 1
        self._lock = threading.Lock()

    def emit(self, stage: str, summary: str, detail: str | None = None) -> None:
        with self._lock:
            self.sequence += 1
            self.store.append_event(
                Event(SCHEMA_VERSION, self.job_id, self.sequence, _now(), stage, summary, detail)
            )


class JobCoordinator:
    def __init__(self, store: LocalStore) -> None:
        self.store = store
        self._queue: queue.Queue[str] = queue.Queue()
        self._stopping = threading.Event()
        self._state_lock = threading.Lock()
        self._running_job: str | None = None
        self._thread = threading.Thread(target=self._run, name="skill-doctor-jobs", daemon=True)
        for job in reversed(store.list_jobs(limit=1_000)):
            if job.status == "queued":
                self._queue.put(job.id)
        self._thread.start()

    def enqueue(self, job_id: str) -> None:
        self._queue.put(job_id)

    def has_work(self) -> bool:
        with self._state_lock:
            return self._running_job is not None or not self._queue.empty()

    def stop(self) -> None:
        self._stopping.set()
        self._thread.join(timeout=5)

    def _run(self) -> None:
        while not self._stopping.is_set():
            try:
                job_id = self._queue.get(timeout=0.2)
            except queue.Empty:
                continue
            emitter: DurableEmitter | None = None
            heartbeat_stop = threading.Event()
            heartbeat: threading.Thread | None = None
            try:
                job = self.store.get_job(job_id)
                if job is None or job.status != "queued":
                    continue
                emitter = DurableEmitter(self.store, job_id)
                if job.cancel_requested:
                    self.store.mark_cancelled(job_id)
                    emitter.emit("cancelled", "Analysis cancelled before execution")
                    continue
                if not self.store.mark_running(job_id):
                    continue
                with self._state_lock:
                    self._running_job = job_id

                try:
                    heartbeat_interval = float(
                        os.environ.get("SKILL_DOCTOR_HEARTBEAT_SECONDS", "30")
                    )
                except ValueError:
                    heartbeat_interval = 30.0
                heartbeat_interval = max(0.05, min(heartbeat_interval, 300.0))

                active_emitter = emitter

                def emit_heartbeats(
                    stop: threading.Event = heartbeat_stop,
                    interval: float = heartbeat_interval,
                    current_emitter: DurableEmitter = active_emitter,
                ) -> None:
                    while not stop.wait(interval):
                        current_emitter.emit(
                            "heartbeat",
                            "Diagnostic job is still running",
                            None,
                        )

                heartbeat = threading.Thread(
                    target=emit_heartbeats,
                    name=f"skill-doctor-heartbeat-{job_id}",
                    daemon=True,
                )
                heartbeat.start()

                def cancellation_requested(current_job_id: str = job_id) -> bool:
                    return self.store.cancellation_requested(current_job_id)

                scope = str(job.options.get("scope", "explicit"))
                dynamic_request = dynamic_request_from_options(job.options)
                if scope == "session":
                    transcript_value = job.options.get("transcript")
                    execute_session_diagnosis(
                        job_id=job_id,
                        created_at=job.created_at,
                        platform_name=cast(Platform, job.options["platform"]),
                        cwd=Path(job.input_path),
                        store=self.store,
                        emit=emitter.emit,
                        cancelled=cancellation_requested,
                        supplied_transcript=(
                            Path(transcript_value) if isinstance(transcript_value, str) else None
                        ),
                        flight_recorder=bool(job.options.get("flight_recorder", False)),
                        added_directories=tuple(
                            Path(value)
                            for value in cast(list[str], job.options.get("added_directories", []))
                        ),
                        active_paths=tuple(
                            Path(value)
                            for value in cast(list[str], job.options.get("active_paths", []))
                        ),
                        dynamic_request=dynamic_request,
                    )
                elif scope in {"named", "all"}:
                    platform_name = cast(Platform, job.options["platform"])
                    selector_value = job.options.get("selector")
                    selector = selector_value if isinstance(selector_value, str) else None
                    execute_discovered_check(
                        job_id=job_id,
                        created_at=job.created_at,
                        platform_name=platform_name,
                        cwd=Path(job.input_path),
                        selector=selector,
                        scope=cast(Any, scope),
                        store=self.store,
                        emit=emitter.emit,
                        cancelled=cancellation_requested,
                        added_directories=tuple(
                            Path(value)
                            for value in cast(list[str], job.options.get("added_directories", []))
                        ),
                        active_paths=tuple(
                            Path(value)
                            for value in cast(list[str], job.options.get("active_paths", []))
                        ),
                        dynamic_request=dynamic_request,
                    )
                else:
                    execute_check(
                        job_id=job_id,
                        created_at=job.created_at,
                        path=Path(job.input_path),
                        store=self.store,
                        emit=emitter.emit,
                        cancelled=cancellation_requested,
                        platform_name=cast(Platform, job.options.get("platform", "codex")),
                        dynamic_request=dynamic_request,
                    )
            except (OSError, StoreError, TypeError, ValueError) as error:
                self.store.fail_job(job_id, str(error))
                if emitter is not None:
                    emitter.emit("error", "Analysis incomplete", str(error))
            except Exception as error:
                error_name = type(error).__name__
                self.store.fail_job(job_id, error_name, result_state="internal_error")
                if emitter is not None:
                    emitter.emit("error", "Internal error", error_name)
            finally:
                heartbeat_stop.set()
                if heartbeat is not None:
                    heartbeat.join(timeout=1)
                with self._state_lock:
                    self._running_job = None
                self._queue.task_done()


@dataclass(slots=True)
class Incoming:
    connection: Connection
    request: dict[str, Any]


def _job_dict(job: JobRecord) -> dict[str, Any]:
    return asdict(job)


def _event_dict(event: Event) -> dict[str, Any]:
    return asdict(event)


class Worker:
    def __init__(self, state_dir: Path, idle_timeout: float) -> None:
        self.state_dir = state_dir.expanduser().absolute()
        self.idle_timeout = max(0.1, idle_timeout)
        self.store = LocalStore(self.state_dir)
        self.store.recover_interrupted_jobs()
        self.coordinator = JobCoordinator(self.store)
        self.server = IPCServer(self.state_dir, self.store.cipher.ipc_auth_key)
        self.incoming: queue.Queue[Incoming] = queue.Queue(maxsize=128)
        self.stopping = threading.Event()
        self.last_activity = time.monotonic()
        self.started_at = self.last_activity
        self.received_request = False

    def _accept(self) -> None:
        while not self.stopping.is_set():
            connection: Connection | None = None
            try:
                connection = self.server.accept()
                request = self.server.receive(connection)
                self.incoming.put(Incoming(connection, request), timeout=1)
            except (IPCError, queue.Full):
                if connection is not None:
                    connection.close()

    def _handle(self, operation: str, params: dict[str, Any]) -> tuple[dict[str, Any], bool]:
        if operation == "ping":
            return {
                "pid": os.getpid(),
                "protocol_version": PROTOCOL_VERSION,
                "idle_timeout": self.idle_timeout,
            }, False
        if operation == "submit":
            raw_path = params.get("path")
            if not isinstance(raw_path, str) or not raw_path:
                raise ValueError("submit path must be a non-empty string")
            raw_options = params.get("options", {})
            if not isinstance(raw_options, dict):
                raise ValueError("submit options must be an object")
            options = cast(dict[str, Any], raw_options)
            dynamic_request_from_options(options)
            scope = options.get("scope", "explicit")
            if scope not in {"explicit", "named", "all", "session"}:
                raise ValueError("submit scope must be explicit, named, all, or session")
            if scope in {"named", "all", "session"}:
                if options.get("platform") not in {"codex", "claude"}:
                    raise ValueError("discovery checks require a supported platform")
                if scope == "named" and not isinstance(options.get("selector"), str):
                    raise ValueError("named checks require a selector")
                for field in ("added_directories", "active_paths"):
                    value = options.get(field, [])
                    if not isinstance(value, list) or not all(
                        isinstance(item, str) for item in value
                    ):
                        raise ValueError(f"{field} must be an array of paths")
                transcript = options.get("transcript")
                if transcript is not None and not isinstance(transcript, str):
                    raise ValueError("transcript must be a path string or null")
                if not isinstance(options.get("flight_recorder", False), bool):
                    raise ValueError("flight_recorder must be a boolean")
            path = Path(raw_path)
            if scope == "explicit" and _state_overlaps_skill(path, self.state_dir):
                raise ValueError("state directory must not be inside the skill being checked")
            job_id = str(uuid.uuid4())
            created = _now()
            self.store.create_job(job_id, created, _database_safe(path), options)
            DurableEmitter(self.store, job_id).emit("queue", "Diagnostic job queued")
            self.coordinator.enqueue(job_id)
            job = self.store.get_job(job_id)
            if job is None:
                raise StoreError("queued job could not be read back")
            return {"job": _job_dict(job)}, False
        if operation == "status":
            raw_job_id = params.get("job_id")
            since = params.get("since", 0)
            if not isinstance(raw_job_id, str) or not isinstance(since, int) or since < 0:
                raise ValueError("status requires a job_id and non-negative sequence")
            job_id = raw_job_id
            job = self.store.get_job(job_id)
            if job is None:
                raise ValueError("job not found")
            events = self.store.events_since(job_id, since)
            return {
                "job": _job_dict(job),
                "events": [_event_dict(event) for event in events],
            }, False
        if operation == "jobs":
            limit = params.get("limit", 100)
            if not isinstance(limit, int):
                raise ValueError("jobs limit must be an integer")
            return {"jobs": [_job_dict(job) for job in self.store.list_jobs(limit)]}, False
        if operation == "cancel":
            raw_job_id = params.get("job_id")
            if not isinstance(raw_job_id, str) or not self.store.request_cancel(raw_job_id):
                raise ValueError("job is not cancellable")
            job_id = raw_job_id
            job = self.store.get_job(job_id)
            if job is not None and job.status == "queued":
                self.store.mark_cancelled(job_id)
                DurableEmitter(self.store, job_id).emit("cancelled", "Queued analysis cancelled")
            updated = self.store.get_job(job_id)
            if updated is None:
                raise StoreError("cancelled job could not be read back")
            return {"job": _job_dict(updated)}, False
        if operation == "resume":
            raw_job_id = params.get("job_id")
            if not isinstance(raw_job_id, str) or not self.store.resume_job(raw_job_id):
                raise ValueError("job is not resumable")
            job_id = raw_job_id
            DurableEmitter(self.store, job_id).emit("resume", "Analysis queued for resumption")
            self.coordinator.enqueue(job_id)
            updated = self.store.get_job(job_id)
            if updated is None:
                raise StoreError("resumed job could not be read back")
            return {"job": _job_dict(updated)}, False
        if operation == "purge_flight_recorder":
            deleted = self.store.purge_flight_recorder()
            return {
                "deleted_records": deleted,
                "flight_recorder": self.store.flight_recorder_status(),
            }, False
        if operation == "shutdown":
            if self.coordinator.has_work():
                raise ValueError("worker cannot shut down while jobs are active")
            return {"shutting_down": True}, True
        raise ValueError(f"unsupported worker operation: {operation}")

    def run(self) -> int:
        acceptor = threading.Thread(target=self._accept, name="skill-doctor-ipc", daemon=True)
        acceptor.start()
        try:
            while not self.stopping.is_set():
                try:
                    incoming = self.incoming.get(timeout=0.2)
                except queue.Empty:
                    if not self.coordinator.has_work():
                        now = time.monotonic()
                        if self.received_request:
                            if now - self.last_activity >= self.idle_timeout:
                                break
                        elif now - self.started_at >= STARTUP_GRACE_SECONDS:
                            break
                    continue
                request_id = str(incoming.request["request_id"])
                should_stop = False
                result: dict[str, Any] | None = None
                response_error: str | None = None
                try:
                    operation = str(incoming.request["operation"])
                    params = cast(dict[str, Any], incoming.request["params"])
                    result, should_stop = self._handle(operation, params)
                except (OSError, StoreError, TypeError, ValueError) as error:
                    response_error = str(error)
                try:
                    self.server.respond(
                        incoming.connection,
                        request_id,
                        result=result,
                        error=response_error,
                    )
                except (OSError, EOFError):
                    # An authenticated client can time out during cold startup and close
                    # its pipe before the response is ready. That must not terminate the
                    # worker or start the short post-request idle countdown.
                    pass
                else:
                    self.last_activity = time.monotonic()
                    self.received_request = True
                finally:
                    incoming.connection.close()
                    self.incoming.task_done()
                if should_stop:
                    break
        finally:
            self.stopping.set()
            self.coordinator.stop()
            self.server.close()
        return 0


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(prog="python -m skill_doctor.worker")
    result.add_argument("--state-dir", required=True, type=Path)
    result.add_argument(
        "--idle-timeout",
        type=float,
        default=float(os.environ.get("SKILL_DOCTOR_IDLE_TIMEOUT", DEFAULT_IDLE_TIMEOUT)),
    )
    return result


def main(argv: Sequence[str] | None = None) -> int:
    arguments = parser().parse_args(argv)
    try:
        with StateLock(arguments.state_dir):
            return Worker(arguments.state_dir, arguments.idle_timeout).run()
    except WorkerAlreadyRunning:
        return 0
    except Exception as error:
        print(json.dumps({"worker_error": type(error).__name__}), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
