from __future__ import annotations

import os
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

from skill_doctor.ipc import IPCError, request
from skill_doctor.platform_support import module_int
from skill_doctor.security import ArtifactCipher

WORKER_START_TIMEOUT = 10.0
WORKER_START_ATTEMPTS = 3


class WorkerUnavailable(RuntimeError):
    pass


def _auth_key(state_dir: Path) -> bytes:
    return ArtifactCipher.for_state(state_dir.expanduser().absolute()).ipc_auth_key


def try_worker_request(
    state_dir: Path,
    operation: str,
    params: dict[str, Any] | None = None,
    *,
    timeout: float = 5.0,
) -> dict[str, Any]:
    return request(
        state_dir.expanduser().absolute(),
        _auth_key(state_dir),
        operation,
        params,
        timeout=timeout,
    )


def ensure_worker(state_dir: Path) -> None:
    state = state_dir.expanduser().absolute()
    try:
        try_worker_request(state, "ping", timeout=0.5)
        return
    except IPCError:
        pass

    command = [sys.executable, "-m", "skill_doctor.worker", "--state-dir", str(state)]
    kwargs: dict[str, Any] = {
        "stdin": subprocess.DEVNULL,
        "stdout": subprocess.DEVNULL,
        "stderr": subprocess.DEVNULL,
        "close_fds": True,
    }
    if os.name == "nt":
        kwargs["creationflags"] = (
            module_int(subprocess, "CREATE_NEW_PROCESS_GROUP")
            | module_int(subprocess, "DETACHED_PROCESS")
            | module_int(subprocess, "CREATE_NO_WINDOW")
        )
    else:
        kwargs["start_new_session"] = True
    deadline = time.monotonic() + WORKER_START_TIMEOUT
    exit_statuses: list[int] = []
    startup_errors: list[str] = []
    for attempt in range(1, WORKER_START_ATTEMPTS + 1):
        if time.monotonic() >= deadline:
            break
        # Another caller may have won the per-state worker lock while a prior
        # process was starting or exiting. Probe again before every launch.
        try:
            try_worker_request(state, "ping", timeout=0.2)
            return
        except IPCError:
            pass
        try:
            process = subprocess.Popen(command, **kwargs)  # noqa: S603
        except OSError as error:
            startup_errors.append(type(error).__name__)
            time.sleep(min(0.1 * attempt, max(0.0, deadline - time.monotonic())))
            continue

        while time.monotonic() < deadline:
            try:
                try_worker_request(state, "ping", timeout=0.5)
                return
            except IPCError:
                exit_status = process.poll()
                if exit_status is not None:
                    exit_statuses.append(exit_status)
                    break
                time.sleep(0.05)
        if process.poll() is None:
            # Do not launch a duplicate while the selected process is alive.
            break
        time.sleep(min(0.1 * attempt, max(0.0, deadline - time.monotonic())))

    details: list[str] = []
    if exit_statuses:
        details.append("exit statuses " + ", ".join(str(item) for item in exit_statuses))
    if startup_errors:
        details.append("launch errors " + ", ".join(startup_errors))
    if not details:
        details.append("startup deadline expired")
    raise WorkerUnavailable("local worker did not become ready (" + "; ".join(details) + ")")


def worker_request(
    state_dir: Path,
    operation: str,
    params: dict[str, Any] | None = None,
    *,
    timeout: float = 5.0,
) -> dict[str, Any]:
    ensure_worker(state_dir)
    return try_worker_request(state_dir, operation, params, timeout=timeout)
