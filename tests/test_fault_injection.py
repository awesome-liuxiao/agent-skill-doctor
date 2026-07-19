import errno
import hashlib
import os
import sqlite3
import sys
from collections.abc import Sequence
from dataclasses import replace
from pathlib import Path

import pytest

from skill_doctor.dynamic_orchestration import (
    DynamicRequest,
    DynamicTarget,
    orchestrate_dynamic,
)
from skill_doctor.engine import execute_check
from skill_doctor.ipc import IPCError, IPCServer, request
from skill_doctor.runtime import RuntimeAdapterError
from skill_doctor.sandbox import (
    SandboxBackendName,
    SandboxCapabilities,
    SandboxLaunch,
    SandboxReadiness,
    SandboxSpec,
)
from skill_doctor.security import ArtifactCipher
from skill_doctor.snapshot import (
    SnapshotCancelled,
    SnapshotError,
    create_snapshot,
    verify_snapshot,
)
from skill_doctor.store import LocalStore

CREATED = "2026-07-16T00:00:00Z"


def _store(root: Path) -> LocalStore:
    return LocalStore(root, cipher=ArtifactCipher(os.urandom(32)))


def _skill(root: Path) -> Path:
    root.mkdir()
    (root / "SKILL.md").write_text(
        "---\nname: fixture\ndescription: Fault-injection fixture.\n---\n",
        encoding="utf-8",
    )
    return root


def _run(store: LocalStore, skill: Path, job_id: str) -> int:
    store.start_job(job_id, CREATED, str(skill))
    return execute_check(
        job_id=job_id,
        created_at=CREATED,
        path=skill,
        store=store,
        emit=lambda _stage, _summary, _detail: None,
        cancelled=lambda: False,
    ).exit_code


def test_fault_injection_worker_crash_is_recoverable(tmp_path: Path) -> None:
    store = _store(tmp_path / "state")
    store.start_job("worker-crash", CREATED, "/fixture")
    assert store.recover_interrupted_jobs() == 1
    recovered = store.get_job("worker-crash")
    assert recovered is not None
    assert recovered.status == "failed"
    assert recovered.result_state == "analysis_incomplete"
    assert store.resume_job("worker-crash") is True


def test_fault_injection_cancellation_stops_before_snapshot(tmp_path: Path) -> None:
    skill = _skill(tmp_path / "cancelled")
    with pytest.raises(SnapshotCancelled, match="cancelled"):
        create_snapshot(skill, cancelled=lambda: True)


def test_fault_injection_stale_input_invalidates_snapshot(tmp_path: Path) -> None:
    skill = _skill(tmp_path / "stale")
    snapshot = create_snapshot(skill)
    (skill / "SKILL.md").write_text("changed", encoding="utf-8")
    with pytest.raises(SnapshotError, match="stale report"):
        verify_snapshot(snapshot)


def test_fault_injection_disk_exhaustion_never_reports_success(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    skill = _skill(tmp_path / "disk")
    store = _store(tmp_path / "state")

    def no_space(_target: Path, _data: bytes) -> None:
        raise OSError(errno.ENOSPC, "synthetic disk exhaustion")

    monkeypatch.setattr(store, "_atomic_write", no_space)
    assert _run(store, skill, "disk-full") == 2
    job = store.get_job("disk-full")
    assert job is not None
    assert job.status == "failed"
    assert job.result_state == "analysis_incomplete"


def test_fault_injection_lost_ipc_fails_closed(tmp_path: Path) -> None:
    state = tmp_path / "ipc"
    key = os.urandom(32)
    server = IPCServer(state, key)
    server.close()
    with pytest.raises(IPCError, match="cannot connect"):
        request(state, key, "status", timeout=0.1)


def test_fault_injection_corrupt_cache_is_recomputed(tmp_path: Path) -> None:
    skill = _skill(tmp_path / "cache")
    store = _store(tmp_path / "state")
    assert _run(store, skill, "cache-seed") == 0
    with sqlite3.connect(store.database) as connection:
        connection.execute("UPDATE static_cache SET payload = 'not-json'")
    stages: list[str] = []
    store.start_job("cache-retry", CREATED, str(skill))
    result = execute_check(
        job_id="cache-retry",
        created_at=CREATED,
        path=skill,
        store=store,
        emit=lambda stage, _summary, _detail: stages.append(stage),
        cancelled=lambda: False,
    )
    assert result.exit_code == 0
    assert "analysis" in stages


class _ReadyBackend:
    name: SandboxBackendName = "linux-hardened-container"

    def readiness(self, *, deep: bool = False) -> SandboxReadiness:
        del deep
        capabilities = SandboxCapabilities(True, True, True, True, True, True, True, True)
        return SandboxReadiness(self.name, sys.platform, True, capabilities, "fixture ready")

    def network_coverage_gap(self, proxy_url: str) -> str | None:
        del proxy_url
        return None

    def build_launch(self, spec: SandboxSpec, inner_argv: Sequence[str]) -> SandboxLaunch:
        del spec, inner_argv
        raise AssertionError("runtime launch was replaced by the fault injector")


class _UnavailableBackend(_ReadyBackend):
    def readiness(self, *, deep: bool = False) -> SandboxReadiness:
        del deep
        capabilities = SandboxCapabilities(False, False, False, False, False, False, False, False)
        return SandboxReadiness(
            backend=self.name,
            host_platform=sys.platform,
            ready=False,
            capabilities=capabilities,
            detail="synthetic sandbox outage",
            coverage_gaps=("synthetic_unavailable",),
        )


def _dynamic_request() -> DynamicRequest:
    return DynamicRequest(
        enabled=True,
        runtime_version="codex-cli 1.2.3",
        model="gpt-fixture",
        permission_mode="never",
        sandbox_mode="danger-full-access",
        config_document=b"",
    )


def test_fault_injection_sandbox_failure_has_no_host_fallback(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    skill = _skill(tmp_path / "sandbox")
    target = DynamicTarget(create_snapshot(skill), "codex", "fixture")
    store = _store(tmp_path / "state")
    monkeypatch.setattr(
        "skill_doctor.dynamic_orchestration.backend_for_host",
        lambda: _UnavailableBackend(),
    )
    planned = orchestrate_dynamic(
        targets=(target,),
        request=_dynamic_request(),
        store=store,
        emit=lambda _stage, _summary, _detail: None,
        cancelled=lambda: False,
        ruleset_version="fixture",
    )
    token = planned.plan.approval_token
    assert token is not None
    outcome = orchestrate_dynamic(
        targets=(target,),
        request=replace(_dynamic_request(), approval_token=token),
        store=store,
        emit=lambda _stage, _summary, _detail: None,
        cancelled=lambda: False,
        ruleset_version="fixture",
    )
    assert outcome.results == ()
    assert outcome.unsupported == ("sandbox:synthetic_unavailable",)
    assert "did not fall back to host execution" in outcome.limitations[0]


def test_fault_injection_unavailable_model_is_indeterminate(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    skill = _skill(tmp_path / "model")
    target = DynamicTarget(create_snapshot(skill), "codex", "fixture")
    store = _store(tmp_path / "state")
    monkeypatch.setattr(
        "skill_doctor.dynamic_orchestration.backend_for_host",
        lambda: _ReadyBackend(),
    )

    def unavailable(**_kwargs: object) -> None:
        raise RuntimeAdapterError("synthetic model unavailable")

    monkeypatch.setattr("skill_doctor.dynamic_orchestration.run_dynamic_tests", unavailable)
    planned = orchestrate_dynamic(
        targets=(target,),
        request=_dynamic_request(),
        store=store,
        emit=lambda _stage, _summary, _detail: None,
        cancelled=lambda: False,
        ruleset_version="fixture",
    )
    token = planned.plan.approval_token
    assert token is not None
    outcome = orchestrate_dynamic(
        targets=(target,),
        request=replace(_dynamic_request(), approval_token=token),
        store=store,
        emit=lambda _stage, _summary, _detail: None,
        cancelled=lambda: False,
        ruleset_version="fixture",
    )
    assert outcome.indeterminate is True
    assert outcome.failed == ("dynamic_runtime:RuntimeAdapterError",)
    assert outcome.results == ()
    assert hashlib.sha256(b"").hexdigest() not in str(outcome.results)
