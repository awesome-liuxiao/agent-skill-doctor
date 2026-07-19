import hashlib
import os
import sys
import time
from collections.abc import Sequence
from dataclasses import replace
from pathlib import Path

import pytest

from skill_doctor.dynamic_orchestration import (
    DynamicRequest,
    DynamicTarget,
    orchestrate_dynamic,
)
from skill_doctor.evals import Assertions, EvalCase, EvalContract
from skill_doctor.runtime import (
    DynamicConsentRequired,
    RuntimeAuth,
    RuntimeContext,
    build_runtime_invocation,
    plan_dynamic_tests,
    run_dynamic_tests,
)
from skill_doctor.sandbox import (
    SandboxBackendName,
    SandboxCapabilities,
    SandboxLaunch,
    SandboxReadiness,
    SandboxSpec,
)
from skill_doctor.snapshot import create_snapshot
from skill_doctor.store import LocalStore

VERSION = "codex-cli 1.2.3"
EMPTY_HASH = hashlib.sha256(b"").hexdigest()


def _context() -> RuntimeContext:
    return RuntimeContext(
        platform="codex",
        runtime_version=VERSION,
        model="gpt-fixture",
        permission_mode="never",
        config_hash=EMPTY_HASH,
        sandbox_mode="danger-full-access",
        approval_policy="never",
        config_document=b"",
    )


def _contract(*, inferred: bool = False) -> EvalContract:
    case = EvalCase("case-1", "secret prompt", Assertions(0, ("complete",)))
    return EvalContract(
        1,
        "fixture",
        "inferred" if inferred else "authored",
        not inferred,
        (case,),
        {},
    )


def test_runtime_prompt_uses_stdin_and_reproduces_codex_controls() -> None:
    invocation = build_runtime_invocation(_context(), "secret prompt")
    assert "secret prompt" not in invocation.argv
    assert invocation.argv[-1] == "-"
    assert invocation.stdin == b"secret prompt"
    assert invocation.argv[invocation.argv.index("--sandbox") + 1] == "danger-full-access"
    assert invocation.argv[invocation.argv.index("--ask-for-approval") + 1] == "never"


def test_substitutions_and_proxy_credentials_require_explicit_safe_values() -> None:
    with pytest.raises(DynamicConsentRequired, match="clean configuration"):
        RuntimeContext(
            "codex",
            VERSION,
            None,
            "never",
            EMPTY_HASH,
            sandbox_mode="workspace-write",
        ).validate()


def test_proxy_token_must_be_doctor_issued_and_short_lived() -> None:
    expires = int(time.time()) + 300
    RuntimeAuth(
        "proxy",
        "https://proxy.example",
        f"asd-job-{expires}-abcdefghijklmnop",
        ("proxy.example",),
    ).validate()
    with pytest.raises(ValueError, match="15 minutes"):
        RuntimeAuth(
            "proxy",
            "https://proxy.example",
            f"asd-job-{int(time.time()) + 3600}-abcdefghijklmnop",
            ("proxy.example",),
        ).validate()
    with pytest.raises(ValueError, match="proxy URL"):
        RuntimeAuth(
            "proxy",
            "https://user:secret@proxy.example",
            "asd-job-token",
            ("proxy.example",),
        ).validate()


def test_depth_plans_are_bounded_and_require_escalation_scopes() -> None:
    quick = plan_dynamic_tests((_contract(),), depth="quick")
    standard = plan_dynamic_tests((_contract(),), depth="standard")
    deep = plan_dynamic_tests((_contract(),), depth="deep")
    assert (quick.repetitions, quick.control_runs, quick.runtime_uses) == (1, 0, 1)
    assert (standard.repetitions, standard.control_runs, standard.runtime_uses) == (3, 1, 4)
    assert (deep.repetitions, deep.control_runs, deep.runtime_uses) == (5, 1, 6)
    assert "depth:deep" in deep.required_consent_scopes


class _RuntimeBackend:
    name: SandboxBackendName = "linux-hardened-container"

    def __init__(self) -> None:
        self.specs: list[SandboxSpec] = []
        self.inner_argv: list[tuple[str, ...]] = []

    def readiness(self, *, deep: bool = False) -> SandboxReadiness:
        del deep
        capabilities = SandboxCapabilities(True, True, True, True, True, True, True, True)
        return SandboxReadiness(self.name, sys.platform, True, capabilities, "fixture ready")

    def network_coverage_gap(self, proxy_url: str) -> str | None:
        del proxy_url
        return None

    def build_launch(self, spec: SandboxSpec, inner_argv: Sequence[str]) -> SandboxLaunch:
        argv = tuple(inner_argv)
        self.specs.append(spec)
        self.inner_argv.append(argv)
        if argv[-1:] == ("--version",):
            script = f"print({VERSION!r})"
        else:
            script = (
                "import json,sys; sys.stdin.buffer.read(); "
                "print(json.dumps({'type':'item.completed','item':"
                "{'type':'agent_message','text':'complete'}}))"
            )
        return SandboxLaunch(
            self.name,
            (sys.executable, "-c", script),
            {"PATH": os.environ.get("PATH", "")},
            {"fixture": True, "skill_exposed": spec.expose_skill},
        )


def test_dynamic_runs_verify_runtime_repeat_and_no_skill_control(tmp_path: Path) -> None:
    snapshot = tmp_path / "snapshot"
    snapshot.mkdir()
    (snapshot / "SKILL.md").write_text("# fixture", encoding="utf-8")
    backend = _RuntimeBackend()
    result = run_dynamic_tests(
        backend=backend,
        snapshot_root=snapshot,
        skill_name="fixture",
        context=_context(),
        contracts=(_contract(),),
        depth="standard",
        approved_scopes=("dynamic_execution", "depth:standard"),
        work_root=tmp_path / "work",
    )
    assert result.runtime_version_attestation["verified"] is True
    assert len(result.trials) == 4
    assert all(trial.passed for trial in result.trials)
    assert [trial.control for trial in result.trials] == [False, False, False, True]
    assert backend.specs[-1].expose_skill is False
    assert all("secret prompt" not in argv for argv in backend.inner_argv)


def test_dynamic_refuses_to_run_before_all_scopes_are_approved(tmp_path: Path) -> None:
    snapshot = tmp_path / "snapshot"
    snapshot.mkdir()
    with pytest.raises(DynamicConsentRequired, match="depth:quick"):
        run_dynamic_tests(
            backend=_RuntimeBackend(),
            snapshot_root=snapshot,
            skill_name="fixture",
            context=_context(),
            contracts=(_contract(),),
            depth="quick",
            approved_scopes=("dynamic_execution",),
            work_root=tmp_path / "work",
        )


def test_orchestration_binds_approval_to_plan_and_encrypts_raw_traces(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    skill = tmp_path / "fixture"
    skill.mkdir()
    (skill / "SKILL.md").write_text(
        "---\nname: fixture\ndescription: Exercise the fixture.\n---\n",
        encoding="utf-8",
    )
    snapshot = create_snapshot(skill)
    backend = _RuntimeBackend()
    monkeypatch.setattr(
        "skill_doctor.dynamic_orchestration.backend_for_host",
        lambda: backend,
    )
    monkeypatch.setattr(
        "skill_doctor.security.load_or_create_master_key",
        lambda root: b"k" * 32,
    )
    store = LocalStore(tmp_path / "state")
    request = DynamicRequest(
        enabled=True,
        runtime_version=VERSION,
        model="gpt-fixture",
        permission_mode="never",
        sandbox_mode="danger-full-access",
        measure_performance=True,
        config_document=b"",
    )
    target = DynamicTarget(snapshot, "codex", "fixture")
    planned = orchestrate_dynamic(
        targets=(target,),
        request=request,
        store=store,
        emit=lambda stage, summary, detail: None,
        cancelled=lambda: False,
        ruleset_version="fixture-rules",
    )
    assert planned.plan.requires_approval
    assert "controlled_load_measurement" in planned.plan.required_consent_scopes
    assert planned.results == ()
    token = planned.plan.approval_token
    assert token is not None

    approved = orchestrate_dynamic(
        targets=(target,),
        request=replace(request, approval_token=token),
        store=store,
        emit=lambda stage, summary, detail: None,
        cancelled=lambda: False,
        ruleset_version="fixture-rules",
    )
    assert not approved.plan.requires_approval
    assert approved.completed
    trial = approved.results[0]["trials"][0]
    assert store.get_bytes(trial["stdout_sha256"])
    changed = orchestrate_dynamic(
        targets=(target,),
        request=replace(request, approval_token=token, model="different-model"),
        store=store,
        emit=lambda stage, summary, detail: None,
        cancelled=lambda: False,
        ruleset_version="fixture-rules",
    )
    assert changed.skipped == ("dynamic_approval_token_mismatch",)
