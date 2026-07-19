import os
import sys
from dataclasses import replace
from pathlib import Path
from typing import Any, cast

import pytest

from skill_doctor.sandbox import (
    LinuxHardenedContainerBackend,
    MacOSVirtualizationBackend,
    NetworkPolicy,
    ResourceLimits,
    SandboxBackendName,
    SandboxCapabilities,
    SandboxLaunch,
    SandboxReadiness,
    SandboxSpec,
    SandboxUnavailable,
    WindowsSandboxBackend,
    create_canaries,
    execute_sandbox,
)

IMAGE = "registry.example/doctor/runtime@sha256:" + "a" * 64


def _spec(tmp_path: Path, *, network: NetworkPolicy | None = None) -> SandboxSpec:
    snapshot = tmp_path / "snapshot"
    workspace = tmp_path / "workspace"
    snapshot.mkdir(parents=True)
    workspace.mkdir(parents=True)
    return SandboxSpec(
        "job-1",
        "codex",
        "fixture-skill",
        snapshot,
        workspace,
        ResourceLimits(timeout_seconds=2),
        network or NetworkPolicy(),
    )


def _ready(backend: SandboxBackendName) -> SandboxReadiness:
    capabilities = SandboxCapabilities(True, True, True, True, True, True, True, True)
    return SandboxReadiness(backend, sys.platform, True, capabilities, "ready")


def test_linux_launch_is_fail_closed_and_contains_hardening_controls(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("skill_doctor.sandbox.sys.platform", "linux")
    monkeypatch.setattr("skill_doctor.sandbox.shutil.which", lambda name: f"/usr/bin/{name}")
    backend = LinuxHardenedContainerBackend(
        {
            "SKILL_DOCTOR_CONTAINER_ENGINE": "docker",
            "SKILL_DOCTOR_LINUX_IMAGE": IMAGE,
            "SKILL_DOCTOR_CONTAINER_ISOLATION_ATTESTED": "1",
        }
    )
    launch = backend.build_launch(_spec(tmp_path), ("codex", "--version"))
    argv = list(launch.argv)
    assert argv[:2] == ["docker", "run"]
    assert "--read-only" in argv
    assert argv[argv.index("--network") + 1] == "none"
    assert argv[argv.index("--cap-drop") + 1] == "ALL"
    assert argv[argv.index("--security-opt") + 1] == "no-new-privileges"
    assert argv[argv.index("--user") + 1] == "65532:65532"
    mounts = [argv[index + 1] for index, value in enumerate(argv) if value == "--mount"]
    assert any("dst=/opt/skill,readonly" in mount for mount in mounts)
    assert any(
        "dst=/home/doctor/.agents/skills/fixture-skill,readonly" in mount for mount in mounts
    )
    assert not any("docker.sock" in value for value in argv)
    assert launch.attestation["snapshot_read_only"] is True
    assert launch.attestation["image_digest"] == "a" * 64


def test_linux_backend_rejects_unpinned_image_and_unattested_network(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("skill_doctor.sandbox.sys.platform", "linux")
    monkeypatch.setattr("skill_doctor.sandbox.shutil.which", lambda name: f"/usr/bin/{name}")
    unpinned = LinuxHardenedContainerBackend(
        {"SKILL_DOCTOR_CONTAINER_ENGINE": "docker", "SKILL_DOCTOR_LINUX_IMAGE": "latest"}
    )
    assert not unpinned.readiness().ready
    with pytest.raises(SandboxUnavailable):
        unpinned.build_launch(_spec(tmp_path), ("true",))

    configured = LinuxHardenedContainerBackend(
        {
            "SKILL_DOCTOR_CONTAINER_ENGINE": "docker",
            "SKILL_DOCTOR_LINUX_IMAGE": IMAGE,
            "SKILL_DOCTOR_CONTAINER_ISOLATION_ATTESTED": "1",
        }
    )
    networked_spec = replace(
        _spec(tmp_path / "network"),
        network=NetworkPolicy(True, ("proxy.example",), "https://proxy.example"),
    )
    with pytest.raises(SandboxUnavailable, match="networking is unavailable"):
        configured.build_launch(networked_spec, ("true",))


def test_windows_and_macos_adapters_pass_only_structured_specs(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    spec = _spec(tmp_path)
    runner = tmp_path / "runner"
    runtime = tmp_path / "runtime"
    manifest = tmp_path / "runtime.manifest.json"
    runner.write_text("signed fixture", encoding="utf-8")
    manifest.write_text("{}", encoding="utf-8")
    runtime.mkdir()

    windows = WindowsSandboxBackend()
    windows.runner = str(runner)
    windows.runtime_bundle = str(runtime)
    windows.runtime_manifest = str(manifest)
    windows.runtime_manifest_sha256 = "a" * 64
    monkeypatch.setattr(windows, "readiness", lambda deep=False: _ready("windows-sandbox"))
    windows_launch = windows.build_launch(spec, ("codex", "--version"))
    payload = windows_launch.argv[windows_launch.argv.index("-SpecJson") + 1]
    decoded = cast(dict[str, Any], __import__("json").loads(payload))
    assert decoded["command"] == ["codex", "--version"]
    assert decoded["network"]["enabled"] is False
    assert decoded["environment_keys"] == []
    assert windows_launch.attestation["snapshot_read_only"] is True

    macos = MacOSVirtualizationBackend()
    macos.runner = str(runner)
    macos.image = IMAGE
    monkeypatch.setattr(
        macos,
        "readiness",
        lambda deep=False: _ready("macos-virtualization-framework"),
    )
    macos_launch = macos.build_launch(spec, ("claude", "--version"))
    assert macos_launch.argv[0] == str(runner)
    assert macos_launch.attestation["image"] == IMAGE


class _ProcessBackend:
    name: SandboxBackendName = "linux-hardened-container"

    def readiness(self, *, deep: bool = False) -> SandboxReadiness:
        return _ready(self.name)

    def network_coverage_gap(self, proxy_url: str) -> str | None:
        del proxy_url
        return None

    def build_launch(self, spec: SandboxSpec, inner_argv: object) -> SandboxLaunch:
        del spec, inner_argv
        return SandboxLaunch(
            self.name,
            (sys.executable, "-c", "import time; time.sleep(30)"),
            {"PATH": os.environ.get("PATH", "")},
            {"fixture": True},
        )


def test_sandbox_execution_cancels_and_forcibly_tears_down(tmp_path: Path) -> None:
    result = execute_sandbox(
        _ProcessBackend(),
        _spec(tmp_path),
        ("ignored",),
        cancelled=lambda: True,
    )
    assert result.cancelled
    assert result.duration_ms < 10_000


class _EchoBackend:
    name: SandboxBackendName = "linux-hardened-container"

    def readiness(self, *, deep: bool = False) -> SandboxReadiness:
        return _ready(self.name)

    def network_coverage_gap(self, proxy_url: str) -> str | None:
        del proxy_url
        return None

    def build_launch(self, spec: SandboxSpec, inner_argv: object) -> SandboxLaunch:
        del spec, inner_argv
        script = (
            "import sys; data=sys.stdin.buffer.read(); "
            "sys.stdout.buffer.write(data); "
            "sys.stderr.buffer.write(b'x'*(11*1024*1024))"
        )
        return SandboxLaunch(
            self.name,
            (sys.executable, "-c", script),
            {"PATH": os.environ.get("PATH", "")},
            {"fixture": True},
        )


def test_sandbox_streams_stdin_and_drains_bounded_output(tmp_path: Path) -> None:
    secret_prompt = b"prompt-must-not-be-in-argv"
    result = execute_sandbox(
        _EchoBackend(),
        _spec(tmp_path),
        ("runtime", "-"),
        stdin=secret_prompt,
    )
    assert result.exit_code == 0
    assert result.stdout == secret_prompt
    assert len(result.stderr) == 10 * 1024 * 1024
    assert result.output_truncated


def test_canaries_are_unique_synthetic_values_inside_workspace(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    canaries = create_canaries(workspace)
    assert canaries.credential_token != canaries.private_file_token
    assert canaries.credential_token in canaries.credential_file.read_text(encoding="utf-8")
    assert canaries.private_file_token in canaries.private_file.read_text(encoding="utf-8")
    assert canaries.exfiltration_sink.stat().st_size == 0
