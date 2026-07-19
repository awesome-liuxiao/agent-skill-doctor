from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import signal
import subprocess
import sys
import threading
import time
import uuid
from collections.abc import Callable, Mapping, Sequence
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, BinaryIO, Literal, Protocol
from urllib.parse import urlsplit

from skill_doctor.discovery import Platform
from skill_doctor.platform_support import module_int

PINNED_IMAGE = re.compile(r"^[a-z0-9][a-z0-9._/-]*@sha256:[0-9a-f]{64}$", re.I)
SAFE_JOB_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
MAX_CAPTURE_BYTES = 10 * 1024 * 1024
DIGEST = re.compile(r"^[0-9a-f]{64}$")

SandboxBackendName = Literal[
    "linux-hardened-container",
    "windows-sandbox",
    "macos-virtualization-framework",
]


class SandboxError(RuntimeError):
    pass


class SandboxUnavailable(SandboxError):
    pass


class SandboxCancelled(SandboxError):
    pass


@dataclass(frozen=True, slots=True)
class ResourceLimits:
    timeout_seconds: int = 300
    memory_mb: int = 2_048
    cpu_count: float = 1.0
    process_count: int = 128
    temporary_mb: int = 256

    def validate(self) -> None:
        if not 1 <= self.timeout_seconds <= 3_600:
            raise ValueError("sandbox timeout must be between 1 and 3600 seconds")
        if not 128 <= self.memory_mb <= 32_768:
            raise ValueError("sandbox memory limit must be between 128 and 32768 MB")
        if not 0.1 <= self.cpu_count <= 32:
            raise ValueError("sandbox CPU limit must be between 0.1 and 32")
        if not 16 <= self.process_count <= 4_096:
            raise ValueError("sandbox process limit must be between 16 and 4096")
        if not 16 <= self.temporary_mb <= 8_192:
            raise ValueError("sandbox temporary limit must be between 16 and 8192 MB")


@dataclass(frozen=True, slots=True)
class NetworkPolicy:
    enabled: bool = False
    allowed_domains: tuple[str, ...] = ()
    proxy_url: str | None = None

    def validate(self) -> None:
        if not self.enabled and (self.allowed_domains or self.proxy_url):
            raise ValueError("disabled sandbox networking cannot have domains or a proxy")
        if self.enabled and (not self.allowed_domains or not self.proxy_url):
            raise ValueError("networked tests require both an allowlist and an attested proxy")
        if len(self.allowed_domains) > 100:
            raise ValueError("network allowlist cannot exceed 100 domains")
        if self.proxy_url is not None:
            if len(self.proxy_url) > 2_048:
                raise ValueError("sandbox proxy URL is too long")
            parsed = urlsplit(self.proxy_url)
            if (
                parsed.scheme not in {"http", "https"}
                or not parsed.hostname
                or parsed.username is not None
                or parsed.password is not None
                or parsed.fragment
            ):
                raise ValueError("sandbox proxy URL is invalid")
        for domain in self.allowed_domains:
            labels = domain.split(".")
            if (
                len(domain) > 253
                or not labels
                or any(
                    not re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?", label)
                    for label in labels
                )
            ):
                raise ValueError(f"invalid network allowlist domain: {domain!r}")


@dataclass(frozen=True, slots=True)
class SandboxCapabilities:
    filesystem_isolation: bool
    process_isolation: bool
    network_isolation: bool
    identity_isolation: bool
    resource_limits: bool
    trace_capture: bool
    forced_teardown: bool
    attestation: bool

    @property
    def complete(self) -> bool:
        return all(asdict(self).values())


@dataclass(frozen=True, slots=True)
class SandboxReadiness:
    backend: SandboxBackendName
    host_platform: str
    ready: bool
    capabilities: SandboxCapabilities
    detail: str
    setup_required: bool = False
    reboot_required: bool = False
    coverage_gaps: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class SandboxSpec:
    job_id: str
    platform: Platform
    skill_name: str
    snapshot_root: Path
    workspace: Path
    limits: ResourceLimits = field(default_factory=ResourceLimits)
    network: NetworkPolicy = field(default_factory=NetworkPolicy)
    environment: Mapping[str, str] = field(default_factory=dict)
    expose_skill: bool = True

    def validate(self) -> None:
        if not SAFE_JOB_ID.fullmatch(self.job_id):
            raise ValueError("invalid sandbox job identifier")
        if not SAFE_JOB_ID.fullmatch(self.skill_name):
            raise ValueError("invalid sandbox skill name")
        snapshot = self.snapshot_root.resolve(strict=True)
        workspace = self.workspace.resolve(strict=True)
        if not snapshot.is_dir() or not workspace.is_dir():
            raise ValueError("sandbox mounts must be directories")
        if (
            snapshot == workspace
            or snapshot.is_relative_to(workspace)
            or workspace.is_relative_to(snapshot)
        ):
            raise ValueError("sandbox snapshot and workspace mounts must not overlap")
        self.limits.validate()
        self.network.validate()
        for key, value in self.environment.items():
            if not re.fullmatch(r"[A-Z][A-Z0-9_]{0,127}", key):
                raise ValueError(f"invalid sandbox environment key: {key!r}")
            if "\0" in value or len(value) > 8_192:
                raise ValueError(f"invalid sandbox environment value for {key}")


@dataclass(frozen=True, slots=True)
class SandboxLaunch:
    backend: SandboxBackendName
    argv: tuple[str, ...]
    environment: Mapping[str, str]
    attestation: Mapping[str, Any]
    cleanup_argv: tuple[str, ...] | None = None
    leak_check_argv: tuple[str, ...] | None = None


@dataclass(frozen=True, slots=True)
class SandboxResult:
    backend: SandboxBackendName
    exit_code: int
    stdout: bytes
    stderr: bytes
    duration_ms: int
    timed_out: bool
    cancelled: bool
    output_truncated: bool
    attestation: Mapping[str, Any]


@dataclass(frozen=True, slots=True)
class CanarySet:
    credential_token: str
    private_file_token: str
    credential_file: Path
    private_file: Path
    exfiltration_sink: Path

    @property
    def tokens(self) -> tuple[str, str]:
        return self.credential_token, self.private_file_token


class SandboxBackend(Protocol):
    name: SandboxBackendName

    def readiness(self, *, deep: bool = False) -> SandboxReadiness: ...

    def network_coverage_gap(self, proxy_url: str) -> str | None: ...

    def build_launch(self, spec: SandboxSpec, inner_argv: Sequence[str]) -> SandboxLaunch: ...


def _capabilities(*, attestation: bool = True) -> SandboxCapabilities:
    return SandboxCapabilities(True, True, True, True, True, True, True, attestation)


def _host_environment(extra: Mapping[str, str] | None = None) -> dict[str, str]:
    allowed = ("PATH", "SYSTEMROOT", "WINDIR", "TMP", "TEMP", "LANG", "LC_ALL")
    result = {key: os.environ[key] for key in allowed if key in os.environ}
    if extra:
        result.update(extra)
    return result


def _skill_destination(spec: SandboxSpec) -> str:
    if spec.platform == "codex":
        return f"/home/doctor/.agents/skills/{spec.skill_name}"
    return f"/home/doctor/.claude/skills/{spec.skill_name}"


def _matches_digest(path: str | None, expected: str | None) -> bool:
    if not path or not expected or not DIGEST.fullmatch(expected):
        return False
    try:
        candidate = Path(path)
        if candidate.stat().st_size > 100 * 1024 * 1024:
            return False
        return hashlib.sha256(candidate.read_bytes()).hexdigest() == expected
    except OSError:
        return False


class LinuxHardenedContainerBackend:
    name: SandboxBackendName = "linux-hardened-container"

    def __init__(self, environment: Mapping[str, str] | None = None) -> None:
        self.environment = os.environ if environment is None else environment
        self.engine = self.environment.get("SKILL_DOCTOR_CONTAINER_ENGINE") or next(
            (name for name in ("podman", "docker") if shutil.which(name)),
            None,
        )
        self.image = self.environment.get("SKILL_DOCTOR_LINUX_IMAGE")
        self.network_name = self.environment.get("SKILL_DOCTOR_NETWORK_NAME")
        self.proxy_url = self.environment.get("SKILL_DOCTOR_PROXY_URL")
        self.isolation_attested = (
            self.environment.get("SKILL_DOCTOR_CONTAINER_ISOLATION_ATTESTED") == "1"
        )

    def network_coverage_gap(self, proxy_url: str) -> str | None:
        if not self.network_name or not self.proxy_url:
            return "attested_allowlist_proxy_network"
        if proxy_url != self.proxy_url:
            return "requested_proxy_does_not_match_attested_proxy"
        return None

    def readiness(self, *, deep: bool = False) -> SandboxReadiness:
        gaps: list[str] = []
        if sys.platform != "linux":
            gaps.append("linux_host_required")
        if not self.engine or shutil.which(self.engine) is None:
            gaps.append("container_engine")
        if not self.image or not PINNED_IMAGE.fullmatch(self.image):
            gaps.append("pinned_container_image")
        if not self.isolation_attested:
            gaps.append("rootless_or_user_namespace_attestation")
        detail = "hardened rootless container backend is configured"
        if deep and not gaps and self.engine and self.image:
            try:
                probe = subprocess.run(  # noqa: S603
                    [self.engine, "image", "inspect", self.image],
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    timeout=10,
                    check=False,
                    env=_host_environment(),
                )
                if probe.returncode != 0:
                    gaps.append("pinned_image_not_local")
            except (OSError, subprocess.TimeoutExpired):
                gaps.append("container_engine_probe")
        if gaps:
            detail = "secure Linux dynamic execution is unavailable: " + ", ".join(gaps)
        return SandboxReadiness(
            self.name,
            sys.platform,
            not gaps,
            _capabilities(),
            detail,
            setup_required=bool(gaps),
            coverage_gaps=tuple(gaps),
        )

    def build_launch(self, spec: SandboxSpec, inner_argv: Sequence[str]) -> SandboxLaunch:
        spec.validate()
        readiness = self.readiness()
        if not readiness.ready or not self.engine or not self.image:
            raise SandboxUnavailable(readiness.detail)
        engine = self.engine
        image = self.image
        if spec.network.enabled:
            gap = self.network_coverage_gap(str(spec.network.proxy_url))
            if gap is not None:
                raise SandboxUnavailable(f"sandbox networking is unavailable: {gap}")
        network = str(self.network_name) if spec.network.enabled else "none"
        container_name = f"skill-doctor-{spec.job_id[:40]}"
        argv = [
            engine,
            "run",
            "--rm",
            "--interactive",
            "--name",
            container_name,
            "--network",
            network,
            "--read-only",
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges",
            "--pids-limit",
            str(spec.limits.process_count),
            "--memory",
            f"{spec.limits.memory_mb}m",
            "--cpus",
            str(spec.limits.cpu_count),
            "--user",
            "65532:65532",
            "--mount",
            f"type=bind,src={spec.snapshot_root.resolve()},dst=/opt/skill,readonly",
            "--mount",
            f"type=bind,src={spec.workspace.resolve()},dst=/workspace",
            "--tmpfs",
            f"/tmp:rw,noexec,nosuid,nodev,size={spec.limits.temporary_mb}m",  # noqa: S108
            "--workdir",
            "/workspace",
            "--env",
            "HOME=/home/doctor",
        ]
        if spec.expose_skill:
            argv.extend(
                (
                    "--mount",
                    "type=bind,src="
                    f"{spec.snapshot_root.resolve()},dst={_skill_destination(spec)},readonly",
                )
            )
        for key, value in sorted(spec.environment.items()):
            # Pass sensitive, short-lived values through the scrubbed docker client
            # environment rather than exposing them in the host process argument list.
            del value
            argv.extend(("--env", key))
        if spec.network.enabled:
            argv.extend(("--env", f"HTTPS_PROXY={spec.network.proxy_url}"))
            argv.extend(("--env", f"ASD_ALLOWED_DOMAINS={','.join(spec.network.allowed_domains)}"))
            argv.extend(("--env", "ASD_NETWORK_CAPTURE=metadata-only"))
        argv.append(image)
        argv.extend(inner_argv)
        attestation = {
            "backend": self.name,
            "capabilities": asdict(readiness.capabilities),
            "image": image,
            "image_digest": image.rsplit("@sha256:", 1)[1],
            "container_isolation_attested": True,
            "network": "allowlist_proxy" if spec.network.enabled else "disabled",
            "network_capture": "metadata_only" if spec.network.enabled else "none",
            "snapshot_read_only": True,
            "skill_exposed": spec.expose_skill,
            "workspace_writable": True,
        }
        return SandboxLaunch(
            self.name,
            tuple(argv),
            _host_environment(spec.environment),
            attestation,
            (engine, "rm", "--force", container_name),
            (
                engine,
                "ps",
                "--all",
                "--filter",
                f"name=^/{container_name}$",
                "--format",
                "{{.ID}}",
            ),
        )


class WindowsSandboxBackend:
    name: SandboxBackendName = "windows-sandbox"

    def __init__(self, environment: Mapping[str, str] | None = None) -> None:
        self.environment = os.environ if environment is None else environment
        self.executable = shutil.which("WindowsSandbox.exe")
        self.runner = self.environment.get("SKILL_DOCTOR_WINDOWS_SANDBOX_RUNNER")
        self.runner_sha256 = self.environment.get("SKILL_DOCTOR_WINDOWS_RUNNER_SHA256")
        self.runtime_bundle = self.environment.get("SKILL_DOCTOR_WINDOWS_RUNTIME_BUNDLE")
        self.runtime_manifest = self.environment.get("SKILL_DOCTOR_WINDOWS_RUNTIME_MANIFEST")
        self.runtime_manifest_sha256 = self.environment.get(
            "SKILL_DOCTOR_WINDOWS_RUNTIME_MANIFEST_SHA256"
        )

    def readiness(self, *, deep: bool = False) -> SandboxReadiness:
        del deep
        gaps: list[str] = []
        if os.name != "nt":
            gaps.append("windows_host_required")
        if not self.executable:
            gaps.append("windows_sandbox_feature")
        if not _matches_digest(self.runner, self.runner_sha256):
            gaps.append("pinned_windows_sandbox_runner")
        if not self.runtime_bundle or not Path(self.runtime_bundle).is_dir():
            gaps.append("signed_runtime_bundle")
        if not _matches_digest(self.runtime_manifest, self.runtime_manifest_sha256):
            gaps.append("pinned_runtime_bundle_manifest")
        detail = (
            "Windows Sandbox with the signed doctor runner is configured"
            if not gaps
            else "secure Windows dynamic execution is unavailable: " + ", ".join(gaps)
        )
        return SandboxReadiness(
            self.name,
            sys.platform,
            not gaps,
            _capabilities(),
            detail,
            setup_required=bool(gaps),
            reboot_required="windows_sandbox_feature" in gaps,
            coverage_gaps=tuple(gaps),
        )

    def network_coverage_gap(self, proxy_url: str) -> str | None:
        del proxy_url
        return "windows_allowlist_proxy_network"

    def build_launch(self, spec: SandboxSpec, inner_argv: Sequence[str]) -> SandboxLaunch:
        spec.validate()
        readiness = self.readiness()
        if (
            not readiness.ready
            or not self.runner
            or not self.runtime_bundle
            or not self.runtime_manifest
            or not self.runtime_manifest_sha256
        ):
            raise SandboxUnavailable(readiness.detail)
        if spec.network.enabled:
            raise SandboxUnavailable("Windows Sandbox allowlisted networking is not configured")
        payload = {
            "command": list(inner_argv),
            "environment_keys": sorted(spec.environment),
            "expose_skill": spec.expose_skill,
            "job_id": spec.job_id,
            "limits": asdict(spec.limits),
            "network": asdict(spec.network),
            "platform": spec.platform,
            "runtime_bundle": str(Path(self.runtime_bundle).resolve()),
            "runtime_manifest": str(Path(self.runtime_manifest).resolve()),
            "skill_name": spec.skill_name,
            "snapshot_root": str(spec.snapshot_root.resolve()),
            "workspace": str(spec.workspace.resolve()),
        }
        encoded = json.dumps(payload, separators=(",", ":"), sort_keys=True)
        argv = ("powershell.exe", "-NoProfile", "-File", self.runner, "-SpecJson", encoded)
        return SandboxLaunch(
            self.name,
            argv,
            _host_environment(spec.environment),
            {
                "backend": self.name,
                "capabilities": asdict(readiness.capabilities),
                "network": "disabled",
                "network_capture": "none",
                "runtime_bundle": str(self.runtime_bundle),
                "runtime_manifest_sha256": self.runtime_manifest_sha256,
                "runner_sha256": self.runner_sha256,
                "snapshot_read_only": True,
                "skill_exposed": spec.expose_skill,
            },
        )


class MacOSVirtualizationBackend:
    name: SandboxBackendName = "macos-virtualization-framework"

    def __init__(self, environment: Mapping[str, str] | None = None) -> None:
        self.environment = os.environ if environment is None else environment
        self.runner = self.environment.get("SKILL_DOCTOR_MACOS_VM_RUNNER")
        self.runner_sha256 = self.environment.get("SKILL_DOCTOR_MACOS_RUNNER_SHA256")
        self.image = self.environment.get("SKILL_DOCTOR_MACOS_VM_IMAGE")
        self.proxy_url = self.environment.get("SKILL_DOCTOR_MACOS_PROXY_URL")

    def network_coverage_gap(self, proxy_url: str) -> str | None:
        if not self.proxy_url:
            return "attested_macos_allowlist_proxy"
        if proxy_url != self.proxy_url:
            return "requested_proxy_does_not_match_attested_proxy"
        return None

    def readiness(self, *, deep: bool = False) -> SandboxReadiness:
        del deep
        gaps: list[str] = []
        if sys.platform != "darwin":
            gaps.append("macos_host_required")
        if not _matches_digest(self.runner, self.runner_sha256):
            gaps.append("pinned_virtualization_framework_runner")
        if not self.image or not re.fullmatch(r"[^\s]+@sha256:[0-9a-f]{64}", self.image):
            gaps.append("pinned_vm_image")
        detail = (
            "Virtualization Framework doctor runner is configured"
            if not gaps
            else "secure macOS dynamic execution is unavailable: " + ", ".join(gaps)
        )
        return SandboxReadiness(
            self.name,
            sys.platform,
            not gaps,
            _capabilities(),
            detail,
            setup_required=bool(gaps),
            coverage_gaps=tuple(gaps),
        )

    def build_launch(self, spec: SandboxSpec, inner_argv: Sequence[str]) -> SandboxLaunch:
        spec.validate()
        readiness = self.readiness()
        if not readiness.ready or not self.runner or not self.image:
            raise SandboxUnavailable(readiness.detail)
        if spec.network.enabled:
            gap = self.network_coverage_gap(str(spec.network.proxy_url))
            if gap is not None:
                raise SandboxUnavailable(f"macOS VM networking is unavailable: {gap}")
        payload = {
            "command": list(inner_argv),
            "environment_keys": sorted(spec.environment),
            "expose_skill": spec.expose_skill,
            "image": self.image,
            "job_id": spec.job_id,
            "limits": asdict(spec.limits),
            "network": asdict(spec.network),
            "platform": spec.platform,
            "skill_name": spec.skill_name,
            "snapshot_root": str(spec.snapshot_root.resolve()),
            "workspace": str(spec.workspace.resolve()),
        }
        encoded = json.dumps(payload, separators=(",", ":"), sort_keys=True)
        return SandboxLaunch(
            self.name,
            (self.runner, "--spec-json", encoded),
            _host_environment(spec.environment),
            {
                "backend": self.name,
                "capabilities": asdict(readiness.capabilities),
                "image": self.image,
                "network": "allowlist_proxy" if spec.network.enabled else "disabled",
                "network_capture": "metadata_only" if spec.network.enabled else "none",
                "runner_sha256": self.runner_sha256,
                "snapshot_read_only": True,
                "skill_exposed": spec.expose_skill,
            },
        )


def backend_for_host(
    environment: Mapping[str, str] | None = None,
) -> SandboxBackend:
    if sys.platform == "linux":
        return LinuxHardenedContainerBackend(environment)
    if sys.platform == "darwin":
        return MacOSVirtualizationBackend(environment)
    if os.name == "nt":
        return WindowsSandboxBackend(environment)
    raise SandboxUnavailable(f"unsupported host platform: {sys.platform}")


def create_canaries(workspace: Path) -> CanarySet:
    root = workspace.resolve(strict=True)
    canary_root = root / ".doctor-canaries"
    canary_root.mkdir(mode=0o700)
    credential_token = f"ASD-CREDENTIAL-{uuid.uuid4()}"
    private_token = f"ASD-PRIVATE-{uuid.uuid4()}"
    credential_file = canary_root / "credentials.env"
    private_file = canary_root / "private.txt"
    sink = canary_root / "exfiltration-sink.jsonl"
    credential_file.write_text(f"DOCTOR_CANARY={credential_token}\n", encoding="utf-8")
    private_file.write_text(private_token + "\n", encoding="utf-8")
    sink.write_bytes(b"")
    return CanarySet(credential_token, private_token, credential_file, private_file, sink)


def _terminate_process(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is not None:
        return
    try:
        if os.name == "nt":
            taskkill = str(
                Path(os.environ.get("SYSTEMROOT", "C:/Windows")) / "System32" / "taskkill.exe"
            )
            subprocess.run(  # noqa: S603
                [taskkill, "/PID", str(process.pid), "/T", "/F"],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=10,
                check=False,
                env=_host_environment(),
            )
        else:
            os.kill(-process.pid, getattr(signal, "SIGKILL", 9))
    except (OSError, subprocess.TimeoutExpired):
        process.kill()


def _drain_stream(
    stream: BinaryIO,
    chunks: list[bytes],
    truncated: list[bool],
) -> None:
    captured = 0
    try:
        while True:
            chunk = stream.read(64 * 1024)
            if not chunk:
                break
            remaining = MAX_CAPTURE_BYTES - captured
            if remaining > 0:
                kept = chunk[:remaining]
                chunks.append(kept)
                captured += len(kept)
            if len(chunk) > max(remaining, 0):
                truncated[0] = True
    finally:
        stream.close()


def _write_stdin(stream: BinaryIO, data: bytes) -> None:
    try:
        stream.write(data)
        stream.flush()
    except (BrokenPipeError, OSError):
        pass
    finally:
        stream.close()


def _cleanup_launch(launch: SandboxLaunch) -> tuple[bool, bool | None]:
    if launch.cleanup_argv is None:
        return False, None
    try:
        subprocess.run(  # noqa: S603
            list(launch.cleanup_argv),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=15,
            check=False,
            env=dict(launch.environment),
        )
    except (OSError, subprocess.TimeoutExpired):
        return True, None
    if launch.leak_check_argv is None:
        return True, None
    try:
        check = subprocess.run(  # noqa: S603
            list(launch.leak_check_argv),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            timeout=15,
            check=False,
            env=dict(launch.environment),
        )
    except (OSError, subprocess.TimeoutExpired):
        return True, None
    if check.returncode != 0:
        return True, None
    return True, bool(check.stdout.strip())


def execute_sandbox(
    backend: SandboxBackend,
    spec: SandboxSpec,
    inner_argv: Sequence[str],
    *,
    cancelled: Callable[[], bool] = lambda: False,
    stdin: bytes | None = None,
) -> SandboxResult:
    launch = backend.build_launch(spec, inner_argv)
    started = time.monotonic()
    kwargs: dict[str, Any] = {
        "stdin": subprocess.PIPE if stdin is not None else subprocess.DEVNULL,
        "stdout": subprocess.PIPE,
        "stderr": subprocess.PIPE,
        "cwd": spec.workspace,
        "env": dict(launch.environment),
    }
    if os.name == "nt":
        kwargs["creationflags"] = module_int(subprocess, "CREATE_NEW_PROCESS_GROUP") | module_int(
            subprocess, "CREATE_NO_WINDOW"
        )
    else:
        kwargs["start_new_session"] = True
    try:
        process = subprocess.Popen(list(launch.argv), **kwargs)  # noqa: S603
    except OSError as error:
        raise SandboxUnavailable(f"cannot launch sandbox backend: {error}") from error
    if process.stdout is None or process.stderr is None:
        _terminate_process(process)
        raise SandboxUnavailable("sandbox backend output capture could not be established")
    stdout_chunks: list[bytes] = []
    stderr_chunks: list[bytes] = []
    stdout_truncated = [False]
    stderr_truncated = [False]
    readers = (
        threading.Thread(
            target=_drain_stream,
            args=(process.stdout, stdout_chunks, stdout_truncated),
            daemon=True,
        ),
        threading.Thread(
            target=_drain_stream,
            args=(process.stderr, stderr_chunks, stderr_truncated),
            daemon=True,
        ),
    )
    for reader in readers:
        reader.start()
    if stdin is not None:
        if process.stdin is None:
            _terminate_process(process)
            raise SandboxUnavailable("sandbox backend stdin could not be established")
        threading.Thread(
            target=_write_stdin,
            args=(process.stdin, stdin),
            daemon=True,
        ).start()
    timed_out = False
    was_cancelled = False
    deadline = started + spec.limits.timeout_seconds
    while process.poll() is None:
        if cancelled():
            was_cancelled = True
            _terminate_process(process)
            break
        if time.monotonic() >= deadline:
            timed_out = True
            _terminate_process(process)
            break
        time.sleep(0.05)
    try:
        process.wait(timeout=10)
    except subprocess.TimeoutExpired:
        _terminate_process(process)
        process.wait(timeout=10)
    for reader in readers:
        reader.join(timeout=10)
    cleanup_attempted, orphan_leak_detected = _cleanup_launch(launch)
    duration_ms = int((time.monotonic() - started) * 1_000)
    stdout = b"".join(stdout_chunks)
    stderr = b"".join(stderr_chunks)
    truncated = stdout_truncated[0] or stderr_truncated[0]
    exit_code = process.returncode if process.returncode is not None else -1
    return SandboxResult(
        launch.backend,
        exit_code,
        stdout,
        stderr,
        duration_ms,
        timed_out,
        was_cancelled,
        truncated,
        {
            **launch.attestation,
            "orphan_cleanup_attempted": cleanup_attempted,
            "orphan_leak_detected": orphan_leak_detected,
            "command_sha256": hashlib.sha256(
                json.dumps(list(inner_argv), separators=(",", ":")).encode()
            ).hexdigest(),
        },
    )
