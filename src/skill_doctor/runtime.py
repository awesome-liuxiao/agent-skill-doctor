from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import tempfile
import threading
import time
from collections.abc import Callable, Collection, Mapping, Sequence
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Literal, cast
from urllib.parse import urlsplit

from skill_doctor.dependencies import DependencyPlan
from skill_doctor.discovery import Platform
from skill_doctor.evals import (
    AssertionResult,
    ContractSource,
    EvalCase,
    EvalContract,
    RuntimeObservation,
    evaluate_assertions,
)
from skill_doctor.sandbox import (
    NetworkPolicy,
    ResourceLimits,
    SandboxBackend,
    SandboxReadiness,
    SandboxResult,
    SandboxSpec,
    create_canaries,
    execute_sandbox,
)

DiagnosticDepth = Literal["quick", "standard", "deep"]
AuthMode = Literal["local", "proxy"]
MAX_RUNTIME_EVENTS = 100_000
MAX_RUNTIME_LINE_BYTES = 2 * 1024 * 1024
MAX_WORKSPACE_ENTRIES = 10_000
DYNAMIC_LOCK = threading.Lock()


class RuntimeAdapterError(RuntimeError):
    pass


class DynamicConsentRequired(RuntimeAdapterError):
    pass


@dataclass(frozen=True, slots=True)
class RuntimeAuth:
    mode: AuthMode = "local"
    proxy_url: str | None = None
    ephemeral_token: str | None = None
    allowed_domains: tuple[str, ...] = ()

    def validate(self) -> None:
        if self.mode == "local":
            if self.proxy_url or self.ephemeral_token or self.allowed_domains:
                raise ValueError("local runtime auth cannot include proxy credentials")
            return
        if not self.proxy_url or not self.ephemeral_token or not self.allowed_domains:
            raise ValueError("proxy auth requires URL, ephemeral token, and domain allowlist")
        parsed = urlsplit(self.proxy_url)
        if (
            parsed.scheme not in {"http", "https"}
            or not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
        ):
            raise ValueError("runtime auth proxy URL is invalid")
        token = re.fullmatch(
            r"asd-job-([0-9]{10})-([A-Za-z0-9_-]{16,128})",
            self.ephemeral_token,
        )
        if token is None:
            raise ValueError("runtime auth token must be short-lived and doctor-issued")
        expires_at = int(token.group(1))
        now = int(time.time())
        if expires_at <= now or expires_at > now + 900:
            raise ValueError("runtime auth token must expire within 15 minutes")


@dataclass(frozen=True, slots=True)
class RuntimeContext:
    platform: Platform
    runtime_version: str
    model: str | None
    permission_mode: str
    config_hash: str
    sandbox_mode: str | None = None
    approval_policy: str | None = None
    config_document: bytes | None = field(default=None, repr=False)
    auth: RuntimeAuth = field(default_factory=RuntimeAuth)
    approved_substitution: bool = False
    substituted_runtime: str | None = None
    substituted_model: str | None = None

    def validate(self) -> None:
        if (
            not self.runtime_version
            or len(self.runtime_version) > 256
            or "\0" in self.runtime_version
            or not self.config_hash
        ):
            raise ValueError("runtime version and configuration hash are required")
        if self.model is not None and (len(self.model) > 256 or "\0" in self.model):
            raise ValueError("runtime model identifier is invalid")
        if not re.fullmatch(r"[0-9a-f]{64}", self.config_hash):
            raise ValueError("runtime configuration hash must be SHA-256")
        if self.config_document is None:
            if not self.approved_substitution:
                raise DynamicConsentRequired(
                    "a clean configuration substitution requires explicit approval"
                )
        elif hashlib.sha256(self.config_document).hexdigest() != self.config_hash:
            raise ValueError("runtime configuration content does not match its hash")
        if (self.substituted_runtime or self.substituted_model) and not self.approved_substitution:
            raise DynamicConsentRequired("runtime or model substitution requires explicit approval")
        if self.platform == "codex":
            if self.permission_mode not in {"untrusted", "on-failure", "on-request", "never"}:
                raise ValueError("unsupported Codex approval policy")
            if self.sandbox_mode not in {"read-only", "workspace-write", "danger-full-access"}:
                raise ValueError("Codex sandbox mode is required")
            if self.approval_policy and self.approval_policy != self.permission_mode:
                raise ValueError("Codex approval policy conflicts with permission mode")
        elif self.permission_mode not in {
            "acceptEdits",
            "auto",
            "bypassPermissions",
            "default",
            "dontAsk",
            "plan",
        }:
            raise ValueError("unsupported Claude Code permission mode")
        self.auth.validate()


@dataclass(frozen=True, slots=True)
class DynamicPlan:
    depth: DiagnosticDepth
    skill_count: int
    authored_test_count: int
    inferred_test_count: int
    repetitions: int
    control_runs: int
    runtime_uses: int
    estimated_seconds: int
    estimated_model_cost_usd: float | None
    required_consent_scopes: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class RuntimeInvocation:
    platform: Platform
    argv: tuple[str, ...]
    environment: Mapping[str, str]
    runtime_version: str
    model: str | None
    permission_mode: str
    substitution_disclosed: bool
    stdin: bytes = field(repr=False)


@dataclass(frozen=True, slots=True)
class ParsedRuntimeTrace:
    output: str
    event_count: int
    tool_calls: int
    model_turns: int
    input_tokens: int | None
    output_tokens: int | None
    cost_usd: float | None
    reported_duration_ms: int | None
    error_events: int


@dataclass(frozen=True, slots=True)
class TrialResult:
    case_id: str
    contract_source: ContractSource
    contract_trusted_for_job: bool
    repetition: int
    control: bool
    exit_code: int
    duration_ms: int
    assertions: tuple[AssertionResult, ...]
    sandbox_attestation: Mapping[str, Any]
    stdout_sha256: str
    stderr_sha256: str
    final_output_sha256: str
    runtime_metrics: Mapping[str, int | float | None]
    output_truncated: bool
    timed_out: bool
    cancelled: bool
    canary_exposure: bool
    orphan_leak_detected: bool
    raw_stdout: bytes = field(repr=False)
    raw_stderr: bytes = field(repr=False)

    @property
    def passed(self) -> bool:
        return (
            not self.timed_out
            and not self.cancelled
            and not self.canary_exposure
            and not self.orphan_leak_detected
            and not self.output_truncated
            and all(assertion.passed for assertion in self.assertions)
        )

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload.pop("raw_stdout")
        payload.pop("raw_stderr")
        payload["passed"] = self.passed
        return payload


class ContainmentViolation(RuntimeAdapterError):
    def __init__(self, trial: TrialResult, reason: str) -> None:
        super().__init__(reason + "; dynamic testing stopped")
        self.trial = trial


@dataclass(frozen=True, slots=True)
class DynamicResult:
    plan: DynamicPlan
    readiness: SandboxReadiness
    context: RuntimeContext
    contract_source: str
    contract_trusted_for_job: bool
    trials: tuple[TrialResult, ...]
    runtime_version_attestation: Mapping[str, Any]
    dependency_plan: DependencyPlan | None = None
    coverage_gaps: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "plan": self.plan.to_dict(),
            "readiness": self.readiness.to_dict(),
            "context": {
                "platform": self.context.platform,
                "runtime_version": self.context.runtime_version,
                "model": self.context.model,
                "permission_mode": self.context.permission_mode,
                "config_hash": self.context.config_hash,
                "configuration_reproduced": self.context.config_document is not None,
                "auth_mode": self.context.auth.mode,
                "substituted_runtime": self.context.substituted_runtime,
                "substituted_model": self.context.substituted_model,
            },
            "contract_source": self.contract_source,
            "contract_trusted_for_job": self.contract_trusted_for_job,
            "trials": [trial.to_dict() for trial in self.trials],
            "runtime_version_attestation": dict(self.runtime_version_attestation),
            "dependency_plan": (
                None if self.dependency_plan is None else self.dependency_plan.to_dict()
            ),
            "coverage_gaps": list(self.coverage_gaps),
        }


def plan_dynamic_tests(
    contracts: Sequence[EvalContract],
    *,
    depth: DiagnosticDepth,
    network: bool = False,
    dependencies: bool = False,
    estimated_cost_per_run: float | None = None,
) -> DynamicPlan:
    if depth == "quick":
        selected_cases = min(1, sum(len(contract.cases) for contract in contracts))
        repetitions = 1
        control_runs = 0
    elif depth == "standard":
        selected_cases = min(3, sum(len(contract.cases) for contract in contracts))
        repetitions = 3
        control_runs = selected_cases
    else:
        selected_cases = sum(len(contract.cases) for contract in contracts)
        repetitions = 5
        control_runs = selected_cases
    runtime_uses = selected_cases * repetitions + control_runs
    scopes = ["dynamic_execution", f"depth:{depth}"]
    if network:
        scopes.extend(("allowlisted_network", "proxied_runtime_auth"))
    if dependencies:
        scopes.extend(("dependency_install", "registry_allowlist_network"))
    if any(contract.source == "inferred" and contract.trusted_for_job for contract in contracts):
        scopes.append("promote_inferred_contract")
    return DynamicPlan(
        depth,
        len(contracts),
        sum(len(contract.cases) for contract in contracts if contract.source == "authored"),
        sum(len(contract.cases) for contract in contracts if contract.source == "inferred"),
        repetitions,
        control_runs,
        runtime_uses,
        runtime_uses * 60,
        None if estimated_cost_per_run is None else runtime_uses * estimated_cost_per_run,
        tuple(scopes),
    )


def _runtime_environment(context: RuntimeContext) -> tuple[dict[str, str], NetworkPolicy]:
    context.auth.validate()
    if context.auth.mode == "local":
        return {}, NetworkPolicy()
    token = cast(str, context.auth.ephemeral_token)
    proxy = cast(str, context.auth.proxy_url)
    if context.platform == "codex":
        environment = {
            "CODEX_API_KEY": token,
            "OPENAI_API_KEY": token,
            "OPENAI_BASE_URL": proxy,
        }
    else:
        environment = {
            "ANTHROPIC_API_KEY": token,
            "ANTHROPIC_BASE_URL": proxy,
            "CLAUDE_CODE_SUBPROCESS_ENV_SCRUB": "1",
        }
    return environment, NetworkPolicy(True, context.auth.allowed_domains, proxy)


def build_runtime_invocation(context: RuntimeContext, prompt: str) -> RuntimeInvocation:
    context.validate()
    environment, _ = _runtime_environment(context)
    runtime_version = context.substituted_runtime or context.runtime_version
    model = context.substituted_model or context.model
    substituted = bool(context.substituted_runtime or context.substituted_model)
    if context.platform == "codex":
        environment["CODEX_HOME"] = "/workspace/.doctor-runtime/codex"
        argv = [
            "codex",
            "--sandbox",
            cast(str, context.sandbox_mode),
            "--ask-for-approval",
            context.approval_policy or context.permission_mode,
        ]
        if model:
            argv.extend(("--model", model))
        argv.extend(("exec", "--json", "--ephemeral", "--cd", "/workspace", "-"))
    else:
        argv = [
            "claude",
            "-p",
            "--output-format",
            "stream-json",
            "--verbose",
            "--no-session-persistence",
            "--bare",
        ]
        if context.config_document is not None:
            argv.extend(("--settings", "/workspace/.doctor-runtime/claude-settings.json"))
        if model:
            argv.extend(("--model", model))
        if context.permission_mode == "bypassPermissions":
            argv.append("--dangerously-skip-permissions")
        else:
            argv.extend(("--permission-mode", context.permission_mode))
    return RuntimeInvocation(
        context.platform,
        tuple(argv),
        environment,
        runtime_version,
        model,
        context.permission_mode,
        substituted,
        prompt.encode("utf-8"),
    )


def _metric_number(value: object) -> int | None:
    if isinstance(value, bool) or not isinstance(value, int | float) or value < 0:
        return None
    return int(value)


def _parse_runtime_output(platform: Platform, stdout: bytes) -> ParsedRuntimeTrace:
    messages: list[str] = []
    event_count = 0
    tool_calls = 0
    model_turns = 0
    input_tokens = 0
    output_tokens = 0
    saw_input_tokens = False
    saw_output_tokens = False
    cost_usd: float | None = None
    reported_duration_ms: int | None = None
    error_events = 0
    for index, raw in enumerate(stdout.splitlines()):
        if index >= MAX_RUNTIME_EVENTS or len(raw) > MAX_RUNTIME_LINE_BYTES:
            break
        try:
            item = json.loads(raw)
        except (json.JSONDecodeError, UnicodeError):
            continue
        if not isinstance(item, dict):
            continue
        event_count += 1
        event = cast(dict[str, Any], item)
        event_type = str(event.get("type", ""))
        if platform == "codex":
            payload = event.get("item")
            if event_type == "turn.completed":
                model_turns += 1
            if event_type in {"error", "turn.failed"}:
                error_events += 1
            if (
                event_type == "item.completed"
                and isinstance(payload, dict)
                and payload.get("type") == "agent_message"
                and isinstance(payload.get("text"), str)
            ):
                messages.append(str(payload["text"]))
            if event_type == "item.completed" and isinstance(payload, dict):
                if payload.get("type") in {
                    "command_execution",
                    "file_change",
                    "mcp_tool_call",
                    "web_search",
                }:
                    tool_calls += 1
            usage = event.get("usage")
            if isinstance(usage, dict):
                value = _metric_number(usage.get("input_tokens"))
                if value is not None:
                    input_tokens += value
                    saw_input_tokens = True
                value = _metric_number(usage.get("output_tokens"))
                if value is not None:
                    output_tokens += value
                    saw_output_tokens = True
        else:
            if event_type == "assistant":
                model_turns += 1
                message = event.get("message")
                if isinstance(message, dict):
                    content = message.get("content")
                    if isinstance(content, list):
                        tool_calls += sum(
                            1
                            for block in content
                            if isinstance(block, dict) and block.get("type") == "tool_use"
                        )
                    usage = message.get("usage")
                    if isinstance(usage, dict):
                        value = _metric_number(usage.get("input_tokens"))
                        if value is not None:
                            input_tokens += value
                            saw_input_tokens = True
                        value = _metric_number(usage.get("output_tokens"))
                        if value is not None:
                            output_tokens += value
                            saw_output_tokens = True
            if event_type == "result":
                if isinstance(event.get("result"), str):
                    messages.append(str(event["result"]))
                if event.get("is_error") is True:
                    error_events += 1
                raw_cost = event.get("total_cost_usd")
                if isinstance(raw_cost, int | float) and not isinstance(raw_cost, bool):
                    cost_usd = float(raw_cost)
                reported_duration_ms = _metric_number(event.get("duration_ms"))
                turns = _metric_number(event.get("num_turns"))
                if turns is not None:
                    model_turns = max(model_turns, turns)
    return ParsedRuntimeTrace(
        "\n".join(messages),
        event_count,
        tool_calls,
        model_turns,
        input_tokens if saw_input_tokens else None,
        output_tokens if saw_output_tokens else None,
        cost_usd,
        reported_duration_ms,
        error_events,
    )


def _versions_match(expected: str, observed: str) -> bool:
    if expected == observed:
        return True
    version = re.fullmatch(r"[0-9]+(?:\.[0-9A-Za-z-]+){1,4}", expected)
    if version is None:
        return False
    observed_versions = re.findall(r"(?<![0-9A-Za-z])([0-9]+(?:\.[0-9A-Za-z-]+){1,4})", observed)
    return observed_versions == [expected]


def _workspace_files(workspace: Path) -> tuple[frozenset[str], bool, int]:
    files: list[str] = []
    entries = 0
    total_bytes = 0
    for current, directories, names in os.walk(workspace, followlinks=False):
        current_path = Path(current)
        directories[:] = [
            name
            for name in directories
            if not _is_link(current_path / name) and not name.startswith(".doctor-")
        ]
        entries += len(directories)
        if entries > MAX_WORKSPACE_ENTRIES:
            return frozenset(files), True, total_bytes
        for name in names:
            entries += 1
            if entries > MAX_WORKSPACE_ENTRIES:
                return frozenset(files), True, total_bytes
            path = current_path / name
            try:
                metadata = path.lstat()
            except OSError:
                continue
            if _is_link(path) or not stat.S_ISREG(metadata.st_mode):
                continue
            relative = path.relative_to(workspace)
            if relative.parts and relative.parts[0].startswith(".doctor-"):
                continue
            files.append(relative.as_posix())
            total_bytes += metadata.st_size
    return frozenset(files), False, total_bytes


def _is_link(path: Path) -> bool:
    is_junction = getattr(path, "is_junction", None)
    return path.is_symlink() or bool(is_junction and is_junction())


def _sink_was_used(path: Path) -> bool:
    try:
        metadata = path.lstat()
    except OSError:
        return True
    return not stat.S_ISREG(metadata.st_mode) or metadata.st_size != 0


def _trial(
    backend: SandboxBackend,
    spec: SandboxSpec,
    context: RuntimeContext,
    case: EvalCase,
    *,
    contract_source: ContractSource,
    contract_trusted_for_job: bool,
    repetition: int,
    control: bool,
    cancelled: Callable[[], bool],
    dependency_plan: DependencyPlan | None,
    dependency_proxy_url: str | None,
) -> TrialResult:
    runtime_root = spec.workspace / ".doctor-runtime"
    runtime_root.mkdir(mode=0o700)
    if context.config_document is not None:
        if context.platform == "codex":
            config_root = runtime_root / "codex"
            config_root.mkdir(mode=0o700)
            config_path = config_root / "config.toml"
        else:
            config_path = runtime_root / "claude-settings.json"
        config_path.write_bytes(context.config_document)
    invocation = build_runtime_invocation(context, case.prompt)
    _, network = _runtime_environment(context)
    environment = dict(invocation.environment)
    canaries = create_canaries(spec.workspace)
    environment.update(
        {
            "DOCTOR_CANARY_CREDENTIAL": canaries.credential_token,
            "DOCTOR_CANARY_PRIVATE_FILE": "/workspace/.doctor-canaries/private.txt",
            "DOCTOR_EXFILTRATION_SINK": ("/workspace/.doctor-canaries/exfiltration-sink.jsonl"),
        }
    )
    trial_spec = SandboxSpec(
        spec.job_id,
        spec.platform,
        spec.skill_name,
        spec.snapshot_root,
        spec.workspace,
        ResourceLimits(
            timeout_seconds=min(case.timeout_seconds, spec.limits.timeout_seconds),
            memory_mb=spec.limits.memory_mb,
            cpu_count=spec.limits.cpu_count,
            process_count=spec.limits.process_count,
            temporary_mb=spec.limits.temporary_mb,
        ),
        network,
        environment,
        spec.expose_skill,
    )
    dependency_attestations: list[dict[str, Any]] = []
    if dependency_plan is not None and dependency_plan.required:
        if not dependency_proxy_url:
            raise RuntimeAdapterError(
                "pinned dependency installation requires an attested registry proxy"
            )
        dependency_network = NetworkPolicy(
            True,
            dependency_plan.registry_domains,
            dependency_proxy_url,
        )
        for command in dependency_plan.commands:
            setup_spec = SandboxSpec(
                spec.job_id,
                spec.platform,
                spec.skill_name,
                spec.snapshot_root,
                spec.workspace,
                spec.limits,
                dependency_network,
                {},
            )
            setup = execute_sandbox(backend, setup_spec, command, cancelled=cancelled)
            dependency_attestations.append(
                {
                    "command_sha256": setup.attestation.get("command_sha256"),
                    "exit_code": setup.exit_code,
                    "stdout_sha256": hashlib.sha256(setup.stdout).hexdigest(),
                    "stderr_sha256": hashlib.sha256(setup.stderr).hexdigest(),
                    "duration_ms": setup.duration_ms,
                }
            )
            if setup.exit_code != 0 or setup.timed_out or setup.cancelled:
                raise RuntimeAdapterError("pinned dependency installation failed in sandbox")
    result: SandboxResult = execute_sandbox(
        backend,
        trial_spec,
        invocation.argv,
        cancelled=cancelled,
        stdin=invocation.stdin,
    )
    trace = _parse_runtime_output(context.platform, result.stdout)
    workspace_files, workspace_inventory_truncated, workspace_bytes = _workspace_files(
        spec.workspace
    )
    observation = RuntimeObservation(result.exit_code, trace.output, workspace_files)
    assertions = evaluate_assertions(case, observation)
    combined = result.stdout + b"\n" + result.stderr
    canary_exposure = any(token.encode() in combined for token in canaries.tokens)
    if _sink_was_used(canaries.exfiltration_sink):
        canary_exposure = True
    return TrialResult(
        case.id,
        contract_source,
        contract_trusted_for_job,
        repetition,
        control,
        result.exit_code,
        result.duration_ms,
        assertions,
        {
            **result.attestation,
            "dependency_setup": dependency_attestations,
            "workspace_inventory_truncated": workspace_inventory_truncated,
        },
        hashlib.sha256(result.stdout).hexdigest(),
        hashlib.sha256(result.stderr).hexdigest(),
        hashlib.sha256(trace.output.encode("utf-8")).hexdigest(),
        {
            "wall_latency_ms": result.duration_ms,
            "runtime_reported_duration_ms": trace.reported_duration_ms,
            "event_count": trace.event_count,
            "tool_calls": trace.tool_calls,
            "model_turns": trace.model_turns,
            "input_tokens": trace.input_tokens,
            "output_tokens": trace.output_tokens,
            "cost_usd": trace.cost_usd,
            "error_events": trace.error_events,
            "workspace_bytes": workspace_bytes,
            "dependency_setup_ms": sum(
                int(item["duration_ms"]) for item in dependency_attestations
            ),
        },
        result.output_truncated or workspace_inventory_truncated,
        result.timed_out,
        result.cancelled,
        canary_exposure,
        result.attestation.get("orphan_leak_detected") is True,
        result.stdout,
        result.stderr,
    )


def run_dynamic_tests(
    *,
    backend: SandboxBackend,
    snapshot_root: Path,
    skill_name: str,
    context: RuntimeContext,
    contracts: Sequence[EvalContract],
    depth: DiagnosticDepth,
    approved_scopes: Collection[str],
    work_root: Path,
    dependency_plan: DependencyPlan | None = None,
    dependency_proxy_url: str | None = None,
    cancelled: Callable[[], bool] = lambda: False,
) -> DynamicResult:
    context.validate()
    plan = plan_dynamic_tests(
        contracts,
        depth=depth,
        network=context.auth.mode == "proxy",
        dependencies=dependency_plan is not None and dependency_plan.required,
    )
    missing = set(plan.required_consent_scopes) - set(approved_scopes)
    if missing:
        raise DynamicConsentRequired(
            "missing dynamic consent scopes: " + ", ".join(sorted(missing))
        )
    readiness = backend.readiness(deep=True)
    if not readiness.ready or not readiness.capabilities.complete:
        raise RuntimeAdapterError(readiness.detail)

    all_cases = [
        (case, contract.source, contract.trusted_for_job)
        for contract in contracts
        for case in contract.cases
    ]
    selected_count = (
        1
        if depth == "quick"
        else (min(3, len(all_cases)) if depth == "standard" else len(all_cases))
    )
    selected = all_cases[:selected_count]
    trials: list[TrialResult] = []
    work_root.mkdir(parents=True, exist_ok=True)
    runtime_attestation: dict[str, Any] = {}
    try:
        acquired = False
        while not acquired:
            if cancelled():
                raise RuntimeAdapterError("dynamic testing cancelled while queued")
            acquired = DYNAMIC_LOCK.acquire(timeout=0.1)
        try:
            with tempfile.TemporaryDirectory(dir=work_root) as temporary:
                version_spec = SandboxSpec(
                    f"{skill_name}-runtime-version"[:128],
                    context.platform,
                    skill_name,
                    snapshot_root,
                    Path(temporary),
                    expose_skill=False,
                )
                version_command = (
                    ("codex", "--version")
                    if context.platform == "codex"
                    else ("claude", "--version")
                )
                version_result = execute_sandbox(
                    backend,
                    version_spec,
                    version_command,
                    cancelled=cancelled,
                )
                expected_version = context.substituted_runtime or context.runtime_version
                observed_version = version_result.stdout.decode("utf-8", errors="replace").strip()
                if (
                    version_result.exit_code != 0
                    or version_result.timed_out
                    or version_result.cancelled
                    or not _versions_match(expected_version, observed_version)
                ):
                    raise RuntimeAdapterError(
                        "sandbox runtime version mismatch: "
                        f"expected {expected_version!r}, observed {observed_version!r}"
                    )
                runtime_attestation = {
                    **version_result.attestation,
                    "expected": expected_version,
                    "observed": observed_version,
                    "verified": True,
                }
            for case, contract_source, contract_trusted in selected:
                for repetition in range(1, plan.repetitions + 1):
                    if cancelled():
                        raise RuntimeAdapterError("dynamic testing cancelled")
                    with tempfile.TemporaryDirectory(dir=work_root) as temporary:
                        workspace = Path(temporary)
                        spec = SandboxSpec(
                            f"{skill_name}-{case.id}-{repetition}"[:128],
                            context.platform,
                            skill_name,
                            snapshot_root,
                            workspace,
                        )
                        trial = _trial(
                            backend,
                            spec,
                            context,
                            case,
                            contract_source=contract_source,
                            contract_trusted_for_job=contract_trusted,
                            repetition=repetition,
                            control=False,
                            cancelled=cancelled,
                            dependency_plan=dependency_plan,
                            dependency_proxy_url=dependency_proxy_url,
                        )
                        trials.append(trial)
                        if trial.canary_exposure:
                            raise ContainmentViolation(
                                trial, "synthetic secret canary exposure detected"
                            )
                        if trial.orphan_leak_detected:
                            raise ContainmentViolation(trial, "orphan sandbox process detected")
                if plan.control_runs:
                    with tempfile.TemporaryDirectory(dir=work_root) as temporary:
                        workspace = Path(temporary)
                        control_spec = SandboxSpec(
                            f"{skill_name}-{case.id}-control"[:128],
                            context.platform,
                            skill_name,
                            snapshot_root,
                            workspace,
                            expose_skill=False,
                        )
                        trial = _trial(
                            backend,
                            control_spec,
                            context,
                            case,
                            contract_source=contract_source,
                            contract_trusted_for_job=contract_trusted,
                            repetition=1,
                            control=True,
                            cancelled=cancelled,
                            dependency_plan=dependency_plan,
                            dependency_proxy_url=dependency_proxy_url,
                        )
                        trials.append(trial)
                        if trial.canary_exposure:
                            raise ContainmentViolation(
                                trial, "synthetic secret canary exposure detected"
                            )
                        if trial.orphan_leak_detected:
                            raise ContainmentViolation(trial, "orphan sandbox process detected")
        finally:
            DYNAMIC_LOCK.release()
    finally:
        pass
    gaps: list[str] = []
    if any(
        contract.source == "inferred" and not contract.trusted_for_job for contract in contracts
    ):
        gaps.append("inferred_contract_cannot_confirm_functional_correctness")
    return DynamicResult(
        plan,
        readiness,
        context,
        ",".join(sorted({contract.source for contract in contracts})),
        all(contract.trusted_for_job for contract in contracts),
        tuple(trials),
        runtime_attestation,
        dependency_plan,
        tuple(gaps),
    )
