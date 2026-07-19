from __future__ import annotations

import hashlib
import json
import os
import tomllib
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from skill_doctor.dependencies import DependencyPlan, build_dependency_plan
from skill_doctor.discovery import Platform
from skill_doctor.evals import (
    EvalContract,
    deep_adversarial_contract,
    infer_contract,
    load_authored_contract,
    promote_inferred_for_job,
)
from skill_doctor.models import DynamicTestPlan
from skill_doctor.runtime import (
    ContainmentViolation,
    DiagnosticDepth,
    DynamicResult,
    RuntimeAdapterError,
    RuntimeAuth,
    RuntimeContext,
    plan_dynamic_tests,
    run_dynamic_tests,
)
from skill_doctor.sandbox import backend_for_host
from skill_doctor.snapshot import Snapshot, materialize_snapshot
from skill_doctor.store import LocalStore

Emit = Callable[[str, str, str | None], None]
Cancelled = Callable[[], bool]


@dataclass(frozen=True, slots=True)
class DynamicRequest:
    enabled: bool = False
    depth: DiagnosticDepth = "quick"
    approval_token: str | None = None
    runtime_version: str | None = None
    model: str | None = None
    permission_mode: str | None = None
    sandbox_mode: str | None = None
    runtime_proxy_url: str | None = None
    allowed_domains: tuple[str, ...] = ()
    dependency_proxy_url: str | None = None
    promote_inferred: bool = False
    approved_substitution: bool = False
    substituted_runtime: str | None = None
    substituted_model: str | None = None
    estimated_cost_per_run: float | None = None
    measure_performance: bool = False
    config_document: bytes | None = field(default=None, repr=False)


@dataclass(frozen=True, slots=True)
class DynamicTarget:
    snapshot: Snapshot
    platform: Platform
    skill_name: str


@dataclass(frozen=True, slots=True)
class _Prepared:
    target: DynamicTarget
    contracts: tuple[EvalContract, ...]
    dependency_plan: DependencyPlan


@dataclass(frozen=True, slots=True)
class DynamicOutcome:
    plan: DynamicTestPlan
    readiness: dict[str, Any]
    results: tuple[dict[str, Any], ...] = ()
    completed: tuple[str, ...] = ()
    skipped: tuple[str, ...] = ()
    unsupported: tuple[str, ...] = ()
    failed: tuple[str, ...] = ()
    limitations: tuple[str, ...] = ()
    indeterminate: bool = False


def dynamic_request_from_options(options: dict[str, Any]) -> DynamicRequest | None:
    enabled = options.get("dynamic", False)
    if not isinstance(enabled, bool):
        raise ValueError("dynamic must be a boolean")
    if not enabled:
        return None
    depth = options.get("depth", "quick")
    if depth not in {"quick", "standard", "deep"}:
        raise ValueError("dynamic depth must be quick, standard, or deep")
    config_document: bytes | None = None
    config_path = options.get("runtime_config")
    if config_path is not None:
        if not isinstance(config_path, str):
            raise ValueError("runtime configuration path must be a string")
        try:
            config_document = Path(config_path).read_bytes()
        except OSError as error:
            raise ValueError(f"cannot read runtime configuration: {error}") from error
        if len(config_document) > 1024 * 1024:
            raise ValueError("runtime configuration exceeds the 1 MB limit")
    domains = options.get("allowed_domains", [])
    if not isinstance(domains, list) or not all(isinstance(item, str) for item in domains):
        raise ValueError("dynamic network domains must be an array of strings")
    for name in ("promote_inferred", "approved_substitution", "measure_performance"):
        if not isinstance(options.get(name, False), bool):
            raise ValueError(f"dynamic option {name} must be a boolean")

    def optional_string(name: str) -> str | None:
        value = options.get(name)
        if value is not None and not isinstance(value, str):
            raise ValueError(f"dynamic option {name} must be a string or null")
        return value

    approval_token = optional_string("approval_token")
    if approval_token is not None and not all(
        character in "0123456789abcdef" for character in approval_token
    ):
        raise ValueError("dynamic approval token must be lowercase hexadecimal")
    if approval_token is not None and len(approval_token) != 64:
        raise ValueError("dynamic approval token must contain 64 characters")
    raw_cost = options.get("estimated_cost_per_run")
    if raw_cost is not None and (
        isinstance(raw_cost, bool)
        or not isinstance(raw_cost, int | float)
        or not 0 <= float(raw_cost) <= 1_000
    ):
        raise ValueError("estimated cost per run must be between 0 and 1000 USD")
    return DynamicRequest(
        enabled=True,
        depth=depth,
        approval_token=approval_token,
        runtime_version=optional_string("runtime_version"),
        model=optional_string("model"),
        permission_mode=optional_string("permission_mode"),
        sandbox_mode=optional_string("sandbox_mode"),
        runtime_proxy_url=optional_string("runtime_proxy_url"),
        allowed_domains=tuple(domains),
        dependency_proxy_url=optional_string("dependency_proxy_url"),
        promote_inferred=bool(options.get("promote_inferred", False)),
        approved_substitution=bool(options.get("approved_substitution", False)),
        substituted_runtime=optional_string("substituted_runtime"),
        substituted_model=optional_string("substituted_model"),
        estimated_cost_per_run=None if raw_cost is None else float(raw_cost),
        measure_performance=bool(options.get("measure_performance", False)),
        config_document=config_document,
    )


def _prepare(
    targets: tuple[DynamicTarget, ...],
    request: DynamicRequest,
    materialization_root: Path,
) -> tuple[_Prepared, ...]:
    prepared: list[_Prepared] = []
    for target in targets:
        with materialize_snapshot(target.snapshot, materialization_root) as root:
            contract = load_authored_contract(root) or infer_contract(
                root,
                skill_name=target.skill_name,
                platform=target.platform,
            )
            if contract.source == "inferred" and request.promote_inferred:
                contract = promote_inferred_for_job(contract, consent=True)
            contracts = [contract]
            if request.depth == "deep":
                contracts.append(
                    deep_adversarial_contract(
                        contract.skill_name,
                        platform=target.platform,
                    )
                )
            prepared.append(_Prepared(target, tuple(contracts), build_dependency_plan(root)))
    return tuple(prepared)


def _model_plan(
    prepared: tuple[_Prepared, ...],
    request: DynamicRequest,
) -> DynamicTestPlan:
    plans = [
        plan_dynamic_tests(
            item.contracts,
            depth=request.depth,
            network=request.runtime_proxy_url is not None,
            dependencies=item.dependency_plan.required,
            estimated_cost_per_run=request.estimated_cost_per_run,
        )
        for item in prepared
    ]
    scopes = {scope for plan in plans for scope in plan.required_consent_scopes}
    if request.config_document is None:
        scopes.add("clean_configuration_substitution")
    if request.substituted_runtime or request.substituted_model:
        scopes.add("runtime_or_model_substitution")
    if request.model is None:
        scopes.add("model_context_substitution")
    if request.permission_mode is None:
        scopes.add("permission_context_substitution")
    if request.sandbox_mode is None and any(item.target.platform == "codex" for item in prepared):
        scopes.add("sandbox_policy_substitution")
    if request.measure_performance:
        scopes.add("controlled_load_measurement")
    token_payload = {
        "depth": request.depth,
        "estimated_cost_per_run": request.estimated_cost_per_run,
        "allowed_domains": sorted(request.allowed_domains),
        "config_hash": (
            None
            if request.config_document is None
            else hashlib.sha256(request.config_document).hexdigest()
        ),
        "dependency_proxy_url": request.dependency_proxy_url,
        "model": request.model,
        "measure_performance": request.measure_performance,
        "permission_mode": request.permission_mode,
        "promote_inferred": request.promote_inferred,
        "runtime_proxy_url": request.runtime_proxy_url,
        "runtime_version": request.runtime_version,
        "sandbox_mode": request.sandbox_mode,
        "scopes": sorted(scopes),
        "snapshots": [item.target.snapshot.digest for item in prepared],
        "targets": [
            {"platform": item.target.platform, "skill_name": item.target.skill_name}
            for item in prepared
        ],
        "substituted_model": request.substituted_model,
        "substituted_runtime": request.substituted_runtime,
    }
    token = hashlib.sha256(
        json.dumps(token_payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
    ).hexdigest()
    return DynamicTestPlan(
        depth=request.depth,
        skill_count=len(prepared),
        test_count=sum(len(contract.cases) for item in prepared for contract in item.contracts),
        estimated_seconds=sum(plan.estimated_seconds for plan in plans),
        runtime_uses=sum(plan.runtime_uses for plan in plans),
        estimated_model_cost_usd=(
            None
            if request.estimated_cost_per_run is None
            else sum(plan.estimated_model_cost_usd or 0.0 for plan in plans)
        ),
        requires_approval=request.approval_token != token,
        authored_test_count=sum(plan.authored_test_count for plan in plans),
        inferred_test_count=sum(plan.inferred_test_count for plan in plans),
        repetitions=max((plan.repetitions for plan in plans), default=1),
        control_runs=sum(plan.control_runs for plan in plans),
        required_consent_scopes=tuple(sorted(scopes)),
        approval_token=token,
    )


def _runtime_context(item: _Prepared, request: DynamicRequest) -> RuntimeContext:
    platform = item.target.platform
    permission = request.permission_mode or ("never" if platform == "codex" else "dontAsk")
    sandbox_mode = request.sandbox_mode if platform == "codex" else None
    config = request.config_document
    if config is not None:
        try:
            if platform == "codex":
                tomllib.loads(config.decode("utf-8"))
            else:
                parsed_config = json.loads(config)
                if not isinstance(parsed_config, dict):
                    raise ValueError("Claude Code runtime configuration must be an object")
        except (UnicodeError, json.JSONDecodeError, tomllib.TOMLDecodeError) as error:
            raise ValueError(f"invalid exact runtime configuration: {error}") from error
    config_hash = hashlib.sha256(config or b"").hexdigest()
    if request.runtime_proxy_url is None:
        auth = RuntimeAuth()
    else:
        token = os.environ.get("SKILL_DOCTOR_EPHEMERAL_TOKEN")
        if not token:
            raise RuntimeAdapterError("SKILL_DOCTOR_EPHEMERAL_TOKEN is unavailable to the worker")
        auth = RuntimeAuth(
            "proxy",
            request.runtime_proxy_url,
            token,
            request.allowed_domains,
        )
    if request.runtime_version is None:
        raise RuntimeAdapterError("an exact originating runtime version is required")
    return RuntimeContext(
        platform=platform,
        runtime_version=request.runtime_version,
        model=request.model,
        permission_mode=permission,
        config_hash=config_hash,
        sandbox_mode=sandbox_mode or ("workspace-write" if platform == "codex" else None),
        approval_policy=permission if platform == "codex" else None,
        config_document=config,
        auth=auth,
        approved_substitution=request.approved_substitution,
        substituted_runtime=request.substituted_runtime,
        substituted_model=request.substituted_model,
    )


def _persist_raw_traces(store: LocalStore, result: DynamicResult) -> None:
    for trial in result.trials:
        store.put_bytes(trial.stdout_sha256, trial.raw_stdout)
        store.put_bytes(trial.stderr_sha256, trial.raw_stderr)


def orchestrate_dynamic(
    *,
    targets: tuple[DynamicTarget, ...],
    request: DynamicRequest,
    store: LocalStore,
    emit: Emit,
    cancelled: Cancelled,
    ruleset_version: str,
) -> DynamicOutcome:
    materialization_root = store.root / "runtime-materializations"
    prepared = _prepare(targets, request, materialization_root)
    plan = _model_plan(prepared, request)
    backend = backend_for_host()
    readiness = backend.readiness(deep=request.approval_token == plan.approval_token)
    readiness_payload = readiness.to_dict()
    if not prepared:
        return DynamicOutcome(
            plan,
            readiness_payload,
            skipped=("dynamic_no_resolved_targets",),
            limitations=("No resolved skill target was available for dynamic execution.",),
        )
    if request.approval_token is None:
        return DynamicOutcome(
            plan,
            readiness_payload,
            skipped=("dynamic_approval_required",),
            limitations=(
                "Dynamic execution requires a second invocation with the exact plan "
                "approval token.",
            ),
        )
    if request.approval_token != plan.approval_token:
        return DynamicOutcome(
            plan,
            readiness_payload,
            skipped=("dynamic_approval_token_mismatch",),
            limitations=("The approved dynamic plan no longer matches the current inputs.",),
        )
    if not readiness.ready or not readiness.capabilities.complete:
        return DynamicOutcome(
            plan,
            readiness_payload,
            unsupported=tuple(f"sandbox:{gap}" for gap in readiness.coverage_gaps)
            or ("sandbox:incomplete_capability_contract",),
            limitations=(
                "Secure dynamic execution is unavailable; the doctor did not fall back "
                "to host execution.",
            ),
        )
    requested_proxies = {
        proxy
        for proxy in (request.runtime_proxy_url, request.dependency_proxy_url)
        if proxy is not None
    }
    network_gaps = {
        gap
        for proxy in requested_proxies
        if (gap := backend.network_coverage_gap(proxy)) is not None
    }
    if network_gaps:
        return DynamicOutcome(
            plan,
            readiness_payload,
            unsupported=tuple(f"sandbox:{gap}" for gap in sorted(network_gaps)),
            limitations=("The approved network request does not match an attested sandbox proxy.",),
        )
    context_substitution = (
        request.config_document is None
        or request.model is None
        or request.permission_mode is None
        or (
            request.sandbox_mode is None
            and any(item.target.platform == "codex" for item in prepared)
        )
        or request.substituted_runtime is not None
        or request.substituted_model is not None
    )
    if context_substitution and not request.approved_substitution:
        return DynamicOutcome(
            plan,
            readiness_payload,
            skipped=("runtime_context_substitution_not_approved",),
        )

    results: list[dict[str, Any]] = []
    try:
        for item in prepared:
            emit(
                "dynamic",
                "Running approved actual-runtime sandbox trials",
                item.target.skill_name,
            )
            context = _runtime_context(item, request)
            with materialize_snapshot(item.target.snapshot, materialization_root) as root:
                result = run_dynamic_tests(
                    backend=backend,
                    snapshot_root=root,
                    skill_name=item.contracts[0].skill_name,
                    context=context,
                    contracts=item.contracts,
                    depth=request.depth,
                    approved_scopes=plan.required_consent_scopes,
                    work_root=store.root / "sandbox-work",
                    dependency_plan=item.dependency_plan,
                    dependency_proxy_url=request.dependency_proxy_url,
                    cancelled=cancelled,
                )
            _persist_raw_traces(store, result)
            payload = result.to_dict()
            payload.update(
                {
                    "ruleset_version": ruleset_version,
                    "skill_name": item.target.skill_name,
                    "snapshot_hash": item.target.snapshot.digest,
                }
            )
            results.append(payload)
    except ContainmentViolation as error:
        store.put_bytes(error.trial.stdout_sha256, error.trial.raw_stdout)
        store.put_bytes(error.trial.stderr_sha256, error.trial.raw_stderr)
        results.append(
            {
                "ruleset_version": ruleset_version,
                "skill_name": item.target.skill_name,
                "snapshot_hash": item.target.snapshot.digest,
                "containment_violation": True,
                "trials": [error.trial.to_dict()],
            }
        )
        return DynamicOutcome(
            plan,
            readiness_payload,
            tuple(results),
            failed=("containment:synthetic_secret_exposure",),
            limitations=(str(error),),
            indeterminate=True,
        )
    except (OSError, RuntimeAdapterError, ValueError) as error:
        return DynamicOutcome(
            plan,
            readiness_payload,
            tuple(results),
            failed=(f"dynamic_runtime:{type(error).__name__}",),
            limitations=(str(error),),
            indeterminate=True,
        )
    treatment_trials = [
        trial
        for result in results
        for trial in result.get("trials", [])
        if isinstance(trial, dict) and not trial.get("control")
    ]
    indeterminate = any(not trial.get("passed", False) for trial in treatment_trials)
    limitations = []
    if any(
        contract.source == "inferred" and not contract.trusted_for_job
        for item in prepared
        for contract in item.contracts
    ):
        limitations.append("An inferred contract alone cannot confirm functional correctness.")
    return DynamicOutcome(
        plan,
        readiness_payload,
        tuple(results),
        completed=(
            "sandbox_capability_attestation",
            "runtime_version_attestation",
            "actual_runtime_trials",
            "encrypted_dynamic_trace_retention",
        ),
        limitations=tuple(limitations),
        indeterminate=indeterminate,
    )
