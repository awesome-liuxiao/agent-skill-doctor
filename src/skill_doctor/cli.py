from __future__ import annotations

import argparse
import json
import os
import sqlite3
import sys
import time
import uuid
from collections.abc import Sequence
from dataclasses import asdict
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal, cast

from skill_doctor.bootstrap import install_bootstrap, plan_bootstrap
from skill_doctor.discovery import Platform
from skill_doctor.dynamic_orchestration import DynamicRequest, dynamic_request_from_options
from skill_doctor.engine import (
    ExecutionResult,
    execute_check,
    execute_discovered_check,
    execute_session_diagnosis,
)
from skill_doctor.exporting import ExportError, plan_export, write_export
from skill_doctor.ipc import IPCError
from skill_doctor.models import SCHEMA_VERSION, Event, Report
from skill_doctor.readiness import readiness_report
from skill_doctor.security import EncryptionUnavailable
from skill_doctor.store import LocalStore, StoreError
from skill_doctor.supply_chain import RulePackManager, SupplyChainError
from skill_doctor.telemetry import TelemetryError, TelemetryManager
from skill_doctor.worker_client import WorkerUnavailable, worker_request

DEFAULT_STATE_DIR = Path.home() / ".skill-doctor"
TERMINAL_STATUSES = {"complete", "failed", "cancelled"}


def now() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def _state_argument(command: argparse.ArgumentParser) -> None:
    command.add_argument("--state-dir", type=Path, default=DEFAULT_STATE_DIR)


def _json_argument(command: argparse.ArgumentParser) -> None:
    command.add_argument("--json", action="store_true")


def _dynamic_arguments(command: argparse.ArgumentParser) -> None:
    command.add_argument(
        "--dynamic",
        action="store_true",
        help="plan sandboxed actual-runtime tests; execution requires a returned approval token",
    )
    command.add_argument("--depth", choices=("quick", "standard", "deep"), default="quick")
    command.add_argument(
        "--approve-dynamic",
        metavar="PLAN_TOKEN",
        help="execute only the previously reported immutable dynamic plan",
    )
    command.add_argument("--runtime-version", help="exact expected runtime --version output")
    command.add_argument("--model", help="originating model identifier")
    command.add_argument("--permission-mode", help="originating runtime permission mode")
    command.add_argument(
        "--sandbox-mode",
        choices=("read-only", "workspace-write", "danger-full-access"),
        help="originating Codex sandbox mode",
    )
    command.add_argument(
        "--runtime-config", type=Path, help="exact bounded runtime config snapshot"
    )
    command.add_argument("--runtime-proxy", help="attested short-lived runtime proxy URL")
    command.add_argument("--allow-domain", action="append", default=[])
    command.add_argument("--dependency-proxy", help="attested dependency registry proxy URL")
    command.add_argument("--promote-inferred", action="store_true")
    command.add_argument("--approve-substitution", action="store_true")
    command.add_argument("--substitute-runtime")
    command.add_argument("--substitute-model")
    command.add_argument(
        "--estimated-cost-per-run",
        type=float,
        help="operator-supplied USD estimate used only for preapproval planning",
    )
    command.add_argument(
        "--measure-performance",
        action="store_true",
        help="include non-overlapping controlled-load measurement in the approved plan",
    )


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(prog="skill-doctor")
    subcommands = result.add_subparsers(dest="command", required=True)

    check = subcommands.add_parser("check", help="statically check local or discovered skills")
    check.add_argument("target", nargs="?", help="local directory or platform skill selector")
    check.add_argument("--all", action="store_true", help="check every discovered skill copy")
    check.add_argument(
        "--platform",
        choices=("codex", "claude"),
        default=(
            os.environ.get("SKILL_DOCTOR_PLATFORM")
            if os.environ.get("SKILL_DOCTOR_PLATFORM") in {"codex", "claude"}
            else "codex"
        ),
        help="originating platform for named and all-skills discovery",
    )
    check.add_argument("--cwd", type=Path, default=Path.cwd())
    check.add_argument("--add-dir", action="append", default=[], type=Path)
    check.add_argument(
        "--active-path",
        action="append",
        default=[],
        type=Path,
        help=argparse.SUPPRESS,
    )
    _state_argument(check)
    check.add_argument("--json", action="store_true", help="print the versioned JSON report")
    check.add_argument("--direct", action="store_true", help=argparse.SUPPRESS)
    _dynamic_arguments(check)

    diagnose = subcommands.add_parser(
        "diagnose", help="diagnose the current Codex or Claude Code session"
    )
    diagnose.add_argument(
        "--platform",
        choices=("codex", "claude"),
        default=(
            os.environ.get("SKILL_DOCTOR_PLATFORM")
            if os.environ.get("SKILL_DOCTOR_PLATFORM") in {"codex", "claude"}
            else "codex"
        ),
    )
    diagnose.add_argument("--cwd", type=Path, default=Path.cwd())
    diagnose.add_argument("--transcript", type=Path)
    diagnose.add_argument(
        "--flight-recorder",
        action="store_true",
        help="opt in to the encrypted 24-hour minimized signal recorder",
    )
    diagnose.add_argument("--add-dir", action="append", default=[], type=Path)
    diagnose.add_argument("--active-path", action="append", default=[], type=Path)
    _state_argument(diagnose)
    _json_argument(diagnose)
    diagnose.add_argument("--direct", action="store_true", help=argparse.SUPPRESS)
    _dynamic_arguments(diagnose)

    jobs = subcommands.add_parser("jobs", help="list durable diagnostic jobs")
    jobs.add_argument("--limit", type=int, default=100)
    _state_argument(jobs)
    _json_argument(jobs)

    status = subcommands.add_parser("status", help="show one durable diagnostic job")
    status.add_argument("job_id")
    status.add_argument("--since", type=int, default=0)
    status.add_argument("--verbose", action="store_true", help="include structured event details")
    _state_argument(status)
    _json_argument(status)

    cancel = subcommands.add_parser("cancel", help="cancel a queued or running job")
    cancel.add_argument("job_id")
    _state_argument(cancel)
    _json_argument(cancel)

    resume = subcommands.add_parser("resume", help="resume a failed or cancelled job")
    resume.add_argument("job_id")
    _state_argument(resume)
    _json_argument(resume)

    purge = subcommands.add_parser("purge", help="delete retained opt-in raw artifacts")
    purge.add_argument(
        "--flight-recorder",
        action="store_true",
        required=True,
        help="immediately delete all flight-recorder records",
    )
    _state_argument(purge)
    _json_argument(purge)

    readiness = subcommands.add_parser(
        "readiness", help="report runtime, credential, and sandbox capabilities"
    )
    readiness.add_argument("--deep", action="store_true", help="probe configured sandbox assets")
    _state_argument(readiness)
    _json_argument(readiness)

    feedback = subcommands.add_parser(
        "feedback", help="record a local confirmed, rejected, or unresolved finding disposition"
    )
    feedback.add_argument("job_id")
    feedback.add_argument("finding_id")
    feedback.add_argument(
        "--disposition", choices=("confirmed", "rejected", "unresolved"), required=True
    )
    feedback.add_argument("--reason")
    _state_argument(feedback)
    _json_argument(feedback)

    export = subcommands.add_parser(
        "export", help="preview and explicitly approve a sanitized local report bundle"
    )
    export.add_argument("job_id")
    export.add_argument("--approve", metavar="PREVIEW_TOKEN")
    _state_argument(export)
    _json_argument(export)

    rules = subcommands.add_parser("rules", help="manage verified signed declarative rule packs")
    rules.add_argument(
        "action",
        choices=(
            "plan",
            "install",
            "update",
            "status",
            "rollback",
            "pin",
            "unpin",
            "configure-auto",
            "disable-auto",
        ),
    )
    rules.add_argument("source", nargs="?", help="signed pack path, HTTPS URL, or version pin")
    rules.add_argument("--approve", metavar="PLAN_TOKEN")
    _state_argument(rules)
    _json_argument(rules)

    bootstrap = subcommands.add_parser(
        "bootstrap", help="preview and explicitly install a verified sandbox backend asset set"
    )
    bootstrap.add_argument("manifest", type=Path, help="verified signed bootstrap manifest")
    bootstrap.add_argument("--platform", choices=("windows", "macos", "linux"))
    bootstrap.add_argument("--architecture")
    bootstrap.add_argument("--approve", metavar="PLAN_TOKEN")
    _state_argument(bootstrap)
    _json_argument(bootstrap)

    telemetry = subcommands.add_parser(
        "telemetry", help="inspect or explicitly configure narrow operational telemetry"
    )
    telemetry.add_argument("action", choices=("status", "enable", "disable"))
    telemetry.add_argument("endpoint", nargs="?")
    telemetry.add_argument("--approve", metavar="PLAN_TOKEN")
    _state_argument(telemetry)
    _json_argument(telemetry)
    return result


class Emitter:
    def __init__(self, job_id: str, store: LocalStore | None = None) -> None:
        self.job_id = job_id
        self.store = store
        self.sequence = 0 if store is None else store.next_event_sequence(job_id) - 1

    def emit(self, stage: str, summary: str, detail: str | None = None) -> None:
        self.sequence += 1
        event = Event(SCHEMA_VERSION, self.job_id, self.sequence, now(), stage, summary, detail)
        if self.store is not None:
            self.store.append_event(event)
        _write_event(asdict(event))


def _write_event(event: dict[str, Any]) -> None:
    print(json.dumps(event, separators=(",", ":"), sort_keys=False), file=sys.stderr, flush=True)


def _terminal_safe(value: object) -> str:
    text = str(value)
    escaped: list[str] = []
    for character in text:
        codepoint = ord(character)
        if character.isprintable() and not 0x7F <= codepoint <= 0x9F:
            escaped.append(character)
        elif codepoint <= 0xFF:
            escaped.append(f"\\x{codepoint:02x}")
        else:
            escaped.append(f"\\u{codepoint:04x}")
    return "".join(escaped)


def _database_safe(value: Path) -> str:
    return str(value).encode("utf-8", errors="backslashreplace").decode("utf-8")


def _dynamic_options(arguments: argparse.Namespace) -> dict[str, Any]:
    return {
        "dynamic": arguments.dynamic,
        "depth": arguments.depth,
        "approval_token": arguments.approve_dynamic,
        "runtime_version": arguments.runtime_version,
        "model": arguments.model,
        "permission_mode": arguments.permission_mode,
        "sandbox_mode": arguments.sandbox_mode,
        "runtime_config": (
            None
            if arguments.runtime_config is None
            else str(arguments.runtime_config.expanduser().absolute())
        ),
        "runtime_proxy_url": arguments.runtime_proxy,
        "allowed_domains": list(arguments.allow_domain),
        "dependency_proxy_url": arguments.dependency_proxy,
        "promote_inferred": arguments.promote_inferred,
        "approved_substitution": arguments.approve_substitution,
        "substituted_runtime": arguments.substitute_runtime,
        "substituted_model": arguments.substitute_model,
        "estimated_cost_per_run": arguments.estimated_cost_per_run,
        "measure_performance": arguments.measure_performance,
    }


def _parse_dynamic_request(
    arguments: argparse.Namespace,
) -> tuple[dict[str, Any], DynamicRequest | None]:
    options = _dynamic_options(arguments)
    if arguments.approve_dynamic and not arguments.dynamic:
        raise ValueError("--approve-dynamic requires --dynamic")
    return options, dynamic_request_from_options(options)


def _state_overlaps_skill(path: Path, state_dir: Path) -> bool:
    skill = Path(os.path.abspath(path.expanduser())).resolve(strict=False)
    state = Path(os.path.abspath(state_dir.expanduser())).resolve(strict=False)
    return state == skill or state.is_relative_to(skill)


def _print_terminal(report: Report, target: Path) -> None:
    print(f"Agent Skill Doctor: {report.result_state.replace('_', ' ')}")
    print(f"Job: {_terminal_safe(report.job_id)}")
    print(f"Snapshot: {_terminal_safe(report.snapshot_hash)}")
    if report.findings:
        suppressed = set(report.suppressed_finding_ids)
        blocking = set(report.blocking_finding_ids)
        for finding in report.findings:
            location = ""
            if finding.path:
                location = f" ({_terminal_safe(finding.path)}"
                if finding.line is not None:
                    location += f":{finding.line}"
                location += ")"
            marker = (
                "suppressed"
                if finding.id in suppressed
                else "blocking"
                if finding.id in blocking
                else "highlighted"
                if finding.confidence == "high"
                else "observation"
            )
            print(
                f"- [{marker}; {finding.severity}/{finding.confidence}] {finding.rule_id}: "
                f"{finding.title}{location}"
            )
    else:
        print("No deterministic issues were found within completed static checks.")
    if report.coverage.failed:
        print(f"Failed coverage: {', '.join(report.coverage.failed)}")
    if report.inventory is not None:
        raw_copies = report.inventory.get("copies", [])
        count = len(raw_copies) if isinstance(raw_copies, list) else 0
        print(f"Inventory: {count} discovered {report.platform or 'platform'} copies")
    if report.dynamic_test_plan is not None:
        plan = report.dynamic_test_plan
        cost = (
            "model cost unknown"
            if plan.estimated_model_cost_usd is None
            else f"estimated model cost ${plan.estimated_model_cost_usd:.4f}"
        )
        print(
            "Dynamic plan"
            f" ({'approval required' if plan.requires_approval else 'approved'}): "
            f"{plan.skill_count} skills, {plan.test_count} tests, "
            f"about {plan.estimated_seconds}s, {cost}"
        )
        if plan.approval_token is not None:
            print(f"Dynamic plan token: {plan.approval_token}")
    if report.sandbox_readiness is not None:
        print(f"Sandbox: {_terminal_safe(report.sandbox_readiness.get('detail', 'unavailable'))}")
    if report.dynamic_results:
        trial_count = sum(
            len(item.get("trials", []))
            for item in report.dynamic_results
            if isinstance(item.get("trials", []), list)
        )
        print(f"Dynamic results: {trial_count} actual-runtime trial(s)")
    if report.scope == "session":
        print(f"Session: {_terminal_safe(report.session_id or 'unavailable')}")
        for hypothesis in report.hypotheses:
            print(
                f"- [hypothesis {hypothesis.rank}/{hypothesis.confidence}] "
                f"{hypothesis.category}: {hypothesis.summary}"
            )
    if report.diagnostic_summary is not None:
        next_experiment = report.diagnostic_summary.get("smallest_useful_next_experiment")
        if isinstance(next_experiment, str):
            print(f"Next experiment: {_terminal_safe(next_experiment)}")
    if report.remediations:
        first = report.remediations[0]
        print(f"Remediation: {_terminal_safe(first.get('action', 'Review linked evidence.'))}")
    print("Limitation: static observations do not establish safety or root cause.")
    artifacts = report.artifacts or {"json": str(target)}
    for name, path in sorted(artifacts.items()):
        print(f"{name.upper()} report: {_terminal_safe(path)}")


def _render_result(result: ExecutionResult, json_output: bool) -> int:
    if result.report is None or result.target is None:
        return result.exit_code
    if json_output:
        print(json.dumps(result.report.to_dict(), indent=2, sort_keys=True))
    else:
        _print_terminal(result.report, result.target)
    return result.exit_code


def _preflight(path: Path, state_dir: Path, emitter: Emitter) -> bool:
    try:
        if _state_overlaps_skill(path, state_dir):
            message = "state directory must not be inside the skill being checked"
            emitter.emit("error", "Analysis incomplete", message)
            print(f"analysis incomplete: {message}", file=sys.stderr)
            return False
    except (OSError, ValueError) as error:
        emitter.emit("error", "Analysis incomplete", str(error))
        print(f"analysis incomplete: {_terminal_safe(error)}", file=sys.stderr)
        return False
    return True


def run_check(
    path: Path,
    state_dir: Path,
    json_output: bool,
    *,
    platform_name: Platform = "codex",
    dynamic_request: DynamicRequest | None = None,
) -> int:
    """Run directly in-process; normal CLI checks use the durable worker."""
    job_id = str(uuid.uuid4())
    created = now()
    preflight = Emitter(job_id)
    if not _preflight(path, state_dir, preflight):
        return 2
    try:
        store = LocalStore(state_dir)
        input_path = Path(os.path.abspath(path.expanduser()))
        store.start_job(job_id, created, _database_safe(input_path))
        emitter = Emitter(job_id, store)
    except (OSError, ValueError, sqlite3.Error, EncryptionUnavailable) as error:
        preflight.emit("error", "State readiness failed", str(error))
        print(f"analysis incomplete: {_terminal_safe(error)}", file=sys.stderr)
        return 2

    result = execute_check(
        job_id=job_id,
        created_at=created,
        path=path,
        store=store,
        emit=emitter.emit,
        cancelled=lambda: False,
        platform_name=platform_name,
        dynamic_request=dynamic_request,
    )
    return _render_result(result, json_output)


def run_discovered_check(
    *,
    platform_name: Platform,
    cwd: Path,
    selector: str | None,
    scope: Literal["named", "all"],
    state_dir: Path,
    json_output: bool,
    added_directories: tuple[Path, ...] = (),
    active_paths: tuple[Path, ...] = (),
    dynamic_request: DynamicRequest | None = None,
) -> int:
    """Run a discovery-aware check directly; normal CLI checks use the worker."""
    job_id = str(uuid.uuid4())
    created = now()
    preflight = Emitter(job_id)
    options: dict[str, Any] = {
        "scope": scope,
        "platform": platform_name,
        "added_directories": [str(path) for path in added_directories],
        "active_paths": [str(path) for path in active_paths],
    }
    if selector is not None:
        options["selector"] = selector
    try:
        store = LocalStore(state_dir)
        input_path = Path(os.path.abspath(cwd.expanduser()))
        store.start_job(job_id, created, _database_safe(input_path), options)
        emitter = Emitter(job_id, store)
    except (OSError, ValueError, sqlite3.Error, EncryptionUnavailable) as error:
        preflight.emit("error", "State readiness failed", str(error))
        print(f"analysis incomplete: {_terminal_safe(error)}", file=sys.stderr)
        return 2
    result = execute_discovered_check(
        job_id=job_id,
        created_at=created,
        platform_name=platform_name,
        cwd=cwd,
        selector=selector,
        scope=scope,
        store=store,
        emit=emitter.emit,
        cancelled=lambda: False,
        added_directories=added_directories,
        active_paths=active_paths,
        dynamic_request=dynamic_request,
    )
    return _render_result(result, json_output)


def run_session_diagnosis(
    *,
    platform_name: Platform,
    cwd: Path,
    state_dir: Path,
    json_output: bool,
    supplied_transcript: Path | None = None,
    flight_recorder: bool = False,
    added_directories: tuple[Path, ...] = (),
    active_paths: tuple[Path, ...] = (),
    dynamic_request: DynamicRequest | None = None,
) -> int:
    job_id = str(uuid.uuid4())
    created = now()
    preflight = Emitter(job_id)
    options: dict[str, Any] = {
        "scope": "session",
        "platform": platform_name,
        "transcript": None if supplied_transcript is None else str(supplied_transcript),
        "flight_recorder": flight_recorder,
        "added_directories": [str(path) for path in added_directories],
        "active_paths": [str(path) for path in active_paths],
    }
    try:
        store = LocalStore(state_dir)
        input_path = Path(os.path.abspath(cwd.expanduser()))
        store.start_job(job_id, created, _database_safe(input_path), options)
        emitter = Emitter(job_id, store)
    except (OSError, ValueError, sqlite3.Error, EncryptionUnavailable) as error:
        preflight.emit("error", "State readiness failed", str(error))
        print(f"analysis incomplete: {_terminal_safe(error)}", file=sys.stderr)
        return 2
    result = execute_session_diagnosis(
        job_id=job_id,
        created_at=created,
        platform_name=platform_name,
        cwd=cwd,
        store=store,
        emit=emitter.emit,
        cancelled=lambda: False,
        supplied_transcript=supplied_transcript,
        flight_recorder=flight_recorder,
        added_directories=added_directories,
        active_paths=active_paths,
        dynamic_request=dynamic_request,
    )
    return _render_result(result, json_output)


def _job_from_result(result: dict[str, Any]) -> dict[str, Any]:
    job = result.get("job")
    if not isinstance(job, dict):
        raise ValueError("worker response is missing a job object")
    return cast(dict[str, Any], job)


def _load_report(state_dir: Path, job: dict[str, Any]) -> tuple[Report, Path]:
    raw_path = job.get("report_path")
    job_id = job.get("id")
    if not isinstance(raw_path, str) or not isinstance(job_id, str):
        raise ValueError("completed job is missing its report path")
    reports = (state_dir.expanduser().absolute() / "reports").resolve(strict=True)
    target = Path(raw_path).resolve(strict=True)
    if not target.is_relative_to(reports) or target.name != f"{job_id}.json":
        raise ValueError("job report path escaped the local report directory")
    payload = json.loads(target.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("job report is not a JSON object")
    return Report.from_dict(cast(dict[str, Any], payload)), target


def _remote_failure(error: Exception) -> int:
    print(f"analysis incomplete: {_terminal_safe(error)}", file=sys.stderr)
    return 2


def _run_worker_check(
    path: Path,
    state_dir: Path,
    json_output: bool,
    *,
    options: dict[str, Any],
    explicit: bool,
) -> int:
    preflight = Emitter(str(uuid.uuid4()))
    if explicit and not _preflight(path, state_dir, preflight):
        return 2
    job_id: str | None = None
    try:
        submitted = worker_request(
            state_dir,
            "submit",
            {"path": str(path.expanduser().absolute()), "options": options},
        )
        job = _job_from_result(submitted)
        job_id = str(job["id"])
        sequence = 0
        while True:
            status = worker_request(
                state_dir,
                "status",
                {"job_id": job_id, "since": sequence},
            )
            events = status.get("events")
            if not isinstance(events, list):
                raise ValueError("worker status is missing events")
            for raw_event in events:
                if not isinstance(raw_event, dict):
                    raise ValueError("worker returned an invalid event")
                event = cast(dict[str, Any], raw_event)
                _write_event(event)
                sequence = max(sequence, int(event["sequence"]))
            job = _job_from_result(status)
            if job.get("status") in TERMINAL_STATUSES:
                break
            time.sleep(0.05)
    except KeyboardInterrupt:
        if job_id is not None:
            try:
                worker_request(state_dir, "cancel", {"job_id": job_id})
            except (IPCError, WorkerUnavailable):
                pass
        print("analysis cancelled", file=sys.stderr)
        return 4
    except (
        IPCError,
        WorkerUnavailable,
        EncryptionUnavailable,
        OSError,
        ValueError,
        KeyError,
        json.JSONDecodeError,
    ) as error:
        return _remote_failure(error)

    status_value = job.get("status")
    if status_value == "cancelled":
        return 4
    if status_value == "failed":
        return 3 if job.get("result_state") == "internal_error" else 2
    try:
        report, target = _load_report(state_dir, job)
    except (OSError, ValueError, KeyError, json.JSONDecodeError) as error:
        return _remote_failure(error)
    return _render_result(
        ExecutionResult(
            (
                2
                if report.result_state == "analysis_incomplete"
                else (1 if report.blocking_finding_ids else 0)
            ),
            report,
            target,
        ),
        json_output,
    )


def run_worker_check(
    path: Path,
    state_dir: Path,
    json_output: bool,
    *,
    options: dict[str, Any] | None = None,
) -> int:
    return _run_worker_check(
        path,
        state_dir,
        json_output,
        options={} if options is None else options,
        explicit=True,
    )


def run_worker_discovered_check(
    *,
    platform_name: Platform,
    cwd: Path,
    selector: str | None,
    scope: Literal["named", "all"],
    state_dir: Path,
    json_output: bool,
    added_directories: tuple[Path, ...] = (),
    active_paths: tuple[Path, ...] = (),
    dynamic_options: dict[str, Any] | None = None,
) -> int:
    options: dict[str, Any] = {
        "scope": scope,
        "platform": platform_name,
        "added_directories": [str(path.expanduser().absolute()) for path in added_directories],
        "active_paths": [str(path.expanduser().absolute()) for path in active_paths],
    }
    if selector is not None:
        options["selector"] = selector
    if dynamic_options:
        options.update(dynamic_options)
    return _run_worker_check(cwd, state_dir, json_output, options=options, explicit=False)


def run_worker_session_diagnosis(
    *,
    platform_name: Platform,
    cwd: Path,
    state_dir: Path,
    json_output: bool,
    supplied_transcript: Path | None = None,
    flight_recorder: bool = False,
    added_directories: tuple[Path, ...] = (),
    active_paths: tuple[Path, ...] = (),
    dynamic_options: dict[str, Any] | None = None,
) -> int:
    options: dict[str, Any] = {
        "scope": "session",
        "platform": platform_name,
        "transcript": (
            None
            if supplied_transcript is None
            else str(supplied_transcript.expanduser().absolute())
        ),
        "flight_recorder": flight_recorder,
        "added_directories": [str(path.expanduser().absolute()) for path in added_directories],
        "active_paths": [str(path.expanduser().absolute()) for path in active_paths],
    }
    if dynamic_options:
        options.update(dynamic_options)
    return _run_worker_check(cwd, state_dir, json_output, options=options, explicit=False)


def _print_job(job: dict[str, Any]) -> None:
    print(
        f"{_terminal_safe(job.get('id'))}  {job.get('status')}  "
        f"attempt={job.get('attempt')}  {job.get('result_state') or '-'}"
    )


def run_management(
    operation: str,
    state_dir: Path,
    params: dict[str, Any],
    json_output: bool,
) -> int:
    try:
        result = worker_request(state_dir, operation, params)
    except (IPCError, WorkerUnavailable, EncryptionUnavailable, OSError, ValueError) as error:
        return _remote_failure(error)
    if json_output:
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0
    if operation == "jobs":
        jobs = result.get("jobs")
        if not isinstance(jobs, list):
            return _remote_failure(ValueError("worker response is missing jobs"))
        for job in jobs:
            if isinstance(job, dict):
                _print_job(cast(dict[str, Any], job))
        return 0
    if operation == "purge_flight_recorder":
        deleted = result.get("deleted_records")
        print(f"Deleted {_terminal_safe(deleted)} flight-recorder record(s).")
        return 0
    job = _job_from_result(result)
    _print_job(job)
    if operation == "status":
        events = result.get("events", [])
        if isinstance(events, list):
            for event in events:
                if isinstance(event, dict):
                    print(f"  {event.get('sequence')}: {event.get('summary')}")
                    if params.get("verbose") and event.get("detail") is not None:
                        print(f"    {_terminal_safe(event.get('detail'))}")
    return 0


def run_feedback(
    *,
    state_dir: Path,
    job_id: str,
    finding_id: str,
    disposition: str,
    reason: str | None,
    json_output: bool,
) -> int:
    try:
        store = LocalStore(state_dir)
        record = store.record_finding_feedback(
            job_id=job_id,
            finding_id=finding_id,
            disposition=disposition,
            reason=reason,
        )
    except (EncryptionUnavailable, OSError, StoreError, ValueError) as error:
        return _remote_failure(error)
    if json_output:
        print(json.dumps(record, indent=2, sort_keys=True))
    else:
        print(f"Recorded {_terminal_safe(disposition)} feedback for {_terminal_safe(finding_id)}.")
    return 0


def run_export(
    *,
    state_dir: Path,
    job_id: str,
    approval_token: str | None,
    json_output: bool,
) -> int:
    try:
        store = LocalStore(state_dir)
        job = store.get_job(job_id)
        if job is None or job.report_path is None:
            raise StoreError("completed export job was not found")
        report, _ = _load_report(state_dir, asdict(job))
        plan = plan_export(report.to_dict())
        if approval_token is None:
            if json_output:
                print(json.dumps(plan.preview, indent=2, sort_keys=True))
            else:
                print("Sanitized export preview:")
                for name, size in cast(dict[str, int], plan.preview["file_sizes"]).items():
                    print(f"- {_terminal_safe(name)}: {size} bytes")
                print("Redactions: " + ", ".join(cast(list[str], plan.preview["redactions"])))
                print(f"Export approval token: {plan.approval_token}")
            return 0
        target = state_dir.expanduser().absolute() / "exports" / f"{job_id}.zip"
        written = write_export(plan, approval_token, target)
    except (
        EncryptionUnavailable,
        ExportError,
        OSError,
        StoreError,
        ValueError,
        json.JSONDecodeError,
    ) as error:
        return _remote_failure(error)
    if json_output:
        print(json.dumps({"export_path": str(written)}, indent=2, sort_keys=True))
    else:
        print(f"Sanitized export: {_terminal_safe(written)}")
    return 0


def run_rules(
    *,
    state_dir: Path,
    action: str,
    source: str | None,
    approval_token: str | None,
    json_output: bool,
) -> int:
    try:
        manager = RulePackManager(state_dir)
        payload: dict[str, Any]
        if action == "status":
            active = manager.load_active()
            payload = {
                "mode": "embedded_offline_baseline" if active is None else "signed_rule_pack",
                "active": None if active is None else asdict(active),
                **manager.status(),
            }
        elif action == "rollback":
            payload = {"active": asdict(manager.rollback())}
        elif action == "pin":
            if source is None:
                raise SupplyChainError("rules pin requires a rule-pack version")
            manager.pin(source)
            payload = {"pinned": source}
        elif action == "unpin":
            if source is not None:
                raise SupplyChainError("rules unpin does not accept a source")
            manager.pin(None)
            payload = {"pinned": None}
        elif action == "configure-auto":
            if source is None:
                raise SupplyChainError("rules configure-auto requires an HTTPS feed URL")
            if approval_token is None:
                payload = manager.plan_feed(source)
            else:
                manager.configure_feed(source, approval_token)
                payload = manager.status()
        elif action == "disable-auto":
            if source is not None:
                raise SupplyChainError("rules disable-auto does not accept a source")
            manager.disable_feed()
            payload = manager.status()
        else:
            if source is None:
                raise SupplyChainError(f"rules {action} requires a signed source")
            document = (
                manager.fetch(source)
                if action == "update"
                else Path(source).expanduser().read_bytes()
            )
            plan = manager.plan(document)
            if action == "plan" or approval_token is None:
                payload = asdict(plan)
            else:
                payload = {"active": asdict(manager.install(document, approval_token))}
        if json_output:
            print(json.dumps(payload, indent=2, sort_keys=True))
        else:
            print(json.dumps(payload, indent=2, sort_keys=True))
        return 0
    except (OSError, SupplyChainError, ValueError) as error:
        return _remote_failure(error)


def run_bootstrap(
    *,
    state_dir: Path,
    manifest: Path,
    target_platform: str | None,
    architecture: str | None,
    approval_token: str | None,
    json_output: bool,
) -> int:
    try:
        document = manifest.expanduser().read_bytes()
        if approval_token is None:
            payload = asdict(
                plan_bootstrap(
                    document,
                    target_platform=target_platform,
                    architecture=architecture,
                )
            )
        else:
            payload = install_bootstrap(
                document,
                approval_token=approval_token,
                state_dir=state_dir,
                target_platform=target_platform,
                architecture=architecture,
            )
    except (OSError, SupplyChainError, ValueError) as error:
        return _remote_failure(error)
    print(json.dumps(payload, indent=2, sort_keys=True))
    return 0


def run_telemetry(
    *,
    state_dir: Path,
    action: str,
    endpoint: str | None,
    approval_token: str | None,
) -> int:
    try:
        manager = TelemetryManager(state_dir)
        if action == "status":
            if endpoint is not None:
                raise TelemetryError("telemetry status does not accept an endpoint")
            payload = manager.status()
        elif action == "disable":
            if endpoint is not None:
                raise TelemetryError("telemetry disable does not accept an endpoint")
            manager.disable()
            payload = manager.status()
        else:
            if endpoint is None:
                raise TelemetryError("telemetry enable requires an HTTPS endpoint")
            if approval_token is None:
                payload = manager.plan_enable(endpoint)
            else:
                manager.enable(endpoint, approval_token)
                payload = manager.status()
    except (OSError, TelemetryError, ValueError) as error:
        return _remote_failure(error)
    print(json.dumps(payload, indent=2, sort_keys=True))
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    arguments = parser().parse_args(argv)
    if arguments.command == "check":
        if arguments.all and arguments.target is not None:
            print("check --all does not accept a target", file=sys.stderr)
            return 2
        if not arguments.all and arguments.target is None:
            print("check requires a local directory, skill selector, or --all", file=sys.stderr)
            return 2
        added_directories = tuple(arguments.add_dir)
        active_paths = tuple(arguments.active_path)
        platform_name = cast(Platform, arguments.platform)
        try:
            dynamic_options, dynamic_request = _parse_dynamic_request(arguments)
        except ValueError as error:
            print(f"invalid dynamic options: {_terminal_safe(error)}", file=sys.stderr)
            return 2
        if arguments.all:
            if arguments.direct:
                return run_discovered_check(
                    platform_name=platform_name,
                    cwd=arguments.cwd,
                    selector=None,
                    scope="all",
                    state_dir=arguments.state_dir,
                    json_output=arguments.json,
                    added_directories=added_directories,
                    active_paths=active_paths,
                    dynamic_request=dynamic_request,
                )
            return run_worker_discovered_check(
                platform_name=platform_name,
                cwd=arguments.cwd,
                selector=None,
                scope="all",
                state_dir=arguments.state_dir,
                json_output=arguments.json,
                added_directories=added_directories,
                active_paths=active_paths,
                dynamic_options=dynamic_options,
            )
        target = str(arguments.target)
        target_path = Path(target)
        explicit = (
            target_path.exists()
            or target_path.is_absolute()
            or target in {".", ".."}
            or "/" in target
            or "\\" in target
        )
        if explicit:
            if arguments.direct:
                return run_check(
                    target_path,
                    arguments.state_dir,
                    arguments.json,
                    platform_name=platform_name,
                    dynamic_request=dynamic_request,
                )
            return run_worker_check(
                target_path,
                arguments.state_dir,
                arguments.json,
                options={"platform": platform_name, **dynamic_options},
            )
        if arguments.direct:
            return run_discovered_check(
                platform_name=platform_name,
                cwd=arguments.cwd,
                selector=target,
                scope="named",
                state_dir=arguments.state_dir,
                json_output=arguments.json,
                added_directories=added_directories,
                active_paths=active_paths,
                dynamic_request=dynamic_request,
            )
        return run_worker_discovered_check(
            platform_name=platform_name,
            cwd=arguments.cwd,
            selector=target,
            scope="named",
            state_dir=arguments.state_dir,
            json_output=arguments.json,
            added_directories=added_directories,
            active_paths=active_paths,
            dynamic_options=dynamic_options,
        )
    if arguments.command == "diagnose":
        platform_name = cast(Platform, arguments.platform)
        added_directories = tuple(arguments.add_dir)
        active_paths = tuple(arguments.active_path)
        try:
            dynamic_options, dynamic_request = _parse_dynamic_request(arguments)
        except ValueError as error:
            print(f"invalid dynamic options: {_terminal_safe(error)}", file=sys.stderr)
            return 2
        if arguments.direct:
            return run_session_diagnosis(
                platform_name=platform_name,
                cwd=arguments.cwd,
                state_dir=arguments.state_dir,
                json_output=arguments.json,
                supplied_transcript=arguments.transcript,
                flight_recorder=arguments.flight_recorder,
                added_directories=added_directories,
                active_paths=active_paths,
                dynamic_request=dynamic_request,
            )
        return run_worker_session_diagnosis(
            platform_name=platform_name,
            cwd=arguments.cwd,
            state_dir=arguments.state_dir,
            json_output=arguments.json,
            supplied_transcript=arguments.transcript,
            flight_recorder=arguments.flight_recorder,
            added_directories=added_directories,
            active_paths=active_paths,
            dynamic_options=dynamic_options,
        )
    if arguments.command == "jobs":
        return run_management(
            "jobs", arguments.state_dir, {"limit": arguments.limit}, arguments.json
        )
    if arguments.command == "status":
        return run_management(
            "status",
            arguments.state_dir,
            {
                "job_id": arguments.job_id,
                "since": arguments.since,
                "verbose": arguments.verbose,
            },
            arguments.json,
        )
    if arguments.command in {"cancel", "resume"}:
        return run_management(
            arguments.command,
            arguments.state_dir,
            {"job_id": arguments.job_id},
            arguments.json,
        )
    if arguments.command == "purge":
        return run_management(
            "purge_flight_recorder",
            arguments.state_dir,
            {},
            arguments.json,
        )
    if arguments.command == "readiness":
        payload = readiness_report(arguments.state_dir, deep=arguments.deep)
        if arguments.json:
            print(json.dumps(payload, indent=2, sort_keys=True))
        else:
            sandbox = cast(dict[str, Any], payload["sandbox"])
            print(f"Dynamic execution: {payload['dynamic_execution_policy']}")
            print(f"Sandbox: {_terminal_safe(sandbox.get('detail', 'unavailable'))}")
            for runtime, status in cast(dict[str, dict[str, Any]], payload["runtimes"]).items():
                print(f"{runtime}: {_terminal_safe(status.get('version') or 'unavailable')}")
        return 0 if payload["dynamic_execution_policy"] == "sandbox_only" else 2
    if arguments.command == "feedback":
        return run_feedback(
            state_dir=arguments.state_dir,
            job_id=arguments.job_id,
            finding_id=arguments.finding_id,
            disposition=arguments.disposition,
            reason=arguments.reason,
            json_output=arguments.json,
        )
    if arguments.command == "export":
        return run_export(
            state_dir=arguments.state_dir,
            job_id=arguments.job_id,
            approval_token=arguments.approve,
            json_output=arguments.json,
        )
    if arguments.command == "rules":
        return run_rules(
            state_dir=arguments.state_dir,
            action=arguments.action,
            source=arguments.source,
            approval_token=arguments.approve,
            json_output=arguments.json,
        )
    if arguments.command == "bootstrap":
        return run_bootstrap(
            state_dir=arguments.state_dir,
            manifest=arguments.manifest,
            target_platform=arguments.platform,
            architecture=arguments.architecture,
            approval_token=arguments.approve,
            json_output=arguments.json,
        )
    if arguments.command == "telemetry":
        return run_telemetry(
            state_dir=arguments.state_dir,
            action=arguments.action,
            endpoint=arguments.endpoint,
            approval_token=arguments.approve,
        )
    return 2
