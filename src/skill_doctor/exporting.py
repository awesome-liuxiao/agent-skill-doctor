from __future__ import annotations

import hashlib
import json
import re
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, cast

from skill_doctor.reporting import render_html_report, render_junit_report, render_sarif_report

WINDOWS_PATH = re.compile(r"(?i)(?:[a-z]:\\|\\\\)[^\r\n\t\"'<>]+")
POSIX_PATH = re.compile(r"(?<![A-Za-z0-9])/(?:[^\s/<>]+/)+[^\s\"'<>]*")


class ExportError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class ExportPlan:
    approval_token: str
    preview: dict[str, Any]
    files: dict[str, bytes]


def _redact_text(value: str) -> str:
    return POSIX_PATH.sub("<redacted-path>", WINDOWS_PATH.sub("<redacted-path>", value))


def _redact_nested(value: object) -> object:
    if isinstance(value, str):
        return _redact_text(value)
    if isinstance(value, list):
        return [_redact_nested(item) for item in value]
    if isinstance(value, dict):
        return {str(key): _redact_nested(item) for key, item in value.items()}
    return value


def sanitized_report(report: dict[str, Any]) -> dict[str, Any]:
    payload = cast(dict[str, Any], _redact_nested(report))
    payload["input_path"] = "<redacted-path>"
    payload["artifacts"] = None
    payload["dynamic_results"] = [
        {
            "skill_name": item.get("skill_name"),
            "snapshot_hash": item.get("snapshot_hash"),
            "trial_summary": [
                {
                    "case_id": trial.get("case_id"),
                    "repetition": trial.get("repetition"),
                    "control": trial.get("control"),
                    "passed": trial.get("passed"),
                    "duration_ms": trial.get("duration_ms"),
                    "timed_out": trial.get("timed_out"),
                }
                for trial in item.get("trials", [])
                if isinstance(trial, dict)
            ],
        }
        for item in report.get("dynamic_results", [])
        if isinstance(item, dict)
    ]
    for evidence in payload.get("evidence", []):
        if isinstance(evidence, dict):
            evidence["artifact_hash"] = None
            evidence["path"] = None
    for finding in payload.get("findings", []):
        if isinstance(finding, dict):
            finding["path"] = None
    inventory = report.get("inventory")
    if isinstance(inventory, dict):
        copies = inventory.get("copies")
        payload["inventory"] = {
            "copy_count": len(copies) if isinstance(copies, list) else 0,
            "platform": inventory.get("platform"),
        }
    payload["collection_manifest"] = [
        {**item, "path": None}
        for item in payload.get("collection_manifest", [])
        if isinstance(item, dict)
    ]
    environment = payload.get("session_environment")
    if isinstance(environment, dict):
        environment.pop("cwd", None)
        environment.pop("configuration_sources", None)
    audit = payload.get("suppression_audit")
    if isinstance(audit, dict):
        payload["suppression_audit"] = {
            "policy": audit.get("policy"),
            "active_count": len(audit.get("active", [])),
            "stale_count": len(audit.get("stale", [])),
            "expired_count": len(audit.get("expired", [])),
            "unmatched_count": len(audit.get("unmatched", [])),
        }
    return payload


def plan_export(report: dict[str, Any]) -> ExportPlan:
    sanitized = sanitized_report(report)
    files = {
        "report.json": (json.dumps(sanitized, indent=2, sort_keys=True) + "\n").encode("utf-8"),
        "report.html": render_html_report(sanitized),
        "report.sarif.json": render_sarif_report(sanitized),
        "report.junit.xml": render_junit_report(sanitized),
    }
    manifest = {
        "version": 1,
        "job_id": report.get("job_id"),
        "files": {name: hashlib.sha256(data).hexdigest() for name, data in sorted(files.items())},
        "redactions": [
            "absolute paths",
            "raw dynamic output and artifact hashes",
            "full inventory and configuration source paths",
            "collection source paths",
            "suppression reasons and source paths",
        ],
        "excluded": ["raw prompts", "raw traces", "credentials", "encrypted local artifacts"],
    }
    manifest_bytes = (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode("utf-8")
    files["manifest.json"] = manifest_bytes
    token = hashlib.sha256(
        b"".join(name.encode() + b"\0" + data for name, data in sorted(files.items()))
    ).hexdigest()
    preview = {
        **manifest,
        "file_sizes": {name: len(data) for name, data in sorted(files.items())},
        "approval_token": token,
        "requires_explicit_consent": True,
    }
    return ExportPlan(token, preview, files)


def write_export(plan: ExportPlan, approval_token: str, target: Path) -> Path:
    if approval_token != plan.approval_token:
        raise ExportError("export approval token does not match the current sanitized preview")
    target.parent.mkdir(parents=True, exist_ok=True)
    temporary = target.with_suffix(target.suffix + ".tmp")
    try:
        with zipfile.ZipFile(temporary, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            for name, data in sorted(plan.files.items()):
                info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
                info.compress_type = zipfile.ZIP_DEFLATED
                info.external_attr = 0o600 << 16
                archive.writestr(info, data)
        temporary.replace(target)
    finally:
        temporary.unlink(missing_ok=True)
    return target
