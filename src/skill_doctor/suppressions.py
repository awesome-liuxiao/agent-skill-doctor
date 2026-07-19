from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, cast

from skill_doctor.models import Finding

MAX_SUPPRESSION_BYTES = 1024 * 1024


class SuppressionError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class Suppression:
    id: str
    rule_id: str
    finding_id: str | None
    reason: str
    created_at: str
    expires_at: str
    snapshot_hash: str
    ruleset_version: str
    source: str


@dataclass(frozen=True, slots=True)
class SuppressionOutcome:
    suppressed_finding_ids: tuple[str, ...]
    blocking_finding_ids: tuple[str, ...]
    audit: dict[str, Any]


def _timestamp(value: object, field: str) -> datetime:
    if not isinstance(value, str):
        raise SuppressionError(f"suppression {field} must be a timestamp")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise SuppressionError(f"suppression {field} is invalid") from error
    if parsed.tzinfo is None:
        raise SuppressionError(f"suppression {field} must include a timezone")
    return parsed.astimezone(UTC)


def _project_path(root: Path) -> Path | None:
    resolved = root.resolve(strict=False)
    for candidate_root in (resolved, *resolved.parents):
        candidate = candidate_root / ".skill-doctor" / "suppressions.json"
        if candidate.is_file():
            return candidate
    return None


def _read(path: Path, scope: str) -> list[Suppression]:
    try:
        data = path.read_bytes()
    except OSError as error:
        raise SuppressionError(f"cannot read suppressions: {error}") from error
    if len(data) > MAX_SUPPRESSION_BYTES:
        raise SuppressionError("suppression file exceeds the 1 MB limit")
    try:
        payload = json.loads(data)
    except (UnicodeError, json.JSONDecodeError) as error:
        raise SuppressionError(f"invalid suppression JSON: {error}") from error
    if not isinstance(payload, dict) or payload.get("version") != 1:
        raise SuppressionError("suppression file must be a version 1 object")
    if set(payload) != {"version", "suppressions"}:
        raise SuppressionError("suppression file contains unknown fields")
    raw_items = payload.get("suppressions")
    if not isinstance(raw_items, list) or len(raw_items) > 10_000:
        raise SuppressionError("suppressions must be a bounded array")
    items: list[Suppression] = []
    required = {
        "id",
        "rule_id",
        "reason",
        "created_at",
        "expires_at",
        "snapshot_hash",
        "ruleset_version",
    }
    for raw in raw_items:
        if not isinstance(raw, dict):
            raise SuppressionError("suppression entry must be an object")
        item = cast(dict[str, Any], raw)
        if set(item) not in (required, required | {"finding_id"}):
            raise SuppressionError("suppression entry has missing or unknown fields")
        for field in required - {"created_at", "expires_at"}:
            if not isinstance(item.get(field), str) or not str(item[field]).strip():
                raise SuppressionError(f"suppression {field} must be a non-empty string")
        created = _timestamp(item["created_at"], "created_at")
        expires = _timestamp(item["expires_at"], "expires_at")
        if expires <= created:
            raise SuppressionError("suppression expiry must follow creation")
        finding_id = item.get("finding_id")
        if finding_id is not None and (not isinstance(finding_id, str) or not finding_id.strip()):
            raise SuppressionError("suppression finding_id must be a non-empty string")
        items.append(
            Suppression(
                str(item["id"]),
                str(item["rule_id"]),
                None if finding_id is None else finding_id,
                str(item["reason"]),
                str(item["created_at"]),
                str(item["expires_at"]),
                str(item["snapshot_hash"]),
                str(item["ruleset_version"]),
                f"{scope}:{path}",
            )
        )
    return items


def resolve_suppressions(
    *,
    findings: list[Finding],
    root: Path,
    snapshot_hash: str,
    ruleset_version: str,
    flagged_finding_ids: set[str] | None = None,
    home: Path | None = None,
    current_time: datetime | None = None,
) -> SuppressionOutcome:
    user_path = (Path.home() if home is None else home) / ".skill-doctor" / "suppressions.json"
    project_path = _project_path(root)
    by_id: dict[str, Suppression] = {}
    for path, scope in ((user_path, "user"), (project_path, "project")):
        if path is None or not path.is_file():
            continue
        for item in _read(path, scope):
            by_id[item.id] = item
    now = datetime.now(UTC) if current_time is None else current_time.astimezone(UTC)
    active: list[dict[str, Any]] = []
    stale: list[dict[str, Any]] = []
    expired: list[dict[str, Any]] = []
    unmatched: list[dict[str, Any]] = []
    suppressed: set[str] = set()
    for item in by_id.values():
        payload = asdict(item)
        if _timestamp(item.expires_at, "expires_at") <= now:
            expired.append(payload)
            continue
        stale_reasons = []
        if item.snapshot_hash != snapshot_hash:
            stale_reasons.append("snapshot_hash_changed")
        if item.ruleset_version != ruleset_version:
            stale_reasons.append("ruleset_version_changed")
        if stale_reasons:
            stale.append({**payload, "stale_reasons": stale_reasons})
            continue
        matches = [
            finding.id
            for finding in findings
            if finding.rule_id == item.rule_id
            and (item.finding_id is None or finding.id == item.finding_id)
        ]
        if not matches:
            unmatched.append(payload)
            continue
        active.append({**payload, "matched_finding_ids": matches})
        suppressed.update(matches)
    blocking = [
        finding.id
        for finding in findings
        if finding.id not in suppressed
        and (flagged_finding_ids is None or finding.id in flagged_finding_ids)
        and finding.severity in {"high", "critical"}
        and finding.confidence == "high"
    ]
    return SuppressionOutcome(
        tuple(sorted(suppressed)),
        tuple(blocking),
        {
            "policy": "Only unsuppressed high-severity, high-confidence findings block CI.",
            "active": active,
            "stale": stale,
            "expired": expired,
            "unmatched": unmatched,
        },
    )
