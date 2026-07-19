from __future__ import annotations

import json
import os
import re
from collections import Counter
from collections.abc import Mapping
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Literal, cast

from skill_doctor.discovery import Platform

MAX_TRACE_BYTES = 50 * 1024 * 1024
MAX_TRACE_LINES = 100_000
MAX_TRACE_LINE_BYTES = 2 * 1024 * 1024
MAX_SIGNAL_TEXT_CHARS = 200_000

EvidenceConfidence = Literal["high", "reduced"]
INVOCATION = re.compile(r"(?<![\w./\\])([$/])([a-z0-9][a-z0-9:-]{0,127})", re.I)
SKILL_PATH = re.compile(
    r"(?i)(?:^|[\s\"'])(?:[^\s\"']+[/\\])?([a-z0-9][a-z0-9_-]{0,127})"
    r"[/\\]SKILL\.md\b"
)
USING_SKILL = re.compile(
    r"(?i)\b(?:using|use|invoke[ds]?)\s+(?:the\s+)?"
    r"([a-z0-9][a-z0-9:-]*)\s+skill\b"
)
TOKEN = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{2,}")
STOPWORDS = frozenset(
    {
        "and",
        "are",
        "for",
        "from",
        "have",
        "into",
        "that",
        "the",
        "this",
        "use",
        "using",
        "with",
        "your",
    }
)


class SessionEvidenceError(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class CollectionItem:
    kind: str
    path: str | None
    bytes: int | None
    collected: bool
    confidence: EvidenceConfidence
    reason: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class SessionSource:
    platform: Platform
    path: Path | None
    session_id: str | None
    confidence: EvidenceConfidence
    reason: str

    def collection_item(self) -> CollectionItem:
        size: int | None = None
        if self.path is not None:
            try:
                size = self.path.stat().st_size
            except OSError:
                size = None
        collected = self.path is not None and size is not None
        reason = self.reason if collected else f"{self.reason}; source is unavailable"
        return CollectionItem(
            "native_session_trace" if self.path is not None else "session_trace",
            None if self.path is None else str(self.path),
            size,
            collected,
            self.confidence,
            reason,
        )


@dataclass(slots=True)
class SessionEvidence:
    platform: Platform
    session_id: str | None
    source_path: Path
    confidence: EvidenceConfidence
    cwd: Path | None = None
    runtime_version: str | None = None
    model: str | None = None
    permission_mode: str | None = None
    sandbox_mode: str | None = None
    invoked_selectors: set[str] = field(default_factory=set)
    explicit_invocations: set[str] = field(default_factory=set)
    accessed_skill_directories: set[str] = field(default_factory=set)
    tool_names: set[str] = field(default_factory=set)
    error_categories: Counter[str] = field(default_factory=Counter)
    timing_ms: dict[str, list[float]] = field(default_factory=dict)
    prompt_terms: set[str] = field(default_factory=set, repr=False)
    line_count: int = 0
    parse_errors: int = 0
    changed_during_collection: bool = False

    def environment_dict(self) -> dict[str, Any]:
        timings = {
            key: {
                "count": len(values),
                "total_ms": round(sum(values), 3),
                "max_ms": round(max(values), 3),
            }
            for key, values in sorted(self.timing_ms.items())
            if values
        }
        return {
            "platform": self.platform,
            "session_id": self.session_id,
            "cwd": None if self.cwd is None else str(self.cwd),
            "runtime_version": self.runtime_version,
            "model": self.model,
            "permission_mode": self.permission_mode,
            "sandbox_mode": self.sandbox_mode,
            "tool_names": sorted(self.tool_names),
            "timings": timings,
            "error_categories": dict(sorted(self.error_categories.items())),
            "trace_confidence": self.confidence,
            "trace_lines": self.line_count,
            "parse_errors": self.parse_errors,
            "changed_during_collection": self.changed_during_collection,
        }


def _latest(paths: list[Path]) -> Path | None:
    candidates: list[tuple[int, str, Path]] = []
    for path in paths:
        try:
            candidates.append((path.stat().st_mtime_ns, str(path), path))
        except OSError:
            continue
    return max(candidates, default=(0, "", None))[2]


def locate_session_source(
    platform: Platform,
    *,
    supplied_transcript: Path | None = None,
    home: Path | None = None,
    environment: Mapping[str, str] | None = None,
) -> SessionSource:
    env = os.environ if environment is None else environment
    user_home = Path.home() if home is None else home
    if supplied_transcript is not None:
        path = supplied_transcript.expanduser().absolute()
        return SessionSource(platform, path, None, "reduced", "explicit visible transcript")

    if platform == "codex":
        session_id = env.get("CODEX_THREAD_ID")
        root = user_home / ".codex" / "sessions"
        exact = [] if not session_id else list(root.rglob(f"*{session_id}*.jsonl"))
        exact_path = _latest(exact)
        if exact_path is not None:
            return SessionSource(
                platform, exact_path, session_id, "high", "matched CODEX_THREAD_ID"
            )
        fallback = _latest(list(root.rglob("*.jsonl"))) if root.is_dir() else None
        return SessionSource(
            platform,
            fallback,
            session_id,
            "reduced",
            "latest Codex session trace; no exact current-session match",
        )

    session_id = env.get("CLAUDE_SESSION_ID")
    root = user_home / ".claude" / "projects"
    exact = [] if not session_id else list(root.rglob(f"{session_id}.jsonl"))
    exact_path = _latest(exact)
    if exact_path is not None:
        return SessionSource(platform, exact_path, session_id, "high", "matched CLAUDE_SESSION_ID")
    fallback = _latest(list(root.rglob("*.jsonl"))) if root.is_dir() else None
    return SessionSource(
        platform,
        fallback,
        session_id,
        "reduced",
        "latest Claude session transcript; no exact current-session match",
    )


def _bounded_strings(value: object, *, depth: int = 0) -> list[str]:
    if depth > 5:
        return []
    if isinstance(value, str):
        return [value[:MAX_SIGNAL_TEXT_CHARS]]
    if isinstance(value, list):
        result: list[str] = []
        for item in value[:1_000]:
            result.extend(_bounded_strings(item, depth=depth + 1))
            if sum(len(text) for text in result) >= MAX_SIGNAL_TEXT_CHARS:
                break
        return result
    if isinstance(value, dict):
        result = []
        for key, item in list(value.items())[:1_000]:
            if key in {"encrypted_content", "thinking", "signature"}:
                continue
            result.extend(_bounded_strings(item, depth=depth + 1))
            if sum(len(text) for text in result) >= MAX_SIGNAL_TEXT_CHARS:
                break
        return result
    return []


def _record_text(evidence: SessionEvidence, text: str, *, user_prompt: bool = False) -> None:
    bounded = text[:MAX_SIGNAL_TEXT_CHARS]
    for match in INVOCATION.finditer(bounded):
        selector = match.group(2).lower()
        evidence.invoked_selectors.add(selector)
        if match.group(1) == "$":
            evidence.explicit_invocations.add(selector)
    for match in USING_SKILL.finditer(bounded):
        selector = match.group(1).lower()
        evidence.invoked_selectors.add(selector)
        evidence.explicit_invocations.add(selector)
    evidence.accessed_skill_directories.update(
        match.group(1).lower() for match in SKILL_PATH.finditer(bounded)
    )
    _record_error_text(evidence, bounded)
    if user_prompt:
        evidence.prompt_terms = {
            token.casefold()
            for token in TOKEN.findall(bounded)
            if token.casefold() not in STOPWORDS
        }


def _record_error_text(evidence: SessionEvidence, text: str) -> None:
    lowered = text.casefold()
    if any(token in lowered for token in ("permission denied", "not permitted", "approval denied")):
        evidence.error_categories["permission"] += 1
    if any(
        token in lowered for token in ("module not found", "command not found", "not recognized")
    ):
        evidence.error_categories["dependency"] += 1
    if any(token in lowered for token in ("traceback", "exception", "internal error", " failed")):
        evidence.error_categories["runtime"] += 1


def _record_tool_input(evidence: SessionEvidence, text: str) -> None:
    bounded = text[:MAX_SIGNAL_TEXT_CHARS]
    evidence.accessed_skill_directories.update(
        match.group(1).lower() for match in SKILL_PATH.finditer(bounded)
    )


def _record_timing(evidence: SessionEvidence, category: str, raw: object) -> None:
    if isinstance(raw, int | float) and 0 <= raw <= 86_400_000:
        evidence.timing_ms.setdefault(category, []).append(float(raw))


def _collect_codex(evidence: SessionEvidence, record: dict[str, Any]) -> None:
    record_type = record.get("type")
    payload = record.get("payload")
    if not isinstance(payload, dict):
        return
    item = cast(dict[str, Any], payload)
    if record_type == "session_meta":
        evidence.session_id = str(item.get("id") or item.get("session_id") or evidence.session_id)
        if isinstance(item.get("cwd"), str):
            evidence.cwd = Path(str(item["cwd"]))
        if isinstance(item.get("cli_version"), str):
            evidence.runtime_version = str(item["cli_version"])
        return
    if record_type == "turn_context":
        if isinstance(item.get("cwd"), str):
            evidence.cwd = Path(str(item["cwd"]))
        if isinstance(item.get("model"), str):
            evidence.model = str(item["model"])
        permission = item.get("approval_policy") or item.get("permission_mode")
        if isinstance(permission, str):
            evidence.permission_mode = permission
        sandbox = item.get("sandbox_policy") or item.get("sandbox_mode")
        if isinstance(sandbox, dict):
            sandbox = sandbox.get("type") or sandbox.get("mode")
        if isinstance(sandbox, str):
            evidence.sandbox_mode = sandbox
        return
    if record_type == "event_msg":
        event_type = str(item.get("type", ""))
        _record_timing(evidence, event_type, item.get("duration_ms"))
        if event_type in {"user_message", "agent_message"}:
            for text in _bounded_strings(item.get("message") or item.get("text")):
                _record_text(evidence, text, user_prompt=event_type == "user_message")
        if event_type in {"task_complete", "mcp_tool_call_end"} and item.get("success") is False:
            evidence.error_categories["runtime"] += 1
        return
    if record_type != "response_item":
        return
    item_type = str(item.get("type", ""))
    name = item.get("name")
    if isinstance(name, str):
        evidence.tool_names.add(name)
    if item_type in {"custom_tool_call", "function_call"}:
        for text in _bounded_strings(item.get("arguments") or item.get("input")):
            _record_tool_input(evidence, text)
    elif item_type in {"custom_tool_call_output", "function_call_output"}:
        for text in _bounded_strings(item.get("output")):
            _record_error_text(evidence, text)
    elif item_type == "message":
        role = str(item.get("role", ""))
        if role not in {"assistant", "user"}:
            return
        for text in _bounded_strings(item.get("content")):
            _record_text(evidence, text, user_prompt=role == "user")


def _collect_claude(evidence: SessionEvidence, record: dict[str, Any]) -> None:
    session_id = record.get("sessionId") or record.get("session_id")
    if isinstance(session_id, str):
        evidence.session_id = session_id
    if isinstance(record.get("cwd"), str):
        evidence.cwd = Path(str(record["cwd"]))
    version = record.get("version") or record.get("claudeCodeVersion")
    if isinstance(version, str):
        evidence.runtime_version = version
    if isinstance(record.get("model"), str):
        evidence.model = str(record["model"])
    permission = record.get("permissionMode") or record.get("permission_mode")
    if isinstance(permission, str):
        evidence.permission_mode = permission

    record_type = str(record.get("type", ""))
    message = record.get("message")
    role = record_type
    if isinstance(message, dict) and isinstance(message.get("role"), str):
        role = str(message["role"])
    if role in {"user", "assistant"} and (
        record_type in {"user", "assistant"} or isinstance(message, dict)
    ):
        for text in _bounded_strings(message):
            _record_text(evidence, text, user_prompt=role == "user")

    for container in (message, record):
        if not isinstance(container, dict):
            continue
        content = container.get("content")
        if not isinstance(content, list):
            continue
        for item in content:
            if not isinstance(item, dict) or item.get("type") not in {"tool_use", "tool_result"}:
                continue
            name = item.get("name")
            if isinstance(name, str):
                evidence.tool_names.add(name)
            if name == "Skill" and isinstance(item.get("input"), dict):
                skill = cast(dict[str, Any], item["input"]).get("skill")
                if isinstance(skill, str):
                    selector = skill.removeprefix("/").casefold()
                    evidence.invoked_selectors.add(selector)
                    evidence.explicit_invocations.add(selector)
            for text in _bounded_strings(item.get("input")):
                _record_tool_input(evidence, text)
            if item.get("is_error") is True:
                evidence.error_categories["runtime"] += 1

    duration = record.get("durationMs") or record.get("duration_ms")
    _record_timing(evidence, record_type or "event", duration)


def collect_session_evidence(source: SessionSource) -> SessionEvidence:
    if source.path is None:
        raise SessionEvidenceError("no current-session transcript is available")
    path = source.path
    try:
        before = path.stat()
    except OSError as error:
        raise SessionEvidenceError(f"cannot inspect session transcript: {error}") from error
    if before.st_size > MAX_TRACE_BYTES:
        raise SessionEvidenceError("session transcript exceeds the 50 MB collection limit")

    evidence = SessionEvidence(source.platform, source.session_id, path, source.confidence)
    total = 0
    try:
        with path.open("rb") as stream:
            for line_number, raw in enumerate(stream, start=1):
                if line_number > MAX_TRACE_LINES:
                    raise SessionEvidenceError("session transcript exceeds the line limit")
                if len(raw) > MAX_TRACE_LINE_BYTES:
                    raise SessionEvidenceError("session transcript contains an oversized line")
                total += len(raw)
                if total > MAX_TRACE_BYTES:
                    raise SessionEvidenceError(
                        "session transcript exceeds the 50 MB collection limit"
                    )
                evidence.line_count = line_number
                try:
                    record = json.loads(raw)
                except (json.JSONDecodeError, UnicodeError):
                    evidence.parse_errors += 1
                    if source.confidence == "reduced":
                        _record_text(evidence, raw.decode("utf-8", errors="replace"))
                    continue
                if not isinstance(record, dict):
                    evidence.parse_errors += 1
                    continue
                typed = cast(dict[str, Any], record)
                if source.platform == "codex":
                    _collect_codex(evidence, typed)
                else:
                    _collect_claude(evidence, typed)
    except OSError as error:
        raise SessionEvidenceError(f"cannot read session transcript: {error}") from error
    try:
        after = path.stat()
        evidence.changed_during_collection = (
            before.st_size != after.st_size or before.st_mtime_ns != after.st_mtime_ns
        )
    except OSError:
        evidence.changed_during_collection = True
    return evidence
