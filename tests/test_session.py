import json
from pathlib import Path

import pytest

from skill_doctor.session import (
    MAX_TRACE_BYTES,
    SessionEvidenceError,
    SessionSource,
    collect_session_evidence,
    locate_session_source,
)


def _jsonl(path: Path, records: list[dict[str, object]]) -> None:
    path.parent.mkdir(parents=True)
    path.write_text(
        "".join(json.dumps(record) + "\n" for record in records),
        encoding="utf-8",
    )


def test_codex_current_session_collection_is_minimized_and_structured(tmp_path: Path) -> None:
    session_id = "thread-123"
    trace = tmp_path / ".codex" / "sessions" / "2026" / "07" / "16" / f"rollout-{session_id}.jsonl"
    _jsonl(
        trace,
        [
            {
                "type": "session_meta",
                "payload": {
                    "id": session_id,
                    "cwd": str(tmp_path / "repo"),
                    "cli_version": "1.2.3",
                },
            },
            {
                "type": "turn_context",
                "payload": {
                    "model": "gpt-fixture",
                    "approval_policy": "never",
                    "sandbox_policy": {"type": "workspace-write"},
                    "cwd": str(tmp_path / "repo"),
                },
            },
            {
                "type": "event_msg",
                "payload": {
                    "type": "user_message",
                    "message": "Use $deploy-helper to deploy the release safely",
                },
            },
            {
                "type": "response_item",
                "payload": {
                    "type": "custom_tool_call",
                    "name": "exec",
                    "arguments": '{"command":"read .agents/skills/deploy-helper/SKILL.md"}',
                },
            },
            {
                "type": "response_item",
                "payload": {
                    "type": "message",
                    "role": "developer",
                    "content": [{"type": "input_text", "text": "Use $catalog-only skill."}],
                },
            },
            {
                "type": "event_msg",
                "payload": {
                    "type": "mcp_tool_call_end",
                    "success": False,
                    "duration_ms": 12,
                },
            },
        ],
    )

    source = locate_session_source(
        "codex",
        home=tmp_path,
        environment={"CODEX_THREAD_ID": session_id},
    )
    assert source.path == trace
    assert source.confidence == "high"
    manifest = source.collection_item()
    assert manifest.collected
    assert manifest.bytes == trace.stat().st_size

    evidence = collect_session_evidence(source)
    assert evidence.session_id == session_id
    assert evidence.runtime_version == "1.2.3"
    assert evidence.model == "gpt-fixture"
    assert evidence.permission_mode == "never"
    assert evidence.invoked_selectors == {"deploy-helper"}
    assert evidence.accessed_skill_directories == {"deploy-helper"}
    assert evidence.tool_names == {"exec"}
    assert evidence.error_categories == {"runtime": 1}
    assert "release" in evidence.prompt_terms
    environment = evidence.environment_dict()
    assert "message" not in json.dumps(environment)


def test_claude_skill_tool_and_errors_are_collected_without_message_content(
    tmp_path: Path,
) -> None:
    trace = tmp_path / ".claude" / "projects" / "fixture" / "session-1.jsonl"
    _jsonl(
        trace,
        [
            {
                "type": "user",
                "sessionId": "session-1",
                "cwd": str(tmp_path / "repo"),
                "version": "2.1.205",
                "message": {"role": "user", "content": "Review this change"},
            },
            {
                "type": "assistant",
                "model": "claude-fixture",
                "permissionMode": "default",
                "message": {
                    "role": "assistant",
                    "content": [
                        {
                            "type": "tool_use",
                            "name": "Skill",
                            "input": {"skill": "/review"},
                        },
                        {
                            "type": "tool_result",
                            "is_error": True,
                            "content": "permission denied",
                        },
                    ],
                },
                "durationMs": 25,
            },
        ],
    )
    source = locate_session_source(
        "claude",
        home=tmp_path,
        environment={"CLAUDE_SESSION_ID": "session-1"},
    )
    evidence = collect_session_evidence(source)
    assert evidence.invoked_selectors == {"review"}
    assert evidence.tool_names == {"Skill"}
    assert evidence.error_categories["runtime"] == 1
    assert evidence.model == "claude-fixture"
    assert evidence.runtime_version == "2.1.205"
    assert evidence.timing_ms == {"assistant": [25.0]}


def test_missing_exact_session_falls_back_with_reduced_confidence(tmp_path: Path) -> None:
    trace = tmp_path / ".codex" / "sessions" / "old.jsonl"
    _jsonl(trace, [{"type": "session_meta", "payload": {"id": "old"}}])
    source = locate_session_source(
        "codex",
        home=tmp_path,
        environment={"CODEX_THREAD_ID": "missing"},
    )
    assert source.path == trace
    assert source.confidence == "reduced"


def test_supplied_plain_transcript_uses_reduced_reconstruction(tmp_path: Path) -> None:
    transcript = tmp_path / "visible.txt"
    transcript.write_text("Please /review this. The tool failed.\n", encoding="utf-8")
    source = locate_session_source("claude", supplied_transcript=transcript, home=tmp_path)
    evidence = collect_session_evidence(source)
    assert evidence.confidence == "reduced"
    assert evidence.invoked_selectors == {"review"}
    assert evidence.parse_errors == 1


def test_trace_collection_enforces_size_limit(tmp_path: Path) -> None:
    trace = tmp_path / "too-large.jsonl"
    with trace.open("wb") as stream:
        stream.truncate(MAX_TRACE_BYTES + 1)
    source = SessionSource("codex", trace, None, "reduced", "fixture")
    with pytest.raises(SessionEvidenceError, match="50 MB"):
        collect_session_evidence(source)
