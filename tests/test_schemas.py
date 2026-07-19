import json
import os
from dataclasses import asdict
from pathlib import Path
from typing import Any, cast

import pytest
from jsonschema import Draft202012Validator
from referencing import Registry, Resource

from skill_doctor.cli import main
from skill_doctor.security import ArtifactCipher
from skill_doctor.store import LocalStore

SCHEMAS = Path(__file__).parents[1] / "schemas"


@pytest.fixture(autouse=True)
def _ephemeral_state_key(monkeypatch: pytest.MonkeyPatch) -> None:
    key = os.urandom(32)
    monkeypatch.setattr(
        "skill_doctor.security.load_or_create_master_key",
        lambda _root: key,
    )


def _schemas() -> list[dict[str, Any]]:
    return [
        cast(dict[str, Any], json.loads(path.read_text(encoding="utf-8")))
        for path in sorted(SCHEMAS.glob("*.json"))
    ]


def test_all_published_schemas_are_valid() -> None:
    for schema in _schemas():
        Draft202012Validator.check_schema(schema)


def test_emitted_report_and_events_match_schemas(
    tmp_path: Path,
    capsys: object,
) -> None:
    schemas = _schemas()
    registry = Registry().with_resources(
        (str(schema["$id"]), Resource.from_contents(schema)) for schema in schemas
    )
    by_title = {str(schema["title"]): schema for schema in schemas}
    fixture = Path(__file__).parent / "fixtures" / "valid-skill"
    assert main(["check", str(fixture), "--state-dir", str(tmp_path), "--json", "--direct"]) == 0
    captured = capsys.readouterr()  # type: ignore[attr-defined]
    report = json.loads(captured.out)
    events = [json.loads(line) for line in captured.err.splitlines()]
    Draft202012Validator(
        by_title["Report"],
        registry=registry,
        format_checker=Draft202012Validator.FORMAT_CHECKER,
    ).validate(report)
    event_validator = Draft202012Validator(
        by_title["Event"],
        registry=registry,
        format_checker=Draft202012Validator.FORMAT_CHECKER,
    )
    for event in events:
        event_validator.validate(event)


def test_durable_job_matches_published_schema(tmp_path: Path) -> None:
    schemas = _schemas()
    by_title = {str(schema["title"]): schema for schema in schemas}
    store = LocalStore(tmp_path, cipher=ArtifactCipher(os.urandom(32)))
    store.create_job(
        "job-schema-fixture",
        "2026-07-16T00:00:00Z",
        "/skill",
        {"depth": "quick"},
    )
    job = store.get_job("job-schema-fixture")
    assert job is not None
    Draft202012Validator(
        by_title["Job"],
        format_checker=Draft202012Validator.FORMAT_CHECKER,
    ).validate(asdict(job))


def test_session_report_matches_published_schema(
    tmp_path: Path,
    capsys: object,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    schemas = _schemas()
    registry = Registry().with_resources(
        (str(schema["$id"]), Resource.from_contents(schema)) for schema in schemas
    )
    by_title = {str(schema["title"]): schema for schema in schemas}
    repo = tmp_path / "repo"
    skill = repo / ".agents" / "skills" / "schema-session"
    skill.mkdir(parents=True)
    (skill / "SKILL.md").write_text(
        "---\nname: schema-session\ndescription: Session schema fixture.\n---\n",
        encoding="utf-8",
    )
    transcript = tmp_path / "transcript.txt"
    transcript.write_text("Use /schema-session.\n", encoding="utf-8")
    monkeypatch.setattr(Path, "home", lambda: tmp_path / "home")
    assert (
        main(
            [
                "diagnose",
                "--cwd",
                str(repo),
                "--transcript",
                str(transcript),
                "--state-dir",
                str(tmp_path / "state"),
                "--json",
                "--direct",
            ]
        )
        == 0
    )
    report = json.loads(capsys.readouterr().out)  # type: ignore[attr-defined]
    Draft202012Validator(
        by_title["Report"],
        registry=registry,
        format_checker=Draft202012Validator.FORMAT_CHECKER,
    ).validate(report)
