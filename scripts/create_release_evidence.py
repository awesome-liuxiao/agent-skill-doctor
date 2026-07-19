from __future__ import annotations

import argparse
import json
import os
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from skill_doctor.benchmark import validate_release_evidence


def _required(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        raise SystemExit(f"required protected input {name} is missing")
    return value


def _json_list(name: str) -> list[Any]:
    try:
        value = json.loads(_required(name))
    except json.JSONDecodeError as error:
        raise SystemExit(f"protected input {name} is invalid JSON") from error
    if not isinstance(value, list):
        raise SystemExit(f"protected input {name} must be an array")
    return value


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    arguments = parser.parse_args()
    try:
        participants = int(_required("PARTICIPANT_COUNT"))
        issues = int(_required("ISSUE_COUNT"))
        remediated = int(_required("REMEDIATED_ISSUE_COUNT"))
        blockers = int(_required("OPEN_RELEASE_BLOCKERS"))
    except ValueError as error:
        raise SystemExit("protected count inputs must be integers") from error
    evidence = {
        "schema_version": "1.0.0",
        "release_version": _required("RELEASE_VERSION"),
        "evaluator_commit": _required("EVALUATOR_COMMIT"),
        "recorded_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        "participant_count": participants,
        "platforms": _json_list("PLATFORMS_JSON"),
        "runtime_contexts": _json_list("RUNTIME_CONTEXTS_JSON"),
        "issue_count": issues,
        "remediated_issue_count": remediated,
        "open_release_blockers": blockers,
        "remediation_started_at": _required("REMEDIATION_STARTED_AT"),
        "remediation_completed_at": _required("REMEDIATION_COMPLETED_AT"),
        "public_preview_completed": _required("PUBLIC_PREVIEW_COMPLETED").casefold() == "true",
        "signoff": _required("SIGNOFF").casefold() == "true",
    }
    validate_release_evidence(evidence)
    arguments.output.write_text(
        json.dumps(evidence, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
