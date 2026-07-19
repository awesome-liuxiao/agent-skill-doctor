from __future__ import annotations

import argparse
import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, cast

from skill_doctor.benchmark import run_static_benchmark, validate_held_out_result


def _object(path: Path) -> dict[str, Any]:
    payload = json.loads(path.read_bytes())
    if not isinstance(payload, dict):
        raise SystemExit(f"{path} must contain an object")
    return cast(dict[str, Any], payload)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--public-manifest", type=Path, required=True)
    parser.add_argument("--release-version", required=True)
    parser.add_argument("--rotation-id", required=True)
    parser.add_argument("--evaluator-commit", required=True)
    parser.add_argument("--output", type=Path, required=True)
    arguments = parser.parse_args()
    held_out_manifest = _object(arguments.manifest)
    public_manifest = _object(arguments.public_manifest)
    held_out_cases = cast(list[dict[str, Any]], held_out_manifest.get("cases", []))
    public_cases = cast(list[dict[str, Any]], public_manifest.get("cases", []))
    held_out_ids = {str(item.get("id")) for item in held_out_cases}
    public_ids = {str(item.get("id")) for item in public_cases}
    if not held_out_ids or held_out_ids & public_ids:
        raise SystemExit(
            "held-out case identities must be non-empty and disjoint from public cases"
        )
    corpus_version = held_out_manifest.get("corpus_version")
    if not isinstance(corpus_version, str) or not corpus_version.startswith("held-out-"):
        raise SystemExit("held-out corpus_version must begin with held-out-")
    static = run_static_benchmark(arguments.manifest)
    commitment = hashlib.sha256("\n".join(sorted(held_out_ids)).encode()).hexdigest()
    result = {
        "schema_version": "1.0.0",
        "corpus_version": corpus_version,
        "release_version": arguments.release_version,
        "rotation_id": arguments.rotation_id,
        "rotating": True,
        "evaluated_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        "evaluator_commit": arguments.evaluator_commit,
        "case_count": len(held_out_ids),
        "disjoint_from_public_sha256": commitment,
        "metrics": static["metrics"],
    }
    validate_held_out_result(result)
    arguments.output.parent.mkdir(parents=True, exist_ok=True)
    arguments.output.write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
