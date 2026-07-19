import json
from pathlib import Path
from typing import Any, cast

from skill_doctor.analysis import analyze
from skill_doctor.snapshot import create_snapshot


def test_seed_benchmark_contract() -> None:
    manifest_path = Path(__file__).parents[1] / "benchmarks" / "seed" / "manifest.json"
    manifest = cast(dict[str, Any], json.loads(manifest_path.read_text(encoding="utf-8")))
    assert manifest["schema_version"] == "1.0.0"
    cases = cast(list[dict[str, Any]], manifest["cases"])
    assert cases
    for case in cases:
        assert case["origin"]
        assert case["license"]
        skill_path = (manifest_path.parent / str(case["path"])).resolve()
        result = analyze(create_snapshot(skill_path))
        assert {finding.rule_id for finding in result.findings} == set(
            cast(list[str], case["expected_rule_ids"])
        )
