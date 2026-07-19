import json
from pathlib import Path

import pytest

from skill_doctor.evals import (
    EvalContractError,
    RuntimeObservation,
    evaluate_assertions,
    infer_contract,
    load_authored_contract,
    promote_inferred_for_job,
)


def _write_skill(tmp_path: Path, contract: dict[str, object]) -> Path:
    skill = tmp_path / "fixture"
    (skill / "evals").mkdir(parents=True)
    (skill / "SKILL.md").write_text(
        "---\nname: fixture\ndescription: Create a bounded fixture.\n---\n# Fixture\n",
        encoding="utf-8",
    )
    (skill / "evals" / "evals.json").write_text(
        json.dumps(contract),
        encoding="utf-8",
    )
    return skill


def test_authored_contract_and_assertions_are_deterministic(tmp_path: Path) -> None:
    skill = _write_skill(
        tmp_path,
        {
            "version": 1,
            "skill": "fixture",
            "x-owner": "doctor-tests",
            "tests": [
                {
                    "id": "creates-output",
                    "prompt": "Create the expected output.",
                    "expected": {
                        "exit_code": 0,
                        "output_contains": ["complete"],
                        "output_regex": ["compl.te"],
                        "files_exist": ["result.txt"],
                        "files_absent": ["secret.txt"],
                    },
                    "tags": ["quick"],
                }
            ],
        },
    )
    contract = load_authored_contract(skill)
    assert contract is not None
    assert contract.source == "authored"
    assert contract.extensions == {"x-owner": "doctor-tests"}
    observation = RuntimeObservation(0, "complete", frozenset({"result.txt"}))
    results = evaluate_assertions(contract.cases[0], observation)
    assert results
    assert all(result.passed for result in results)


@pytest.mark.parametrize(
    "expected",
    [
        {"files_exist": ["../host.txt"]},
        {"output_regex": ["(a+)+$"]},
    ],
)
def test_authored_contract_rejects_escape_paths_and_complex_regex(
    tmp_path: Path,
    expected: dict[str, object],
) -> None:
    skill = _write_skill(
        tmp_path,
        {
            "version": 1,
            "tests": [{"id": "unsafe", "prompt": "test", "expected": expected}],
        },
    )
    with pytest.raises(EvalContractError):
        load_authored_contract(skill)


def test_inferred_contract_requires_per_job_promotion(tmp_path: Path) -> None:
    skill = _write_skill(tmp_path, {"version": 1, "tests": []})
    contract = infer_contract(skill)
    assert contract.source == "inferred"
    assert not contract.trusted_for_job
    with pytest.raises(EvalContractError, match="per-job consent"):
        promote_inferred_for_job(contract, consent=False)
    promoted = promote_inferred_for_job(contract, consent=True)
    assert promoted.trusted_for_job
    assert promoted.extensions["x-skill-doctor"]["promotion_scope"] == "one_job"
