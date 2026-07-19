from skill_doctor.causal import assess_causality


def _trial(
    repetition: int, *, control: bool, passed: bool, trusted: bool = True
) -> dict[str, object]:
    return {
        "case_id": "case-1",
        "contract_source": "authored",
        "contract_trusted_for_job": trusted,
        "repetition": repetition,
        "control": control,
        "passed": passed,
        "stdout_sha256": "a" * 64,
        "canary_exposure": False,
        "orphan_leak_detected": False,
        "timed_out": False,
    }


def test_confirmation_requires_repetition_and_successful_counterfactual() -> None:
    result = assess_causality(
        existing_findings=[],
        existing_evidence=[],
        dynamic_results=[
            {
                "skill_name": "fixture",
                "snapshot_hash": "b" * 64,
                "trials": [
                    _trial(1, control=False, passed=False),
                    _trial(2, control=False, passed=False),
                    _trial(1, control=True, passed=True),
                ],
            }
        ],
    )
    assert result.confirmed
    assert result.findings[0].causal_role == "caused"
    assert result.findings[0].confidence == "high"
    assert len(result.findings[0].evidence_ids) == 3
    assert result.graph["confirmation_rule"]["satisfied"] is True
    assert all(not item["generates_patch"] for item in result.remediations)


def test_lone_or_untrusted_reproduction_remains_indeterminate() -> None:
    result = assess_causality(
        existing_findings=[],
        existing_evidence=[],
        dynamic_results=[
            {
                "skill_name": "fixture",
                "snapshot_hash": "b" * 64,
                "trials": [_trial(1, control=False, passed=False, trusted=False)],
            }
        ],
    )
    assert not result.confirmed
    assert result.indeterminate
    assert not result.findings
    assert set(result.summary["missing_evidence"]) == {
        "controlled_counterfactual",
        "repeated_reproduction",
        "trusted_functional_contract",
    }


def test_passing_treatment_and_failing_control_eliminates_skill_hypothesis() -> None:
    result = assess_causality(
        existing_findings=[],
        existing_evidence=[],
        dynamic_results=[
            {
                "skill_name": "fixture",
                "snapshot_hash": "b" * 64,
                "trials": [
                    _trial(1, control=False, passed=True),
                    _trial(2, control=False, passed=True),
                    _trial(1, control=True, passed=False),
                ],
            }
        ],
    )
    assert not result.confirmed
    assert result.summary["eliminated_hypotheses"] == ["skill:fixture:case-1"]
    skill = next(node for node in result.graph["nodes"] if node["category"] == "skill")
    assert skill["status"] == "eliminated"
