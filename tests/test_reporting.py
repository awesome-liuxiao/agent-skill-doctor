import json
import xml.etree.ElementTree as ET

from skill_doctor.reporting import render_html_report, render_junit_report, render_sarif_report


def _report() -> dict[str, object]:
    return {
        "job_id": "job",
        "snapshot_hash": "a" * 64,
        "tool_version": "1.0",
        "result_state": "indeterminate",
        "findings": [
            {
                "id": "finding-stable",
                "rule_id": "ASD999",
                "title": "</style><script>alert(1)</script>",
                "message": "<img src=https://attacker.invalid/x onerror=alert(1)>",
                "severity": "high",
                "confidence": "high",
                "causal_role": "indeterminate",
                "evidence_ids": ["evidence-stable"],
                "path": "<svg/onload=alert(1)>",
                "line": 1,
            }
        ],
        "evidence": [
            {
                "id": "evidence-stable",
                "kind": "fixture",
                "description": "<iframe src=https://attacker.invalid>",
            }
        ],
        "limitations": [],
        "dynamic_results": [],
        "causal_graph": {"edges": []},
        "suppressed_finding_ids": [],
        "blocking_finding_ids": ["finding-stable"],
        "artifacts": {},
    }


def test_offline_html_escapes_hostile_markup_and_forbids_network() -> None:
    document = render_html_report(_report()).decode("utf-8")
    assert "<script>" not in document
    assert "<img src=" not in document
    assert "<iframe" not in document
    assert "&lt;script&gt;" in document
    assert "default-src 'none'" in document
    assert "connect-src 'none'" in document
    assert "script-src 'none'" in document
    assert 'http-equiv="Content-Security-Policy"' in document


def test_sarif_and_junit_preserve_stable_finding_and_evidence_ids() -> None:
    sarif = json.loads(render_sarif_report(_report()))
    result = sarif["runs"][0]["results"][0]
    assert result["fingerprints"]["agentSkillDoctorFindingId"] == "finding-stable"
    assert result["properties"]["evidenceIds"] == ["evidence-stable"]
    junit = ET.fromstring(render_junit_report(_report()))  # noqa: S314 - generated fixture only
    case = junit.find("testcase")
    assert case is not None and case.attrib["name"] == "finding-stable"
    assert case.find("failure") is not None
