from __future__ import annotations

import html
import json
import xml.etree.ElementTree as ET
from collections.abc import Mapping
from typing import Any, cast


def _text(value: object) -> str:
    return html.escape(str(value), quote=True)


def _objects(value: object) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    return [cast(dict[str, Any], item) for item in value if isinstance(item, dict)]


def _identifiers(value: object) -> list[str]:
    if not isinstance(value, list):
        return []
    return [str(item) for item in value if isinstance(item, str)]


def render_html_report(report: Mapping[str, Any]) -> bytes:
    findings = _objects(report.get("findings"))
    evidence = _objects(report.get("evidence"))
    suppressed = set(_identifiers(report.get("suppressed_finding_ids")))
    finding_rows = []
    for finding in findings:
        identity = str(finding.get("id", "finding"))
        marker = " — suppressed" if identity in suppressed else ""
        location = ""
        if finding.get("path") is not None:
            location = f"<div>Location: <code>{_text(finding['path'])}"
            if finding.get("line") is not None:
                location += f":{_text(finding['line'])}"
            location += "</code></div>"
        finding_rows.append(
            "<article><h3>"
            f"{_text(finding.get('rule_id', ''))}: {_text(finding.get('title', ''))}"
            f"{_text(marker)}</h3>"
            f"<div>{_text(finding.get('severity', ''))} severity / "
            f"{_text(finding.get('confidence', ''))} confidence / "
            f"{_text(finding.get('causal_role', 'indeterminate'))}</div>"
            f"<p>{_text(finding.get('message', ''))}</p>{location}"
            f"<div>Evidence: <code>{_text(', '.join(_identifiers(finding.get('evidence_ids'))))}"
            "</code></div></article>"
        )
    evidence_rows = [
        "<li>"
        f"<code>{_text(item.get('id', ''))}</code> "
        f"<strong>{_text(item.get('kind', ''))}</strong>: "
        f"{_text(item.get('description', ''))}</li>"
        for item in evidence
    ]
    trial_rows: list[str] = []
    for result in _objects(report.get("dynamic_results")):
        skill_name = result.get("skill_name", "skill")
        for trial in _objects(result.get("trials")):
            trial_rows.append(
                "<li>"
                f"{_text(skill_name)} / {_text(trial.get('case_id', 'case'))} / "
                f"repeat {_text(trial.get('repetition', '?'))} / "
                f"{'control' if trial.get('control') else 'with skill'} / "
                f"{'passed' if trial.get('passed') else 'failed'} / "
                f"{_text(trial.get('duration_ms', '?'))} ms</li>"
            )
    graph = report.get("causal_graph")
    graph_rows: list[str] = []
    if isinstance(graph, dict):
        for edge in _objects(graph.get("edges")):
            graph_rows.append(
                f"<li>{_text(edge.get('source', ''))} &rarr; "
                f"{_text(edge.get('target', ''))}: {_text(edge.get('relation', ''))}</li>"
            )
    artifacts = report.get("artifacts")
    artifact_rows: list[str] = []
    if isinstance(artifacts, dict):
        artifact_rows = [
            f"<li>{_text(name)}: <code>{_text(path)}</code></li>"
            for name, path in sorted(artifacts.items())
        ]
    limitations = [
        f"<li>{_text(item)}</li>" for item in report.get("limitations", []) if isinstance(item, str)
    ]
    conclusion = str(report.get("result_state", "indeterminate")).replace("_", " ")
    csp = (
        "default-src 'none'; style-src 'unsafe-inline'; img-src 'none'; media-src 'none'; "
        "font-src 'none'; script-src 'none'; connect-src 'none'; object-src 'none'; "
        "frame-src 'none'; base-uri 'none'; form-action 'none'"
    )
    style = (
        "body{font:16px system-ui;max-width:72rem;margin:2rem auto;padding:0 1rem;"
        "line-height:1.5}article{border:1px solid #888;padding:1rem;margin:1rem 0}"
        "code{overflow-wrap:anywhere}summary{font-weight:700;cursor:pointer}"
    )
    findings_html = "".join(finding_rows) or "<p>No flagged or observed finding was recorded.</p>"
    trials_html = "".join(trial_rows) or "<li>No dynamic trial was completed.</li>"
    graph_html = "".join(graph_rows) or "<li>No causal edge was established.</li>"
    document = (
        '<!doctype html><html lang="en"><head><meta charset="utf-8">'
        f'<meta http-equiv="Content-Security-Policy" content="{csp}">'
        '<meta name="referrer" content="no-referrer">'
        f"<title>Agent Skill Doctor report</title><style>{style}</style></head><body>"
        f"<h1>Agent Skill Doctor</h1><p>Conclusion: <strong>{_text(conclusion)}</strong></p>"
        f"<p>Job <code>{_text(report.get('job_id', ''))}</code>; snapshot "
        f"<code>{_text(report.get('snapshot_hash', ''))}</code>.</p>"
        f"<h2>Findings</h2>{findings_html}"
        "<details open><summary>Evidence timeline</summary>"
        f"<ol>{''.join(evidence_rows)}</ol><h3>Dynamic trials</h3>"
        f"<ol>{trials_html}</ol></details>"
        f"<details><summary>Causal graph</summary><ul>{graph_html}</ul></details>"
        "<details><summary>Coverage limitations</summary>"
        f"<ul>{''.join(limitations)}</ul></details>"
        f"<details><summary>Local artifacts</summary><ul>{''.join(artifact_rows)}</ul>"
        "</details></body></html>"
    )
    return document.encode("utf-8")


def render_sarif_report(report: Mapping[str, Any]) -> bytes:
    findings = _objects(report.get("findings"))
    suppressed = set(_identifiers(report.get("suppressed_finding_ids")))
    levels = {"critical": "error", "high": "error", "medium": "warning", "low": "note"}
    rules: dict[str, dict[str, Any]] = {}
    results: list[dict[str, Any]] = []
    for finding in findings:
        rule_id = str(finding.get("rule_id", "ASD000"))
        rules.setdefault(
            rule_id,
            {
                "id": rule_id,
                "name": str(finding.get("title", rule_id)),
                "shortDescription": {"text": str(finding.get("title", rule_id))},
            },
        )
        result: dict[str, Any] = {
            "ruleId": rule_id,
            "level": levels.get(str(finding.get("severity")), "note"),
            "message": {"text": str(finding.get("message", ""))},
            "fingerprints": {"agentSkillDoctorFindingId": str(finding.get("id", ""))},
            "properties": {
                "confidence": finding.get("confidence"),
                "causalRole": finding.get("causal_role"),
                "evidenceIds": _identifiers(finding.get("evidence_ids")),
            },
        }
        if str(finding.get("id")) in suppressed:
            result["suppressions"] = [{"kind": "external", "status": "accepted"}]
        path = finding.get("path")
        if isinstance(path, str):
            region: dict[str, Any] = {}
            if isinstance(finding.get("line"), int):
                region["startLine"] = finding["line"]
            result["locations"] = [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": path.replace("\\", "/")},
                        **({"region": region} if region else {}),
                    }
                }
            ]
        results.append(result)
    payload = {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Agent Skill Doctor",
                        "version": report.get("tool_version"),
                        "rules": list(rules.values()),
                    }
                },
                "results": results,
                "properties": {
                    "jobId": report.get("job_id"),
                    "snapshotHash": report.get("snapshot_hash"),
                },
            }
        ],
    }
    return (json.dumps(payload, indent=2, sort_keys=True) + "\n").encode("utf-8")


def render_junit_report(report: Mapping[str, Any]) -> bytes:
    findings = _objects(report.get("findings"))
    blocking = set(_identifiers(report.get("blocking_finding_ids")))
    suite = ET.Element(
        "testsuite",
        {
            "name": "agent-skill-doctor",
            "tests": str(len(findings) or 1),
            "failures": str(sum(str(item.get("id")) in blocking for item in findings)),
            "skipped": str(sum(str(item.get("id")) not in blocking for item in findings)),
        },
    )
    if not findings:
        ET.SubElement(suite, "testcase", {"name": "no-confirmed-blocking-finding"})
    for finding in findings:
        identity = str(finding.get("id", "finding"))
        case = ET.SubElement(
            suite,
            "testcase",
            {"classname": str(finding.get("rule_id", "ASD")), "name": identity},
        )
        if identity in blocking:
            failure = ET.SubElement(
                case,
                "failure",
                {
                    "type": str(finding.get("rule_id", "ASD")),
                    "message": str(finding.get("title", "blocking finding")),
                },
            )
            failure.text = str(finding.get("message", ""))
        else:
            ET.SubElement(case, "skipped", {"message": "non-blocking or suppressed observation"})
        output = ET.SubElement(case, "system-out")
        output.text = json.dumps(
            {"finding_id": identity, "evidence_ids": _identifiers(finding.get("evidence_ids"))},
            separators=(",", ":"),
            sort_keys=True,
        )
    return cast(bytes, ET.tostring(suite, encoding="utf-8", xml_declaration=True)) + b"\n"
