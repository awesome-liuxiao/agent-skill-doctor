from __future__ import annotations

import hashlib
from collections import defaultdict
from dataclasses import asdict, dataclass
from typing import Any, Literal, cast

from skill_doctor.models import Confidence, Evidence, Finding, Hypothesis, Severity

NodeStatus = Literal["confirmed", "remaining", "eliminated", "unsupported"]
CATEGORIES = (
    "skill",
    "runtime",
    "model",
    "dependency",
    "permission",
    "configuration",
    "environment",
    "unrelated",
)


@dataclass(frozen=True, slots=True)
class CausalNode:
    id: str
    category: str
    status: NodeStatus
    confidence: Confidence
    evidence_ids: tuple[str, ...] = ()
    reason: str | None = None


@dataclass(frozen=True, slots=True)
class CausalEdge:
    source: str
    target: str
    relation: str
    evidence_ids: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class Remediation:
    id: str
    finding_id: str
    action: str
    expected_effect: str
    risk: str
    verification: str
    generates_patch: bool = False


@dataclass(frozen=True, slots=True)
class CausalOutcome:
    findings: tuple[Finding, ...]
    evidence: tuple[Evidence, ...]
    graph: dict[str, Any]
    remediations: tuple[dict[str, Any], ...]
    summary: dict[str, Any]
    confirmed: bool
    indeterminate: bool


def _trial_evidence(
    skill_name: str,
    snapshot_hash: str,
    trial: dict[str, Any],
) -> Evidence:
    identity = {
        "case": trial.get("case_id"),
        "control": bool(trial.get("control")),
        "repetition": trial.get("repetition"),
        "snapshot": snapshot_hash,
    }
    digest = hashlib.sha256(repr(sorted(identity.items())).encode("utf-8")).hexdigest()[:20]
    kind = "controlled_counterfactual" if trial.get("control") else "dynamic_reproduction"
    status = "passed" if trial.get("passed") else "failed"
    return Evidence(
        f"dynamic-{digest}",
        kind,
        f"{skill_name} case {trial.get('case_id')!r} {kind} {status}.",
        artifact_hash=(
            str(trial["stdout_sha256"]) if isinstance(trial.get("stdout_sha256"), str) else None
        ),
    )


def _severity_for_confirmation(trials: list[dict[str, Any]]) -> Severity:
    if any(trial.get("canary_exposure") or trial.get("orphan_leak_detected") for trial in trials):
        return "critical"
    if any(trial.get("timed_out") for trial in trials):
        return "high"
    return "medium"


def _remediation(finding: Finding) -> Remediation:
    if finding.rule_id == "ASD600":
        action = (
            "Disable the implicated skill for the failing scenario, then narrow or correct its "
            "instructions outside the doctor."
        )
        effect = "The no-skill counterfactual behavior should replace the reproduced failure."
        risk = "The workflow may lose behavior that depends on the skill."
        verification = "Repeat the same authored standard-depth case and control at least twice."
    elif finding.rule_id.startswith("ASD0"):
        action = (
            "Review the cited instruction or metadata and make the smallest owner-approved edit."
        )
        effect = "The deterministic static observation should no longer be present."
        risk = "Instruction changes can alter triggering or runtime behavior."
        verification = "Re-run the static check, then run the narrowest authored dynamic case."
    else:
        action = "Review the linked evidence and change only the implicated configuration or input."
        effect = "The linked observation should stop recurring under the same controlled context."
        risk = "Changing multiple variables would weaken causal attribution."
        verification = "Repeat the same experiment while changing exactly one variable."
    return Remediation(
        f"remediation-{finding.id}",
        finding.id,
        action,
        effect,
        risk,
        verification,
    )


def assess_causality(
    *,
    existing_findings: list[Finding],
    existing_evidence: list[Evidence],
    dynamic_results: list[dict[str, Any]],
    hypotheses: list[Hypothesis] | None = None,
    source_language: str = "original",
) -> CausalOutcome:
    evidence = list(existing_evidence)
    evidence_by_trial: dict[int, str] = {}
    grouped: dict[tuple[str, str, str], list[dict[str, Any]]] = defaultdict(list)
    for result in dynamic_results:
        skill_name = str(result.get("skill_name", "skill"))
        snapshot_hash = str(result.get("snapshot_hash", ""))
        raw_trials = result.get("trials", [])
        if not isinstance(raw_trials, list):
            continue
        for raw_trial in raw_trials:
            if not isinstance(raw_trial, dict):
                continue
            trial = cast(dict[str, Any], raw_trial)
            item = _trial_evidence(skill_name, snapshot_hash, trial)
            evidence.append(item)
            evidence_by_trial[id(trial)] = item.id
            grouped[(skill_name, snapshot_hash, str(trial.get("case_id")))].append(trial)

    causal_findings: list[Finding] = []
    skill_evidence: list[str] = []
    eliminated: list[str] = []
    remaining: set[str] = set(CATEGORIES[:-1])
    edges: list[CausalEdge] = []
    missing: set[str] = set()
    next_experiment = "Run a standard-depth authored reproduction with a no-skill control."

    for (skill_name, snapshot_hash, case_id), trials in grouped.items():
        treatments = [trial for trial in trials if not trial.get("control")]
        controls = [trial for trial in trials if trial.get("control")]
        trusted = all(bool(trial.get("contract_trusted_for_job")) for trial in treatments)
        treatment_failed = [trial for trial in treatments if not trial.get("passed")]
        control_passed = [trial for trial in controls if trial.get("passed")]
        treatment_passed = [trial for trial in treatments if trial.get("passed")]
        treatment_ids = [evidence_by_trial[id(trial)] for trial in treatments]
        control_ids = [evidence_by_trial[id(trial)] for trial in controls]

        reproducible_failure = (
            trusted and len(treatments) >= 2 and len(treatment_failed) == len(treatments)
        )
        successful_counterfactual = bool(controls) and len(control_passed) == len(controls)
        if reproducible_failure and successful_counterfactual:
            identifier = hashlib.sha256(
                f"{snapshot_hash}:{case_id}:confirmed".encode()
            ).hexdigest()[:20]
            linked = tuple((*treatment_ids, *control_ids))
            causal_findings.append(
                Finding(
                    f"causal-{identifier}",
                    "ASD600",
                    "Reproducible skill-caused failure",
                    f"The trusted case {case_id!r} failed in every repeated skill run while "
                    "the controlled no-skill counterfactual passed.",
                    _severity_for_confirmation(trials),
                    "high",
                    "caused",
                    linked,
                )
            )
            skill_evidence.extend(linked)
            remaining.discard("skill")
            edges.append(CausalEdge("skill", "observed-failure", "caused", linked))
            next_experiment = (
                "Verify the owner-approved remediation with the identical case and control."
            )
        elif (
            treatments
            and len(treatment_passed) == len(treatments)
            and controls
            and not control_passed
        ):
            eliminated.append(f"skill:{skill_name}:{case_id}")
            remaining.discard("skill")
            linked = tuple((*treatment_ids, *control_ids))
            edges.append(CausalEdge("skill", "observed-failure", "unrelated", linked))
        elif treatment_failed:
            if treatment_passed:
                linked = tuple(treatment_ids)
                edges.append(CausalEdge("skill", "observed-failure", "contributed", linked))
            treatment_exposure = any(
                trial.get("canary_exposure") or trial.get("orphan_leak_detected")
                for trial in treatments
            )
            control_exposure = any(
                trial.get("canary_exposure") or trial.get("orphan_leak_detected")
                for trial in controls
            )
            if treatment_exposure and not control_exposure:
                edges.append(
                    CausalEdge(
                        "skill",
                        "containment-boundary",
                        "exposed",
                        tuple(treatment_ids),
                    )
                )
            if len(treatments) < 2:
                missing.add("repeated_reproduction")
                next_experiment = (
                    "Escalate the same case to standard depth without changing context."
                )
            if not controls:
                missing.add("controlled_counterfactual")
            if not trusted:
                missing.add("trusted_functional_contract")
            if controls and not control_passed:
                remaining.update(("runtime", "model", "configuration", "environment"))
                next_experiment = (
                    "Repeat the failing treatment and control while changing one approved runtime "
                    "or configuration variable."
                )

    hypothesis_categories = {
        hypothesis.category
        for hypothesis in (hypotheses or [])
        if hypothesis.category in CATEGORIES
    }
    remaining.update(hypothesis_categories)
    if not grouped:
        missing.update(("dynamic_reproduction", "controlled_counterfactual"))

    nodes: list[CausalNode] = []
    confirmed = bool(causal_findings)
    for category in CATEGORIES:
        if category == "skill" and confirmed:
            status: NodeStatus = "confirmed"
            confidence: Confidence = "high"
            ids = tuple(dict.fromkeys(skill_evidence))
            reason = "Repeated trusted reproduction plus a successful no-skill counterfactual."
        elif category not in remaining:
            status = "eliminated"
            confidence = "medium"
            ids = ()
            reason = "Available controlled evidence did not reproduce the failure with this factor."
        else:
            status = "remaining"
            confidence = "low"
            ids = ()
            reason = "Evidence is insufficient to eliminate or confirm this factor."
        nodes.append(CausalNode(category, category, status, confidence, ids, reason))

    all_findings = [*existing_findings, *causal_findings]
    evidence_kinds = {item.id: item.kind for item in evidence}
    flagged_ids: list[str] = []
    for finding in all_findings:
        kinds = {evidence_kinds.get(identifier) for identifier in finding.evidence_ids}
        kinds.discard(None)
        if finding.rule_id == "ASD600" or len(kinds) >= 2:
            flagged_ids.append(finding.id)
    remediations = tuple(asdict(_remediation(finding)) for finding in all_findings)
    graph = {
        "nodes": [asdict(node) for node in nodes],
        "edges": [asdict(edge) for edge in edges],
        "confirmation_rule": {
            "requires": [
                "trusted deterministic assertion",
                "at least two identical failing reproductions",
                "successful controlled counterfactual",
            ],
            "satisfied": confirmed,
        },
        "flagging_rule": {
            "minimum_independent_evidence_types": 2,
            "model_judgment_alone_allowed": False,
        },
    }
    summary = {
        "confirmed_root_causes": [finding.id for finding in causal_findings],
        "eliminated_hypotheses": eliminated,
        "remaining_candidates": sorted(remaining),
        "missing_evidence": sorted(missing),
        "smallest_useful_next_experiment": next_experiment,
        "causal_roles_observed": sorted({edge.relation for edge in edges}),
        "flagged_issue_ids": flagged_ids,
        "non_blocking_observation_ids": [
            finding.id for finding in all_findings if finding.id not in flagged_ids
        ],
        "source_language": source_language,
        "translation_fallback_used": False,
    }
    indeterminate = bool(grouped or existing_findings or hypotheses) and not confirmed
    return CausalOutcome(
        tuple(causal_findings),
        tuple(evidence[len(existing_evidence) :]),
        graph,
        remediations,
        summary,
        confirmed,
        indeterminate,
    )
