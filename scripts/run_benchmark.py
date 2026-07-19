from __future__ import annotations

import argparse
import json
from datetime import UTC, datetime
from pathlib import Path

from skill_doctor.benchmark import (
    release_gate_report,
    run_causal_benchmark,
    run_static_benchmark,
    unresolved_critical_escapes,
    validate_release_evidence,
    validation_from_junit,
)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--causal", type=Path, required=True)
    parser.add_argument("--junit", type=Path, action="append", default=[])
    parser.add_argument("--platform", action="append", default=[])
    parser.add_argument("--known-escapes", type=Path)
    parser.add_argument("--held-out-result", type=Path)
    parser.add_argument("--held-out-attestation-verified", action="store_true")
    parser.add_argument("--advisory", action="store_true")
    parser.add_argument("--public-gate", action="store_true")
    parser.add_argument("--expected-evaluator-commit")
    parser.add_argument("--expected-release-version")
    parser.add_argument("--release-evidence", type=Path)
    parser.add_argument("--release-evidence-attestation-verified", action="store_true")
    parser.add_argument("--output", type=Path, required=True)
    arguments = parser.parse_args()
    if len(arguments.junit) != len(arguments.platform):
        raise SystemExit("each --junit requires one corresponding --platform")
    if arguments.junit and arguments.known_escapes is None:
        raise SystemExit("--known-escapes is required with platform validation")
    static = run_static_benchmark(arguments.manifest)
    if (
        arguments.expected_release_version is not None
        and arguments.expected_release_version != f"v{static['tool_version']}"
    ):
        raise SystemExit("release version does not match the packaged tool version")
    causal = run_causal_benchmark(arguments.causal)
    escape_count = (
        None
        if arguments.known_escapes is None
        else unresolved_critical_escapes(arguments.known_escapes)
    )
    validations = [
        validation_from_junit(
            path,
            platform_name=platform_name,
            known_critical_sandbox_escapes=escape_count,
        )
        for path, platform_name in zip(arguments.junit, arguments.platform, strict=True)
    ]
    held_out = (
        None
        if arguments.held_out_result is None
        else json.loads(arguments.held_out_result.read_bytes())
    )
    release_evidence = (
        None
        if arguments.release_evidence is None
        else validate_release_evidence(json.loads(arguments.release_evidence.read_bytes()))
    )
    if held_out is not None:
        if (
            arguments.expected_evaluator_commit is not None
            and held_out.get("evaluator_commit") != arguments.expected_evaluator_commit
        ):
            raise SystemExit("held-out result was produced from a different evaluator commit")
        if (
            arguments.expected_release_version is not None
            and held_out.get("release_version") != arguments.expected_release_version
        ):
            raise SystemExit("held-out result targets a different release version")
    if release_evidence is not None:
        if (
            arguments.expected_evaluator_commit is not None
            and release_evidence.get("evaluator_commit") != arguments.expected_evaluator_commit
        ):
            raise SystemExit("release evidence was produced from a different evaluator commit")
        if (
            arguments.expected_release_version is not None
            and release_evidence.get("release_version") != arguments.expected_release_version
        ):
            raise SystemExit("release evidence targets a different release version")
    gate = release_gate_report(
        static=static,
        causal=causal,
        validations=validations,
        held_out=held_out,
        held_out_attested=arguments.held_out_attestation_verified,
        release_evidence=release_evidence,
        release_evidence_attested=arguments.release_evidence_attestation_verified,
    )
    payload = {
        "schema_version": "1.0.0",
        "generated_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        "static": static,
        "causal": causal,
        "validation": validations,
        "held_out": held_out,
        "release_evidence": release_evidence,
        "release": gate,
    }
    arguments.output.parent.mkdir(parents=True, exist_ok=True)
    arguments.output.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    if arguments.advisory:
        return 0
    if arguments.public_gate:
        public_gate_names = {
            "precision_at_least_95_percent",
            "benign_false_positive_at_most_2_percent",
            "root_cause_accuracy_at_least_90_percent",
            "reproduction_consistency_at_least_90_percent",
            "static_completion_at_least_99_5_percent",
            "containment_and_canary_100_percent",
            "fault_injection_100_percent",
            "public_functional_100_percent",
            "no_known_critical_sandbox_escape",
        }
        return 0 if all(gate["gates"][name] for name in public_gate_names) else 2
    return 0 if gate["stable_v1_ready"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
