from pathlib import Path

from skill_doctor.analysis import analyze
from skill_doctor.snapshot import create_snapshot

FIXTURES = Path(__file__).parent / "fixtures"


def test_valid_seed_has_no_findings() -> None:
    result = analyze(create_snapshot(FIXTURES / "valid-skill"))
    assert result.findings == []
    assert result.evidence
    assert "agent_skills_metadata" in result.coverage.completed


def test_hostile_seed_is_advisory_and_deterministic() -> None:
    result = analyze(create_snapshot(FIXTURES / "hostile-skill"))
    assert {finding.rule_id for finding in result.findings} == {
        "ASD004",
        "ASD005",
        "ASD006",
        "ASD007",
    }
    assert all(finding.causal_role == "indeterminate" for finding in result.findings)


def test_detects_windows_and_encoded_path_escape(tmp_path: Path) -> None:
    root = tmp_path / "path-hazards"
    root.mkdir()
    (root / "SKILL.md").write_text(
        "---\nname: path-hazards\ndescription: Path hazards.\n---\n"
        "[drive](C:\\secret.txt) [encoded](%2e%2e/secret.txt) [unc](\\\\host\\share)",
        encoding="utf-8",
    )
    result = analyze(create_snapshot(root))
    assert [finding.rule_id for finding in result.findings].count("ASD004") == 3


def test_first_class_script_analyzers(tmp_path: Path) -> None:
    root = tmp_path / "script-check"
    scripts = root / "scripts"
    scripts.mkdir(parents=True)
    (root / "SKILL.md").write_text(
        "---\nname: script-check\ndescription: Script analyzer fixture.\n---",
        encoding="utf-8",
    )
    cases = {
        "risk.py": "import os\nos.system(user_input)\n",
        "risk.sh": 'eval "$COMMAND"\n',
        "risk.ps1": "$ErrorActionPreference = 'SilentlyContinue'\n",
        "risk.ts": "eval(source)\n",
        "risk.cmd": "call %USER_COMMAND%\n",
    }
    for name, content in cases.items():
        (scripts / name).write_text(content, encoding="utf-8")
    result = analyze(create_snapshot(root))
    matched_paths = {
        finding.path for finding in result.findings if finding.rule_id in {"ASD016", "ASD017"}
    }
    assert matched_paths == {f"scripts/{name}" for name in cases}
