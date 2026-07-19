import pytest

from skill_doctor.frontmatter import (
    FrontmatterError,
    parse_skill_document,
    validate_skill_document,
)


def test_parses_required_scalars() -> None:
    document = parse_skill_document("---\nname: demo\ndescription: Demo skill\n---\nBody")
    assert document.metadata["name"] == "demo"
    assert document.body == "Body"


def test_rejects_duplicate_keys() -> None:
    with pytest.raises(FrontmatterError, match="duplicate"):
        parse_skill_document("---\nname: one\nname: two\ndescription: Demo\n---")


def test_preserves_standard_metadata_map_and_comments() -> None:
    document = parse_skill_document(
        "---\nname: demo # selected name\ndescription: Demo skill\n"
        'metadata:\n  author: example-org\n  version: "1.0"\n'
        "x-platform:\n  mode: strict\n---\nBody"
    )
    assert document.metadata["metadata"] == {
        "author": "example-org",
        "version": "1.0",
    }
    assert document.metadata["x-platform"] == {"mode": "strict"}
    assert validate_skill_document(document, "demo") == []


def test_reports_agent_skills_name_constraints() -> None:
    document = parse_skill_document("---\nname: Bad--Name\ndescription: Demo skill\n---")
    issues = validate_skill_document(document, "other")
    assert {issue.rule_id for issue in issues} == {"ASD010"}


def test_rejects_implicit_non_string_yaml_value() -> None:
    with pytest.raises(FrontmatterError, match="YAML string"):
        parse_skill_document("---\nname: demo\ndescription: true\n---")
