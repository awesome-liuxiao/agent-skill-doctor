from __future__ import annotations

import json
import re
from dataclasses import dataclass

KEY = re.compile(r"^[A-Za-z][A-Za-z0-9_-]*$")
SKILL_NAME = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
YAML_NON_STRING = re.compile(
    r"(?i)^(?:null|true|false|yes|no|on|off|~|"
    r"[-+]?(?:0|[1-9][0-9_]*)(?:\.[0-9_]+)?(?:e[-+]?[0-9]+)?)$"
)
MAX_FRONTMATTER_LINES = 100

MetadataValue = str | dict[str, str]


class FrontmatterError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class SkillDocument:
    metadata: dict[str, MetadataValue]
    field_lines: dict[str, int]
    body: str
    body_start_line: int


@dataclass(frozen=True, slots=True)
class MetadataIssue:
    rule_id: str
    title: str
    message: str
    line: int


def _without_comment(value: str) -> str:
    quote: str | None = None
    escaped = False
    for index, character in enumerate(value):
        if quote == '"' and character == "\\" and not escaped:
            escaped = True
            continue
        if character in {"'", '"'} and not escaped:
            if quote is None:
                quote = character
            elif quote == character:
                quote = None
        if character == "#" and quote is None and (index == 0 or value[index - 1].isspace()):
            return value[:index].rstrip()
        escaped = False
    return value.rstrip()


def _parse_string(value: str, line: int) -> str:
    value = _without_comment(value).strip()
    if not value:
        raise FrontmatterError(f"string value is empty at line {line}")
    if value.startswith('"'):
        try:
            parsed = json.loads(value)
        except json.JSONDecodeError as error:
            raise FrontmatterError(f"invalid double-quoted string at line {line}") from error
        if not isinstance(parsed, str):
            raise FrontmatterError(f"only string values are supported at line {line}")
        return parsed
    if value.startswith("'"):
        if len(value) < 2 or not value.endswith("'"):
            raise FrontmatterError(f"invalid single-quoted string at line {line}")
        return value[1:-1].replace("''", "'")
    if value[0] in "[{|>&*!@`":
        raise FrontmatterError(
            f"only plain or quoted string values and one-level maps are supported at line {line}"
        )
    if YAML_NON_STRING.fullmatch(value):
        raise FrontmatterError(f"value must be a YAML string at line {line}")
    return value


def _split_entry(raw: str, line: int) -> tuple[str, str]:
    if ":" not in raw:
        raise FrontmatterError(f"unsupported frontmatter syntax at line {line}")
    key, value = raw.split(":", 1)
    key = key.strip()
    if not KEY.fullmatch(key):
        raise FrontmatterError(f"invalid frontmatter key at line {line}")
    return key, value


def parse_skill_document(text: str) -> SkillDocument:
    """Parse the bounded Agent Skills frontmatter profile used by the static slice."""
    lines = text.splitlines()
    if not lines or lines[0].strip() != "---":
        raise FrontmatterError("SKILL.md must begin with a YAML frontmatter delimiter")

    metadata: dict[str, MetadataValue] = {}
    field_lines: dict[str, int] = {}
    current_map: dict[str, str] | None = None
    current_map_name: str | None = None
    map_indent: int | None = None
    closing: int | None = None

    for index, raw in enumerate(lines[1 : MAX_FRONTMATTER_LINES + 1], start=2):
        if raw.strip() == "---":
            closing = index
            break
        if "\t" in raw[: len(raw) - len(raw.lstrip())]:
            raise FrontmatterError(f"tabs are not allowed for indentation at line {index}")
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue

        indent = len(raw) - len(raw.lstrip(" "))
        if indent:
            if current_map is None or current_map_name is None:
                raise FrontmatterError(f"unexpected indentation at line {index}")
            if map_indent is None:
                map_indent = indent
            elif indent != map_indent:
                raise FrontmatterError(f"inconsistent map indentation at line {index}")
            key, raw_value = _split_entry(raw.strip(), index)
            if key in current_map:
                raise FrontmatterError(
                    f"duplicate map key {key!r} in {current_map_name!r} at line {index}"
                )
            current_map[key] = _parse_string(raw_value, index)
            continue

        current_map = None
        current_map_name = None
        map_indent = None
        key, raw_value = _split_entry(raw, index)
        if key in metadata:
            raise FrontmatterError(f"duplicate frontmatter key {key!r} at line {index}")
        field_lines[key] = index
        if not _without_comment(raw_value).strip():
            mapping: dict[str, str] = {}
            metadata[key] = mapping
            current_map = mapping
            current_map_name = key
        else:
            metadata[key] = _parse_string(raw_value, index)

    if closing is None:
        raise FrontmatterError(f"frontmatter is not closed within {MAX_FRONTMATTER_LINES} lines")
    return SkillDocument(metadata, field_lines, "\n".join(lines[closing:]), closing + 1)


def validate_skill_document(document: SkillDocument, directory_name: str) -> list[MetadataIssue]:
    issues: list[MetadataIssue] = []
    name = document.metadata.get("name")
    name_line = document.field_lines.get("name", 1)
    if not isinstance(name, str) or not name:
        issues.append(
            MetadataIssue(
                "ASD009",
                "Missing or non-string skill name",
                "The Agent Skills specification requires a non-empty string name.",
                name_line,
            )
        )
    elif len(name) > 64 or not SKILL_NAME.fullmatch(name):
        issues.append(
            MetadataIssue(
                "ASD010",
                "Invalid skill name",
                "The name must be at most 64 lowercase letters, digits, or single hyphens.",
                name_line,
            )
        )
    elif name != directory_name:
        issues.append(
            MetadataIssue(
                "ASD011",
                "Skill name does not match its directory",
                f"The declared name {name!r} does not match directory {directory_name!r}.",
                name_line,
            )
        )

    description = document.metadata.get("description")
    if not isinstance(description, str) or not 1 <= len(description) <= 1024:
        issues.append(
            MetadataIssue(
                "ASD012",
                "Invalid skill description",
                "The description must be a non-empty string of at most 1024 characters.",
                document.field_lines.get("description", 1),
            )
        )

    compatibility = document.metadata.get("compatibility")
    if compatibility is not None and (
        not isinstance(compatibility, str) or not 1 <= len(compatibility) <= 500
    ):
        issues.append(
            MetadataIssue(
                "ASD013",
                "Invalid compatibility metadata",
                "Compatibility must be a non-empty string of at most 500 characters.",
                document.field_lines.get("compatibility", 1),
            )
        )

    metadata_map = document.metadata.get("metadata")
    if metadata_map is not None and not isinstance(metadata_map, dict):
        issues.append(
            MetadataIssue(
                "ASD014",
                "Invalid metadata extension map",
                "The optional metadata field must be a map of string keys to string values.",
                document.field_lines.get("metadata", 1),
            )
        )

    for field in ("license", "allowed-tools"):
        value = document.metadata.get(field)
        if value is not None and not isinstance(value, str):
            issues.append(
                MetadataIssue(
                    "ASD015",
                    f"Invalid {field} metadata",
                    f"The optional {field} field must be a string.",
                    document.field_lines.get(field, 1),
                )
            )
    return issues
