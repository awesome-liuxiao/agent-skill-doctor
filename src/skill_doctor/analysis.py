from __future__ import annotations

import hashlib
import re
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from pathlib import PurePosixPath
from urllib.parse import unquote, urlsplit

from skill_doctor.errors import OperationCancelled
from skill_doctor.frontmatter import (
    FrontmatterError,
    MetadataIssue,
    parse_skill_document,
    validate_skill_document,
)
from skill_doctor.models import Coverage, Evidence, Finding, Severity, StaticAnalysis
from skill_doctor.snapshot import Snapshot

RULESET_VERSION = "2026-07-16.1"

MARKDOWN_LINK = re.compile(
    r"!?\[[^\]\n]*\]\(\s*(?:<(?P<angle>[^>\n]+)>|(?P<plain>[^)\s]+))"
    r"(?:\s+(?:\"[^\"]*\"|'[^']*'))?\s*\)"
)
BARE_RESOURCE = re.compile(
    r"(?<![\w./\\-])(?P<path>(?:scripts|references|assets)[/\\]"
    r"[\w@+.,{}\[\]-]+(?:[/\\][\w@+.,{}\[\]-]+)*)"
)
FENCE = re.compile(r"^\s*(?P<marker>`{3,}|~{3,})")
REFERENCE_DIRECTIVE = re.compile(
    r"(?i)\b(?:read|see|open|load|use|run|execute|consult|review|follow)\b"
)
WINDOWS_ABSOLUTE = re.compile(r"^[A-Za-z]:[/\\]")
SUSPICIOUS = re.compile(
    r"(?i)(?:curl|wget)\b[^\n]*(?:\||>)|invoke-expression|\biex\b|rm\s+-rf\s+[/~]|"
    r"powershell\b[^\n]*-(?:enc|encodedcommand)"
)
SECRET = re.compile(
    r"(?i)(?:api[_-]?key|secret|token|password)\s*[:=]\s*['\"]?"
    r"([A-Za-z0-9_./+=-]{12,})"
)

SCRIPT_EXTENSIONS: dict[str, frozenset[str]] = {
    "python": frozenset({".py", ".pyw"}),
    "posix_shell": frozenset({".sh", ".bash", ".zsh", ".ksh"}),
    "powershell": frozenset({".ps1", ".psm1", ".psd1"}),
    "javascript_typescript": frozenset(
        {".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".mts", ".cts"}
    ),
    "windows_batch": frozenset({".bat", ".cmd"}),
}
SCRIPT_PATTERNS: dict[str, tuple[re.Pattern[str], ...]] = {
    "python": (
        re.compile(r"\b(?:eval|exec)\s*\("),
        re.compile(r"\bos\.system\s*\("),
        re.compile(
            r"\bsubprocess\.(?:run|Popen|call|check_call|check_output)"
            r"\([^\n)]*\bshell\s*=\s*True"
        ),
    ),
    "posix_shell": (
        re.compile(r"(?m)(?:^|[;&|])\s*eval\s+[\"']?\$"),
        re.compile(r"(?m)(?:^|[;&|])\s*(?:ba)?sh\s+-c\s+[\"']?\$"),
    ),
    "powershell": (),
    "javascript_typescript": (
        re.compile(r"\beval\s*\("),
        re.compile(r"\bnew\s+Function\s*\("),
        re.compile(r"\bchild_process\s*\.\s*exec\s*\("),
    ),
    "windows_batch": (re.compile(r"(?i)\bcall\s+%[^%\r\n]+%"),),
}
SUPPRESSION_PATTERNS: dict[str, re.Pattern[str]] = {
    "python": re.compile(r"(?m)^\s*except(?:\s+Exception)?\s*:\s*(?:#.*)?\n\s+pass\b"),
    "posix_shell": re.compile(r"(?:\|\|\s*true\b|2>\s*/dev/null)"),
    "powershell": re.compile(
        r"(?i)(?:-ErrorAction\s+SilentlyContinue|\$ErrorActionPreference\s*=\s*"
        r"['\"]?SilentlyContinue)"
    ),
    "javascript_typescript": re.compile(r"\.catch\s*\(\s*\(?.*?\)?\s*=>\s*\{\s*\}\s*\)"),
    "windows_batch": re.compile(r"(?i)2>\s*nul\b"),
}


@dataclass(frozen=True, slots=True)
class Reference:
    raw: str
    line: int


def _id(prefix: str, value: str) -> str:
    encoded = value.encode("utf-8", errors="surrogatepass")
    return f"{prefix}-{hashlib.sha256(encoded).hexdigest()[:16]}"


def _line(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def _references(text: str) -> Iterator[Reference]:
    visible_lines: list[str] = []
    fence_character: str | None = None
    fence_length = 0
    for raw_line in text.splitlines(keepends=True):
        fence = FENCE.match(raw_line)
        if fence is not None:
            marker = fence.group("marker")
            if fence_character is None:
                fence_character = marker[0]
                fence_length = len(marker)
            elif marker[0] == fence_character and len(marker) >= fence_length:
                fence_character = None
                fence_length = 0
            visible_lines.append("\n" if raw_line.endswith("\n") else "")
        elif fence_character is None:
            visible_lines.append(raw_line)
        else:
            visible_lines.append("\n" if raw_line.endswith("\n") else "")
    visible = "".join(visible_lines)
    seen: set[tuple[str, int]] = set()
    for match in MARKDOWN_LINK.finditer(visible):
        raw = match.group("angle") or match.group("plain")
        line_number = _line(visible, match.start())
        seen.add((raw, line_number))
        yield Reference(raw, line_number)
    for match in BARE_RESOURCE.finditer(visible):
        raw = match.group("path").rstrip(".,;:!?")
        line_number = _line(visible, match.start())
        line_start = visible.rfind("\n", 0, match.start()) + 1
        prefix = visible[line_start : match.start()]
        if "example" in prefix.casefold() or REFERENCE_DIRECTIVE.search(prefix) is None:
            continue
        if (raw, line_number) not in seen:
            yield Reference(raw, line_number)


def _reference_path(raw: str) -> tuple[str | None, bool]:
    decoded = unquote(raw.strip())
    if not decoded or decoded.startswith("#"):
        return None, False
    if (
        decoded.startswith(("/", "\\"))
        or WINDOWS_ABSOLUTE.match(decoded)
        or decoded.lower().startswith("file:")
    ):
        return decoded, True
    parsed = urlsplit(decoded)
    if parsed.scheme or parsed.netloc:
        return None, False
    path = PurePosixPath(parsed.path.replace("\\", "/"))
    unsafe = path.is_absolute() or ".." in path.parts
    return str(path), unsafe


def _add_pattern_finding(
    findings: list[Finding],
    evidence: list[Evidence],
    *,
    rule_id: str,
    title: str,
    message: str,
    severity: Severity,
    confidence: str,
    path: str,
    digest: str,
    text: str,
    match: re.Match[str],
) -> None:
    line = _line(text, match.start())
    evidence_id = _id("ev-pattern", f"{rule_id}:{path}:{line}")
    evidence.append(Evidence(evidence_id, "pattern_match", title, digest, path, line))
    findings.append(
        Finding(
            _id("finding", evidence_id),
            rule_id,
            title,
            message,
            severity,
            confidence,  # type: ignore[arg-type]
            "indeterminate",
            (evidence_id,),
            path,
            line,
        )
    )


def _script_language(path: str, text: str) -> str | None:
    suffix = PurePosixPath(path).suffix.lower()
    for language, extensions in SCRIPT_EXTENSIONS.items():
        if suffix in extensions:
            return language
    first_line = text.splitlines()[0] if text.splitlines() else ""
    if first_line.startswith("#!"):
        if re.search(r"\bpython(?:3(?:\.\d+)?)?\b", first_line):
            return "python"
        if re.search(r"\b(?:ba|z|k)?sh\b", first_line):
            return "posix_shell"
        if re.search(r"\b(?:node|deno|bun)\b", first_line):
            return "javascript_typescript"
        if re.search(r"\b(?:pwsh|powershell)\b", first_line, re.IGNORECASE):
            return "powershell"
    return None


def _metadata_findings(
    issues: list[MetadataIssue],
    skill_digest: str,
    findings: list[Finding],
    evidence: list[Evidence],
) -> None:
    for issue in issues:
        evidence_id = _id("ev-metadata", f"{issue.rule_id}:{issue.line}:{issue.message}")
        evidence.append(
            Evidence(
                evidence_id,
                "metadata_validation",
                issue.title,
                skill_digest,
                "SKILL.md",
                issue.line,
            )
        )
        findings.append(
            Finding(
                _id("finding", evidence_id),
                issue.rule_id,
                issue.title,
                issue.message,
                "medium",
                "high",
                "indeterminate",
                (evidence_id,),
                "SKILL.md",
                issue.line,
            )
        )


def analyze(
    snapshot: Snapshot,
    *,
    cancelled: Callable[[], bool] | None = None,
) -> StaticAnalysis:
    def check_cancelled() -> None:
        if cancelled is not None and cancelled():
            raise OperationCancelled("static analysis cancelled")

    check_cancelled()
    legacy_command = snapshot.kind == "claude_command"
    findings: list[Finding] = []
    evidence: list[Evidence] = []
    completed = ["local_references", "static_patterns", "script_analysis"]
    skipped: list[str] = []
    failed: list[str] = []
    by_path = {item.relative_path: item for item in snapshot.files}
    skill = by_path.get("SKILL.md")

    skill_text: str | None = None
    if skill is None:
        evidence.append(Evidence("ev-skill-missing", "absence", "SKILL.md is absent"))
        findings.append(
            Finding(
                "finding-skill-missing",
                "ASD001",
                "Missing SKILL.md",
                "The selected directory does not contain SKILL.md.",
                "high",
                "high",
                "indeterminate",
                ("ev-skill-missing",),
                "SKILL.md",
            )
        )
        failed.extend(("skill_document", "frontmatter", "local_references"))
        completed.remove("local_references")
    else:
        evidence.append(
            Evidence(
                "ev-skill-document",
                "snapshot_file",
                "Snapshotted SKILL.md",
                skill.digest,
                "SKILL.md",
            )
        )
        try:
            skill_text = skill.data.decode("utf-8")
        except UnicodeDecodeError:
            findings.append(
                Finding(
                    "finding-skill-encoding",
                    "ASD002",
                    "Invalid SKILL.md encoding",
                    "SKILL.md is not valid UTF-8.",
                    "high",
                    "high",
                    "indeterminate",
                    ("ev-skill-document",),
                    "SKILL.md",
                )
            )
            failed.extend(("skill_document", "frontmatter", "local_references"))
            completed.remove("local_references")

    if skill_text is not None and skill is not None:
        if legacy_command and not skill_text.startswith("---"):
            completed.append("claude_command_metadata")
        else:
            try:
                document = parse_skill_document(skill_text)
            except FrontmatterError as error:
                findings.append(
                    Finding(
                        "finding-frontmatter",
                        "ASD003",
                        "Invalid frontmatter",
                        str(error),
                        "medium",
                        "high",
                        "indeterminate",
                        ("ev-skill-document",),
                        "SKILL.md",
                    )
                )
                failed.append("frontmatter")
            else:
                completed.append("frontmatter")
                if legacy_command:
                    completed.append("claude_command_metadata")
                else:
                    _metadata_findings(
                        validate_skill_document(document, snapshot.root.name),
                        skill.digest,
                        findings,
                        evidence,
                    )
                    completed.append("agent_skills_metadata")

        known = set(by_path)
        for reference in _references(skill_text):
            check_cancelled()
            normalized, unsafe = _reference_path(reference.raw)
            if normalized is None:
                continue
            evidence_id = _id(
                "ev-link",
                f"SKILL.md:{reference.line}:{reference.raw}",
            )
            evidence.append(
                Evidence(
                    evidence_id,
                    "local_reference",
                    f"Local reference: {reference.raw}",
                    skill.digest,
                    "SKILL.md",
                    reference.line,
                )
            )
            if unsafe:
                findings.append(
                    Finding(
                        _id("finding", "path:" + evidence_id),
                        "ASD004",
                        "Unsafe local reference",
                        "A local reference may escape the skill root.",
                        "high",
                        "high",
                        "indeterminate",
                        (evidence_id,),
                        "SKILL.md",
                        reference.line,
                    )
                )
            elif normalized not in known and not legacy_command:
                findings.append(
                    Finding(
                        _id("finding", "broken:" + evidence_id),
                        "ASD005",
                        "Broken local reference",
                        f"Referenced file does not exist: {normalized}",
                        "medium",
                        "high",
                        "indeterminate",
                        (evidence_id,),
                        "SKILL.md",
                        reference.line,
                    )
                )
            elif normalized not in known:
                skipped.append(
                    f"local_references:SKILL.md:{reference.line}:legacy_command_project_context"
                )

    for item in snapshot.files:
        check_cancelled()
        if item.relative_path.startswith(".git/"):
            skipped.append(f"static_patterns:{item.relative_path}:version_control_metadata")
            continue
        try:
            decoded = item.data.decode("utf-8")
        except UnicodeDecodeError:
            if item.relative_path != "SKILL.md":
                skipped.append(f"static_patterns:{item.relative_path}:non_utf8")
            continue

        for rule_id, title, regex, severity in (
            ("ASD006", "Credential-shaped value", SECRET, "high"),
            ("ASD007", "Suspicious command pattern", SUSPICIOUS, "medium"),
        ):
            pattern_match = regex.search(decoded)
            if pattern_match:
                _add_pattern_finding(
                    findings,
                    evidence,
                    rule_id=rule_id,
                    title=title,
                    message=(
                        f"Deterministic pattern {rule_id} matched; review the referenced line."
                    ),
                    severity=severity,  # type: ignore[arg-type]
                    confidence="medium",
                    path=item.relative_path,
                    digest=item.digest,
                    text=decoded,
                    match=pattern_match,
                )

        language = _script_language(item.relative_path, decoded)
        if item.relative_path.startswith("scripts/") and language is None:
            skipped.append(f"script_analysis:{item.relative_path}:unsupported_language")
        if language is None:
            continue
        for regex in SCRIPT_PATTERNS[language]:
            pattern_match = regex.search(decoded)
            if pattern_match:
                _add_pattern_finding(
                    findings,
                    evidence,
                    rule_id="ASD016",
                    title="Dynamic command or code evaluation",
                    message=(
                        f"The {language} analyzer found dynamic evaluation; verify that input "
                        "cannot influence the evaluated value."
                    ),
                    severity="medium",
                    confidence="medium",
                    path=item.relative_path,
                    digest=item.digest,
                    text=decoded,
                    match=pattern_match,
                )
                break
        suppression_match = SUPPRESSION_PATTERNS[language].search(decoded)
        if suppression_match:
            _add_pattern_finding(
                findings,
                evidence,
                rule_id="ASD017",
                title="Broad error suppression",
                message=(
                    f"The {language} analyzer found an error-suppression fallback that may hide "
                    "a failed operation."
                ),
                severity="low",
                confidence="medium",
                path=item.relative_path,
                digest=item.digest,
                text=decoded,
                match=suppression_match,
            )

    for skipped_path in snapshot.skipped_paths:
        check_cancelled()
        evidence_id = _id(
            "ev-skipped",
            f"{skipped_path.reason}:{skipped_path.relative_path}",
        )
        if skipped_path.reason == "symlink":
            title = "Skipped symlink"
            message = (
                "A symlink or junction was excluded from the snapshot; referenced content may "
                "be incomplete."
            )
        else:
            title = "Skipped non-regular file"
            message = "A non-regular filesystem entry was excluded from static analysis."
        evidence.append(
            Evidence(
                evidence_id,
                "skipped_path",
                title,
                path=skipped_path.relative_path,
            )
        )
        findings.append(
            Finding(
                _id("finding", evidence_id),
                "ASD008",
                title,
                message,
                "low",
                "high",
                "indeterminate",
                (evidence_id,),
                skipped_path.relative_path,
            )
        )
        skipped.append(f"snapshot:{skipped_path.relative_path}:{skipped_path.reason}")

    unsupported = ["dynamic_execution", "platform_resolution", "semantic_correctness"]
    if legacy_command:
        unsupported.append("legacy_command_project_reference_resolution")
    coverage = Coverage(
        completed=tuple(dict.fromkeys(completed)),
        skipped=tuple(sorted(set(skipped))),
        unsupported=tuple(unsupported),
        failed=tuple(dict.fromkeys(failed)),
    )
    check_cancelled()
    return StaticAnalysis(findings, evidence, coverage)
