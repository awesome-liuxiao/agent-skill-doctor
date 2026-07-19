from __future__ import annotations

import json
import os
import sys
import tomllib
from collections import defaultdict
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import asdict, dataclass, field, replace
from hashlib import sha256
from pathlib import Path
from typing import Any, Literal, cast

from skill_doctor.frontmatter import FrontmatterError, parse_skill_document

Platform = Literal["codex", "claude"]
CopyStatus = Literal["active", "inactive", "shadowed", "ambiguous", "unresolved"]
MAX_DISCOVERY_MANIFEST_BYTES = 1_048_576


class DiscoveryError(RuntimeError):
    pass


class SkillNotFound(DiscoveryError):
    pass


class AmbiguousSkill(DiscoveryError):
    def __init__(self, name: str, copies: Sequence[DiscoveredSkill]) -> None:
        self.name = name
        self.copies = tuple(copies)
        locations = ", ".join(str(copy.skill_path) for copy in copies)
        super().__init__(f"skill {name!r} is ambiguous: {locations}")


@dataclass(frozen=True, slots=True)
class DiscoveryDiagnostic:
    code: str
    message: str
    paths: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class DiscoveredSkill:
    copy_id: str
    platform: Platform
    name: str
    declared_name: str | None
    source: str
    status: CopyStatus
    skill_path: Path
    manifest_path: Path
    resolved_path: Path | None
    selector: str
    precedence: int
    enabled: bool
    is_symlink: bool
    plugin: str | None = None
    status_reason: str | None = None

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        for key in ("skill_path", "manifest_path", "resolved_path"):
            value = payload[key]
            payload[key] = None if value is None else str(value)
        return payload


@dataclass(frozen=True, slots=True)
class Inventory:
    platform: Platform
    cwd: Path
    repository_root: Path
    copies: tuple[DiscoveredSkill, ...] = ()
    diagnostics: tuple[DiscoveryDiagnostic, ...] = ()
    configuration_sources: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "platform": self.platform,
            "cwd": str(self.cwd),
            "repository_root": str(self.repository_root),
            "copies": [copy.to_dict() for copy in self.copies],
            "diagnostics": [diagnostic.to_dict() for diagnostic in self.diagnostics],
            "configuration_sources": list(self.configuration_sources),
        }

    def resolve(self, name: str) -> DiscoveredSkill:
        selectable = [
            copy
            for copy in self.copies
            if copy.selector == name and copy.status in {"active", "ambiguous"}
        ]
        if not selectable:
            raise SkillNotFound(f"no active {self.platform} skill matches {name!r}")
        active = [copy for copy in selectable if copy.status == "active"]
        if len(active) == 1 and len(selectable) == 1:
            return active[0]
        raise AmbiguousSkill(name, selectable)


@dataclass(frozen=True, slots=True)
class DiscoveryContext:
    cwd: Path
    repository_root: Path | None = None
    home: Path | None = None
    codex_home: Path | None = None
    claude_home: Path | None = None
    codex_admin_skills: Path | None = None
    claude_managed_root: Path | None = None
    added_directories: tuple[Path, ...] = ()
    active_paths: tuple[Path, ...] = ()
    plugin_roots: tuple[Path, ...] = ()

    def normalized(self) -> DiscoveryContext:
        cwd = _absolute(self.cwd)
        repository_root = (
            find_repository_root(cwd)
            if self.repository_root is None
            else _absolute(self.repository_root)
        )
        if not cwd.is_relative_to(repository_root):
            raise DiscoveryError("working directory must be inside the repository root")
        home = _absolute(self.home or Path.home())
        return replace(
            self,
            cwd=cwd,
            repository_root=repository_root,
            home=home,
            codex_home=_absolute(self.codex_home or home / ".codex"),
            claude_home=_absolute(self.claude_home or home / ".claude"),
            codex_admin_skills=_absolute(self.codex_admin_skills or _default_codex_admin_skills()),
            claude_managed_root=_absolute(
                self.claude_managed_root or _default_claude_managed_root()
            ),
            added_directories=tuple(_absolute(path) for path in self.added_directories),
            active_paths=tuple(_absolute(path) for path in self.active_paths),
            plugin_roots=tuple(_absolute(path) for path in self.plugin_roots),
        )


@dataclass(frozen=True, slots=True)
class _Candidate:
    platform: Platform
    source: str
    root: Path
    skill_path: Path
    manifest_path: Path
    name: str
    declared_name: str | None
    selector: str
    precedence: int
    enabled: bool = True
    plugin: str | None = None
    reason: str | None = None
    force_unresolved: bool = False


@dataclass(slots=True)
class _Settings:
    values: dict[str, Any] = field(default_factory=dict)
    sources: list[str] = field(default_factory=list)
    diagnostics: list[DiscoveryDiagnostic] = field(default_factory=list)


def _absolute(path: Path) -> Path:
    return Path(os.path.abspath(path.expanduser()))


def find_repository_root(cwd: Path) -> Path:
    current = _absolute(cwd)
    for candidate in (current, *current.parents):
        if (candidate / ".git").exists():
            return candidate
    return current


def _default_codex_admin_skills() -> Path:
    if os.name == "nt":
        return Path(os.environ.get("PROGRAMDATA", "C:/ProgramData")) / "codex" / "skills"
    return Path("/etc/codex/skills")


def _default_claude_managed_root() -> Path:
    if os.name == "nt":
        return Path(os.environ.get("ProgramFiles", "C:/Program Files")) / "ClaudeCode"
    if sys.platform == "darwin":
        return Path("/Library/Application Support/ClaudeCode")
    return Path("/etc/claude-code")


def _walk_to_root(start: Path, root: Path) -> tuple[Path, ...]:
    result: list[Path] = []
    current = start
    while True:
        result.append(current)
        if current == root:
            return tuple(result)
        if current.parent == current or not current.is_relative_to(root):
            return tuple(result)
        current = current.parent


def _read_json(path: Path, settings: _Settings) -> dict[str, Any]:
    if not path.is_file():
        return {}
    settings.sources.append(str(path))
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(payload, dict):
            raise ValueError("configuration root is not an object")
        return cast(dict[str, Any], payload)
    except (OSError, UnicodeError, ValueError) as error:
        settings.diagnostics.append(
            DiscoveryDiagnostic(
                "DISCOVERY_CONFIG",
                f"Cannot read configuration: {error}",
                (str(path),),
            )
        )
        return {}


def _read_toml(path: Path, settings: _Settings) -> dict[str, Any]:
    if not path.is_file():
        return {}
    settings.sources.append(str(path))
    try:
        return tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, tomllib.TOMLDecodeError) as error:
        settings.diagnostics.append(
            DiscoveryDiagnostic(
                "DISCOVERY_CONFIG",
                f"Cannot read configuration: {error}",
                (str(path),),
            )
        )
        return {}


def _deep_merge(target: dict[str, Any], incoming: Mapping[str, Any]) -> None:
    for key, value in incoming.items():
        current = target.get(key)
        if isinstance(current, dict) and isinstance(value, Mapping):
            _deep_merge(current, cast(Mapping[str, Any], value))
        else:
            target[key] = value


def _manifest_name(path: Path, fallback: str) -> tuple[str, str | None, str | None]:
    try:
        with path.open("rb") as stream:
            data = stream.read(MAX_DISCOVERY_MANIFEST_BYTES + 1)
        if len(data) > MAX_DISCOVERY_MANIFEST_BYTES:
            return fallback, None, "manifest exceeds the discovery read limit"
        text = data.decode("utf-8")
        document = parse_skill_document(text)
        declared = document.metadata.get("name")
        return fallback, declared if isinstance(declared, str) else None, None
    except (OSError, UnicodeError, FrontmatterError) as error:
        return fallback, None, str(error)


def _iter_skill_directories(root: Path) -> Iterable[tuple[Path, Path]]:
    try:
        children = sorted(root.iterdir(), key=lambda path: (path.name.casefold(), path.name))
    except OSError:
        return
    for child in children:
        try:
            if child.is_dir() or child.is_symlink():
                yield child, child / "SKILL.md"
        except OSError:
            yield child, child / "SKILL.md"


def _candidate_for_directory(
    platform: Platform,
    source: str,
    root: Path,
    skill_path: Path,
    manifest_path: Path,
    *,
    precedence: int,
    selector_prefix: str = "",
    enabled: bool = True,
    plugin: str | None = None,
    reason: str | None = None,
) -> _Candidate:
    fallback = skill_path.name
    name, declared_name, manifest_error = _manifest_name(manifest_path, fallback)
    selector = f"{selector_prefix}{name}"
    return _Candidate(
        platform,
        source,
        root,
        skill_path,
        manifest_path,
        name,
        declared_name,
        selector,
        precedence,
        enabled,
        plugin,
        reason or manifest_error,
        manifest_error is not None and not manifest_path.is_file(),
    )


def _materialize(
    candidates: Sequence[_Candidate],
) -> tuple[list[DiscoveredSkill], list[DiscoveryDiagnostic]]:
    copies: list[DiscoveredSkill] = []
    diagnostics: list[DiscoveryDiagnostic] = []
    for candidate in candidates:
        resolved: Path | None = None
        unresolved = candidate.force_unresolved
        try:
            resolved = candidate.skill_path.resolve(strict=True)
            manifest = candidate.manifest_path.resolve(strict=True)
            if not manifest.is_file() or not manifest.is_relative_to(resolved):
                unresolved = True
        except OSError:
            unresolved = True
        status: CopyStatus = (
            "unresolved" if unresolved else ("active" if candidate.enabled else "inactive")
        )
        identity = "\0".join(
            (
                candidate.platform,
                candidate.source,
                str(candidate.skill_path),
                candidate.selector,
            )
        )
        copy = DiscoveredSkill(
            sha256(identity.encode("utf-8", errors="surrogatepass")).hexdigest()[:20],
            candidate.platform,
            candidate.name,
            candidate.declared_name,
            candidate.source,
            status,
            candidate.skill_path,
            candidate.manifest_path,
            resolved,
            candidate.selector,
            candidate.precedence,
            candidate.enabled,
            candidate.skill_path.is_symlink(),
            candidate.plugin,
            candidate.reason if status != "active" else None,
        )
        copies.append(copy)
        if unresolved:
            diagnostics.append(
                DiscoveryDiagnostic(
                    "DISCOVERY_UNRESOLVED",
                    candidate.reason or "Skill entrypoint cannot be resolved",
                    (str(candidate.skill_path), str(candidate.manifest_path)),
                )
            )

    by_target: dict[str, list[int]] = defaultdict(list)
    for index, copy in enumerate(copies):
        if copy.resolved_path is not None and copy.status != "unresolved":
            by_target[os.path.normcase(str(copy.resolved_path))].append(index)
    for indexes in by_target.values():
        if len(indexes) < 2:
            continue
        ordered = sorted(indexes, key=lambda index: copies[index].precedence)
        keeper = ordered[0]
        paths = tuple(str(copies[index].skill_path) for index in ordered)
        diagnostics.append(
            DiscoveryDiagnostic(
                "DISCOVERY_SYMLINK_DEDUP",
                "The same resolved skill target is reachable from multiple locations "
                "and loads once.",
                paths,
            )
        )
        for index in ordered[1:]:
            copy = copies[index]
            copies[index] = replace(
                copy,
                status="shadowed" if copy.enabled else "inactive",
                status_reason=f"same resolved target as {copies[keeper].skill_path}",
            )
    return copies, diagnostics


def _codex_disabled_paths(config: Mapping[str, Any]) -> set[str]:
    disabled: set[str] = set()
    skills = config.get("skills")
    if not isinstance(skills, Mapping):
        return disabled
    entries = skills.get("config")
    if not isinstance(entries, list):
        return disabled
    for entry in entries:
        if isinstance(entry, Mapping) and entry.get("enabled") is False:
            path = entry.get("path")
            if isinstance(path, str):
                disabled.add(os.path.normcase(str(_absolute(Path(path)))))
    return disabled


def _codex_plugin_state(
    config: Mapping[str, Any],
    plugin_name: str,
    identifier: str,
) -> bool | None:
    plugins = config.get("plugins")
    if not isinstance(plugins, Mapping):
        return None
    entry = plugins.get(identifier, plugins.get(plugin_name))
    if isinstance(entry, bool):
        return entry
    if isinstance(entry, Mapping) and isinstance(entry.get("enabled"), bool):
        return bool(entry["enabled"])
    return None


def discover_codex(context: DiscoveryContext) -> Inventory:
    ctx = context.normalized()
    repository_root = cast(Path, ctx.repository_root)
    home = cast(Path, ctx.home)
    codex_home = cast(Path, ctx.codex_home)
    codex_admin_skills = cast(Path, ctx.codex_admin_skills)
    settings = _Settings()
    config = _read_toml(codex_home / "config.toml", settings)
    disabled = _codex_disabled_paths(config)
    candidates: list[_Candidate] = []

    roots: list[tuple[str, Path, int]] = []
    for index, directory in enumerate(_walk_to_root(ctx.cwd, repository_root)):
        roots.append(("repository", directory / ".agents" / "skills", 100 + index))
    roots.extend(
        (
            ("user", home / ".agents" / "skills", 300),
            ("user-legacy", codex_home / "skills", 310),
            ("admin", codex_admin_skills, 400),
            ("system", codex_home / "skills" / ".system", 500),
        )
    )
    seen_roots: set[str] = set()
    for source, root, precedence in roots:
        normalized_root = os.path.normcase(str(root))
        if normalized_root in seen_roots:
            continue
        seen_roots.add(normalized_root)
        for skill_path, manifest_path in _iter_skill_directories(root):
            if source == "user-legacy" and skill_path.name == ".system":
                continue
            manifest_key = os.path.normcase(str(_absolute(manifest_path)))
            enabled = manifest_key not in disabled
            candidates.append(
                _candidate_for_directory(
                    "codex",
                    source,
                    root,
                    skill_path,
                    manifest_path,
                    precedence=precedence,
                    enabled=enabled,
                    reason=None if enabled else "disabled by skills.config",
                )
            )

    cache = codex_home / "plugins" / "cache"
    plugin_roots = list(ctx.plugin_roots)
    if cache.is_dir():
        plugin_roots.extend(sorted(cache.glob("*/*/*")))
    for plugin_root in plugin_roots:
        manifest = plugin_root / ".codex-plugin" / "plugin.json"
        plugin_name = plugin_root.name
        if manifest.is_file():
            try:
                raw = json.loads(manifest.read_text(encoding="utf-8"))
                if isinstance(raw, dict) and isinstance(raw.get("name"), str):
                    plugin_name = str(raw["name"])
            except (OSError, UnicodeError, json.JSONDecodeError):
                pass
        marketplace = plugin_root.parent.parent.name if len(plugin_root.parents) >= 2 else "local"
        identifier = f"{plugin_name}@{marketplace}"
        configured = _codex_plugin_state(config, plugin_name, identifier)
        enabled = configured is not False
        for skill_path, manifest_path in _iter_skill_directories(plugin_root / "skills"):
            candidates.append(
                _candidate_for_directory(
                    "codex",
                    "plugin",
                    plugin_root / "skills",
                    skill_path,
                    manifest_path,
                    precedence=600,
                    enabled=enabled,
                    plugin=identifier,
                    reason=None if enabled else "plugin is disabled",
                )
            )

    copies, diagnostics = _materialize(candidates)
    by_selector: dict[str, list[int]] = defaultdict(list)
    for index, copy in enumerate(copies):
        if copy.status == "active":
            by_selector[copy.selector].append(index)
    for selector, indexes in by_selector.items():
        if len(indexes) < 2:
            continue
        paths = tuple(str(copies[index].skill_path) for index in indexes)
        diagnostics.append(
            DiscoveryDiagnostic(
                "CODEX_DUPLICATE_NAME",
                f"Codex exposes multiple skills named {selector!r}; selection is "
                "genuinely ambiguous.",
                paths,
            )
        )
        for index in indexes:
            copies[index] = replace(
                copies[index],
                status="ambiguous",
                status_reason="duplicate Codex selector",
            )
    return Inventory(
        "codex",
        ctx.cwd,
        repository_root,
        tuple(
            sorted(copies, key=lambda copy: (copy.precedence, copy.selector, str(copy.skill_path)))
        ),
        tuple((*settings.diagnostics, *diagnostics)),
        tuple(settings.sources),
    )


def _claude_settings(ctx: DiscoveryContext) -> _Settings:
    repository_root = cast(Path, ctx.repository_root)
    claude_home = cast(Path, ctx.claude_home)
    managed_root = cast(Path, ctx.claude_managed_root)
    result = _Settings()
    _deep_merge(result.values, _read_json(claude_home / "settings.json", result))
    for directory in reversed(_walk_to_root(ctx.cwd, repository_root)):
        _deep_merge(result.values, _read_json(directory / ".claude" / "settings.json", result))
    _deep_merge(result.values, _read_json(ctx.cwd / ".claude" / "settings.local.json", result))

    managed: dict[str, Any] = {}
    _deep_merge(managed, _read_json(managed_root / "managed-settings.json", result))
    dropins = managed_root / "managed-settings.d"
    if dropins.is_dir():
        for path in sorted(dropins.glob("*.json")):
            if not path.name.startswith("."):
                _deep_merge(managed, _read_json(path, result))
    _deep_merge(result.values, managed)
    return result


def _skills_locked(settings: Mapping[str, Any]) -> bool:
    value = settings.get("strictPluginOnlyCustomization")
    return value is True or (isinstance(value, list) and "skills" in value)


def _skill_override(settings: Mapping[str, Any], selector: str) -> bool:
    overrides = settings.get("skillOverrides")
    return not (isinstance(overrides, Mapping) and overrides.get(selector) == "off")


def _claude_plugin_enabled(settings: Mapping[str, Any], identifier: str) -> bool:
    enabled = settings.get("enabledPlugins")
    if not isinstance(enabled, Mapping):
        return False
    value = enabled.get(identifier)
    if isinstance(value, bool):
        return value
    name = identifier.split("@", 1)[0]
    matches = [value for key, value in enabled.items() if str(key).split("@", 1)[0] == name]
    return any(value is True for value in matches)


def _command_candidates(
    root: Path,
    source: str,
    precedence: int,
    settings: Mapping[str, Any],
    *,
    locked: bool,
) -> list[_Candidate]:
    candidates: list[_Candidate] = []
    try:
        commands = sorted(root.glob("*.md"), key=lambda path: (path.name.casefold(), path.name))
    except OSError:
        return candidates
    for command in commands:
        name = command.stem
        enabled = not locked and _skill_override(settings, name)
        candidates.append(
            _Candidate(
                "claude",
                source,
                root,
                command,
                command,
                name,
                None,
                name,
                precedence,
                enabled,
                None,
                None if enabled else "disabled by policy or skillOverrides",
            )
        )
    return candidates


def _nested_roots(ctx: DiscoveryContext) -> list[tuple[Path, str]]:
    repository_root = cast(Path, ctx.repository_root)
    result: list[tuple[Path, str]] = []
    seen: set[str] = set()
    for active in ctx.active_paths:
        directory = active if active.is_dir() else active.parent
        if not directory.is_relative_to(ctx.cwd) or not directory.is_relative_to(repository_root):
            continue
        for current in reversed(_walk_to_root(directory, ctx.cwd)):
            if current == ctx.cwd:
                continue
            key = os.path.normcase(str(current))
            if key in seen:
                continue
            seen.add(key)
            qualifier = current.relative_to(ctx.cwd).as_posix()
            result.append((current / ".claude" / "skills", qualifier))
    return result


def discover_claude(context: DiscoveryContext) -> Inventory:
    ctx = context.normalized()
    repository_root = cast(Path, ctx.repository_root)
    claude_home = cast(Path, ctx.claude_home)
    managed_root = cast(Path, ctx.claude_managed_root)
    settings = _claude_settings(ctx)
    locked = _skills_locked(settings.values)
    candidates: list[_Candidate] = []

    roots: list[tuple[str, Path, int, str, bool]] = [
        ("enterprise", managed_root / "skills", 0, "", False),
        ("personal", claude_home / "skills", 100, "", locked),
    ]
    for index, directory in enumerate(reversed(_walk_to_root(ctx.cwd, repository_root))):
        roots.append(("project", directory / ".claude" / "skills", 200 + index, "", locked))
    for index, (root, qualifier) in enumerate(_nested_roots(ctx)):
        roots.append(("nested", root, 400 + index, f"{qualifier}:", locked))
    for index, directory in enumerate(ctx.added_directories):
        roots.append(("added-directory", directory / ".claude" / "skills", 500 + index, "", locked))

    for source, root, precedence, prefix, policy_blocked in roots:
        for skill_path, manifest_path in _iter_skill_directories(root):
            selector = f"{prefix}{skill_path.name}"
            enabled = not policy_blocked and _skill_override(settings.values, selector)
            candidates.append(
                _candidate_for_directory(
                    "claude",
                    source,
                    root,
                    skill_path,
                    manifest_path,
                    precedence=precedence,
                    selector_prefix=prefix,
                    enabled=enabled,
                    reason=None if enabled else "disabled by policy or skillOverrides",
                )
            )

    candidates.extend(
        _command_candidates(
            claude_home / "commands",
            "personal-command",
            800,
            settings.values,
            locked=locked,
        )
    )
    for index, directory in enumerate(reversed(_walk_to_root(ctx.cwd, repository_root))):
        candidates.extend(
            _command_candidates(
                directory / ".claude" / "commands",
                "project-command",
                810 + index,
                settings.values,
                locked=locked,
            )
        )

    plugin_roots = list(ctx.plugin_roots)
    cache = claude_home / "plugins" / "cache"
    if cache.is_dir():
        plugin_roots.extend(sorted(cache.glob("*/*/*")))
    for plugin_root in plugin_roots:
        marketplace = plugin_root.parent.parent.name if len(plugin_root.parents) >= 2 else "local"
        plugin_name = (
            plugin_root.parent.name if plugin_root.parent != plugin_root else plugin_root.name
        )
        manifest = plugin_root / ".claude-plugin" / "plugin.json"
        if manifest.is_file():
            try:
                raw = json.loads(manifest.read_text(encoding="utf-8"))
                if isinstance(raw, dict) and isinstance(raw.get("name"), str):
                    plugin_name = str(raw["name"])
            except (OSError, UnicodeError, json.JSONDecodeError):
                pass
        identifier = f"{plugin_name}@{marketplace}"
        enabled = _claude_plugin_enabled(settings.values, identifier)
        for skill_path, manifest_path in _iter_skill_directories(plugin_root / "skills"):
            candidates.append(
                _candidate_for_directory(
                    "claude",
                    "plugin",
                    plugin_root / "skills",
                    skill_path,
                    manifest_path,
                    precedence=600,
                    selector_prefix=f"{plugin_name}:",
                    enabled=enabled,
                    plugin=identifier,
                    reason=None if enabled else "plugin is not enabled in resolved settings",
                )
            )

    copies, diagnostics = _materialize(candidates)
    active_base_names = {
        copy.selector
        for copy in copies
        if copy.source != "nested" and copy.status == "active" and ":" not in copy.selector
    }
    for index, copy in enumerate(copies):
        if copy.source != "nested" or copy.status != "active" or ":" not in copy.selector:
            continue
        qualifier, base_name = copy.selector.rsplit(":", 1)
        if base_name not in active_base_names:
            copies[index] = replace(copy, selector=base_name)
        elif not qualifier:
            copies[index] = replace(copy, selector=base_name)
    by_selector: dict[str, list[int]] = defaultdict(list)
    for index, copy in enumerate(copies):
        if copy.status == "active":
            by_selector[copy.selector].append(index)
    for selector, indexes in by_selector.items():
        if len(indexes) < 2:
            continue
        ordered = sorted(indexes, key=lambda index: copies[index].precedence)
        winner = ordered[0]
        shadowed_paths: list[str] = []
        for index in ordered[1:]:
            copy = copies[index]
            copies[index] = replace(
                copy,
                status="shadowed",
                status_reason=f"shadowed by {copies[winner].skill_path}",
            )
            shadowed_paths.append(str(copy.skill_path))
        diagnostics.append(
            DiscoveryDiagnostic(
                "CLAUDE_SHADOWED_NAME",
                f"Claude resolves {selector!r} to the highest-precedence copy.",
                (str(copies[winner].skill_path), *shadowed_paths),
            )
        )
    return Inventory(
        "claude",
        ctx.cwd,
        repository_root,
        tuple(
            sorted(copies, key=lambda copy: (copy.precedence, copy.selector, str(copy.skill_path)))
        ),
        tuple((*settings.diagnostics, *diagnostics)),
        tuple(settings.sources),
    )


def discover(platform: Platform, context: DiscoveryContext) -> Inventory:
    if platform == "codex":
        return discover_codex(context)
    if platform == "claude":
        return discover_claude(context)
    raise DiscoveryError(f"unsupported platform: {platform}")


def discover_all(context: DiscoveryContext) -> tuple[Inventory, Inventory]:
    return discover_codex(context), discover_claude(context)
