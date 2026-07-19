from __future__ import annotations

import hashlib
import json
import re
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Literal, cast

MAX_LOCK_BYTES = 5 * 1024 * 1024
PINNED_REQUIREMENT = re.compile(
    r"^[A-Za-z0-9][A-Za-z0-9._-]*(?:\[[A-Za-z0-9_,.-]+\])?==[^\s;]+"
    r"(?:\s*;\s*[^#]+)?(?:\s+--hash=sha256:[0-9a-f]{64})+$",
    re.I,
)
SAFE_REGISTRY = re.compile(r"^https://[A-Za-z0-9.-]+(?::[0-9]+)?(?:/[^\s]*)?$", re.I)
NPM_SHA512 = re.compile(r"^sha512-[A-Za-z0-9+/]{86}==$")

Ecosystem = Literal["python", "npm"]
PYTHON_REGISTRIES = ("https://pypi.org/simple", "https://files.pythonhosted.org")
NPM_REGISTRIES = ("https://registry.npmjs.org",)


class DependencyPlanError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class DependencyLock:
    ecosystem: Ecosystem
    path: str
    sha256: str
    package_count: int


@dataclass(frozen=True, slots=True)
class DependencyPlan:
    locks: tuple[DependencyLock, ...]
    commands: tuple[tuple[str, ...], ...]
    registry_urls: tuple[str, ...]
    registry_domains: tuple[str, ...]
    scripts_disabled: bool

    @property
    def required(self) -> bool:
        return bool(self.locks)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _read_lock(path: Path) -> bytes:
    try:
        data = path.read_bytes()
    except OSError as error:
        raise DependencyPlanError(f"cannot read dependency lock {path.name}: {error}") from error
    if len(data) > MAX_LOCK_BYTES:
        raise DependencyPlanError(f"dependency lock exceeds 5 MB: {path.name}")
    return data


def _registry_domains(urls: tuple[str, ...]) -> tuple[str, ...]:
    domains: list[str] = []
    for url in urls:
        if not SAFE_REGISTRY.fullmatch(url):
            raise DependencyPlanError(f"registry URL is not a bounded HTTPS URL: {url}")
        domain = url.split("/", 3)[2].split(":", 1)[0].casefold()
        domains.append(domain)
    return tuple(dict.fromkeys(domains))


def _python_lock(
    skill_root: Path,
) -> tuple[DependencyLock, tuple[tuple[str, ...], ...]] | None:
    candidates = (skill_root / "requirements.lock", skill_root / "requirements.txt")
    path = next((candidate for candidate in candidates if candidate.is_file()), None)
    if path is None:
        return None
    data = _read_lock(path)
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as error:
        raise DependencyPlanError("Python dependency lock must be UTF-8") from error
    requirements: list[str] = []
    for line_number, raw in enumerate(text.splitlines(), start=1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith(("-", "http:", "https:", "git+", ".", "/")):
            raise DependencyPlanError(
                f"unsupported Python dependency directive at {path.name}:{line_number}"
            )
        if not PINNED_REQUIREMENT.fullmatch(line):
            raise DependencyPlanError(
                f"Python requirement must pin a version and SHA-256 hash at "
                f"{path.name}:{line_number}"
            )
        requirements.append(line)
    if not requirements:
        return None
    relative = path.relative_to(skill_root).as_posix()
    lock = DependencyLock("python", relative, hashlib.sha256(data).hexdigest(), len(requirements))
    command = (
        "python",
        "-m",
        "pip",
        "install",
        "--disable-pip-version-check",
        "--no-deps",
        "--require-hashes",
        "--target",
        "/workspace/.doctor-dependencies/python",
        "-r",
        f"/opt/skill/{relative}",
    )
    return lock, (command,)


def _npm_lock(
    skill_root: Path,
) -> tuple[DependencyLock, tuple[tuple[str, ...], ...]] | None:
    path = skill_root / "package-lock.json"
    if not path.is_file():
        return None
    if not (skill_root / "package.json").is_file():
        raise DependencyPlanError("package-lock.json requires a sibling package.json")
    data = _read_lock(path)
    try:
        payload = json.loads(data)
    except (json.JSONDecodeError, UnicodeError) as error:
        raise DependencyPlanError(f"invalid package-lock.json: {error}") from error
    if not isinstance(payload, dict) or not isinstance(payload.get("lockfileVersion"), int):
        raise DependencyPlanError("package-lock.json requires a numeric lockfileVersion")
    packages = payload.get("packages")
    if not isinstance(packages, dict):
        raise DependencyPlanError("package-lock.json requires a packages object")
    count = 0
    for key, value in packages.items():
        if key == "":
            continue
        if not isinstance(value, dict):
            raise DependencyPlanError("package-lock.json contains an invalid package entry")
        item = cast(dict[str, Any], value)
        integrity = item.get("integrity")
        resolved = item.get("resolved")
        if (
            item.get("link") is True
            or not isinstance(integrity, str)
            or not NPM_SHA512.fullmatch(integrity)
            or not isinstance(resolved, str)
            or not SAFE_REGISTRY.fullmatch(resolved)
        ):
            raise DependencyPlanError(
                "every npm dependency must be non-linked, HTTPS-resolved, and include "
                "full SHA-512 integrity"
            )
        count += 1
    if count == 0:
        return None
    lock = DependencyLock("npm", "package-lock.json", hashlib.sha256(data).hexdigest(), count)
    copy_command = (
        "cp",
        "/opt/skill/package.json",
        "/opt/skill/package-lock.json",
        "/workspace/",
    )
    install_command = (
        "npm",
        "ci",
        "--ignore-scripts",
        "--no-audit",
        "--no-fund",
        "--prefix",
        "/workspace",
    )
    return lock, (copy_command, install_command)


def build_dependency_plan(
    skill_root: Path,
    *,
    registry_urls: tuple[str, ...] | None = None,
) -> DependencyPlan:
    root = skill_root.resolve(strict=True)
    if not root.is_dir():
        raise DependencyPlanError("skill dependency root must be a directory")
    locks: list[DependencyLock] = []
    commands: list[tuple[str, ...]] = []
    for candidate in (_python_lock(root), _npm_lock(root)):
        if candidate is not None:
            lock, lock_commands = candidate
            locks.append(lock)
            commands.extend(lock_commands)
    if registry_urls is None:
        ecosystems = {lock.ecosystem for lock in locks}
        selected_registries = (
            *(PYTHON_REGISTRIES if "python" in ecosystems else ()),
            *(NPM_REGISTRIES if "npm" in ecosystems else ()),
        )
    else:
        selected_registries = registry_urls
    domains = _registry_domains(selected_registries)
    return DependencyPlan(
        tuple(locks),
        tuple(commands),
        selected_registries if locks else (),
        domains if locks else (),
        scripts_disabled=True,
    )
