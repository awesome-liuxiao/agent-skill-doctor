from __future__ import annotations

import hashlib
import json
import os
import stat
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from tempfile import TemporaryDirectory

from skill_doctor.errors import OperationCancelled

SNAPSHOT_FORMAT_VERSION = "2"
MAX_FILES = 1_000
MAX_DIRECTORIES = 1_000
MAX_FILE_BYTES = 2 * 1024 * 1024
MAX_TOTAL_BYTES = 20 * 1024 * 1024


class SnapshotError(RuntimeError):
    pass


class SnapshotCancelled(SnapshotError, OperationCancelled):
    pass


@dataclass(frozen=True, slots=True)
class SnapshotFile:
    relative_path: str
    digest: str
    data: bytes


@dataclass(frozen=True, slots=True)
class SkippedPath:
    relative_path: str
    reason: str


@dataclass(frozen=True, slots=True)
class Snapshot:
    root: Path
    digest: str
    files: tuple[SnapshotFile, ...]
    skipped_paths: tuple[SkippedPath, ...]
    kind: str = "skill_directory"
    source_file: Path | None = None

    @property
    def skipped_symlinks(self) -> tuple[str, ...]:
        return tuple(item.relative_path for item in self.skipped_paths if item.reason == "symlink")

    def manifest_bytes(self) -> bytes:
        manifest = {
            "format_version": SNAPSHOT_FORMAT_VERSION,
            "kind": self.kind,
            "files": [
                {
                    "bytes": len(item.data),
                    "path": item.relative_path,
                    "sha256": item.digest,
                }
                for item in self.files
            ],
            "skipped_paths": [
                {"path": item.relative_path, "reason": item.reason} for item in self.skipped_paths
            ],
        }
        return json.dumps(
            manifest,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")


def _is_link(path: Path) -> bool:
    is_junction = getattr(path, "is_junction", None)
    return path.is_symlink() or bool(is_junction and is_junction())


def _raise_walk_error(error: OSError) -> None:
    raise SnapshotError(f"cannot enumerate skill directory: {error}") from error


def _resolved_root(root: Path) -> Path:
    lexical = Path(os.path.abspath(root.expanduser()))
    if _is_link(lexical):
        raise SnapshotError("skill path must be a real directory, not a symlink or junction")
    try:
        resolved = lexical.resolve(strict=True)
    except OSError as error:
        raise SnapshotError(f"cannot resolve skill path: {error}") from error
    if os.path.normcase(str(lexical)) != os.path.normcase(str(resolved)):
        raise SnapshotError("skill path must not traverse a symlink or junction")
    if not resolved.is_dir():
        raise SnapshotError("skill path must be a real directory")
    return resolved


def _check_cancelled(cancelled: Callable[[], bool] | None) -> None:
    if cancelled is not None and cancelled():
        raise SnapshotCancelled("snapshot cancelled")


def _read_regular_file(
    path: Path,
    relative: str,
    cancelled: Callable[[], bool] | None,
) -> bytes:
    _check_cancelled(cancelled)
    try:
        before = path.lstat()
    except OSError as error:
        raise SnapshotError(f"cannot inspect file: {relative}: {error}") from error
    if not stat.S_ISREG(before.st_mode):
        raise SnapshotError(f"path stopped being a regular file: {relative}")
    if before.st_size > MAX_FILE_BYTES:
        raise SnapshotError(f"file exceeds byte limit: {relative}")

    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise SnapshotError(f"cannot open file: {relative}: {error}") from error
    try:
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode) or not os.path.samestat(before, opened):
            raise SnapshotError(f"file changed while being opened: {relative}")
        with os.fdopen(descriptor, "rb", closefd=False) as stream:
            data = stream.read(MAX_FILE_BYTES + 1)
        _check_cancelled(cancelled)
        after = os.fstat(descriptor)
    except OSError as error:
        raise SnapshotError(f"cannot read file: {relative}: {error}") from error
    finally:
        os.close(descriptor)

    if len(data) > MAX_FILE_BYTES:
        raise SnapshotError(f"file exceeds byte limit: {relative}")
    identity_changed = not os.path.samestat(opened, after)
    content_changed = (
        opened.st_size,
        opened.st_mtime_ns,
        getattr(opened, "st_ctime_ns", 0),
    ) != (
        after.st_size,
        after.st_mtime_ns,
        getattr(after, "st_ctime_ns", 0),
    )
    if identity_changed or content_changed or len(data) != after.st_size:
        raise SnapshotError(f"file changed while being read: {relative}")
    return data


def create_snapshot(
    root: Path,
    *,
    cancelled: Callable[[], bool] | None = None,
) -> Snapshot:
    _check_cancelled(cancelled)
    resolved_root = _resolved_root(root)
    files: list[SnapshotFile] = []
    skipped: list[SkippedPath] = []
    total = 0
    directory_count = 0

    for current, dirs, names in os.walk(
        resolved_root,
        followlinks=False,
        onerror=_raise_walk_error,
    ):
        _check_cancelled(cancelled)
        directory_count += 1
        if directory_count > MAX_DIRECTORIES:
            raise SnapshotError(f"skill exceeds directory limit ({MAX_DIRECTORIES})")
        current_path = Path(current)
        try:
            current_path.resolve(strict=True).relative_to(resolved_root)
        except (OSError, ValueError) as error:
            raise SnapshotError("directory escaped the resolved skill root") from error

        safe_dirs: list[str] = []
        for name in sorted(dirs):
            _check_cancelled(cancelled)
            candidate = current_path / name
            relative = candidate.relative_to(resolved_root).as_posix()
            if _is_link(candidate):
                skipped.append(SkippedPath(relative, "symlink"))
            else:
                safe_dirs.append(name)
        dirs[:] = safe_dirs

        for name in sorted(names):
            _check_cancelled(cancelled)
            path = current_path / name
            relative = path.relative_to(resolved_root).as_posix()
            if _is_link(path):
                skipped.append(SkippedPath(relative, "symlink"))
                continue
            try:
                path.resolve(strict=True).relative_to(resolved_root)
                path_stat = path.lstat()
            except (OSError, ValueError) as error:
                raise SnapshotError(f"file escaped the resolved skill root: {relative}") from error
            if not stat.S_ISREG(path_stat.st_mode):
                skipped.append(SkippedPath(relative, "non_regular_file"))
                continue
            if len(files) >= MAX_FILES:
                raise SnapshotError(f"skill exceeds file limit ({MAX_FILES})")
            data = _read_regular_file(path, relative, cancelled)
            total += len(data)
            if total > MAX_TOTAL_BYTES:
                raise SnapshotError(f"skill exceeds aggregate byte limit ({MAX_TOTAL_BYTES})")
            files.append(SnapshotFile(relative, hashlib.sha256(data).hexdigest(), data))

    files.sort(key=lambda item: item.relative_path)
    skipped.sort(key=lambda item: (item.relative_path, item.reason))
    provisional = Snapshot(resolved_root, "", tuple(files), tuple(skipped))
    digest = hashlib.sha256(provisional.manifest_bytes()).hexdigest()
    return Snapshot(resolved_root, digest, provisional.files, provisional.skipped_paths)


def create_legacy_command_snapshot(
    path: Path,
    *,
    cancelled: Callable[[], bool] | None = None,
) -> Snapshot:
    """Snapshot one legacy Claude command without manufacturing a filesystem skill."""
    _check_cancelled(cancelled)
    lexical = Path(os.path.abspath(path.expanduser()))
    if _is_link(lexical):
        raise SnapshotError("legacy command path must not be a symlink or junction")
    try:
        resolved = lexical.resolve(strict=True)
    except OSError as error:
        raise SnapshotError(f"cannot resolve legacy command: {error}") from error
    if os.path.normcase(str(lexical)) != os.path.normcase(str(resolved)):
        raise SnapshotError("legacy command path must not traverse a symlink or junction")
    data = _read_regular_file(resolved, resolved.name, cancelled)
    item = SnapshotFile("SKILL.md", hashlib.sha256(data).hexdigest(), data)
    virtual_root = resolved.parent / resolved.stem
    provisional = Snapshot(
        virtual_root,
        "",
        (item,),
        (),
        kind="claude_command",
        source_file=resolved,
    )
    digest = hashlib.sha256(provisional.manifest_bytes()).hexdigest()
    return Snapshot(
        virtual_root,
        digest,
        provisional.files,
        (),
        kind="claude_command",
        source_file=resolved,
    )


def verify_snapshot(
    snapshot: Snapshot,
    *,
    cancelled: Callable[[], bool] | None = None,
) -> None:
    current = (
        create_legacy_command_snapshot(snapshot.source_file, cancelled=cancelled)
        if snapshot.kind == "claude_command" and snapshot.source_file is not None
        else create_snapshot(snapshot.root, cancelled=cancelled)
    )
    if current.digest != snapshot.digest:
        raise SnapshotError("skill changed after it was snapshotted; refusing a stale report")


@contextmanager
def materialize_snapshot(snapshot: Snapshot, parent: Path) -> Iterator[Path]:
    """Create a disposable tree exclusively from immutable in-memory snapshot bytes."""
    parent.mkdir(parents=True, exist_ok=True)
    with TemporaryDirectory(prefix="snapshot-", dir=parent) as temporary:
        root = Path(temporary)
        for item in snapshot.files:
            relative = Path(*item.relative_path.split("/"))
            if relative.is_absolute() or ".." in relative.parts:
                raise SnapshotError("snapshot contains an unsafe materialization path")
            target = root / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(item.data)
            if hashlib.sha256(target.read_bytes()).hexdigest() != item.digest:
                raise SnapshotError("materialized snapshot content failed integrity verification")
            try:
                target.chmod(stat.S_IREAD)
            except OSError:
                pass
        yield root
