import hashlib
from pathlib import Path

import pytest

from skill_doctor.snapshot import (
    MAX_FILE_BYTES,
    SnapshotCancelled,
    SnapshotError,
    create_legacy_command_snapshot,
    create_snapshot,
    materialize_snapshot,
    verify_snapshot,
)

FIXTURES = Path(__file__).parent / "fixtures"


def test_snapshot_is_deterministic() -> None:
    first = create_snapshot(FIXTURES / "valid-skill")
    second = create_snapshot(FIXTURES / "valid-skill")
    assert first.digest == second.digest
    assert [item.relative_path for item in first.files] == ["SKILL.md", "references/guide.md"]
    assert hashlib.sha256(first.manifest_bytes()).hexdigest() == first.digest


def test_rejects_oversized_file(tmp_path: Path) -> None:
    root = tmp_path / "oversized"
    root.mkdir()
    (root / "SKILL.md").write_bytes(b"x" * (MAX_FILE_BYTES + 1))
    with pytest.raises(SnapshotError, match="byte limit"):
        create_snapshot(root)


def test_skips_symlink_without_following_it(tmp_path: Path) -> None:
    root = tmp_path / "linked"
    root.mkdir()
    (root / "SKILL.md").write_text(
        "---\nname: linked\ndescription: Symlink fixture.\n---",
        encoding="utf-8",
    )
    outside = tmp_path / "outside.txt"
    outside.write_text("secret", encoding="utf-8")
    link = root / "outside.txt"
    try:
        link.symlink_to(outside)
    except OSError:
        pytest.skip("symlink creation is unavailable")
    snapshot = create_snapshot(root)
    assert snapshot.skipped_symlinks == ("outside.txt",)
    assert all(item.data != b"secret" for item in snapshot.files)


def test_detects_stale_snapshot(tmp_path: Path) -> None:
    root = tmp_path / "stale"
    root.mkdir()
    skill = root / "SKILL.md"
    skill.write_text(
        "---\nname: stale\ndescription: Initial content.\n---",
        encoding="utf-8",
    )
    snapshot = create_snapshot(root)
    skill.write_text(
        "---\nname: stale\ndescription: Changed content.\n---",
        encoding="utf-8",
    )
    with pytest.raises(SnapshotError, match="stale report"):
        verify_snapshot(snapshot)


def test_snapshot_honors_cooperative_cancellation(tmp_path: Path) -> None:
    root = tmp_path / "cancelled"
    root.mkdir()
    with pytest.raises(SnapshotCancelled, match="cancelled"):
        create_snapshot(root, cancelled=lambda: True)


def test_legacy_command_snapshot_is_bounded_and_stale_checked(tmp_path: Path) -> None:
    command = tmp_path / "deploy.md"
    command.write_text("Deploy the application.\n", encoding="utf-8")
    snapshot = create_legacy_command_snapshot(command)
    assert snapshot.kind == "claude_command"
    assert snapshot.source_file == command.resolve()
    assert snapshot.files[0].relative_path == "SKILL.md"
    assert snapshot.files[0].data == command.read_bytes()

    command.write_text("Changed command.\n", encoding="utf-8")
    with pytest.raises(SnapshotError, match="stale report"):
        verify_snapshot(snapshot)


def test_materialized_snapshot_uses_captured_bytes_not_changed_source(tmp_path: Path) -> None:
    skill = tmp_path / "skill"
    skill.mkdir()
    document = skill / "SKILL.md"
    document.write_text("captured", encoding="utf-8")
    snapshot = create_snapshot(skill)
    document.write_text("changed", encoding="utf-8")
    with materialize_snapshot(snapshot, tmp_path / "materialized") as root:
        assert (root / "SKILL.md").read_text(encoding="utf-8") == "captured"
