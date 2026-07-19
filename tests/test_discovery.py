import json
import os
from pathlib import Path

import pytest

from skill_doctor.discovery import (
    AmbiguousSkill,
    DiscoveryContext,
    discover_claude,
    discover_codex,
)


def _skill(root: Path, name: str, *, declared: str | None = None) -> Path:
    target = root / name
    target.mkdir(parents=True)
    skill_name = declared or name
    (target / "SKILL.md").write_text(
        f"---\nname: {skill_name}\ndescription: Discovery fixture for {name}.\n---\n",
        encoding="utf-8",
    )
    return target


def _context(tmp_path: Path, cwd: Path, **values: object) -> DiscoveryContext:
    defaults: dict[str, object] = {
        "cwd": cwd,
        "repository_root": tmp_path / "repo",
        "home": tmp_path / "home",
        "codex_home": tmp_path / "codex-home",
        "claude_home": tmp_path / "claude-home",
        "codex_admin_skills": tmp_path / "codex-admin",
        "claude_managed_root": tmp_path / "claude-managed",
    }
    defaults.update(values)
    return DiscoveryContext(**defaults)  # type: ignore[arg-type]


def test_codex_inventory_keeps_all_scopes_and_reports_real_ambiguity(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    cwd = repo / "packages" / "app"
    cwd.mkdir(parents=True)
    home = tmp_path / "home"
    codex_home = tmp_path / "codex-home"
    admin = tmp_path / "codex-admin"

    _skill(repo / ".agents" / "skills", "deploy")
    disabled = _skill(cwd / ".agents" / "skills", "disabled")
    _skill(home / ".agents" / "skills", "deploy")
    _skill(codex_home / "skills", "legacy")
    _skill(codex_home / "skills" / ".system", "system-doctor")
    _skill(admin, "admin-doctor")
    plugin = tmp_path / "plugin"
    _skill(plugin / "skills", "plugin-doctor")
    (plugin / ".codex-plugin").mkdir()
    (plugin / ".codex-plugin" / "plugin.json").write_text(
        json.dumps({"name": "fixture-plugin"}), encoding="utf-8"
    )
    codex_home.mkdir(exist_ok=True)
    plugin_identifier = f"fixture-plugin@{plugin.parent.parent.name}"
    (codex_home / "config.toml").write_text(
        "[[skills.config]]\n"
        f'path = "{(disabled / "SKILL.md").as_posix()}"\n'
        "enabled = false\n"
        f'[plugins."{plugin_identifier}"]\n'
        "enabled = false\n",
        encoding="utf-8",
    )

    inventory = discover_codex(
        _context(
            tmp_path,
            cwd,
            plugin_roots=(plugin,),
        )
    )

    assert {copy.source for copy in inventory.copies} == {
        "repository",
        "user",
        "user-legacy",
        "admin",
        "system",
        "plugin",
    }
    assert next(copy for copy in inventory.copies if copy.name == "disabled").status == "inactive"
    plugin_copy = next(copy for copy in inventory.copies if copy.name == "plugin-doctor")
    assert plugin_copy.status == "inactive"
    assert plugin_copy.plugin == plugin_identifier
    deploy = [copy for copy in inventory.copies if copy.selector == "deploy"]
    assert len(deploy) == 2
    assert {copy.status for copy in deploy} == {"ambiguous"}
    with pytest.raises(AmbiguousSkill):
        inventory.resolve("deploy")
    assert inventory.resolve("legacy").source == "user-legacy"
    assert any(item.code == "CODEX_DUPLICATE_NAME" for item in inventory.diagnostics)


def test_codex_follows_and_deduplicates_skill_symlinks(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    target = _skill(tmp_path / "shared", "linked")
    first_root = repo / ".agents" / "skills"
    second_root = tmp_path / "home" / ".agents" / "skills"
    first_root.mkdir(parents=True)
    second_root.mkdir(parents=True)
    try:
        (first_root / "linked").symlink_to(target, target_is_directory=True)
        (second_root / "linked-copy").symlink_to(target, target_is_directory=True)
    except OSError as error:
        pytest.skip(f"directory symlinks are unavailable: {error}")

    inventory = discover_codex(_context(tmp_path, repo))
    linked = [copy for copy in inventory.copies if copy.resolved_path == target.resolve()]
    assert len(linked) == 2
    assert [copy.status for copy in linked] == ["active", "shadowed"]
    assert any(item.code == "DISCOVERY_SYMLINK_DEDUP" for item in inventory.diagnostics)


def test_claude_precedence_nested_commands_added_directory_and_plugin(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    cwd = repo / "apps" / "api"
    active_file = cwd / "src" / "main.py"
    active_file.parent.mkdir(parents=True)
    active_file.write_text("pass\n", encoding="utf-8")
    claude_home = tmp_path / "claude-home"
    managed = tmp_path / "claude-managed"
    added = tmp_path / "added"

    _skill(managed / "skills", "deploy")
    _skill(claude_home / "skills", "deploy")
    _skill(repo / ".claude" / "skills", "deploy")
    _skill(cwd / ".claude" / "skills", "local-only")
    _skill(active_file.parent / ".claude" / "skills", "deploy")
    _skill(active_file.parent / ".claude" / "skills", "lint")
    _skill(added / ".claude" / "skills", "from-added")

    commands = repo / ".claude" / "commands"
    commands.mkdir(parents=True)
    (commands / "deploy.md").write_text("Legacy deploy command.\n", encoding="utf-8")
    (commands / "legacy.md").write_text("Legacy-only command.\n", encoding="utf-8")

    plugin = tmp_path / "plugins" / "fixture" / "1.0.0"
    _skill(plugin / "skills", "review")
    (plugin / ".claude-plugin").mkdir()
    (plugin / ".claude-plugin" / "plugin.json").write_text(
        json.dumps({"name": "fixture"}), encoding="utf-8"
    )
    claude_home.mkdir(exist_ok=True)
    (claude_home / "settings.json").write_text(
        json.dumps({"enabledPlugins": {"fixture@plugins": True}}),
        encoding="utf-8",
    )

    inventory = discover_claude(
        _context(
            tmp_path,
            cwd,
            active_paths=(active_file,),
            added_directories=(added,),
            plugin_roots=(plugin,),
        )
    )

    assert inventory.resolve("deploy").source == "enterprise"
    deploy = [copy for copy in inventory.copies if copy.name == "deploy"]
    assert sum(copy.status == "active" for copy in deploy) == 2
    assert {copy.selector for copy in deploy if copy.source == "nested"} == {"src:deploy"}
    assert next(copy for copy in deploy if copy.source == "project-command").status == "shadowed"
    assert inventory.resolve("lint").source == "nested"
    assert inventory.resolve("from-added").source == "added-directory"
    assert inventory.resolve("legacy").source == "project-command"
    plugin_copy = inventory.resolve("fixture:review")
    assert plugin_copy.plugin == "fixture@plugins"
    assert any(item.code == "CLAUDE_SHADOWED_NAME" for item in inventory.diagnostics)


def test_claude_policy_and_skill_overrides_keep_inactive_copies_visible(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    home = tmp_path / "claude-home"
    managed = tmp_path / "claude-managed"
    _skill(repo / ".claude" / "skills", "project-skill")
    _skill(home / "skills", "personal-skill")
    _skill(managed / "skills", "managed-skill")
    managed.mkdir(exist_ok=True)
    (managed / "managed-settings.json").write_text(
        json.dumps(
            {
                "strictPluginOnlyCustomization": ["skills"],
                "skillOverrides": {"managed-skill": "off"},
            }
        ),
        encoding="utf-8",
    )

    inventory = discover_claude(_context(tmp_path, repo))
    statuses = {copy.name: copy.status for copy in inventory.copies}
    assert statuses == {
        "managed-skill": "inactive",
        "personal-skill": "inactive",
        "project-skill": "inactive",
    }
    assert str(managed / "managed-settings.json") in inventory.configuration_sources


def test_broken_skill_symlink_is_reported_as_unresolved(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    root = repo / ".agents" / "skills"
    root.mkdir(parents=True)
    broken = root / "broken"
    try:
        broken.symlink_to(tmp_path / "does-not-exist", target_is_directory=True)
    except OSError as error:
        pytest.skip(f"directory symlinks are unavailable: {error}")

    inventory = discover_codex(_context(tmp_path, repo))
    copy = next(copy for copy in inventory.copies if copy.name == "broken")
    assert copy.status == "unresolved"
    assert any(item.code == "DISCOVERY_UNRESOLVED" for item in inventory.diagnostics)


def test_inventory_serialization_contains_only_json_values(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    _skill(repo / ".agents" / "skills", "serializable")
    inventory = discover_codex(_context(tmp_path, repo))
    payload = inventory.to_dict()
    assert json.loads(json.dumps(payload))["copies"][0]["name"] == "serializable"
    assert os.path.isabs(payload["copies"][0]["skill_path"])
