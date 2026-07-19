import os
from pathlib import Path

from skill_doctor.discovery import DiscoveryContext
from skill_doctor.engine import execute_discovered_check
from skill_doctor.security import ArtifactCipher
from skill_doctor.store import LocalStore


def _skill(root: Path, name: str, content: str | None = None) -> Path:
    target = root / name
    target.mkdir(parents=True)
    (target / "SKILL.md").write_text(
        content or f"---\nname: {name}\ndescription: Aggregate discovery fixture.\n---\n",
        encoding="utf-8",
    )
    return target


def _store(root: Path, job_id: str) -> LocalStore:
    store = LocalStore(root, cipher=ArtifactCipher(os.urandom(32)))
    store.start_job(job_id, "2026-07-16T00:00:00Z", str(root.parent))
    return store


def _context(tmp_path: Path, repo: Path) -> DiscoveryContext:
    return DiscoveryContext(
        cwd=repo,
        repository_root=repo,
        home=tmp_path / "home",
        codex_home=tmp_path / "codex-home",
        claude_home=tmp_path / "claude-home",
        codex_admin_skills=tmp_path / "admin",
        claude_managed_root=tmp_path / "managed",
    )


def test_all_skills_deduplicates_static_analysis_by_content_hash(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    content = "---\nname: deploy\ndescription: Identical copies.\n---\n"
    _skill(repo / ".agents" / "skills", "deploy", content)
    _skill(tmp_path / "home" / ".agents" / "skills", "deploy", content)
    store = _store(tmp_path / "state", "all-job")
    events: list[tuple[str, str]] = []

    result = execute_discovered_check(
        job_id="all-job",
        created_at="2026-07-16T00:00:00Z",
        platform_name="codex",
        cwd=repo,
        selector=None,
        scope="all",
        store=store,
        emit=lambda stage, summary, _detail: events.append((stage, summary)),
        cancelled=lambda: False,
        context=_context(tmp_path, repo),
    )

    assert result.exit_code == 0
    assert result.report is not None
    assert result.report.scope == "all"
    assert result.report.inventory is not None
    assert len(result.report.inventory["copies"]) == 2
    assert len(result.report.analyzed_copies) == 1
    analyzed = result.report.analyzed_copies[0]
    assert len(analyzed.copy_ids) == 2
    assert analyzed.reused_by_content_hash
    assert result.report.dynamic_test_plan is not None
    assert result.report.dynamic_test_plan.skill_count == 1
    assert [stage for stage, _ in events].count("analysis") == 1


def test_named_check_resolves_effective_claude_copy(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    project = _skill(repo / ".claude" / "skills", "review")
    personal = _skill(tmp_path / "claude-home" / "skills", "review")
    store = _store(tmp_path / "state", "named-job")

    result = execute_discovered_check(
        job_id="named-job",
        created_at="2026-07-16T00:00:00Z",
        platform_name="claude",
        cwd=repo,
        selector="review",
        scope="named",
        store=store,
        emit=lambda _stage, _summary, _detail: None,
        cancelled=lambda: False,
        context=_context(tmp_path, repo),
    )

    assert result.exit_code == 0
    assert result.report is not None
    assert result.report.analyzed_copies[0].copy_ids
    copies = result.report.inventory["copies"] if result.report.inventory else []
    active = next(copy for copy in copies if copy["status"] == "active")
    shadowed = next(copy for copy in copies if copy["status"] == "shadowed")
    assert Path(active["skill_path"]) == personal
    assert Path(shadowed["skill_path"]) == project


def test_named_codex_ambiguity_fails_without_guessing(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    _skill(repo / ".agents" / "skills", "ambiguous")
    _skill(tmp_path / "home" / ".agents" / "skills", "ambiguous")
    store = _store(tmp_path / "state", "ambiguous-job")

    result = execute_discovered_check(
        job_id="ambiguous-job",
        created_at="2026-07-16T00:00:00Z",
        platform_name="codex",
        cwd=repo,
        selector="ambiguous",
        scope="named",
        store=store,
        emit=lambda _stage, _summary, _detail: None,
        cancelled=lambda: False,
        context=_context(tmp_path, repo),
    )

    assert result.exit_code == 2
    assert result.report is None
    job = store.get_job("ambiguous-job")
    assert job is not None
    assert job.status == "failed"
    assert job.error is not None and "ambiguous" in job.error


def test_all_skills_statically_analyzes_legacy_commands(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    command_root = repo / ".claude" / "commands"
    command_root.mkdir(parents=True)
    (command_root / "legacy.md").write_text("Legacy command.\n", encoding="utf-8")
    store = _store(tmp_path / "state", "commands-job")

    result = execute_discovered_check(
        job_id="commands-job",
        created_at="2026-07-16T00:00:00Z",
        platform_name="claude",
        cwd=repo,
        selector=None,
        scope="all",
        store=store,
        emit=lambda _stage, _summary, _detail: None,
        cancelled=lambda: False,
        context=_context(tmp_path, repo),
    )

    assert result.exit_code == 0
    assert result.report is not None
    assert result.report.analyzed_copies[0].analyzed
    assert "claude_command_metadata" in result.report.coverage.completed
    assert "legacy_command_project_reference_resolution" in result.report.coverage.unsupported
    assert result.report.dynamic_test_plan is not None
    assert result.report.dynamic_test_plan.skill_count == 1
