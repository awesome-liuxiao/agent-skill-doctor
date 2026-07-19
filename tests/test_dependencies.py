import base64
import json
from pathlib import Path

import pytest

from skill_doctor.dependencies import DependencyPlanError, build_dependency_plan


def test_python_dependencies_require_exact_versions_and_hashes(tmp_path: Path) -> None:
    digest = "a" * 64
    (tmp_path / "requirements.lock").write_text(
        f"demo==1.2.3 --hash=sha256:{digest}\n",
        encoding="utf-8",
    )
    plan = build_dependency_plan(tmp_path)
    assert plan.required
    assert plan.locks[0].ecosystem == "python"
    assert plan.locks[0].package_count == 1
    assert "--require-hashes" in plan.commands[0]
    assert plan.registry_domains == (
        "pypi.org",
        "files.pythonhosted.org",
    )


def test_unpinned_python_dependency_is_rejected(tmp_path: Path) -> None:
    (tmp_path / "requirements.txt").write_text("demo>=1\n", encoding="utf-8")
    with pytest.raises(DependencyPlanError, match="pin a version"):
        build_dependency_plan(tmp_path)


def test_npm_dependencies_require_integrity_and_disable_scripts(tmp_path: Path) -> None:
    (tmp_path / "package.json").write_text('{"name":"fixture"}', encoding="utf-8")
    (tmp_path / "package-lock.json").write_text(
        json.dumps(
            {
                "lockfileVersion": 3,
                "packages": {
                    "": {"name": "fixture"},
                    "node_modules/demo": {
                        "integrity": "sha512-" + base64.b64encode(b"a" * 64).decode("ascii"),
                        "resolved": "https://registry.npmjs.org/demo/-/demo-1.0.0.tgz",
                    },
                },
            }
        ),
        encoding="utf-8",
    )
    plan = build_dependency_plan(tmp_path)
    assert plan.locks[0].ecosystem == "npm"
    assert plan.scripts_disabled
    assert "--ignore-scripts" in plan.commands[-1]


def test_dependency_registry_must_be_https(tmp_path: Path) -> None:
    digest = "b" * 64
    (tmp_path / "requirements.lock").write_text(
        f"demo==1 --hash=sha256:{digest}\n",
        encoding="utf-8",
    )
    with pytest.raises(DependencyPlanError, match="HTTPS"):
        build_dependency_plan(tmp_path, registry_urls=("http://registry.example",))
