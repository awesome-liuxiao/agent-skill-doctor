from __future__ import annotations

import argparse
import os
import re
import subprocess
import tomllib
from pathlib import Path

_COMMIT = re.compile(r"[0-9a-f]{40}")
_STABLE_TAG = re.compile(r"v[1-9][0-9]*\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)")
_PREVIEW_TAG = re.compile(
    r"v(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)(?:a|b|rc)[1-9][0-9]*"
)


def source_errors(
    *,
    release_ref: str,
    resolved_release_commit: str,
    checked_out_commit: str,
    github_sha: str,
    github_ref: str,
    release_tag: str | None = None,
    package_version: str | None = None,
    require_stable_tag: bool = False,
    require_preview_tag: bool = False,
) -> list[str]:
    errors: list[str] = []
    commits = (resolved_release_commit, checked_out_commit, github_sha)
    if any(_COMMIT.fullmatch(item) is None for item in commits):
        errors.append("source commits must be exact lowercase 40-character Git SHAs")
    elif len(set(commits)) != 1:
        errors.append(
            "release_ref, checked-out HEAD, and GitHub's attested source SHA do not match"
        )
    if require_stable_tag:
        if release_tag is None or _STABLE_TAG.fullmatch(release_tag) is None:
            errors.append("stable release tag must have the form vMAJOR.MINOR.PATCH")
        elif release_ref != release_tag:
            errors.append("stable release_ref must be the release_tag")
        elif github_ref != f"refs/tags/{release_tag}":
            errors.append("stable workflow must be dispatched from the release tag")
    if require_preview_tag:
        if release_tag is None or _PREVIEW_TAG.fullmatch(release_tag) is None:
            errors.append("preview release tag must have the form vMAJOR.MINOR.PATCHaN, bN, or rcN")
        elif release_ref != release_tag:
            errors.append("preview release_ref must be the release_tag")
        elif github_ref != f"refs/tags/{release_tag}":
            errors.append("preview workflow must be dispatched from the release tag")
    if (require_stable_tag or require_preview_tag) and release_tag is not None:
        if package_version is None or f"v{package_version}" != release_tag:
            errors.append("package version must match the release tag exactly")
    return errors


def _git_commit(reference: str, *, cwd: Path) -> str:
    try:
        result = subprocess.run(  # noqa: S603 - Arguments are not executed by a shell.
            [  # noqa: S607 - Git is the required workflow tool on the runner.
                "git",
                "rev-parse",
                "--verify",
                f"{reference}^{{commit}}",
            ],
            check=True,
            cwd=cwd,
            capture_output=True,
            text=True,
        )
    except (OSError, subprocess.CalledProcessError) as error:
        raise SystemExit(f"cannot resolve release source {reference!r}: {error}") from error
    return result.stdout.strip().lower()


def _package_version(*, cwd: Path) -> str:
    data = tomllib.loads((cwd / "pyproject.toml").read_text(encoding="utf-8"))
    project = data.get("project")
    version = project.get("version") if isinstance(project, dict) else None
    if not isinstance(version, str) or not version:
        raise SystemExit("pyproject.toml must declare project.version")
    return version


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--release-ref", required=True)
    parser.add_argument("--release-tag")
    tag_kind = parser.add_mutually_exclusive_group()
    tag_kind.add_argument("--require-stable-tag", action="store_true")
    tag_kind.add_argument("--require-preview-tag", action="store_true")
    arguments = parser.parse_args()
    repository = Path.cwd()
    github_sha = os.environ.get("GITHUB_SHA", "").lower()
    github_ref = os.environ.get("GITHUB_REF", "")
    errors = source_errors(
        release_ref=arguments.release_ref,
        resolved_release_commit=_git_commit(arguments.release_ref, cwd=repository),
        checked_out_commit=_git_commit("HEAD", cwd=repository),
        github_sha=github_sha,
        github_ref=github_ref,
        release_tag=arguments.release_tag,
        package_version=_package_version(cwd=repository),
        require_stable_tag=arguments.require_stable_tag,
        require_preview_tag=arguments.require_preview_tag,
    )
    if errors:
        raise SystemExit("release source verification failed: " + "; ".join(errors))
    print(f"verified exact workflow source {github_sha} ({github_ref})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
