from scripts.verify_workflow_source import source_errors

SHA = "a" * 40


def test_matching_dispatch_checkout_and_stable_tag_pass() -> None:
    assert (
        source_errors(
            release_ref="v1.2.3",
            resolved_release_commit=SHA,
            checked_out_commit=SHA,
            github_sha=SHA,
            github_ref="refs/tags/v1.2.3",
            release_tag="v1.2.3",
            package_version="1.2.3",
            require_stable_tag=True,
        )
        == []
    )


def test_different_dispatch_source_fails_closed() -> None:
    errors = source_errors(
        release_ref="release-candidate",
        resolved_release_commit=SHA,
        checked_out_commit=SHA,
        github_sha="b" * 40,
        github_ref="refs/heads/main",
    )
    assert any("do not match" in error for error in errors)


def test_stable_release_requires_existing_matching_tag_ref() -> None:
    errors = source_errors(
        release_ref=SHA,
        resolved_release_commit=SHA,
        checked_out_commit=SHA,
        github_sha=SHA,
        github_ref="refs/heads/main",
        release_tag="v1.2.3",
        package_version="1.2.3",
        require_stable_tag=True,
    )
    assert "stable release_ref must be the release_tag" in errors


def test_matching_dispatch_checkout_and_preview_tag_pass() -> None:
    assert (
        source_errors(
            release_ref="v0.1.0a1",
            resolved_release_commit=SHA,
            checked_out_commit=SHA,
            github_sha=SHA,
            github_ref="refs/tags/v0.1.0a1",
            release_tag="v0.1.0a1",
            package_version="0.1.0a1",
            require_preview_tag=True,
        )
        == []
    )


def test_preview_release_rejects_stable_or_mismatched_tags() -> None:
    stable = source_errors(
        release_ref="v1.0.0",
        resolved_release_commit=SHA,
        checked_out_commit=SHA,
        github_sha=SHA,
        github_ref="refs/tags/v1.0.0",
        release_tag="v1.0.0",
        package_version="1.0.0",
        require_preview_tag=True,
    )
    mismatched = source_errors(
        release_ref="v0.1.0a1",
        resolved_release_commit=SHA,
        checked_out_commit=SHA,
        github_sha=SHA,
        github_ref="refs/tags/v0.1.0a1",
        release_tag="v0.1.0a2",
        package_version="0.1.0a1",
        require_preview_tag=True,
    )
    assert any("preview release tag" in error for error in stable)
    assert "preview release_ref must be the release_tag" in mismatched
    assert "package version must match the release tag exactly" in mismatched
