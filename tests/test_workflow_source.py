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
        require_stable_tag=True,
    )
    assert "stable release_ref must be the release_tag" in errors
