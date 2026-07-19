import re
import tomllib
from importlib.resources import files
from pathlib import Path


def test_release_workflow_builds_three_signed_attested_sbom_bundles() -> None:
    root = Path(__file__).parents[1]
    workflow = (root / ".github" / "workflows" / "release.yml").read_text(encoding="utf-8")
    for target in ("windows-amd64", "macos-arm64", "linux-amd64"):
        assert target in workflow
    assert "actions/attest-build-provenance" in workflow
    assert "sigstore/gh-action-sigstore-python" in workflow
    assert "cyclonedx-py" in workflow
    assert "SOURCE_DATE_EPOCH" in workflow
    assert "requirements-release.lock" in workflow
    assert "--no-deps" in workflow
    assert "python -m pip check" in workflow
    assert "held-out-result.json" in workflow
    assert "release-evidence.json" in workflow
    assert "--held-out-attestation-verified" in workflow
    assert "--release-evidence-attestation-verified" in workflow
    assert "--source-digest" in workflow
    assert "verify_workflow_source.py" in workflow
    assert "--require-stable-tag" in workflow
    assert "verify: true" in workflow


def test_protected_release_evidence_workflows_are_fail_closed() -> None:
    root = Path(__file__).parents[1]
    held_out = (root / ".github" / "workflows" / "held-out-evaluation.yml").read_text(
        encoding="utf-8"
    )
    partners = (root / ".github" / "workflows" / "design-partner-signoff.yml").read_text(
        encoding="utf-8"
    )
    assert "stable-release-held-out" in held_out
    assert "extract_held_out.py" in held_out
    assert "actions/attest-build-provenance" in held_out
    assert "verify_workflow_source.py" in held_out
    assert "stable-release-design-partner" in partners
    assert "create_release_evidence.py" in partners
    assert "actions/attest-build-provenance" in partners
    assert "verify_workflow_source.py" in partners


def test_package_versions_stay_synchronized() -> None:
    root = Path(__file__).parents[1]
    pyproject = tomllib.loads((root / "pyproject.toml").read_text(encoding="utf-8"))
    package = (root / "src" / "skill_doctor" / "__init__.py").read_text(encoding="utf-8")
    match = re.search(r'^__version__ = "([^"]+)"$', package, re.MULTILINE)
    assert match is not None
    assert pyproject["project"]["version"] == match.group(1)


def test_release_toolchain_transitives_are_exactly_pinned() -> None:
    root = Path(__file__).parents[1]
    lock = (root / "requirements-release.lock").read_text(encoding="utf-8")
    for requirement in (
        "pyinstaller==6.14.2",
        "pyinstaller-hooks-contrib==2026.6",
        "cyclonedx-bom==7.0.0",
        "cyclonedx-python-lib==10.5.0",
        "setuptools==83.0.0",
    ):
        assert requirement in lock
    build = (root / "scripts" / "build_standalone.py").read_text(encoding="utf-8")
    assert '"USERPROFILE"' in build
    assert '"--specpath"' in build
    assert '"PYINSTALLER_CONFIG_DIR"' in build


def test_installers_verify_checksum_and_attestation_before_execution() -> None:
    root = Path(__file__).parents[1]
    powershell = (root / "install.ps1").read_text(encoding="utf-8")
    shell = (root / "install.sh").read_text(encoding="utf-8")
    for document in (powershell, shell):
        document = document.casefold()
        checksum = document.find("checksum verification")
        manifest_attestation = document.find("attestation verify")
        binary_attestation = document.find("attestation verify", manifest_attestation + 1)
        readiness = document.find("readiness --deep")
        assert 0 <= manifest_attestation < checksum < binary_attestation < readiness
        assert document.count("--signer-workflow") == 2
        assert document.count("--source-ref") == 2
        assert document.count("--deny-self-hosted-runners") == 2
    assert "GitHub CLI is required" in powershell
    assert "GitHub CLI is required" in shell


def test_embedded_baseline_signing_key_and_revocation_list_are_packaged() -> None:
    package = files("skill_doctor")
    assert package.joinpath("embedded-rules.json").read_bytes()
    assert b"BEGIN PUBLIC KEY" in package.joinpath("trust/release-public-key.pem").read_bytes()
    assert b"revoked_key_ids" in package.joinpath("trust/revoked-keys.json").read_bytes()
