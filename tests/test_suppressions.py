import json
from datetime import UTC, datetime
from pathlib import Path

from skill_doctor.models import Finding
from skill_doctor.suppressions import resolve_suppressions


def _finding() -> Finding:
    return Finding(
        "finding-1",
        "ASD900",
        "Fixture",
        "Fixture",
        "high",
        "high",
        "indeterminate",
        ("evidence-1",),
    )


def test_suppressions_are_expiring_auditable_and_stale_on_content_change(
    tmp_path: Path,
) -> None:
    config = tmp_path / ".skill-doctor"
    config.mkdir()
    snapshot = "a" * 64
    (config / "suppressions.json").write_text(
        json.dumps(
            {
                "version": 1,
                "suppressions": [
                    {
                        "id": "accepted-risk",
                        "rule_id": "ASD900",
                        "finding_id": "finding-1",
                        "reason": "Owner accepted this finite risk.",
                        "created_at": "2026-01-01T00:00:00Z",
                        "expires_at": "2027-01-01T00:00:00Z",
                        "snapshot_hash": snapshot,
                        "ruleset_version": "rules-1",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    active = resolve_suppressions(
        findings=[_finding()],
        root=tmp_path,
        snapshot_hash=snapshot,
        ruleset_version="rules-1",
        flagged_finding_ids={"finding-1"},
        home=tmp_path / "empty-home",
        current_time=datetime(2026, 7, 16, tzinfo=UTC),
    )
    assert active.suppressed_finding_ids == ("finding-1",)
    assert active.blocking_finding_ids == ()
    assert active.audit["active"][0]["reason"] == "Owner accepted this finite risk."

    stale = resolve_suppressions(
        findings=[_finding()],
        root=tmp_path,
        snapshot_hash="b" * 64,
        ruleset_version="rules-1",
        flagged_finding_ids={"finding-1"},
        home=tmp_path / "empty-home",
        current_time=datetime(2026, 7, 16, tzinfo=UTC),
    )
    assert stale.suppressed_finding_ids == ()
    assert stale.blocking_finding_ids == ("finding-1",)
    assert stale.audit["stale"][0]["stale_reasons"] == ["snapshot_hash_changed"]
