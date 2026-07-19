import json
from pathlib import Path

import pytest

from skill_doctor.telemetry import OperationalEvent, TelemetryError, TelemetryManager


def test_telemetry_is_off_by_default_and_schema_cannot_carry_sensitive_data(
    tmp_path: Path,
) -> None:
    manager = TelemetryManager(tmp_path)
    assert manager.status() == {"enabled": False, "endpoint": None, "default": "off"}
    event = OperationalEvent(
        "1.0.0",
        "diagnostic_completed",
        "success",
        "1s_to_10s",
        "windows",
        "0.1.0",
    )
    payload = json.dumps(event.__dict__ if hasattr(event, "__dict__") else str(event))
    for forbidden in ("skill", "prompt", "trace", "path", "finding", "generated_test"):
        assert forbidden not in payload.casefold()
    assert manager.send(event) is False


def test_telemetry_enablement_requires_exact_endpoint_bound_consent(tmp_path: Path) -> None:
    manager = TelemetryManager(tmp_path)
    plan = manager.plan_enable("https://operations.invalid/v1/events")
    with pytest.raises(TelemetryError, match="approval token"):
        manager.enable("https://operations.invalid/v1/events", "0" * 64)
    manager.enable(
        "https://operations.invalid/v1/events",
        str(plan["approval_token"]),
    )
    assert manager.status()["enabled"] is True
    manager.disable()
    assert manager.status()["enabled"] is False
