from __future__ import annotations

import hashlib
import json
import os
import tempfile
import urllib.parse
import urllib.request
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Literal, cast

from skill_doctor import __version__

TelemetryEventName = Literal["readiness", "diagnostic_completed", "bootstrap_completed"]
TelemetryOutcome = Literal["success", "incomplete", "cancelled", "internal_error"]
DurationBucket = Literal["under_1s", "1s_to_10s", "10s_to_60s", "over_60s", "unknown"]


class TelemetryError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class OperationalEvent:
    schema_version: str
    event: TelemetryEventName
    outcome: TelemetryOutcome
    duration_bucket: DurationBucket
    host_family: Literal["windows", "macos", "linux", "other"]
    tool_version: str


class TelemetryManager:
    def __init__(self, state_dir: Path) -> None:
        self.root = state_dir.expanduser().absolute()
        self.config = self.root / "telemetry.json"

    @staticmethod
    def _endpoint(value: str) -> str:
        parsed = urllib.parse.urlsplit(value)
        if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
            raise TelemetryError("telemetry endpoint must be credential-free HTTPS")
        if parsed.query or parsed.fragment:
            raise TelemetryError("telemetry endpoint cannot contain query or fragment data")
        return value

    def plan_enable(self, endpoint: str) -> dict[str, object]:
        normalized = self._endpoint(endpoint)
        token = hashlib.sha256(
            json.dumps(
                {"action": "enable_narrow_operational_telemetry", "endpoint": normalized},
                separators=(",", ":"),
                sort_keys=True,
            ).encode()
        ).hexdigest()
        return {
            "endpoint": normalized,
            "approval_token": token,
            "requires_approval": True,
            "fields": [
                "schema_version",
                "event",
                "outcome",
                "duration_bucket",
                "host_family",
                "tool_version",
            ],
            "forbidden": [
                "skill",
                "prompt",
                "trace",
                "path",
                "finding",
                "generated_test",
            ],
        }

    def _atomic_write(self, data: bytes) -> None:
        self.root.mkdir(parents=True, exist_ok=True)
        handle, temporary = tempfile.mkstemp(dir=self.root)
        try:
            with os.fdopen(handle, "wb") as stream:
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, self.config)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)

    def enable(self, endpoint: str, approval_token: str) -> None:
        plan = self.plan_enable(endpoint)
        if approval_token != plan["approval_token"]:
            raise TelemetryError("telemetry approval token does not match the preview")
        self._atomic_write(
            (
                json.dumps({"version": 1, "enabled": True, "endpoint": endpoint}, sort_keys=True)
                + "\n"
            ).encode()
        )

    def disable(self) -> None:
        self._atomic_write(b'{"enabled":false,"endpoint":null,"version":1}\n')

    def status(self) -> dict[str, object]:
        if not self.config.is_file():
            return {"enabled": False, "endpoint": None, "default": "off"}
        try:
            payload = json.loads(self.config.read_bytes())
        except (OSError, UnicodeError, json.JSONDecodeError) as error:
            raise TelemetryError("telemetry configuration is corrupt") from error
        if (
            not isinstance(payload, dict)
            or set(payload) != {"version", "enabled", "endpoint"}
            or payload.get("version") != 1
            or not isinstance(payload.get("enabled"), bool)
        ):
            raise TelemetryError("telemetry configuration is corrupt")
        endpoint = payload.get("endpoint")
        if payload["enabled"]:
            if not isinstance(endpoint, str):
                raise TelemetryError("telemetry configuration is corrupt")
            self._endpoint(endpoint)
        elif endpoint is not None:
            raise TelemetryError("telemetry configuration is corrupt")
        return {
            "enabled": payload["enabled"],
            "endpoint": endpoint,
            "default": "off",
        }

    def send(self, event: OperationalEvent) -> bool:
        status = self.status()
        if not status["enabled"]:
            return False
        endpoint = cast(str, status["endpoint"])
        data = json.dumps(asdict(event), separators=(",", ":"), sort_keys=True).encode()
        request = urllib.request.Request(  # noqa: S310 - endpoint is validated HTTPS
            endpoint,
            data=data,
            headers={
                "Content-Type": "application/json",
                "User-Agent": f"skill-doctor/{__version__}",
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=5) as response:  # noqa: S310
                if urllib.parse.urlsplit(response.geturl()).scheme != "https":
                    raise TelemetryError("telemetry redirected outside HTTPS")
                if not 200 <= response.status < 300:
                    raise TelemetryError("telemetry endpoint rejected the event")
        except OSError as error:
            raise TelemetryError(f"telemetry delivery failed: {error}") from error
        return True
