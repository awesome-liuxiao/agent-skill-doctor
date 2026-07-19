from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
from importlib.resources import files
from pathlib import Path
from typing import Any

from skill_doctor.bootstrap import bootstrap_readiness
from skill_doctor.sandbox import SandboxUnavailable, backend_for_host
from skill_doctor.security import platform_encryption_readiness
from skill_doctor.supply_chain import (
    RulePackManager,
    SupplyChainError,
    public_key_id,
)


def _version(executable: str) -> dict[str, Any]:
    resolved = shutil.which(executable)
    if resolved is None:
        return {"available": False, "version": None}
    try:
        result = subprocess.run(  # noqa: S603
            [resolved, "--version"],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            timeout=5,
            check=False,
            env={key: os.environ[key] for key in ("PATH", "SYSTEMROOT") if key in os.environ},
        )
    except (OSError, subprocess.TimeoutExpired):
        return {"available": True, "version": None}
    output = (result.stdout or result.stderr)[:4096].decode("utf-8", errors="replace").strip()
    return {
        "available": result.returncode == 0,
        "version": output or None,
    }


def readiness_report(state_dir: Path, *, deep: bool = False) -> dict[str, Any]:
    try:
        sandbox = backend_for_host().readiness(deep=deep).to_dict()
    except SandboxUnavailable as error:
        sandbox = {
            "ready": False,
            "host_platform": sys.platform,
            "detail": str(error),
            "coverage_gaps": ["supported_sandbox_backend"],
        }
    runtimes = {name: _version(name) for name in ("codex", "claude")}
    tools = {
        name: shutil.which(name) is not None
        for name in ("docker", "node", "npm", "ollama", "podman", "python")
    }
    embedded = files("skill_doctor").joinpath("embedded-rules.json").read_bytes()
    public_key = files("skill_doctor").joinpath("trust/release-public-key.pem").read_bytes()
    try:
        active_pack = RulePackManager(state_dir).load_active()
        rule_pack = {
            "verified": True,
            "mode": "embedded_offline_baseline" if active_pack is None else "signed_rule_pack",
            "active_version": (
                json.loads(embedded)["ruleset_version"]
                if active_pack is None
                else active_pack.effective_version
            ),
            "document_sha256": (
                hashlib.sha256(embedded).hexdigest()
                if active_pack is None
                else active_pack.document_sha256
            ),
        }
    except (OSError, SupplyChainError, UnicodeError, json.JSONDecodeError) as error:
        rule_pack = {
            "verified": False,
            "mode": "blocked_unverified_rule_pack",
            "detail": str(error),
        }
    local_endpoint = any(
        value.startswith(("http://127.0.0.1", "http://localhost", "http://[::1]"))
        for value in (
            os.environ.get("OPENAI_BASE_URL", ""),
            os.environ.get("ANTHROPIC_BASE_URL", ""),
        )
    )
    return {
        "schema_version": "1.0.0",
        "host_platform": sys.platform,
        "sandbox": sandbox,
        "runtimes": runtimes,
        "credentials": {
            "encrypted_state": platform_encryption_readiness(state_dir),
            "ephemeral_runtime_proxy_token_available": bool(
                os.environ.get("SKILL_DOCTOR_EPHEMERAL_TOKEN")
            ),
            "host_credential_files_mounted": False,
        },
        "tools": tools,
        "virtualization": {
            "sandbox_backend": sandbox.get("backend"),
            "ready": bool(sandbox.get("ready")),
            "coverage_gaps": sandbox.get("coverage_gaps", []),
        },
        "bootstrap": bootstrap_readiness(state_dir),
        "local_models": {
            "ollama_available": tools["ollama"],
            "loopback_endpoint_configured": local_endpoint,
        },
        "rule_pack": rule_pack,
        "release_trust": {
            "algorithm": "Ed25519",
            "key_id": public_key_id(public_key),
            "unverified_assets_run": False,
        },
        "dynamic_execution_policy": ("sandbox_only" if sandbox.get("ready") else "static_only"),
    }
