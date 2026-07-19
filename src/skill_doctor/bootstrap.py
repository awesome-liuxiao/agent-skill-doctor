from __future__ import annotations

import hashlib
import json
import os
import platform
import tempfile
import urllib.parse
import urllib.request
from collections.abc import Callable
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, cast

from skill_doctor import __version__
from skill_doctor.supply_chain import SupplyChainError, verify_signed_document

MAX_BOOTSTRAP_ASSETS = 16
MAX_BOOTSTRAP_ASSET_BYTES = 4 * 1024 * 1024 * 1024


@dataclass(frozen=True, slots=True)
class BootstrapAsset:
    name: str
    url: str
    sha256: str
    bytes: int


@dataclass(frozen=True, slots=True)
class BootstrapPlan:
    platform: str
    architecture: str
    manifest_sha256: str
    key_id: str
    assets: tuple[BootstrapAsset, ...]
    total_bytes: int
    approval_token: str
    requires_approval: bool = True


def _host_platform() -> str:
    return {"Windows": "windows", "Darwin": "macos", "Linux": "linux"}.get(
        platform.system(), platform.system().casefold()
    )


def plan_bootstrap(
    document: bytes,
    *,
    target_platform: str | None = None,
    architecture: str | None = None,
    public_key_pem: bytes | None = None,
) -> BootstrapPlan:
    payload, digest, key_id = verify_signed_document(document, public_key_pem=public_key_pem)
    if set(payload) != {"kind", "version", "release", "targets"}:
        raise SupplyChainError("sandbox bootstrap manifest is invalid")
    if payload.get("kind") != "sandbox_bootstrap" or payload.get("version") != 1:
        raise SupplyChainError("sandbox bootstrap manifest is invalid")
    platform_name = _host_platform() if target_platform is None else target_platform
    machine = platform.machine().casefold() if architecture is None else architecture.casefold()
    targets = payload.get("targets")
    if not isinstance(targets, list):
        raise SupplyChainError("sandbox bootstrap targets are invalid")
    target = next(
        (
            cast(dict[str, Any], item)
            for item in targets
            if isinstance(item, dict)
            and item.get("platform") == platform_name
            and str(item.get("architecture", "")).casefold() == machine
        ),
        None,
    )
    if target is None or set(target) != {"platform", "architecture", "assets"}:
        raise SupplyChainError("sandbox bootstrap has no exact host target")
    raw_assets = target.get("assets")
    if not isinstance(raw_assets, list) or not 1 <= len(raw_assets) <= MAX_BOOTSTRAP_ASSETS:
        raise SupplyChainError("sandbox bootstrap assets are invalid")
    assets: list[BootstrapAsset] = []
    for raw in raw_assets:
        if not isinstance(raw, dict) or set(raw) != {"name", "url", "sha256", "bytes"}:
            raise SupplyChainError("sandbox bootstrap asset is invalid")
        item = cast(dict[str, Any], raw)
        name = item.get("name")
        url = item.get("url")
        checksum = item.get("sha256")
        size = item.get("bytes")
        if not isinstance(name, str) or Path(name).name != name or not name or len(name) > 128:
            raise SupplyChainError("sandbox bootstrap asset name is invalid")
        parsed = urllib.parse.urlsplit(str(url))
        if (
            not isinstance(url, str)
            or parsed.scheme != "https"
            or not parsed.hostname
            or parsed.username
            or parsed.password
        ):
            raise SupplyChainError("sandbox bootstrap asset URL must be credential-free HTTPS")
        if (
            not isinstance(checksum, str)
            or len(checksum) != 64
            or any(character not in "0123456789abcdef" for character in checksum)
        ):
            raise SupplyChainError("sandbox bootstrap asset checksum is invalid")
        if (
            isinstance(size, bool)
            or not isinstance(size, int)
            or not 1 <= size <= MAX_BOOTSTRAP_ASSET_BYTES
        ):
            raise SupplyChainError("sandbox bootstrap asset size is invalid")
        assets.append(BootstrapAsset(name, url, checksum, size))
    total = sum(asset.bytes for asset in assets)
    token = hashlib.sha256(
        json.dumps(
            {
                "action": "install_verified_sandbox_backend",
                "architecture": machine,
                "manifest_sha256": digest,
                "platform": platform_name,
            },
            separators=(",", ":"),
            sort_keys=True,
        ).encode()
    ).hexdigest()
    return BootstrapPlan(platform_name, machine, digest, key_id, tuple(assets), total, token)


def _download(asset: BootstrapAsset) -> bytes:
    request = urllib.request.Request(  # noqa: S310 - HTTPS validated while planning
        asset.url, headers={"User-Agent": f"skill-doctor/{__version__}"}
    )
    try:
        with urllib.request.urlopen(request, timeout=60) as response:  # noqa: S310
            if urllib.parse.urlsplit(response.geturl()).scheme != "https":
                raise SupplyChainError("sandbox asset redirected outside HTTPS")
            return cast(bytes, response.read(asset.bytes + 1))
    except OSError as error:
        raise SupplyChainError(f"cannot download sandbox asset: {error}") from error


def install_bootstrap(
    document: bytes,
    *,
    approval_token: str,
    state_dir: Path,
    target_platform: str | None = None,
    architecture: str | None = None,
    public_key_pem: bytes | None = None,
    fetch: Callable[[BootstrapAsset], bytes] = _download,
) -> dict[str, Any]:
    plan = plan_bootstrap(
        document,
        target_platform=target_platform,
        architecture=architecture,
        public_key_pem=public_key_pem,
    )
    if approval_token != plan.approval_token:
        raise SupplyChainError("bootstrap approval token does not match the verified plan")
    root = state_dir.expanduser().absolute() / "bootstrap" / plan.platform / plan.architecture
    root.mkdir(parents=True, exist_ok=True)
    installed: list[dict[str, Any]] = []
    for asset in plan.assets:
        data = fetch(asset)
        if len(data) != asset.bytes or hashlib.sha256(data).hexdigest() != asset.sha256:
            raise SupplyChainError(f"sandbox asset verification failed: {asset.name}")
        target = root / asset.name
        handle, temporary = tempfile.mkstemp(dir=root)
        try:
            with os.fdopen(handle, "wb") as stream:
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, target)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)
        installed.append({**asdict(asset), "path": str(target)})
    receipt = {
        "version": 1,
        "platform": plan.platform,
        "architecture": plan.architecture,
        "manifest_sha256": plan.manifest_sha256,
        "key_id": plan.key_id,
        "assets": installed,
        "verification_required_before_use": True,
    }
    receipt_path = root / "receipt.json"
    receipt_path.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return receipt


def bootstrap_readiness(
    state_dir: Path,
    *,
    target_platform: str | None = None,
    architecture: str | None = None,
) -> dict[str, Any]:
    platform_name = _host_platform() if target_platform is None else target_platform
    machine = platform.machine().casefold() if architecture is None else architecture.casefold()
    root = state_dir.expanduser().absolute() / "bootstrap" / platform_name / machine
    receipt_path = root / "receipt.json"
    if not receipt_path.is_file():
        return {"installed": False, "verified": False, "detail": "explicit bootstrap not run"}
    try:
        receipt = json.loads(receipt_path.read_bytes())
        assets = receipt["assets"]
        if not isinstance(assets, list):
            raise ValueError
        for asset in assets:
            if not isinstance(asset, dict):
                raise ValueError
            path = Path(str(asset["path"])).resolve(strict=True)
            if not path.is_relative_to(root.resolve(strict=True)):
                raise ValueError
            data = path.read_bytes()
            if len(data) != asset["bytes"] or hashlib.sha256(data).hexdigest() != asset["sha256"]:
                raise ValueError
    except (KeyError, OSError, TypeError, ValueError, json.JSONDecodeError):
        return {
            "installed": True,
            "verified": False,
            "detail": "bootstrap receipt or asset failed verification",
        }
    return {
        "installed": True,
        "verified": True,
        "platform": receipt.get("platform"),
        "architecture": receipt.get("architecture"),
        "manifest_sha256": receipt.get("manifest_sha256"),
    }
