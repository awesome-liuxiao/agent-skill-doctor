import base64
import hashlib
import json
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from skill_doctor.bootstrap import (
    BootstrapAsset,
    bootstrap_readiness,
    install_bootstrap,
    plan_bootstrap,
)
from skill_doctor.supply_chain import SupplyChainError, public_key_id


def _manifest(asset: bytes) -> tuple[bytes, bytes]:
    private = Ed25519PrivateKey.generate()
    public = private.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    payload = {
        "kind": "sandbox_bootstrap",
        "version": 1,
        "release": "fixture",
        "targets": [
            {
                "platform": "windows",
                "architecture": "amd64",
                "assets": [
                    {
                        "name": "runner.bin",
                        "url": "https://fixtures.invalid/runner.bin",
                        "sha256": hashlib.sha256(asset).hexdigest(),
                        "bytes": len(asset),
                    }
                ],
            }
        ],
    }
    canonical = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()
    document = json.dumps(
        {
            "version": 1,
            "algorithm": "Ed25519",
            "key_id": public_key_id(public),
            "payload": payload,
            "signature": base64.b64encode(private.sign(canonical)).decode(),
        },
        separators=(",", ":"),
        sort_keys=True,
    ).encode()
    return document, public


def test_bootstrap_requires_preview_and_verifies_every_asset(tmp_path: Path) -> None:
    asset = b"verified sandbox runner"
    document, public = _manifest(asset)
    plan = plan_bootstrap(
        document,
        target_platform="windows",
        architecture="amd64",
        public_key_pem=public,
    )
    with pytest.raises(SupplyChainError, match="approval token"):
        install_bootstrap(
            document,
            approval_token="0" * 64,
            state_dir=tmp_path,
            target_platform="windows",
            architecture="amd64",
            public_key_pem=public,
        )
    with pytest.raises(SupplyChainError, match="verification failed"):
        install_bootstrap(
            document,
            approval_token=plan.approval_token,
            state_dir=tmp_path,
            target_platform="windows",
            architecture="amd64",
            public_key_pem=public,
            fetch=lambda _item: b"tampered sandbox runner",
        )
    receipt = install_bootstrap(
        document,
        approval_token=plan.approval_token,
        state_dir=tmp_path,
        target_platform="windows",
        architecture="amd64",
        public_key_pem=public,
        fetch=lambda item: asset if isinstance(item, BootstrapAsset) else b"",
    )
    runner = Path(receipt["assets"][0]["path"])
    assert runner.read_bytes() == asset
    assert (
        bootstrap_readiness(tmp_path, target_platform="windows", architecture="amd64")["verified"]
        is True
    )
    runner.write_bytes(b"tampered")
    assert (
        bootstrap_readiness(tmp_path, target_platform="windows", architecture="amd64")["verified"]
        is False
    )
