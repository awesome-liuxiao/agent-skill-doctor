import base64
import json
import os
from datetime import UTC, datetime
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from skill_doctor.engine import execute_check
from skill_doctor.security import ArtifactCipher
from skill_doctor.snapshot import create_snapshot
from skill_doctor.store import LocalStore
from skill_doctor.supply_chain import (
    RulePackManager,
    SupplyChainError,
    analyze_declarative_rules,
    public_key_id,
    verify_rule_pack,
    verify_signed_document,
)


def _keys() -> tuple[Ed25519PrivateKey, bytes]:
    private = Ed25519PrivateKey.generate()
    public = private.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return private, public


def _document(
    private: Ed25519PrivateKey,
    public: bytes,
    *,
    version: str = "fixture-1",
    literal: str = "signed-fixture",
) -> bytes:
    payload = {
        "kind": "rule_pack",
        "version": 1,
        "ruleset_version": version,
        "issued_at": "2026-01-01T00:00:00Z",
        "expires_at": "2030-01-01T00:00:00Z",
        "minimum_tool_version": "0.1.0",
        "rules": [
            {
                "id": "ASD800",
                "title": "Signed fixture matched",
                "message": "The signed declarative fixture matched.",
                "literal": literal,
                "severity": "high",
                "case_sensitive": False,
            }
        ],
    }
    canonical = json.dumps(
        payload, ensure_ascii=False, separators=(",", ":"), sort_keys=True
    ).encode("utf-8")
    envelope = {
        "version": 1,
        "algorithm": "Ed25519",
        "key_id": public_key_id(public),
        "payload": payload,
        "signature": base64.b64encode(private.sign(canonical)).decode("ascii"),
    }
    return json.dumps(envelope, separators=(",", ":"), sort_keys=True).encode("utf-8")


def test_signed_rule_pack_verification_rejects_tampering_and_revocation() -> None:
    private, public = _keys()
    document = _document(private, public)
    pack = verify_rule_pack(
        document,
        public_key_pem=public,
        current_time=datetime(2026, 7, 16, tzinfo=UTC),
    )
    assert pack.ruleset_version == "fixture-1"
    tampered = document.replace(b"signed-fixture", b"signed-FIXTURE")
    with pytest.raises(SupplyChainError, match="signature verification"):
        verify_rule_pack(tampered, public_key_pem=public)
    with pytest.raises(SupplyChainError, match="revoked"):
        verify_signed_document(
            document,
            public_key_pem=public,
            revoked_key_ids={public_key_id(public)},
        )


def test_rule_pack_install_pin_rollback_and_runtime_checksum(
    tmp_path: Path,
) -> None:
    private, public = _keys()
    first = _document(private, public, version="fixture-1")
    second = _document(private, public, version="fixture-2", literal="new-fixture")
    manager = RulePackManager(tmp_path / "state", public_key_pem=public)
    plan = manager.plan(first)
    installed = manager.install(first, plan.approval_token)
    loaded = manager.load_active()
    assert loaded is not None
    assert loaded.document_sha256 == installed.document_sha256
    manager.pin("fixture-1")
    with pytest.raises(SupplyChainError, match="pinned"):
        manager.install(second, manager.plan(second).approval_token)
    manager.pin(None)
    manager.install(second, manager.plan(second).approval_token)
    assert manager.rollback().ruleset_version == "fixture-1"
    active = manager.load_active()
    assert active is not None and active.source_path is not None
    Path(active.source_path).write_bytes(b"tampered")
    with pytest.raises(SupplyChainError, match="checksum"):
        manager.load_active()


def test_verified_declarative_rule_runs_without_code_execution(tmp_path: Path) -> None:
    private, public = _keys()
    pack = verify_rule_pack(_document(private, public), public_key_pem=public)
    skill = tmp_path / "fixture"
    skill.mkdir()
    (skill / "SKILL.md").write_text(
        "---\nname: fixture\ndescription: signed-fixture check.\n---\n",
        encoding="utf-8",
    )
    analysis = analyze_declarative_rules(create_snapshot(skill), pack)
    assert [finding.rule_id for finding in analysis.findings] == ["ASD800"]
    assert analysis.evidence[0].kind == "verified_signed_declarative_rule"


def test_approved_automatic_update_installs_only_verified_feed_document(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    private, public = _keys()
    document = _document(private, public)
    manager = RulePackManager(tmp_path / "state", public_key_pem=public)
    feed = "https://updates.invalid/rules.json"
    feed_plan = manager.plan_feed(feed)
    manager.configure_feed(feed, str(feed_plan["approval_token"]))
    monkeypatch.setattr(manager, "fetch", lambda _url: document)
    updated = manager.maybe_auto_update(current_time=datetime(2026, 7, 16, tzinfo=UTC))
    assert updated["updated"] is True
    assert manager.load_active() is not None
    repeated = manager.maybe_auto_update(current_time=datetime(2026, 7, 16, 1, tzinfo=UTC))
    assert repeated == {"checked": False, "reason": "update_interval_not_elapsed"}


def test_verified_active_pack_is_included_in_effective_analysis_and_cache_key(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    private, public = _keys()
    document = _document(private, public)
    monkeypatch.setattr("skill_doctor.supply_chain._default_public_key", lambda: public)
    state = tmp_path / "state"
    manager = RulePackManager(state)
    manager.install(document, manager.plan(document).approval_token)
    skill = tmp_path / "fixture"
    skill.mkdir()
    (skill / "SKILL.md").write_text(
        "---\nname: fixture\ndescription: signed-fixture integration.\n---\n",
        encoding="utf-8",
    )
    store = LocalStore(state, cipher=ArtifactCipher(os.urandom(32)))
    store.start_job("signed-job", "2026-07-16T00:00:00Z", str(skill))
    result = execute_check(
        job_id="signed-job",
        created_at="2026-07-16T00:00:00Z",
        path=skill,
        store=store,
        emit=lambda _stage, _summary, _detail: None,
        cancelled=lambda: False,
    )
    assert result.report is not None
    assert "+signed.fixture-1+" in result.report.ruleset_version
    assert any(finding.rule_id == "ASD800" for finding in result.report.findings)
