from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import tempfile
import urllib.parse
import urllib.request
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from importlib.resources import files
from pathlib import Path
from typing import Any, cast

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from skill_doctor import __version__
from skill_doctor.models import Coverage, Evidence, Finding, Severity, StaticAnalysis
from skill_doctor.snapshot import Snapshot

MAX_SIGNED_DOCUMENT_BYTES = 2 * 1024 * 1024
RULE_ID = re.compile(r"^ASD[0-9]{3}$")
PACK_VERSION = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.+-]{0,127}$")


class SupplyChainError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class DeclarativeRule:
    id: str
    title: str
    message: str
    literal: str
    severity: Severity
    case_sensitive: bool


@dataclass(frozen=True, slots=True)
class VerifiedRulePack:
    ruleset_version: str
    issued_at: str
    expires_at: str
    rules: tuple[DeclarativeRule, ...]
    document_sha256: str
    key_id: str
    source_path: str | None = None

    @property
    def effective_version(self) -> str:
        return f"{self.ruleset_version}+{self.document_sha256[:12]}"


@dataclass(frozen=True, slots=True)
class RulePackPlan:
    ruleset_version: str
    document_sha256: str
    key_id: str
    rule_count: int
    approval_token: str
    requires_approval: bool


def _canonical(payload: dict[str, Any]) -> bytes:
    return json.dumps(payload, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode(
        "utf-8"
    )


def _timestamp(value: object, label: str) -> datetime:
    if not isinstance(value, str):
        raise SupplyChainError(f"{label} must be a timestamp")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise SupplyChainError(f"{label} is invalid") from error
    if parsed.tzinfo is None:
        raise SupplyChainError(f"{label} must include a timezone")
    return parsed.astimezone(UTC)


def _default_public_key() -> bytes:
    return files("skill_doctor").joinpath("trust/release-public-key.pem").read_bytes()


def _revoked_key_ids() -> set[str]:
    raw = files("skill_doctor").joinpath("trust/revoked-keys.json").read_bytes()
    try:
        payload = json.loads(raw)
    except (UnicodeError, json.JSONDecodeError) as error:
        raise SupplyChainError("embedded key revocation list is invalid") from error
    if not isinstance(payload, dict) or payload.get("version") != 1:
        raise SupplyChainError("embedded key revocation list is invalid")
    values = payload.get("revoked_key_ids")
    if not isinstance(values, list) or not all(isinstance(item, str) for item in values):
        raise SupplyChainError("embedded key revocation list is invalid")
    return set(values)


def public_key_id(public_key_pem: bytes) -> str:
    try:
        key = serialization.load_pem_public_key(public_key_pem)
    except (TypeError, ValueError) as error:
        raise SupplyChainError("trusted signing key is invalid") from error
    if not isinstance(key, Ed25519PublicKey):
        raise SupplyChainError("trusted signing key must use Ed25519")
    der = key.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return hashlib.sha256(der).hexdigest()[:32]


def verify_signed_document(
    document: bytes,
    *,
    public_key_pem: bytes | None = None,
    revoked_key_ids: set[str] | None = None,
) -> tuple[dict[str, Any], str, str]:
    if not 1 <= len(document) <= MAX_SIGNED_DOCUMENT_BYTES:
        raise SupplyChainError("signed document exceeds its byte limit")
    try:
        envelope = json.loads(document)
    except (UnicodeError, json.JSONDecodeError) as error:
        raise SupplyChainError("signed document is invalid JSON") from error
    if not isinstance(envelope, dict) or set(envelope) != {
        "version",
        "algorithm",
        "key_id",
        "payload",
        "signature",
    }:
        raise SupplyChainError("signed document envelope is invalid")
    if envelope.get("version") != 1 or envelope.get("algorithm") != "Ed25519":
        raise SupplyChainError("signed document algorithm or version is unsupported")
    payload = envelope.get("payload")
    if not isinstance(payload, dict):
        raise SupplyChainError("signed document payload must be an object")
    key_bytes = _default_public_key() if public_key_pem is None else public_key_pem
    key_id = public_key_id(key_bytes)
    if envelope.get("key_id") != key_id:
        raise SupplyChainError("signed document key identifier is not trusted")
    revoked = _revoked_key_ids() if revoked_key_ids is None else revoked_key_ids
    if key_id in revoked:
        raise SupplyChainError("signed document key has been revoked")
    signature_value = envelope.get("signature")
    if not isinstance(signature_value, str):
        raise SupplyChainError("signed document signature is invalid")
    try:
        signature = base64.b64decode(signature_value, validate=True)
        key = serialization.load_pem_public_key(key_bytes)
        if not isinstance(key, Ed25519PublicKey):
            raise SupplyChainError("trusted signing key must use Ed25519")
        key.verify(signature, _canonical(cast(dict[str, Any], payload)))
    except (InvalidSignature, TypeError, ValueError) as error:
        raise SupplyChainError("signed document signature verification failed") from error
    return cast(dict[str, Any], payload), hashlib.sha256(document).hexdigest(), key_id


def verify_rule_pack(
    document: bytes,
    *,
    public_key_pem: bytes | None = None,
    current_time: datetime | None = None,
) -> VerifiedRulePack:
    payload, digest, key_id = verify_signed_document(document, public_key_pem=public_key_pem)
    required = {
        "kind",
        "version",
        "ruleset_version",
        "issued_at",
        "expires_at",
        "minimum_tool_version",
        "rules",
    }
    if (
        set(payload) != required
        or payload.get("kind") != "rule_pack"
        or payload.get("version") != 1
    ):
        raise SupplyChainError("rule-pack payload is invalid")
    version = payload.get("ruleset_version")
    if not isinstance(version, str) or PACK_VERSION.fullmatch(version) is None:
        raise SupplyChainError("rule-pack version is invalid")
    issued = _timestamp(payload.get("issued_at"), "rule-pack issued_at")
    expires = _timestamp(payload.get("expires_at"), "rule-pack expires_at")
    now = datetime.now(UTC) if current_time is None else current_time.astimezone(UTC)
    if expires <= issued or expires <= now:
        raise SupplyChainError("rule pack is expired")
    minimum = payload.get("minimum_tool_version")
    if not isinstance(minimum, str) or not minimum:
        raise SupplyChainError("rule-pack minimum tool version is invalid")
    raw_rules = payload.get("rules")
    if not isinstance(raw_rules, list) or not 1 <= len(raw_rules) <= 10_000:
        raise SupplyChainError("rule pack must contain a bounded non-empty rules array")
    rules: list[DeclarativeRule] = []
    for raw in raw_rules:
        if not isinstance(raw, dict) or set(raw) != {
            "id",
            "title",
            "message",
            "literal",
            "severity",
            "case_sensitive",
        }:
            raise SupplyChainError("declarative rule has an invalid shape")
        item = cast(dict[str, Any], raw)
        identifier = item.get("id")
        title = item.get("title")
        message = item.get("message")
        literal = item.get("literal")
        severity = item.get("severity")
        case_sensitive = item.get("case_sensitive")
        if not isinstance(identifier, str) or RULE_ID.fullmatch(identifier) is None:
            raise SupplyChainError("declarative rule identifier is invalid")
        if not isinstance(title, str) or not 1 <= len(title) <= 200:
            raise SupplyChainError("declarative rule title is invalid")
        if not isinstance(message, str) or not 1 <= len(message) <= 2_000:
            raise SupplyChainError("declarative rule message is invalid")
        if not isinstance(literal, str) or not 2 <= len(literal.encode("utf-8")) <= 256:
            raise SupplyChainError("declarative rule literal is invalid")
        if severity not in {"info", "low", "medium", "high", "critical"}:
            raise SupplyChainError("declarative rule severity is invalid")
        if not isinstance(case_sensitive, bool):
            raise SupplyChainError("declarative rule case_sensitive must be a boolean")
        rules.append(
            DeclarativeRule(
                identifier,
                title,
                message,
                literal,
                cast(Severity, severity),
                case_sensitive,
            )
        )
    return VerifiedRulePack(
        version,
        str(payload["issued_at"]),
        str(payload["expires_at"]),
        tuple(rules),
        digest,
        key_id,
    )


class RulePackManager:
    def __init__(self, state_dir: Path, *, public_key_pem: bytes | None = None) -> None:
        self.root = state_dir.expanduser().absolute() / "rules"
        self.packs = self.root / "packs"
        self.metadata = self.root / "state.json"
        self.public_key_pem = public_key_pem
        self.packs.mkdir(parents=True, exist_ok=True)

    def _atomic_write(self, target: Path, data: bytes) -> None:
        handle, temporary = tempfile.mkstemp(dir=target.parent)
        try:
            with os.fdopen(handle, "wb") as stream:
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, target)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)

    def _state(self) -> dict[str, Any]:
        if not self.metadata.is_file():
            return {
                "version": 1,
                "active": None,
                "history": [],
                "pinned": None,
                "feed": None,
                "feed_approval": None,
                "last_checked": None,
            }
        try:
            payload = json.loads(self.metadata.read_bytes())
        except (OSError, UnicodeError, json.JSONDecodeError) as error:
            raise SupplyChainError("rule-pack state is corrupt") from error
        if isinstance(payload, dict) and set(payload) == {
            "version",
            "active",
            "history",
            "pinned",
        }:
            payload.update({"feed": None, "feed_approval": None, "last_checked": None})
        if not isinstance(payload, dict) or set(payload) != {
            "version",
            "active",
            "history",
            "pinned",
            "feed",
            "feed_approval",
            "last_checked",
        }:
            raise SupplyChainError("rule-pack state is corrupt")
        if payload.get("version") != 1 or not isinstance(payload.get("history"), list):
            raise SupplyChainError("rule-pack state is corrupt")
        return cast(dict[str, Any], payload)

    def _write_state(self, state: dict[str, Any]) -> None:
        self._atomic_write(
            self.metadata,
            (json.dumps(state, indent=2, sort_keys=True) + "\n").encode("utf-8"),
        )

    def plan(self, document: bytes) -> RulePackPlan:
        pack = verify_rule_pack(document, public_key_pem=self.public_key_pem)
        token = hashlib.sha256(
            _canonical(
                {
                    "action": "install_signed_rule_pack",
                    "document_sha256": pack.document_sha256,
                    "ruleset_version": pack.ruleset_version,
                }
            )
        ).hexdigest()
        return RulePackPlan(
            pack.ruleset_version,
            pack.document_sha256,
            pack.key_id,
            len(pack.rules),
            token,
            True,
        )

    def install(self, document: bytes, approval_token: str) -> VerifiedRulePack:
        plan = self.plan(document)
        if approval_token != plan.approval_token:
            raise SupplyChainError("rule-pack approval token does not match the verified plan")
        return self._activate(document)

    def _activate(self, document: bytes) -> VerifiedRulePack:
        pack = verify_rule_pack(document, public_key_pem=self.public_key_pem)
        state = self._state()
        pinned = state.get("pinned")
        if pinned is not None and pinned != pack.ruleset_version:
            raise SupplyChainError("rule-pack updates are pinned to another version")
        name = f"{pack.ruleset_version}-{pack.document_sha256}.json"
        target = self.packs / name
        if not target.is_file():
            self._atomic_write(target, document)
        active = {"file": name, "sha256": pack.document_sha256}
        history = [item for item in state["history"] if item != active]
        previous = state.get("active")
        if isinstance(previous, dict) and previous != active:
            history.append(previous)
        state.update({"active": active, "history": history[-10:]})
        self._write_state(state)
        return pack

    @staticmethod
    def _feed_url(url: str) -> str:
        parsed = urllib.parse.urlsplit(url)
        if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
            raise SupplyChainError("rule-pack update URL must be credential-free HTTPS")
        return url

    def plan_feed(self, url: str) -> dict[str, Any]:
        normalized = self._feed_url(url)
        token = hashlib.sha256(
            _canonical({"action": "enable_automatic_signed_rule_updates", "url": normalized})
        ).hexdigest()
        return {
            "url": normalized,
            "approval_token": token,
            "requires_approval": True,
            "network_scope": "fetch_only_this_signed_rule_pack_url",
        }

    def configure_feed(self, url: str, approval_token: str) -> None:
        plan = self.plan_feed(url)
        if approval_token != plan["approval_token"]:
            raise SupplyChainError("automatic update approval token does not match the plan")
        state = self._state()
        state.update(
            {
                "feed": plan["url"],
                "feed_approval": approval_token,
                "last_checked": None,
            }
        )
        self._write_state(state)

    def disable_feed(self) -> None:
        state = self._state()
        state.update({"feed": None, "feed_approval": None, "last_checked": None})
        self._write_state(state)

    def status(self) -> dict[str, Any]:
        state = self._state()
        return {
            "pinned": state["pinned"],
            "automatic_update_url": state["feed"],
            "automatic_update_approved": state["feed"] is not None,
            "last_checked": state["last_checked"],
        }

    def maybe_auto_update(self, *, current_time: datetime | None = None) -> dict[str, Any]:
        state = self._state()
        feed = state.get("feed")
        if not isinstance(feed, str):
            return {"checked": False, "reason": "automatic_updates_disabled"}
        if state.get("feed_approval") != self.plan_feed(feed)["approval_token"]:
            raise SupplyChainError("automatic rule-pack update consent is invalid")
        now = datetime.now(UTC) if current_time is None else current_time.astimezone(UTC)
        last_checked = state.get("last_checked")
        if isinstance(last_checked, str):
            last = _timestamp(last_checked, "rule-pack last_checked")
            if (now - last).total_seconds() < 24 * 60 * 60:
                return {"checked": False, "reason": "update_interval_not_elapsed"}
        state["last_checked"] = now.isoformat().replace("+00:00", "Z")
        self._write_state(state)
        try:
            document = self.fetch(feed)
            candidate = verify_rule_pack(document, public_key_pem=self.public_key_pem)
            active = self.load_active()
            if active is not None and active.document_sha256 == candidate.document_sha256:
                return {"checked": True, "updated": False, "reason": "already_current"}
            installed = self._activate(document)
        except SupplyChainError as error:
            return {"checked": True, "updated": False, "error": str(error)}
        return {"checked": True, "updated": True, "active": installed.effective_version}

    def load_active(self) -> VerifiedRulePack | None:
        state = self._state()
        active = state.get("active")
        if active is None:
            return None
        if not isinstance(active, dict) or set(active) != {"file", "sha256"}:
            raise SupplyChainError("active rule-pack state is corrupt")
        name = active.get("file")
        digest = active.get("sha256")
        if not isinstance(name, str) or Path(name).name != name or not isinstance(digest, str):
            raise SupplyChainError("active rule-pack state is corrupt")
        path = self.packs / name
        try:
            document = path.read_bytes()
        except OSError as error:
            raise SupplyChainError("active rule pack is unavailable") from error
        if hashlib.sha256(document).hexdigest() != digest:
            raise SupplyChainError("active rule pack failed checksum verification")
        pack = verify_rule_pack(document, public_key_pem=self.public_key_pem)
        return replace(pack, source_path=str(path))

    def rollback(self) -> VerifiedRulePack:
        state = self._state()
        history = state.get("history")
        if not isinstance(history, list) or not history:
            raise SupplyChainError("no verified rule-pack rollback is available")
        previous = history.pop()
        current = state.get("active")
        state["active"] = previous
        if isinstance(current, dict):
            history.append(current)
        state["history"] = history[-10:]
        self._write_state(state)
        pack = self.load_active()
        if pack is None:
            raise SupplyChainError("verified rule-pack rollback failed")
        return pack

    def pin(self, ruleset_version: str | None) -> None:
        if ruleset_version is not None and PACK_VERSION.fullmatch(ruleset_version) is None:
            raise SupplyChainError("rule-pack pin is invalid")
        state = self._state()
        state["pinned"] = ruleset_version
        self._write_state(state)

    def fetch(self, url: str) -> bytes:
        url = self._feed_url(url)
        request = urllib.request.Request(  # noqa: S310 - credential-free HTTPS validated above
            url, headers={"User-Agent": f"skill-doctor/{__version__}"}
        )
        try:
            with urllib.request.urlopen(request, timeout=15) as response:  # noqa: S310
                final = urllib.parse.urlsplit(response.geturl())
                if final.scheme != "https":
                    raise SupplyChainError("rule-pack update redirected outside HTTPS")
                document = cast(bytes, response.read(MAX_SIGNED_DOCUMENT_BYTES + 1))
        except OSError as error:
            raise SupplyChainError(f"cannot fetch signed rule pack: {error}") from error
        if len(document) > MAX_SIGNED_DOCUMENT_BYTES:
            raise SupplyChainError("signed rule pack exceeds its byte limit")
        verify_rule_pack(document, public_key_pem=self.public_key_pem)
        return document


def analyze_declarative_rules(snapshot: Snapshot, pack: VerifiedRulePack) -> StaticAnalysis:
    document = next((item for item in snapshot.files if item.relative_path == "SKILL.md"), None)
    if document is None:
        return StaticAnalysis(coverage=Coverage(skipped=("signed_declarative_rules:no_SKILL.md",)))
    try:
        text = document.data.decode("utf-8")
    except UnicodeError:
        return StaticAnalysis(coverage=Coverage(skipped=("signed_declarative_rules:non_utf8",)))
    findings: list[Finding] = []
    evidence: list[Evidence] = []
    for rule in pack.rules:
        haystack = text if rule.case_sensitive else text.casefold()
        needle = rule.literal if rule.case_sensitive else rule.literal.casefold()
        offset = haystack.find(needle)
        if offset < 0:
            continue
        line = text.count("\n", 0, offset) + 1
        identity = hashlib.sha256(
            f"{pack.document_sha256}:{rule.id}:{document.digest}:{line}".encode()
        ).hexdigest()[:20]
        evidence_id = f"signed-rule-{identity}"
        evidence.append(
            Evidence(
                evidence_id,
                "verified_signed_declarative_rule",
                f"Verified rule pack {pack.ruleset_version} matched literal {rule.literal!r}.",
                pack.document_sha256,
                "SKILL.md",
                line,
            )
        )
        findings.append(
            Finding(
                f"finding-{identity}",
                rule.id,
                rule.title,
                rule.message,
                rule.severity,
                "high",
                "indeterminate",
                (evidence_id,),
                "SKILL.md",
                line,
            )
        )
    return StaticAnalysis(
        findings,
        evidence,
        Coverage(completed=(f"signed_declarative_rules:{pack.effective_version}",)),
    )
