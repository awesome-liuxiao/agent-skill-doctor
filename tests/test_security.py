import hashlib
import os
import sys
from pathlib import Path

import pytest

from skill_doctor.security import ENVELOPE_MAGIC, ArtifactCipher, IntegrityError
from skill_doctor.store import LocalStore


def test_aes_gcm_envelope_round_trip_and_tamper_detection() -> None:
    cipher = ArtifactCipher(os.urandom(32))
    plaintext = b"sensitive snapshot bytes"
    digest = hashlib.sha256(plaintext).hexdigest()
    first = cipher.encrypt(digest, plaintext)
    second = cipher.encrypt(digest, plaintext)
    assert first.startswith(ENVELOPE_MAGIC)
    assert first != second
    assert plaintext not in first
    assert cipher.decrypt(digest, first) == plaintext
    tampered = first[:-1] + bytes([first[-1] ^ 1])
    with pytest.raises(IntegrityError, match="authentication failed"):
        cipher.decrypt(digest, tampered)


def test_local_store_never_writes_raw_artifact_bytes(tmp_path: Path) -> None:
    cipher = ArtifactCipher(os.urandom(32))
    store = LocalStore(tmp_path, cipher=cipher)
    plaintext = b"raw skill content"
    digest = hashlib.sha256(plaintext).hexdigest()
    target = store.put_bytes(digest, plaintext)
    assert target.read_bytes().startswith(ENVELOPE_MAGIC)
    assert target.read_bytes() != plaintext
    assert store.get_bytes(digest) == plaintext


@pytest.mark.skipif(sys.platform != "win32", reason="Windows DPAPI integration test")
def test_windows_master_key_is_dpapi_protected_and_stable(tmp_path: Path) -> None:
    first = ArtifactCipher.for_state(tmp_path)
    protected = (tmp_path / "master-key.dpapi").read_bytes()
    second = ArtifactCipher.for_state(tmp_path)
    assert len(protected) > 32
    assert first.ipc_auth_key == second.ipc_auth_key
    assert first.ipc_auth_key not in protected
