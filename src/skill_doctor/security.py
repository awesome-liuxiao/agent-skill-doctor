from __future__ import annotations

import base64
import ctypes
import hashlib
import hmac
import os
import sys
import tempfile
from ctypes import wintypes
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

ENVELOPE_MAGIC = b"ASDENC\x01"
MASTER_KEY_BYTES = 32
NONCE_BYTES = 12
KEYCHAIN_SERVICE = b"dev.agent-skill-doctor.master-key"


class EncryptionUnavailable(RuntimeError):
    pass


class IntegrityError(RuntimeError):
    pass


class _DataBlob(ctypes.Structure):
    _fields_ = [("size", wintypes.DWORD), ("data", ctypes.POINTER(ctypes.c_ubyte))]


def _atomic_write(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    handle, temporary = tempfile.mkstemp(dir=path.parent)
    try:
        with os.fdopen(handle, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def _dpapi(data: bytes, *, protect: bool) -> bytes:
    if sys.platform != "win32":
        raise EncryptionUnavailable("DPAPI is available only on Windows")
    try:
        crypt32 = ctypes.WinDLL("crypt32", use_last_error=True)
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    except OSError as error:
        raise EncryptionUnavailable("Windows DPAPI could not be loaded") from error

    buffer = (ctypes.c_ubyte * len(data)).from_buffer_copy(data)
    input_blob = _DataBlob(len(data), ctypes.cast(buffer, ctypes.POINTER(ctypes.c_ubyte)))
    output_blob = _DataBlob()
    flags = 0x1  # CRYPTPROTECT_UI_FORBIDDEN
    if protect:
        function = crypt32.CryptProtectData
        arguments = (
            ctypes.byref(input_blob),
            None,
            None,
            None,
            None,
            flags,
            ctypes.byref(output_blob),
        )
    else:
        function = crypt32.CryptUnprotectData
        arguments = (
            ctypes.byref(input_blob),
            None,
            None,
            None,
            None,
            flags,
            ctypes.byref(output_blob),
        )
    if not function(*arguments):
        error_code = ctypes.get_last_error()
        raise EncryptionUnavailable(f"Windows DPAPI operation failed ({error_code})")
    try:
        return ctypes.string_at(output_blob.data, output_blob.size)
    finally:
        kernel32.LocalFree(output_blob.data)


def _state_account(root: Path) -> bytes:
    normalized = os.path.normcase(str(root.resolve(strict=False))).encode("utf-8")
    return hashlib.sha256(normalized).hexdigest().encode("ascii")


def _load_windows_key(root: Path) -> bytes:
    key_file = root / "master-key.dpapi"
    if key_file.exists():
        try:
            protected = key_file.read_bytes()
        except OSError as error:
            raise EncryptionUnavailable("DPAPI key file cannot be read") from error
        key = _dpapi(protected, protect=False)
    else:
        key = os.urandom(MASTER_KEY_BYTES)
        _atomic_write(key_file, _dpapi(key, protect=True))
    return key


def _load_macos_key(root: Path) -> bytes:
    try:
        security = ctypes.CDLL("/System/Library/Frameworks/Security.framework/Security")
    except OSError as error:
        raise EncryptionUnavailable("macOS Security framework is unavailable") from error

    account = _state_account(root)
    password_length = ctypes.c_uint32()
    password_data = ctypes.c_void_p()
    item = ctypes.c_void_p()
    status = security.SecKeychainFindGenericPassword(
        None,
        len(KEYCHAIN_SERVICE),
        KEYCHAIN_SERVICE,
        len(account),
        account,
        ctypes.byref(password_length),
        ctypes.byref(password_data),
        ctypes.byref(item),
    )
    if status == 0:
        try:
            encoded = ctypes.string_at(password_data, password_length.value)
        finally:
            security.SecKeychainItemFreeContent(None, password_data)
        try:
            return base64.b64decode(encoded, validate=True)
        except ValueError as error:
            raise EncryptionUnavailable("macOS Keychain key is corrupt") from error
    if status != -25300:  # errSecItemNotFound
        raise EncryptionUnavailable(f"macOS Keychain lookup failed ({status})")

    key = os.urandom(MASTER_KEY_BYTES)
    encoded = base64.b64encode(key)
    status = security.SecKeychainAddGenericPassword(
        None,
        len(KEYCHAIN_SERVICE),
        KEYCHAIN_SERVICE,
        len(account),
        account,
        len(encoded),
        encoded,
        None,
    )
    if status != 0:
        raise EncryptionUnavailable(f"macOS Keychain write failed ({status})")
    return key


def _load_linux_key(root: Path) -> bytes:
    try:
        import secretstorage  # type: ignore[import-not-found, unused-ignore]
    except ImportError as error:
        raise EncryptionUnavailable("Python Secret Service support is unavailable") from error
    attributes = {
        "application": "agent-skill-doctor",
        "state": _state_account(root).decode("ascii"),
    }
    try:
        bus = secretstorage.dbus_init()
        collection = secretstorage.get_default_collection(bus)
        if collection.is_locked():
            collection.unlock()
        items = list(collection.search_items(attributes))
        if items:
            return bytes(items[0].get_secret())
        key = os.urandom(MASTER_KEY_BYTES)
        collection.create_item(
            "Agent Skill Doctor state master key",
            attributes,
            key,
            replace=True,
        )
        return key
    except Exception as error:
        raise EncryptionUnavailable("Secret Service is unavailable or locked") from error


def load_or_create_master_key(root: Path) -> bytes:
    root.mkdir(parents=True, exist_ok=True)
    try:
        root.chmod(0o700)
    except OSError:
        pass
    if sys.platform == "win32":
        key = _load_windows_key(root)
    elif sys.platform == "darwin":
        key = _load_macos_key(root)
    elif sys.platform.startswith("linux"):
        key = _load_linux_key(root)
    else:
        raise EncryptionUnavailable(f"unsupported credential-store platform: {sys.platform}")
    if len(key) != MASTER_KEY_BYTES:
        raise EncryptionUnavailable("credential store returned an invalid master key")
    return key


class ArtifactCipher:
    def __init__(self, key: bytes) -> None:
        if len(key) != MASTER_KEY_BYTES:
            raise ValueError("AES-256-GCM requires a 32-byte key")
        self._key = key
        self._aead = AESGCM(key)

    @classmethod
    def for_state(cls, root: Path) -> ArtifactCipher:
        return cls(load_or_create_master_key(root))

    @property
    def ipc_auth_key(self) -> bytes:
        return hmac.new(self._key, b"ipc-auth-v1", hashlib.sha256).digest()

    def encrypt(self, digest: str, plaintext: bytes) -> bytes:
        nonce = os.urandom(NONCE_BYTES)
        associated = ENVELOPE_MAGIC + digest.encode("ascii")
        ciphertext = self._aead.encrypt(nonce, plaintext, associated)
        return ENVELOPE_MAGIC + nonce + ciphertext

    def decrypt(self, digest: str, envelope: bytes) -> bytes:
        if not envelope.startswith(ENVELOPE_MAGIC):
            raise IntegrityError("raw artifact is not an encrypted envelope")
        minimum = len(ENVELOPE_MAGIC) + NONCE_BYTES + 16
        if len(envelope) < minimum:
            raise IntegrityError("encrypted artifact envelope is truncated")
        nonce_start = len(ENVELOPE_MAGIC)
        nonce = envelope[nonce_start : nonce_start + NONCE_BYTES]
        ciphertext = envelope[nonce_start + NONCE_BYTES :]
        associated = ENVELOPE_MAGIC + digest.encode("ascii")
        try:
            return self._aead.decrypt(nonce, ciphertext, associated)
        except InvalidTag as error:
            raise IntegrityError("encrypted artifact authentication failed") from error


def platform_encryption_readiness(root: Path) -> dict[str, Any]:
    try:
        ArtifactCipher.for_state(root)
    except EncryptionUnavailable as error:
        return {"ready": False, "detail": str(error)}
    return {"ready": True, "detail": "OS-protected AES-256-GCM key is available"}
