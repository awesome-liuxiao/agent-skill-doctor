from __future__ import annotations

import hashlib
import json
import os
import stat
import tempfile
import uuid
from dataclasses import dataclass
from multiprocessing import AuthenticationError
from multiprocessing.connection import Client, Connection, Listener
from pathlib import Path
from typing import Any, cast

PROTOCOL_VERSION = "1.0.0"
MAX_MESSAGE_BYTES = 4 * 1024 * 1024


class IPCError(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class Endpoint:
    address: str
    family: str


def endpoint_for_state(state_dir: Path) -> Endpoint:
    resolved = str(state_dir.expanduser().absolute())
    identity = hashlib.sha256(os.path.normcase(resolved).encode("utf-8")).hexdigest()[:24]
    if os.name == "nt":
        return Endpoint(rf"\\.\pipe\agent-skill-doctor-{identity}", "AF_PIPE")

    candidate = state_dir.expanduser().absolute() / "ipc" / "worker.sock"
    if len(os.fsencode(candidate)) < 100:
        return Endpoint(str(candidate), "AF_UNIX")
    user = str(getattr(os, "getuid", lambda: 0)())
    runtime = Path(tempfile.gettempdir()) / f"agent-skill-doctor-{user}"
    return Endpoint(str(runtime / f"{identity}.sock"), "AF_UNIX")


def _encode(payload: dict[str, Any]) -> bytes:
    encoded = json.dumps(
        payload,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    if len(encoded) > MAX_MESSAGE_BYTES:
        raise IPCError("IPC message exceeds the protocol byte limit")
    return encoded


def _decode(payload: bytes) -> dict[str, Any]:
    if len(payload) > MAX_MESSAGE_BYTES:
        raise IPCError("IPC message exceeds the protocol byte limit")
    try:
        decoded = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise IPCError("IPC message is not valid UTF-8 JSON") from error
    if not isinstance(decoded, dict):
        raise IPCError("IPC message must be a JSON object")
    return cast(dict[str, Any], decoded)


def make_request(operation: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
    return {
        "protocol_version": PROTOCOL_VERSION,
        "request_id": str(uuid.uuid4()),
        "operation": operation,
        "params": params or {},
    }


def validate_request(payload: dict[str, Any]) -> None:
    if payload.get("protocol_version") != PROTOCOL_VERSION:
        raise IPCError("unsupported IPC protocol version")
    if not isinstance(payload.get("request_id"), str):
        raise IPCError("IPC request_id must be a string")
    if not isinstance(payload.get("operation"), str):
        raise IPCError("IPC operation must be a string")
    if not isinstance(payload.get("params"), dict):
        raise IPCError("IPC params must be an object")


class IPCServer:
    def __init__(self, state_dir: Path, auth_key: bytes) -> None:
        self.endpoint = endpoint_for_state(state_dir)
        if self.endpoint.family == "AF_UNIX":
            socket_path = Path(self.endpoint.address)
            socket_path.parent.mkdir(parents=True, exist_ok=True)
            socket_path.parent.chmod(0o700)
            if socket_path.exists() or socket_path.is_symlink():
                mode = socket_path.lstat().st_mode
                if not stat.S_ISSOCK(mode):
                    raise IPCError("refusing to replace a non-socket IPC path")
                socket_path.unlink()
        try:
            self._listener = Listener(
                address=self.endpoint.address,
                family=self.endpoint.family,
                authkey=auth_key,
            )
        except (OSError, ValueError) as error:
            raise IPCError(f"cannot create local IPC endpoint: {error}") from error
        if self.endpoint.family == "AF_UNIX":
            Path(self.endpoint.address).chmod(0o600)

    def accept(self) -> Connection:
        try:
            return self._listener.accept()
        except (OSError, EOFError, AuthenticationError) as error:
            raise IPCError("local IPC accept failed") from error

    @staticmethod
    def receive(connection: Connection) -> dict[str, Any]:
        try:
            payload = connection.recv_bytes(MAX_MESSAGE_BYTES)
        except (OSError, EOFError) as error:
            raise IPCError("local IPC receive failed") from error
        request = _decode(payload)
        validate_request(request)
        return request

    @staticmethod
    def respond(
        connection: Connection,
        request_id: str,
        *,
        result: dict[str, Any] | None = None,
        error: str | None = None,
    ) -> None:
        response = {
            "protocol_version": PROTOCOL_VERSION,
            "request_id": request_id,
            "ok": error is None,
            "result": result,
            "error": error,
        }
        connection.send_bytes(_encode(response))

    def close(self) -> None:
        self._listener.close()
        if self.endpoint.family == "AF_UNIX":
            socket_path = Path(self.endpoint.address)
            if socket_path.exists() and stat.S_ISSOCK(socket_path.lstat().st_mode):
                socket_path.unlink()


def request(
    state_dir: Path,
    auth_key: bytes,
    operation: str,
    params: dict[str, Any] | None = None,
    *,
    timeout: float = 5.0,
) -> dict[str, Any]:
    endpoint = endpoint_for_state(state_dir)
    message = make_request(operation, params)
    try:
        connection = Client(endpoint.address, family=endpoint.family, authkey=auth_key)
    except (OSError, EOFError, AuthenticationError) as error:
        raise IPCError("cannot connect to the authenticated local worker") from error
    try:
        connection.send_bytes(_encode(message))
        if not connection.poll(timeout):
            raise IPCError("local worker response timed out")
        response = _decode(connection.recv_bytes(MAX_MESSAGE_BYTES))
    except (OSError, EOFError) as error:
        raise IPCError("local worker request failed") from error
    finally:
        connection.close()
    if response.get("protocol_version") != PROTOCOL_VERSION:
        raise IPCError("worker returned an unsupported protocol version")
    if response.get("request_id") != message["request_id"]:
        raise IPCError("worker response request_id does not match")
    if response.get("ok") is not True:
        raise IPCError(str(response.get("error") or "worker request failed"))
    result = response.get("result")
    if not isinstance(result, dict):
        raise IPCError("worker result must be an object")
    return cast(dict[str, Any], result)
