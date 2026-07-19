import os
import threading
from pathlib import Path

from skill_doctor.ipc import IPCServer, request


def test_platform_local_transport_uses_authenticated_json_bytes(tmp_path: Path) -> None:
    auth_key = os.urandom(32)
    server = IPCServer(tmp_path, auth_key)

    def serve_once() -> None:
        connection = server.accept()
        incoming = server.receive(connection)
        server.respond(
            connection,
            str(incoming["request_id"]),
            result={"echo": incoming["params"]},
        )
        connection.close()

    thread = threading.Thread(target=serve_once, daemon=True)
    thread.start()
    try:
        result = request(tmp_path, auth_key, "echo", {"value": "hello"})
        assert result == {"echo": {"value": "hello"}}
    finally:
        thread.join(timeout=5)
        server.close()
    assert not thread.is_alive()
