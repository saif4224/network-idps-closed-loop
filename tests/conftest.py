"""Session-scoped fixture that runs the real attacker controller Flask
app on a real localhost socket, so attacker-client tests exercise a
genuine HTTP call and a genuine TCP connect scan.
"""
from __future__ import annotations

import socket
import sys
import threading
import time
from pathlib import Path

import pytest
from werkzeug.serving import make_server

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "containers" / "attacker"))
from controller import app as attacker_app  # noqa: E402


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture(scope="session")
def attacker_controller_url():
    port = _free_port()
    server = make_server("127.0.0.1", port, attacker_app)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    time.sleep(0.2)

    yield f"http://127.0.0.1:{port}"

    server.shutdown()
    thread.join(timeout=5)


@pytest.fixture(scope="session")
def listening_port():
    """A real open TCP port on localhost for the attacker to successfully connect to."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("127.0.0.1", 0))
    sock.listen(1)
    port = sock.getsockname()[1]

    yield port

    sock.close()
