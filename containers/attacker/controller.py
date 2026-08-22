"""Attacker control API: a tiny Flask app that, on request, runs a
real TCP connect scan (the same wire-level behavior as `nmap -sT`,
just implemented directly in Python sockets rather than shelling out
to nmap) against a target. Exists so the sensor can trigger the
"attack" phase on demand via a normal HTTP call, rather than needing
to reach into another container's process.

`repeat_after_seconds` lets the sensor schedule BOTH scan bursts (the
one that gets detected/blocked, and the one that verifies the block)
from a single upfront call. This matters: once the sensor blocks this
container's IP, its own inbound responses - including the reply to any
further HTTP call to this API - get dropped by that same rule, so the
sensor can never reach this endpoint again post-block. Self-scheduling
the second burst sidesteps that without weakening the block (it's
still a real, blanket source-IP DROP, not scoped to spare this port).

Every request here happens entirely inside the isolated docker-compose
demo network - this controller is never exposed to the host or the
internet, and only ever targets the bundled victim container.
"""
from __future__ import annotations

import socket
import threading
import time

from flask import Flask, jsonify, request

app = Flask(__name__)


def _connect_scan(target: str, ports: list[int], timeout: float = 0.5) -> dict:
    open_ports, closed_ports = [], []
    for port in ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        try:
            result = sock.connect_ex((target, port))
            (open_ports if result == 0 else closed_ports).append(port)
        except OSError:
            closed_ports.append(port)
        finally:
            sock.close()
    return {"target": target, "open_ports": open_ports, "closed_ports": closed_ports}


def _run_scheduled_scans(target: str, ports: list[int], repeat_after_seconds: float) -> None:
    _connect_scan(target, ports)
    if repeat_after_seconds:
        time.sleep(repeat_after_seconds)
        _connect_scan(target, ports)


@app.route("/scan", methods=["POST"])
def scan():
    payload = request.get_json()
    target = payload["target"]
    ports = payload["ports"]
    repeat_after_seconds = payload.get("repeat_after_seconds", 0)

    if repeat_after_seconds:
        # fire-and-forget: the second burst must still happen even though this
        # container's replies will be unreachable by then (see module docstring)
        threading.Thread(
            target=_run_scheduled_scans, args=(target, ports, repeat_after_seconds), daemon=True
        ).start()
        return jsonify({"status": "scheduled", "repeat_after_seconds": repeat_after_seconds}), 202

    result = _connect_scan(target, ports)
    return jsonify(result)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=9000)
