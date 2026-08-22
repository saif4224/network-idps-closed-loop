"""Client for the attacker container's small HTTP control API - lets
the sensor trigger a real TCP connect scan against the victim on
demand (once before the block, once after), so the "verify" half of
the closed loop is driven by an explicit, repeatable action rather
than by timing luck.

Only ever used against the bundled attacker/victim containers on the
isolated demo network - see Scope & safety in the README.
"""
from __future__ import annotations

import logging

import requests

logger = logging.getLogger(__name__)


class AttackerClient:
    def __init__(self, base_url: str, timeout: int = 30):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout

    def trigger_scan(self, target: str, ports: list[int], repeat_after_seconds: float = 0) -> dict:
        logger.info(
            "Triggering scan: attacker -> %s (%d ports)%s",
            target, len(ports), f", repeating after {repeat_after_seconds}s" if repeat_after_seconds else "",
        )
        payload = {"target": target, "ports": ports}
        if repeat_after_seconds:
            payload["repeat_after_seconds"] = repeat_after_seconds
        resp = requests.post(f"{self.base_url}/scan", json=payload, timeout=self.timeout)
        resp.raise_for_status()
        return resp.json()
