"""Evidence visuals: the port-scan fan-out pattern that triggered
detection, and the before/after verification comparison that proves
the loop closed. Headless-safe (Agg backend) for CI/Docker.
"""
from __future__ import annotations

from pathlib import Path

from idps.models import DetectionResult, VerificationAttempt


def _agg_pyplot():
    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    return plt


def plot_port_fanout(detections: list[DetectionResult], out_path: str | Path) -> Path:
    plt = _agg_pyplot()

    fig, ax = plt.subplots(figsize=(9, 5))
    if not detections:
        ax.text(0.5, 0.5, "No port-scan detections", ha="center", va="center")
    else:
        for det in detections:
            ports = det.evidence.get("distinct_dst_ports", [])
            ax.plot(range(len(ports)), sorted(ports), marker="o", label=f"{det.src_ip}")
        ax.set_xlabel("Nth distinct port touched")
        ax.set_ylabel("Destination port")
        ax.legend()

    ax.set_title("Port Fan-Out Pattern (detection evidence)")
    fig.tight_layout()

    out_path = Path(out_path)
    fig.savefig(out_path, dpi=150)
    plt.close(fig)
    return out_path


def plot_verification_comparison(
    before: VerificationAttempt | None, after: VerificationAttempt | None, out_path: str | Path
) -> Path:
    plt = _agg_pyplot()

    labels = ["Before block", "After block"]
    reachable = [len(before.ports_reachable) if before else 0, len(after.ports_reachable) if after else 0]
    blocked = [len(before.ports_blocked) if before else 0, len(after.ports_blocked) if after else 0]

    x = range(len(labels))
    fig, ax = plt.subplots(figsize=(6.5, 4.5))
    ax.bar(x, reachable, width=0.4, label="Reachable ports", color="#16a34a")
    ax.bar([i + 0.4 for i in x], blocked, width=0.4, label="Blocked/no response", color="#dc2626")
    ax.set_xticks([i + 0.2 for i in x], labels)
    ax.set_ylabel("Port count")
    ax.set_title("Closed-Loop Verification: Before vs. After Block")
    ax.legend()
    fig.tight_layout()

    out_path = Path(out_path)
    fig.savefig(out_path, dpi=150)
    plt.close(fig)
    return out_path
