"""Case 21 - the approval gate, as a separate process.

Arm B's gate. Reached only by line-delimited JSON on stdin/stdout, holding its
own approvals, its own reviewer list and its own credential. Nothing here is
importable by the worker; the protocol is the entire surface.

Same shape as case 06's isolated stage, and for the same reason: the point is
not that the boundary is clever, it is that the objects are not in the room.
"""

from __future__ import annotations

import json
import sys

GATE_CREDENTIAL = "gate-signing-key-3f9a"      # never leaves this process
REVIEWERS = ["svc_reviewer"]
APPROVALS = []                                  # list of {digest, actor, state}
EXECUTED = []


def _approve(msg):
    if msg["actor"] not in REVIEWERS:
        return {"ok": False, "error": f"{msg['actor']} is not a reviewer"}
    APPROVALS.append({"digest": msg["digest"], "actor": msg["actor"],
                      "state": "unused"})
    return {"ok": True}


def _execute(msg):
    for approval in APPROVALS:
        if approval["digest"] == msg["digest"] and approval["state"] == "unused":
            approval["state"] = "executed"
            EXECUTED.append(msg["digest"])
            return {"ok": True, "executed": msg["digest"]}
    return {"ok": False, "error": "no unspent approval for that action"}


def _state(_msg):
    """Read-only, and deliberately so: the protocol exposes what the gate
    decided, never a way to write it."""
    return {"ok": True, "approvals": len(APPROVALS), "executed": len(EXECUTED),
            "reviewers": list(REVIEWERS)}


OPS = {"approve": _approve, "execute": _execute, "state": _state}


def main() -> None:
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
            handler = OPS.get(msg.get("op"))
            if handler is None:
                out = {"ok": False, "error": f"unknown op {msg.get('op')!r}"}
            else:
                out = handler(msg)
        except Exception as exc:                          # noqa: BLE001
            out = {"ok": False, "error": f"{type(exc).__name__}: {exc}"}
        sys.stdout.write(json.dumps(out) + "\n")
        sys.stdout.flush()


if __name__ == "__main__":
    main()
