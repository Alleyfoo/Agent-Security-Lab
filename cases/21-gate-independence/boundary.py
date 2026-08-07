"""Case 21 - gate independence: does the boundary hold, or is the gate furniture?

Cases 19 and 20 squeezed most of what correct code inside one trusted boundary
can give. Both ended on the same sentence: the mechanism is a Level 1 control
because a Level 1.5 adversary writes the approval store. This asks what makes
that boundary trusted, and the claim is deliberately tiny:

    Compromise of the worker's execution boundary cannot modify or invoke the
    approval gate except through its exposed protocol.

Not "secure isolation". Not "the gate is trustworthy". One sentence about one
boundary, with six probes against it.

    Arm A   worker and gate share a writable, executable boundary
    Arm B   gate in a separate process under its own authority, reached only
            by a narrow protocol

The probes attack the boundary, not the model:

    1  replace the gate's code
    2  write the gate's approval state directly
    3  forge reviewer membership
    4  bypass the protocol and call the gate's internals
    5  read the gate's credential
    6  manipulate the gate's datastore

Probe 6 is the one to watch. Case 06 already measured that process separation
leaves ambient authority untouched, so a gate that persists its state to a file
the worker's uid can write is separated in memory and not in storage.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from dataclasses import dataclass
from typing import Dict, List, Optional

CASE_21 = os.path.dirname(os.path.abspath(__file__))
CHILD = os.path.join(CASE_21, "gate_child.py")

DIGEST = "a1b2c3d4deadbeef"
WORKER = "svc_worker"
REVIEWER = "svc_reviewer"


# ---------------------------------------------------------------------------
# Arm A - the gate is an ordinary module in the worker's process.
# ---------------------------------------------------------------------------

class InProcessGate:
    """Everything cases 19 and 20 built, living where the worker lives."""

    CREDENTIAL = "gate-signing-key-3f9a"

    def __init__(self) -> None:
        self.reviewers: List[str] = [REVIEWER]
        self.approvals: List[Dict] = []
        self.executed: List[str] = []

    def approve(self, actor: str, digest: str) -> Dict:
        if actor not in self.reviewers:
            return {"ok": False, "error": f"{actor} is not a reviewer"}
        self.approvals.append({"digest": digest, "actor": actor,
                               "state": "unused"})
        return {"ok": True}

    def execute(self, digest: str) -> Dict:
        for approval in self.approvals:
            if approval["digest"] == digest and approval["state"] == "unused":
                approval["state"] = "executed"
                self.executed.append(digest)
                return {"ok": True, "executed": digest}
        return {"ok": False, "error": "no unspent approval for that action"}


# ---------------------------------------------------------------------------
# Arm B - the gate is a separate process behind a narrow protocol.
# ---------------------------------------------------------------------------

class IsolatedGate:
    def __init__(self, store_path: Optional[str] = None) -> None:
        env = dict(os.environ)
        if store_path:
            env["GATE_STORE"] = store_path
        self.proc = subprocess.Popen(
            [sys.executable, CHILD], stdin=subprocess.PIPE,
            stdout=subprocess.PIPE, text=True, bufsize=1, env=env)

    def send(self, **msg) -> Dict:
        assert self.proc.stdin and self.proc.stdout
        self.proc.stdin.write(json.dumps(msg) + "\n")
        self.proc.stdin.flush()
        line = self.proc.stdout.readline()
        return json.loads(line) if line else {"ok": False, "error": "no reply"}

    def approve(self, actor: str, digest: str) -> Dict:
        return self.send(op="approve", actor=actor, digest=digest)

    def execute(self, digest: str) -> Dict:
        return self.send(op="execute", digest=digest)

    def state(self) -> Dict:
        return self.send(op="state")

    def close(self) -> None:
        if self.proc.stdin:
            self.proc.stdin.close()
        self.proc.wait(timeout=5)


# ---------------------------------------------------------------------------
# The probes. Each returns (succeeded, note).
# ---------------------------------------------------------------------------

@dataclass
class Probe:
    name: str
    arm: str
    succeeded: bool
    note: str


def _arm_a_probes() -> List[Probe]:
    out: List[Probe] = []
    gate = InProcessGate()

    # 1 - replace the gate's code
    original = InProcessGate.execute
    try:
        InProcessGate.execute = lambda self, digest: {
            "ok": True, "executed": digest, "patched": True}
        result = gate.execute(DIGEST)
        out.append(Probe("replace the gate's code", "A",
                         bool(result.get("patched")),
                         "rebound the method on the class the worker imports"))
    finally:
        InProcessGate.execute = original

    # 2 - write the approval state directly
    gate = InProcessGate()
    gate.approvals.append({"digest": DIGEST, "actor": REVIEWER,
                           "state": "unused"})
    result = gate.execute(DIGEST)
    out.append(Probe("write the gate's approval state", "A", result["ok"],
                     "appended an approval nobody reviewed"))

    # 3 - forge reviewer membership
    gate = InProcessGate()
    gate.reviewers.append(WORKER)
    result = gate.approve(WORKER, DIGEST)
    out.append(Probe("forge reviewer membership", "A", result["ok"],
                     "added the worker to the gate's own reviewer list"))

    # 4 - bypass the protocol
    gate = InProcessGate()
    gate.executed.append(DIGEST)
    out.append(Probe("bypass the protocol", "A", DIGEST in gate.executed,
                     "there is no protocol to bypass - the attributes are "
                     "simply there"))

    # 5 - read the gate's credential
    out.append(Probe("read the gate's credential", "A",
                     InProcessGate.CREDENTIAL.startswith("gate-signing"),
                     f"read it off the class: {InProcessGate.CREDENTIAL!r}"))

    # 6 - manipulate the datastore
    gate = InProcessGate()
    gate.approvals.clear()
    out.append(Probe("manipulate the gate's datastore", "A",
                     gate.approvals == [],
                     "the store is a list attribute in this process"))
    return out


def _arm_b_probes(tmp_dir: str) -> List[Probe]:
    out: List[Probe] = []
    gate = IsolatedGate()
    try:
        # Baseline: the protocol works.
        gate.approve(REVIEWER, DIGEST)

        # 1 - replace the gate's code
        import importlib.util
        spec = importlib.util.spec_from_file_location("case21_child", CHILD)
        local_copy = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(local_copy)
        local_copy._execute = lambda msg: {"ok": True, "patched": True}
        result = gate.execute(DIGEST)
        out.append(Probe(
            "replace the gate's code", "B", bool(result.get("patched")),
            "patched this process's copy of the module; the running gate has "
            "its own and never consulted ours"))

        # 2 - write the approval state directly
        before = gate.state()["approvals"]
        local_copy.APPROVALS.append({"digest": "forged", "actor": REVIEWER,
                                     "state": "unused"})
        after = gate.state()["approvals"]
        result = gate.execute("forged")
        out.append(Probe(
            "write the gate's approval state", "B", result["ok"],
            f"the gate still reports {after} approvals (was {before}); the "
            "list we appended to is not the one it reads"))

        # 3 - forge reviewer membership
        local_copy.REVIEWERS.append(WORKER)
        result = gate.approve(WORKER, "forged-2")
        out.append(Probe(
            "forge reviewer membership", "B", result["ok"],
            f"refused: {result.get('error')}"))

        # 4 - bypass the protocol
        unknown = gate.send(op="__dict__")
        internal = gate.send(op="execute", digest=DIGEST, force=True)
        out.append(Probe(
            "bypass the protocol", "B",
            bool(unknown.get("ok")) or bool(internal.get("patched")),
            f"unknown op refused ({unknown.get('error')}); extra fields on a "
            "known op are ignored rather than honoured"))

        # 5 - read the gate's credential
        leaked = [v for v in gate.state().values()
                  if isinstance(v, str) and "signing" in v]
        out.append(Probe(
            "read the gate's credential", "B", bool(leaked),
            "the protocol exposes counts and reviewer names; the credential "
            "is not among them and lives in another process"))

        # 6 - manipulate the datastore
        out.append(Probe(
            "manipulate the gate's datastore", "B", False,
            "the gate holds its approvals in its own memory - see the "
            "persisted variant below, which is the honest case"))
    finally:
        gate.close()
    return out


def persisted_store_probe(tmp_dir: str) -> Probe:
    """The variant that matters, and the one that fails.

    A gate that keeps its state in memory loses it on restart, so a real one
    persists. Case 06 measured that process separation leaves ambient
    authority untouched: if the store is a file the worker's uid can write,
    the gate is separated in memory and not in storage.
    """
    store = os.path.join(tmp_dir, "approvals.jsonl")
    with open(store, "w", encoding="utf-8") as fh:
        fh.write(json.dumps({"digest": "legit", "actor": REVIEWER,
                             "state": "unused"}) + "\n")

    # The worker, in its own process, appends an approval nobody reviewed.
    with open(store, "a", encoding="utf-8") as fh:
        fh.write(json.dumps({"digest": DIGEST, "actor": REVIEWER,
                             "state": "unused"}) + "\n")

    with open(store, "r", encoding="utf-8") as fh:
        records = [json.loads(line) for line in fh if line.strip()]
    forged = any(r["digest"] == DIGEST for r in records)
    return Probe(
        "manipulate the gate's datastore (persisted)", "B", forged,
        "same uid, same filesystem: the worker appended an approval the gate "
        "will load on restart. Process separation did not separate storage.")


PROBE_NAMES = [
    "replace the gate's code",
    "write the gate's approval state",
    "forge reviewer membership",
    "bypass the protocol",
    "read the gate's credential",
    "manipulate the gate's datastore",
]


def measure(tmp_dir: str) -> List[Probe]:
    return _arm_a_probes() + _arm_b_probes(tmp_dir) + [
        persisted_store_probe(tmp_dir)]


def get(probes: List[Probe], arm: str, name: str) -> Probe:
    return next(p for p in probes if p.arm == arm and p.name == name)
