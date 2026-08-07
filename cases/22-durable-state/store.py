"""Case 22 - does the boundary survive persistence?

Case 21 measured process independence and left durable state entirely open: the
gate's persisted approvals sat on a filesystem the worker's own uid could
write. This tests the part that did not move.

    Compromise of the worker boundary cannot create, modify or DELETE durable
    gate authority except through the gate's exposed protocol.

**Deletion is attacked as hard as insertion**, and it is the more interesting
half. After cases 19 and 20 the durable store holds *security state* rather
than persistence: a consumption record is what makes a spent approval spent. A
worker that can delete one resurrects it.

Three arms, and the third is the finding:

    D0  the store is a file the worker writes        (case 21's arm B)
    D1  the store is owned by the gate process and
        the protocol offers approve / execute / state only
    D2  the same, plus one ordinary maintenance operation

**What is modelled and what is measured.** D1 and D2 model the store being
unreachable except through the protocol; this platform cannot enforce that with
separate OS users, so the enforcement is *modelled* exactly as case 12's arm A
modelled permission checks rather than emulating Unix. What is genuinely
measured is what the protocol's own vocabulary permits - which is the point,
because that is where D2 fails.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from typing import Dict, List, Optional

DIGEST = "a1b2c3d4deadbeef"
OTHER = "beefbeefbeefbeef"
WORKER = "svc_worker"
REVIEWER = "svc_reviewer"


class Refused(RuntimeError):
    """The gate refused, naming the operation."""


# ---------------------------------------------------------------------------
# The durable record. Append-only by API, in the sense cases 10 and 11 fixed.
# ---------------------------------------------------------------------------

@dataclass
class DurableStore:
    path: str
    records: List[Dict] = field(default_factory=list)

    def load(self) -> None:
        self.records = []
        if not os.path.exists(self.path):
            return
        with open(self.path, "r", encoding="utf-8") as fh:
            for line in fh:
                if line.strip():
                    self.records.append(json.loads(line))

    def append(self, record: Dict) -> None:
        self.records.append(record)
        with open(self.path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(record, sort_keys=True) + "\n")

    def rewrite(self, records: List[Dict]) -> None:
        """Only the gate ever calls this, and only in D2."""
        self.records = list(records)
        with open(self.path, "w", encoding="utf-8") as fh:
            for record in self.records:
                fh.write(json.dumps(record, sort_keys=True) + "\n")

    def spent(self, digest: str) -> bool:
        return any(r["kind"] == "consumed" and r["digest"] == digest
                   for r in self.records)

    def approved(self, digest: str) -> bool:
        return any(r["kind"] == "approved" and r["digest"] == digest
                   for r in self.records)


# ---------------------------------------------------------------------------
# The gate. Its protocol vocabulary is the whole security surface in D1/D2.
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Arm:
    name: str
    worker_can_write_the_file: bool
    offers_maintenance: bool


D0 = Arm("D0 store on the worker's filesystem", True, False)
D1 = Arm("D1 store behind the protocol", False, False)
D2 = Arm("D2 protocol + a maintenance op", False, True)

ARMS = (D0, D1, D2)


class Gate:
    def __init__(self, store: DurableStore, arm: Arm) -> None:
        self.store = store
        self.arm = arm

    # -- the protocol -----------------------------------------------------
    def approve(self, actor: str, digest: str) -> Dict:
        if actor != REVIEWER:
            raise Refused(f"{actor!r} is not a reviewer")
        self.store.append({"kind": "approved", "digest": digest,
                           "actor": actor})
        return {"ok": True}

    def execute(self, digest: str) -> Dict:
        self.store.load()
        if not self.store.approved(digest):
            raise Refused(f"no approval for {digest[:8]}...")
        if self.store.spent(digest):
            raise Refused(f"approval for {digest[:8]}... is already spent")
        self.store.append({"kind": "consumed", "digest": digest})
        return {"ok": True, "executed": digest}

    def compact(self, keep_kinds: Optional[List[str]] = None) -> Dict:
        """An ordinary maintenance operation: drop records the operator says
        are no longer needed. Every persistent store grows and every team
        eventually writes one of these."""
        if not self.arm.offers_maintenance:
            raise Refused("no such operation")
        keep = keep_kinds or ["approved", "consumed"]
        self.store.rewrite([r for r in self.store.records
                            if r["kind"] in keep])
        return {"ok": True, "records": len(self.store.records)}


# ---------------------------------------------------------------------------
# The attacks. Insertion, and deletion which is the interesting half.
# ---------------------------------------------------------------------------

@dataclass
class Result:
    arm: str
    attack: str
    succeeded: bool
    note: str


def _setup(arm: Arm, tmp_dir: str, tag: str):
    path = os.path.join(tmp_dir, f"{tag}.jsonl")
    store = DurableStore(path)
    store.load()
    gate = Gate(store, arm)
    gate.approve(REVIEWER, DIGEST)
    gate.execute(DIGEST)                       # legitimately spent
    return gate, store, path


def _worker_writes(path: str, records: List[Dict], mode: str) -> None:
    with open(path, mode, encoding="utf-8") as fh:
        for record in records:
            fh.write(json.dumps(record, sort_keys=True) + "\n")


def forge_approval(arm: Arm, tmp_dir: str) -> Result:
    """Insertion: an approval nobody reviewed."""
    gate, store, path = _setup(arm, tmp_dir, "forge")
    if arm.worker_can_write_the_file:
        _worker_writes(path, [{"kind": "approved", "digest": OTHER,
                               "actor": REVIEWER}], "a")
        store.load()
        obtained = store.approved(OTHER)
        note = "appended an approval directly to the file"
    else:
        try:
            gate.approve(WORKER, OTHER)
            obtained = True
            note = "the protocol accepted it"
        except Refused as exc:
            obtained = False
            note = f"REFUSED: {exc}"
    return Result(arm.name, "forge an approval", obtained, note)


def resurrect_spent_approval(arm: Arm, tmp_dir: str) -> Result:
    """DELETION, and the attack case 21 did not think to run.

    The consumption record is what makes a spent approval spent. Remove it and
    the approval is live again - one legitimate review, two executions.
    """
    gate, store, path = _setup(arm, tmp_dir, "resurrect")
    assert store.spent(DIGEST)

    if arm.worker_can_write_the_file:
        kept = [r for r in store.records if r["kind"] != "consumed"]
        _worker_writes(path, kept, "w")
        store.load()
        note = "rewrote the file without the consumption record"
    else:
        note = "no protocol operation removes a consumption record"

    try:
        gate.execute(DIGEST)
        return Result(arm.name, "resurrect a spent approval", True,
                      f"{note} - and it executed a second time")
    except Refused as exc:
        return Result(arm.name, "resurrect a spent approval", False,
                      f"{note}; REFUSED: {exc}")


def resurrect_via_maintenance(arm: Arm, tmp_dir: str) -> Result:
    """The same deletion, through the protocol's own vocabulary."""
    gate, store, path = _setup(arm, tmp_dir, "maint")
    try:
        gate.compact(keep_kinds=["approved"])          # drop consumption
    except Refused as exc:
        return Result(arm.name, "resurrect via maintenance", False,
                      f"REFUSED: {exc}")
    try:
        gate.execute(DIGEST)
        return Result(arm.name, "resurrect via maintenance", True,
                      "the maintenance operation dropped the consumption "
                      "record and the approval went live again")
    except Refused as exc:
        return Result(arm.name, "resurrect via maintenance", False,
                      f"REFUSED: {exc}")


def delete_all_approvals(arm: Arm, tmp_dir: str) -> Result:
    """Availability rather than authority: can the worker destroy the record?"""
    gate, store, path = _setup(arm, tmp_dir, "wipe")
    if arm.worker_can_write_the_file:
        _worker_writes(path, [], "w")
        store.load()
        return Result(arm.name, "destroy the durable record", True,
                      "truncated the file; every approval and consumption "
                      "record is gone")
    return Result(arm.name, "destroy the durable record", False,
                  "no protocol operation empties the store")


ATTACKS = (forge_approval, resurrect_spent_approval, resurrect_via_maintenance,
           delete_all_approvals)

ATTACK_NAMES = ("forge an approval", "resurrect a spent approval",
                "resurrect via maintenance", "destroy the durable record")


def measure(tmp_dir: str) -> List[Result]:
    out: List[Result] = []
    for arm in ARMS:
        arm_dir = os.path.join(tmp_dir, arm.name.split()[0])
        os.makedirs(arm_dir, exist_ok=True)
        for attack in ATTACKS:
            out.append(attack(arm, arm_dir))
    return out


def get(results: List[Result], arm: Arm, attack: str) -> Result:
    return next(r for r in results if r.arm == arm.name and r.attack == attack)
