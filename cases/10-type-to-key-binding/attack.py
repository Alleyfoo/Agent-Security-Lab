"""Case 10 - executable attack: the type-to-key binding.

Run it:

    python cases/10-type-to-key-binding/attack.py

Case 08 measured the artifact map as the cheapest authority surface in the
object model: one edit, persisted, surviving resume, and reading as bookkeeping
rather than policy. Case 09 deliberately left it alone.

Two arms, same workflow, same attacker as case 08 - may alter persisted policy
or workflow records before or between steps, may not modify evaluator code.

  stored   the object carries {artifact_type: key} and the workflow writes it
  derived  a runner-owned append-only production ledger records what each
           completed step produced, and the map is computed from it

Three attacks, all mid-flight against a live workflow, because a map that never
changes is not the thing the architecture describes.
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
from dataclasses import dataclass
from typing import List, Optional

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__)))))

from object_model import (  # noqa: E402
    QueueItem, WorkObject, load_object, pin_versions, reset_registry,
    save_object,
)
from object_model import evaluator, skills  # noqa: E402
from object_model.ledger import (  # noqa: E402
    LedgerIntegrityError, ProductionLedger, ProductionRecord,
)

TARGET = "artifact.key_material"
OBJ = "obj_812"

STORED, DERIVED = "stored map", "derived map"


@dataclass
class Arm:
    name: str
    obj: WorkObject
    ledger: Optional[ProductionLedger]
    pins: dict
    store: str

    def map_now(self):
        return evaluator.artifact_map(self.obj, self.ledger)

    def step(self):
        item = QueueItem(self.obj.object_id, evaluator.required_skill(self.obj))
        return evaluator.run_step(self.obj, item, self.store, self.pins,
                                  self.ledger)

    def conflicts(self) -> List[str]:
        return self.ledger.conflicts_for(OBJ) if self.ledger else []


def _start(name: str, store: str) -> Arm:
    reset_registry()
    evaluator.reset_workflow()
    obj = WorkObject(OBJ, "orders_table", "ingested", {})
    ledger = (ProductionLedger(path=os.path.join(store, "ledger.jsonl"))
              if name == DERIVED else None)
    seed = {skills.T_TABLE_PREVIEW: "artifact.raw_input",
            skills.T_KEY_MATERIAL: TARGET}
    if ledger is not None:
        ledger.seed(OBJ, seed)
    else:
        obj.artifacts.update(seed)
    save_object(obj, store)
    pins = pin_versions(evaluator.OBJECT_TYPES["orders_table"])
    return Arm(name, obj, ledger, pins, store)


# ---------------------------------------------------------------------------
# The two ways to say "type T is now at key K", one per arm.
# ---------------------------------------------------------------------------

def _rebind_through_the_api(arm: Arm, artifact_type: str, key: str) -> str:
    """What the architecture offers. Refused in the derived arm by design."""
    if arm.ledger is None:
        arm.obj.artifacts[artifact_type] = key
        save_object(arm.obj, arm.store)
        return "wrote the object's artifact map and persisted it"
    try:
        arm.ledger.record(OBJ, arm.obj.state, "attacker", artifact_type, key)
        return "appended a production record"
    except LedgerIntegrityError as exc:
        return f"REFUSED: {exc}"


def _rebind_past_the_api(arm: Arm, artifact_type: str, key: str) -> str:
    """Level 2: reach the record directly, as case 01 established one can."""
    if arm.ledger is None:
        arm.obj.artifacts[artifact_type] = key
        save_object(arm.obj, arm.store)
        return "wrote the object's artifact map directly"
    arm.ledger._records.append(
        ProductionRecord(OBJ, arm.obj.state, "attacker", artifact_type, key))
    return "appended past the API check"


def _overwrite_past_the_api(arm: Arm, artifact_type: str, key: str) -> str:
    """Level 2, and the expensive version: replace the record that exists."""
    if arm.ledger is None:
        return _rebind_past_the_api(arm, artifact_type, key)
    for index, entry in enumerate(arm.ledger._records):
        if entry.object_id == OBJ and entry.artifact_type == artifact_type:
            arm.ledger._records[index] = ProductionRecord(
                OBJ, entry.at_state, entry.skill, artifact_type, key)
            return "overwrote the existing production record"
    return "no record to overwrite"


def _show(label: str, detail: str, obtained: bool, arm: Arm) -> None:
    mark = "!!" if obtained else "  "
    print(f"   {mark} {label:22s} {'OBTAINED' if obtained else 'no':9s} {detail}")
    if arm.conflicts():
        print(f"        conflicts visible in the record: {arm.conflicts()}")


def attack_a() -> dict:
    """Rebind an existing entry between steps."""
    print("\n--- A. Rebind an existing binding, mid-workflow ---")
    out = {}
    for name in (STORED, DERIVED):
        with tempfile.TemporaryDirectory() as store:
            arm = _start(name, store)
            arm.step()                                   # infer_schema

            print(f"\n  {name}")
            detail = _rebind_through_the_api(arm, skills.T_TABLE_PREVIEW, TARGET)
            grant = evaluator.derive_grant(arm.obj, "clean_table", arm.pins,
                                           arm.ledger)
            via_api = grant.permits_read(TARGET)
            _show("through the API", detail, via_api, arm)

            arm2 = _start(name, store + "_2")
            arm2.step()
            detail = _rebind_past_the_api(arm2, skills.T_TABLE_PREVIEW, TARGET)
            grant = evaluator.derive_grant(arm2.obj, "clean_table", arm2.pins,
                                           arm2.ledger)
            appended = grant.permits_read(TARGET)
            _show("appended past it", detail, appended, arm2)

            arm3 = _start(name, store + "_3")
            arm3.step()
            detail = _overwrite_past_the_api(arm3, skills.T_TABLE_PREVIEW, TARGET)
            grant = evaluator.derive_grant(arm3.obj, "clean_table", arm3.pins,
                                           arm3.ledger)
            overwritten = grant.permits_read(TARGET)
            _show("overwrote the record", detail, overwritten, arm3)

            out[name] = {"api": via_api, "append": appended,
                         "overwrite": overwritten,
                         "conflicts": bool(arm2.conflicts())}
    return out


def attack_b() -> dict:
    """Pre-seed a type before the step that legitimately produces it."""
    print("\n--- B. Pre-seed a future binding ---")
    out = {}
    for name in (STORED, DERIVED):
        with tempfile.TemporaryDirectory() as store:
            arm = _start(name, store)
            arm.step()                                   # infer_schema

            print(f"\n  {name}")
            detail = _rebind_past_the_api(arm, skills.T_CLEANED_OUTPUT, TARGET)
            print(f"      {detail}")

            # The legitimate producer of cleaned_output now runs.
            broke = None
            try:
                arm.step()                               # clean_table
            except Exception as exc:  # noqa: BLE001
                broke = f"{type(exc).__name__}: {exc}"

            if broke:
                print(f"      the legitimate producer FAILED: {broke}")
                obtained = False
            else:
                grant = evaluator.derive_grant(arm.obj, "validate_chain",
                                               arm.pins, arm.ledger)
                obtained = grant.permits_read(TARGET)
                _show("pre-seeded binding", "used by a later step", obtained, arm)
            out[name] = {"obtained": obtained, "broke": broke,
                         "conflicts": arm.conflicts()}
    return out


def attack_c() -> dict:
    """Tamper after completion, then resume."""
    print("\n--- C. Tamper after completion, then resume ---")
    out = {}
    for name in (STORED, DERIVED):
        with tempfile.TemporaryDirectory() as store:
            arm = _start(name, store)
            evaluator.run_to_completion(arm.obj, store, arm.pins, arm.ledger)

            print(f"\n  {name}")
            detail = _rebind_past_the_api(arm, skills.T_TABLE_PREVIEW, TARGET)

            # Resume: the object is reloaded and re-run from an earlier state.
            reloaded = load_object(OBJ, store)
            reloaded.state = "profiled"
            ledger = (ProductionLedger.load(os.path.join(store, "ledger.jsonl"))
                      if name == DERIVED else None)
            if ledger is not None:
                # Persisted tampering, as an attacker with file access does it.
                with open(os.path.join(store, "ledger.jsonl"), "a",
                          encoding="utf-8") as fh:
                    fh.write(json.dumps({
                        "object_id": OBJ, "at_state": "profiled",
                        "skill": "attacker",
                        "artifact_type": skills.T_TABLE_PREVIEW,
                        "key": TARGET}, sort_keys=True) + "\n")
                ledger = ProductionLedger.load(
                    os.path.join(store, "ledger.jsonl"))

            grant = evaluator.derive_grant(reloaded, "clean_table", arm.pins,
                                           ledger)
            obtained = grant.permits_read(TARGET)
            conflicts = ledger.conflicts_for(OBJ) if ledger else []
            mark = "!!" if obtained else "  "
            print(f"   {mark} survives resume    "
                  f"{'OBTAINED' if obtained else 'no':9s} {detail}")
            if conflicts:
                print(f"        conflicts visible in the record: {conflicts}")
            out[name] = {"obtained": obtained, "conflicts": bool(conflicts)}
    return out


if __name__ == "__main__":
    print("The artifact map: case 08's cheapest surface, now measured against")
    print("a workflow that actually maintains it.")

    a = attack_a()
    b = attack_b()
    c = attack_c()

    print("\n=== RESULT ===")
    print(f"{'':24s} {'stored':>10s} {'derived':>10s}")
    rows = [
        ("A rebind, via API", a[STORED]["api"], a[DERIVED]["api"]),
        ("A rebind, appended", a[STORED]["append"], a[DERIVED]["append"]),
        ("A rebind, overwritten", a[STORED]["overwrite"], a[DERIVED]["overwrite"]),
        ("B pre-seed a future type", b[STORED]["obtained"], b[DERIVED]["obtained"]),
        ("C survives resume", c[STORED]["obtained"], c[DERIVED]["obtained"]),
    ]
    for label, stored, derived in rows:
        print(f"{label:24s} {('OBTAINED' if stored else 'no'):>10s} "
              f"{('OBTAINED' if derived else 'no'):>10s}")

    print()
    if b[DERIVED]["broke"]:
        print("B in the derived arm did not merely fail - it broke the")
        print(f"legitimate producer: {b[DERIVED]['broke']}")
    print(f"conflicts left in the derived record: A={a[DERIVED]['conflicts']} "
          f"B={bool(b[DERIVED]['conflicts'])} C={c[DERIVED]['conflicts']}")
    raise SystemExit(0)
