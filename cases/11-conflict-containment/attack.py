"""Case 11 - executable attack: contain a contradiction the moment it appears.

Run it:

    python cases/11-conflict-containment/attack.py

Case 10 built a record that keeps a contradiction instead of losing it, and
then did nothing with the contradiction. An appended rebinding was inert, the
object carried on working, and `conflicts_for()` sat there waiting for a caller
that never came.

This case adds one thing and nothing else: the step lifecycle reads the record
it already has, and an object whose production record contradicts itself runs
no further step. No new surfaces, no new records, no new arms.

Same attacker as cases 08-10: may alter persisted policy or workflow records
before or between steps, may not modify evaluator code.

Four measurements, and two of them are costs.
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
from typing import Optional, Tuple

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__)))))

from object_model import (  # noqa: E402
    ObjectContainedError, QueueItem, WorkObject, load_object, pin_versions,
    reset_registry, save_object,
)
from object_model import evaluator, skills  # noqa: E402
from object_model.ledger import ProductionLedger, ProductionRecord  # noqa: E402

OBJ = "obj_812"
TARGET = "artifact.key_material"
SOURCE = "artifact.raw_input"

UNCONTAINED, CONTAINED = "no containment", "contained"


def _start(store: str):
    reset_registry()
    evaluator.reset_workflow()
    obj = WorkObject(OBJ, "orders_table", "ingested", {})
    ledger = ProductionLedger(path=os.path.join(store, "ledger.jsonl"))
    ledger.seed(OBJ, {skills.T_TABLE_PREVIEW: SOURCE,
                      skills.T_KEY_MATERIAL: TARGET})
    save_object(obj, store)
    pins = pin_versions(evaluator.OBJECT_TYPES["orders_table"])
    return obj, ledger, pins


def _step(obj, ledger, pins, store, contain=True):
    item = QueueItem(obj.object_id, evaluator.required_skill(obj))
    return evaluator.run_step(obj, item, store, pins, ledger, contain)


def _forge_append(ledger, obj, artifact_type=skills.T_TABLE_PREVIEW,
                  key=TARGET) -> str:
    """Case 10's attack A-append. Inert then; the starting position now."""
    ledger._records.append(
        ProductionRecord(OBJ, obj.state, "attacker", artifact_type, key))
    return f"appended a contradicting record for {artifact_type!r}"


def _forge_on_disk(store, artifact_type=skills.T_TABLE_PREVIEW, key=TARGET) -> str:
    """Case 10's attack C: the same forgery, persisted."""
    with open(os.path.join(store, "ledger.jsonl"), "a", encoding="utf-8") as fh:
        fh.write(json.dumps({
            "object_id": OBJ, "at_state": "profiled", "skill": "attacker",
            "artifact_type": artifact_type, "key": key}, sort_keys=True) + "\n")
    return "appended the same record to the persisted ledger"


def _forge_overwrite(ledger) -> str:
    """Case 10's residual: the one route that obtains the capability."""
    for index, entry in enumerate(ledger._records):
        if entry.artifact_type == skills.T_TABLE_PREVIEW:
            ledger._records[index] = ProductionRecord(
                OBJ, entry.at_state, entry.skill, entry.artifact_type, TARGET)
            return "overwrote the existing production record"
    return "no record to overwrite"


def _finish(obj, ledger, pins, store, contain) -> Tuple[str, Optional[str]]:
    """Run what is left of the workflow. Returns (final state, refusal)."""
    try:
        evaluator.run_to_completion(obj, store, pins, ledger, contain=contain)
        return obj.state, None
    except ObjectContainedError as exc:
        return obj.state, f"{type(exc).__name__}: {exc}"


def _show(label: str, state: str, refusal: Optional[str],
          completing_is_the_finding: bool = True) -> None:
    stopped = refusal is not None
    mark = "!!" if completing_is_the_finding and not stopped else "  "
    verdict = "stopped" if stopped else "COMPLETED"
    print(f"   {mark} {label:16s} {verdict:10s} final state {state!r}")
    if refusal:
        print(f"        {refusal}")


# ---------------------------------------------------------------------------

def attack_a() -> dict:
    """Leave a contradiction in the record and let the object keep working."""
    print("\n--- A. Keep working on a record that contradicts itself ---")
    out = {}
    for name, contain in ((UNCONTAINED, False), (CONTAINED, True)):
        with tempfile.TemporaryDirectory() as store:
            obj, ledger, pins = _start(store)
            _step(obj, ledger, pins, store, contain)          # infer_schema
            print(f"\n  {name}")
            print(f"      {_forge_append(ledger, obj)}")
            print(f"      conflicts in the record: {ledger.conflicts_for(OBJ)}")

            state, refusal = _finish(obj, ledger, pins, store, contain)
            _show("continue", state, refusal)
            out[name] = {"state": state, "stopped": refusal is not None}
    return out


def attack_b() -> dict:
    """Retry, and resume from the persisted record."""
    print("\n--- B. Retry, reload, resume ---")
    out = {}
    with tempfile.TemporaryDirectory() as store:
        obj, ledger, pins = _start(store)
        _step(obj, ledger, pins, store)                       # infer_schema
        print(f"\n  {_forge_on_disk(store)}")
        ledger = ProductionLedger.load(os.path.join(store, "ledger.jsonl"))

        refusals = 0
        for _ in range(3):
            _, refusal = _finish(obj, ledger, pins, store, True)
            refusals += refusal is not None
        print(f"   {'  '} {'retry x3':16s} refused {refusals}/3")

        reloaded = ProductionLedger.load(os.path.join(store, "ledger.jsonl"))
        resumed = load_object(OBJ, store)
        resumed.state = "profiled"
        state, refusal = _finish(resumed, reloaded, pins, store, True)
        _show("resume", state, refusal)
        out = {"retries_refused": refusals, "resume_stopped": refusal is not None}
    return out


def attack_c() -> dict:
    """The blind spot: destroy the evidence instead of adding to it."""
    print("\n--- C. Overwrite instead of append ---")
    out = {}
    with tempfile.TemporaryDirectory() as store:
        obj, ledger, pins = _start(store)
        _step(obj, ledger, pins, store)                       # infer_schema
        print(f"\n  {_forge_overwrite(ledger)}")
        print(f"      conflicts in the record: {ledger.conflicts_for(OBJ)}")

        grant = evaluator.derive_grant(obj, "clean_table", pins, ledger)
        obtained = grant.permits_read(TARGET)
        state, refusal = _finish(obj, ledger, pins, store, True)
        _show("with containment", state, refusal)
        print(f"        unauthorized read of {TARGET}: "
              f"{'OBTAINED' if obtained else 'no'}")
        out = {"obtained": obtained, "stopped": refusal is not None,
               "conflicts": bool(ledger.conflicts_for(OBJ))}
    return out


def attack_d() -> dict:
    """What it costs. One forged line, and a type nothing reads."""
    print("\n--- D. The cost ---")
    out = {}
    with tempfile.TemporaryDirectory() as store:
        obj, ledger, pins = _start(store)
        _step(obj, ledger, pins, store)
        print(f"\n  {_forge_append(ledger, obj, skills.T_KEY_MATERIAL, SOURCE)}")
        print("      key_material is read by no skill in this workflow")
        state, refusal = _finish(obj, ledger, pins, store, True)
        _show("irrelevant type", state, refusal)
        out["irrelevant_type_stops_it"] = refusal is not None

    with tempfile.TemporaryDirectory() as store:
        obj, ledger, pins = _start(store)
        state, refusal = _finish(obj, ledger, pins, store, True)
        _show("honest run", state, refusal, completing_is_the_finding=False)
        out["honest_run_completes"] = refusal is None
    return out


if __name__ == "__main__":
    print("Case 10 left contradictions reported and unacted on. This measures")
    print("what acting on them changes, and what it costs.")

    a = attack_a()
    b = attack_b()
    c = attack_c()
    d = attack_d()

    print("\n=== RESULT ===")
    print(f"{'':30s} {'no containment':>16s} {'contained':>12s}")
    print(f"{'A object keeps working':30s} "
          f"{('COMPLETED' if not a[UNCONTAINED]['stopped'] else 'stopped'):>16s} "
          f"{('COMPLETED' if not a[CONTAINED]['stopped'] else 'stopped'):>12s}")
    print(f"{'B retries refused':30s} {'-':>16s} {b['retries_refused']:>10d}/3")
    print(f"{'B resume':30s} {'-':>16s} "
          f"{('stopped' if b['resume_stopped'] else 'COMPLETED'):>12s}")
    print(f"{'C overwrite - read obtained':30s} {'-':>16s} "
          f"{('OBTAINED' if c['obtained'] else 'no'):>12s}")
    print(f"{'C overwrite - contained':30s} {'-':>16s} "
          f"{('stopped' if c['stopped'] else 'never fired'):>12s}")

    print()
    print("The append that case 10 measured as inert now stops the object")
    print("permanently. The overwrite that case 10 measured as OBTAINED leaves")
    print("no contradiction, so containment never looks at it:")
    print(f"  conflicts after an overwrite: {c['conflicts']}")
    print("A contradiction about a type no step reads still stops the object:")
    print(f"  {d['irrelevant_type_stops_it']}")
    print(f"An untampered run is unaffected: {d['honest_run_completes']}")
    raise SystemExit(0)
