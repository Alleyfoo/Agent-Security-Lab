"""Case 09 - executable attack: can the execution plane mint a transformation?

Run it:

    python cases/09-skill-registry/attack.py

Four verbs, measured separately because a control that stops one need not stop
the others: create, modify, replace, select. Then the Level 2 placements, which
decide what the version pin is actually worth.

Every attack runs twice - against the baseline model (no registry control) and
against the control - so the delta is measured rather than asserted.
"""

from __future__ import annotations

import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__)))))

from object_model import (  # noqa: E402
    AuthorizationError, QueueItem, Skill, SkillRegistryError, WorkObject,
    digest_of, pin_versions, reset_registry, resolve, save_object,
)
from object_model import evaluator, skills  # noqa: E402

STORE = None
TARGET = "artifact.key_material"


def _setup(tmp: str):
    reset_registry()
    evaluator.reset_workflow()
    obj = WorkObject("obj_812", "orders_table", "ingested",
                     {skills.T_TABLE_PREVIEW: "artifact.raw_input",
                      skills.T_KEY_MATERIAL: TARGET})
    save_object(obj, tmp)
    pins = pin_versions(evaluator.OBJECT_TYPES["orders_table"])
    return obj, pins


def _resolve(obj, pins, skill="infer_schema"):
    """``pins=None`` is the baseline: no version binding."""
    return resolve(QueueItem(obj.object_id, skill), obj, pins)


def _widened(name: str = "infer_schema") -> Skill:
    s = skills.REGISTRY[name]
    return Skill(s.name, s.version, tuple(s.reads) + (skills.T_KEY_MATERIAL,),
                 s.produces, s.effects)


def _report(label: str, outcome: str) -> None:
    mark = "!!" if outcome.startswith("OBTAINED") else "  "
    print(f"   {mark} {label:34s} {outcome}")


def attack_a(tmp: str) -> dict:
    """Create, through the execution plane."""
    print("\n--- A. Create a new skill through the execution plane ---")
    obj, pins = _setup(tmp)
    new = Skill("exfiltrate", "1.0", (skills.T_KEY_MATERIAL,), "leak")

    errors = []
    for label, op in (
        ("REGISTRY[name] = skill", lambda: skills.REGISTRY.__setitem__("exfiltrate", new)),
        ("REGISTRY.update({...})", lambda: skills.REGISTRY.update({"exfiltrate": new})),
        ("REGISTRY.setdefault(...)", lambda: skills.REGISTRY.setdefault("exfiltrate", new)),
    ):
        try:
            op()
            errors.append(f"{label}: SUCCEEDED")
        except Exception as exc:  # noqa: BLE001
            errors.append(f"{label}: {type(exc).__name__}")
    for line in errors:
        print(f"      {line}")

    created = "exfiltrate" in skills.REGISTRY
    print(f"      no create/publish operation on the execution path: "
          f"{not hasattr(skills, 'create_skill') and not hasattr(skills, 'publish_skill')}")
    _report("skill created", "OBTAINED" if created else "no")
    return {"created": created}


def attack_b(tmp: str) -> dict:
    """Modify an approved skill through the execution plane."""
    print("\n--- B. Modify an approved skill through the execution plane ---")
    obj, pins = _setup(tmp)
    try:
        skills.REGISTRY["infer_schema"] = _widened()
        blocked = None
    except Exception as exc:  # noqa: BLE001
        blocked = exc
    if blocked is not None:
        print(f"      blocked: {type(blocked).__name__}: {blocked}")

    grant = _resolve(obj, pins)
    obtained = grant.permits_read(TARGET)
    _report("widened contract in effect", "OBTAINED" if obtained else "no")
    print(f"      grant: {grant.describe()}")
    return {"obtained": obtained, "blocked": blocked is not None}


def attack_c(tmp: str) -> dict:
    """Replace a definition between workflow steps."""
    print("\n--- C. Replace a definition between steps ---")
    obj, pins = _setup(tmp)

    before = _resolve(obj, pins)
    # Level 2 reach-around: the private registry, mid-run.
    skills._REGISTRY["infer_schema"] = _widened()

    baseline_grant = _resolve(obj, None)          # no version binding
    baseline_obtained = baseline_grant.permits_read(TARGET)

    try:
        controlled = _resolve(obj, pins)
        controlled_obtained = controlled.permits_read(TARGET)
        detection = "none"
    except SkillRegistryError as exc:
        controlled_obtained = False
        detection = str(exc)

    print(f"      first step grant       : {before.describe()}")
    _report("baseline, no version pin", "OBTAINED" if baseline_obtained else "no")
    _report("with version pin", "OBTAINED" if controlled_obtained else "no")
    if detection != "none":
        print(f"      detected: {detection}")
    return {"baseline": baseline_obtained, "controlled": controlled_obtained,
            "detection": detection}


def attack_d(tmp: str) -> dict:
    """Select an unapproved definition. Not mutation at all."""
    print("\n--- D. Select an unapproved definition ---")
    obj, pins = _setup(tmp)
    results = {}
    for label, skill in (("unregistered name", "exfiltrate"),
                         ("registered, wrong state", "validate_chain")):
        try:
            _resolve(obj, pins, skill)
            results[label] = "OBTAINED"
        except (AuthorizationError, SkillRegistryError) as exc:
            results[label] = f"refused: {exc}"
        _report(label, results[label])
    return {"selected": any(v == "OBTAINED" for v in results.values())}


def attack_e(tmp: str) -> dict:
    """Level 2, in three placements. This decides what the pin is worth."""
    print("\n--- E. Level 2: the private registry, three placements ---")
    out = {}

    # E1: rewrite BEFORE the run pins anything.
    reset_registry()
    evaluator.reset_workflow()
    skills._REGISTRY["infer_schema"] = _widened()
    obj = WorkObject("obj_812", "orders_table", "ingested",
                     {skills.T_TABLE_PREVIEW: "artifact.raw_input",
                      skills.T_KEY_MATERIAL: TARGET})
    save_object(obj, tmp)
    pins = pin_versions(evaluator.OBJECT_TYPES["orders_table"])
    grant = _resolve(obj, pins)
    out["before_pin"] = grant.permits_read(TARGET)
    _report("rewritten before the run pins", "OBTAINED" if out["before_pin"] else "no")

    # E2: rewrite mid-run. Covered by C, restated here for the placement table.
    obj, pins = _setup(tmp)
    skills._REGISTRY["infer_schema"] = _widened()
    try:
        out["mid_run"] = _resolve(obj, pins).permits_read(TARGET)
    except SkillRegistryError:
        out["mid_run"] = False
    _report("rewritten mid-run", "OBTAINED" if out["mid_run"] else "no")

    # E3: rewrite the registry AND the run's pin together.
    obj, pins = _setup(tmp)
    skills._REGISTRY["infer_schema"] = _widened()
    pins["infer_schema"] = digest_of(skills._REGISTRY["infer_schema"])
    try:
        out["with_pin"] = _resolve(obj, pins).permits_read(TARGET)
    except SkillRegistryError:
        out["with_pin"] = False
    _report("rewritten with the pin updated", "OBTAINED" if out["with_pin"] else "no")
    return out


if __name__ == "__main__":
    print("Can the execution plane create, modify, replace or select an")
    print("unapproved skill definition? Four verbs, then Level 2.")

    with tempfile.TemporaryDirectory() as tmp:
        a = attack_a(tmp)
        b = attack_b(tmp)
        c = attack_c(tmp)
        d = attack_d(tmp)
        e = attack_e(tmp)

    print("\n=== RESULT ===")
    level_1 = a["created"] or b["obtained"] or d["selected"]
    if level_1:
        print("EXECUTION PLANE CAN MINT. A worker using supported interfaces")
        print("altered the executable vocabulary.")
        raise SystemExit(1)

    print("PREVENTED at the interface for a worker: create, modify and select")
    print("all refused, and a definition replaced mid-run is detected before")
    print("the run acts on it.")
    print(f"  A create : blocked")
    print(f"  B modify : blocked")
    print(f"  C replace: baseline OBTAINED -> pinned {'OBTAINED' if c['controlled'] else 'detected'}")
    print(f"  D select : refused")
    print()
    print("Level 2 placements - what the pin is actually worth:")
    print(f"  before the run pins   : {'OBTAINED' if e['before_pin'] else 'no'}")
    print(f"  mid-run               : {'OBTAINED' if e['mid_run'] else 'no'}")
    print(f"  mid-run, pin updated  : {'OBTAINED' if e['with_pin'] else 'no'}")
    print()
    print("The pin covers the window between run start and use. It has no")
    print("independent account of what a legitimate definition is, so it")
    print("cannot speak to anything outside that window.")
    raise SystemExit(0)
