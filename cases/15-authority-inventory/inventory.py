"""Case 15 - what a normal deployment already contains, and what that costs.

Cases 12-14 measured architectures. This measures **deployments**: for each of
the three models, one piece of pre-existing authority that a normal, competent
installation plausibly has, and what its presence does to the same attack.

    arm A   an identity that already holds the target authority
    arm B   a credential scoped across two boundaries
    arm C   an approved skill that legitimately reads the target

None of these is a misconfiguration in the ordinary sense. Somebody's job needs
key material; somebody's integration spans two systems; somebody's workflow
rotates keys. They are what a deployment accumulates.

Three things are measured per arm, present and absent:

  commits      the settled unit - minimum independently committed state changes
  scope        how far the cheapest yielding edit reaches
  inventory    whether the *standing authority inventory* changes at all

The third is the instrument this case adds. An attacker who must **create**
authority shows up in a diff of what authority exists. An attacker who only
has to **point at** authority that already exists does not.
"""

from __future__ import annotations

import importlib.util
import os
import sys
from dataclasses import dataclass
from typing import Dict, List, Optional, Set, Tuple

CASE_15 = os.path.dirname(os.path.abspath(__file__))
CASES = os.path.dirname(CASE_15)
CASE_14 = os.path.join(CASES, "14-selector-map")

for path in (CASE_14, os.path.dirname(CASES)):
    if path not in sys.path:
        sys.path.insert(0, path)


def _load14(name: str):
    spec = importlib.util.spec_from_file_location(
        f"case14_{name}", os.path.join(CASE_14, f"{name}.py"))
    module = importlib.util.module_from_spec(spec)
    sys.modules[f"case14_{name}"] = module
    spec.loader.exec_module(module)
    return module


sel = _load14("selectors")
c12, arm_a, arm_b, arm_c = sel.c12, sel.arm_a, sel.arm_b, sel.arm_c
p13 = sel.p13

TARGET = c12.TARGET
STAGE = c12.ATTACK_STAGE


@dataclass
class Measured:
    arm: str
    present: bool
    obtained: bool
    commits: Optional[int]
    commit_of: str
    scope: str
    inventory_changed: Optional[bool]
    note: str = ""


# ---------------------------------------------------------------------------
# The standing authority inventory, per arm. What an auditor would list if
# asked "who or what may reach the target, today?"
# ---------------------------------------------------------------------------

def inventory_a() -> Set[Tuple[str, str, str]]:
    return {(subject, key, op)
            for subject, grants in arm_a.PERMISSIONS.items()
            for key, ops in grants.items() for op in ops}


def inventory_b() -> Set[Tuple[str, str]]:
    return {(name, key) for name, scope in arm_b.CONNECTIONS.items()
            for key in scope}


def inventory_c() -> Set[Tuple[str, str]]:
    from object_model import skills
    return {(name, artifact_type)
            for name, skill in skills.REGISTRY.items()
            for artifact_type in skill.reads}


# ---------------------------------------------------------------------------
# Arm A - an identity that already holds the authority.
# ---------------------------------------------------------------------------

def _safe_resolve_a() -> bool:
    try:
        return arm_a.resolve(STAGE).permits_read(TARGET)
    except c12.AuthorizationError:
        return False


def measure_a(present: bool) -> List[Measured]:
    out: List[Measured] = []

    # Route 1: create the authority by widening the permission table.
    arm_a.reset()
    if not present:
        del arm_a.PERMISSIONS[arm_a.KEY_OWNER]
    before = inventory_a()
    arm_a.mutate_permission_table(TARGET)
    out.append(Measured(
        "A", present, arm_a.resolve(STAGE).permits_read(TARGET), 1,
        "the permission table", c12.SCOPE_SUBJECT,
        inventory_a() != before,
        "creates authority that did not exist - a permissions audit sees a "
        "new entry"))

    # Route 2: point at an identity that already holds it.
    arm_a.reset()
    if not present:
        del arm_a.PERMISSIONS[arm_a.KEY_OWNER]
    before = inventory_a()
    arm_a.mutate_subject_assignment(TARGET)
    # With the identity removed the reassignment names a subject that does not
    # exist, and the model refuses. That refusal *is* the measurement: the
    # route depends entirely on the identity already being there.
    obtained = _safe_resolve_a()
    out.append(Measured(
        "A", present, obtained, 1 if obtained else None,
        "the stage-to-subject assignment", c12.SCOPE_SUBJECT,
        inventory_a() != before,
        "creates no authority anywhere - the permission set is untouched"))

    arm_a.reset()
    return out


# ---------------------------------------------------------------------------
# Arm B - a credential scoped across two boundaries.
# ---------------------------------------------------------------------------

def measure_b(present: bool) -> List[Measured]:
    out: List[Measured] = []

    arm_b.reset()
    if present:
        arm_b.CONNECTIONS[sel.OVERSCOPED] = set(
            arm_b.CONNECTIONS[arm_b.CONN_ORDERS]) | {TARGET}
    before = inventory_b()

    if present:
        # One write to the step record: name the key and point at the
        # credential that already spans both sides.
        sel._write_step_record(sel.OVERSCOPED)
        obtained = _safe_resolve_b()
        out.append(Measured(
            "B", present, obtained, 1 if obtained else None,
            "the step record", c12.SCOPE_WORKFLOW, inventory_b() != before,
            "the credential inventory is untouched - only the step changed"))
    else:
        arm_b.mutate_step_configuration(TARGET)
        arm_b.mutate_connection_scope(TARGET)
        obtained = _safe_resolve_b()
        out.append(Measured(
            "B", present, obtained, 2 if obtained else None,
            "the step record and the connection scope", c12.SCOPE_WORKFLOW,
            inventory_b() != before,
            "a credential had to be widened, and that is what an audit of "
            "connection scopes would list"))

    arm_b.reset()
    return out


def _safe_resolve_b() -> bool:
    try:
        return arm_b.resolve(STAGE).permits_read(TARGET)
    except c12.AuthorizationError:
        return False


# ---------------------------------------------------------------------------
# Arm C - an approved skill that legitimately reads the target.
#
# Measured on the **execute** path: the required skill comes from the object's
# type and state, which is the object model's actual claim. Case 12's adapter
# mapped stage to skill statically, which was right for what case 12 compared
# and wrong for this question.
# ---------------------------------------------------------------------------

ROTATION_TYPE = "key_rotation"


def _install_rotation_skill() -> None:
    """A legitimate, approved transformation that reads key material. Nothing
    hostile about it: it is somebody's key-rotation workflow."""
    from object_model import evaluator, skills

    skills._REGISTRY["rotate_keys"] = skills.Skill(
        name="rotate_keys", version="1.0",
        reads=(skills.T_TABLE_PREVIEW, skills.T_KEY_MATERIAL),
        produces="rotation_report")
    evaluator._OBJECT_TYPES[ROTATION_TYPE] = ("rotate_keys",)
    evaluator._TRANSITIONS[(ROTATION_TYPE, "ingested")] = "rotate_keys"
    evaluator._NEXT_STATE[(ROTATION_TYPE, "ingested")] = "rotated"


def _grant_on_the_execute_path(obj, ledger, pins) -> bool:
    from object_model import evaluator
    try:
        skill = evaluator.required_skill(obj)
        grant = evaluator.derive_grant(obj, skill, pins, ledger)
        return grant.permits_read(TARGET)
    except Exception:                                     # noqa: BLE001
        return False


def measure_c(present: bool, store_dir: str) -> List[Measured]:
    from object_model import evaluator, pin_versions, skills

    out: List[Measured] = []

    # -- route: retype the object at a permissive type that already exists --
    arm_c.reset(os.path.join(store_dir, f"c_retype_{present}"))
    if present:
        _install_rotation_skill()
    before = inventory_c()
    obj = arm_c._state["obj"]
    obj.object_type = ROTATION_TYPE                       # the one commit
    # The edit precedes the run, so the run pins whatever it now finds -
    # case 09's undetected placement, unchanged.
    try:
        pins = pin_versions(evaluator.OBJECT_TYPES.get(ROTATION_TYPE, ()))
    except Exception:                                     # noqa: BLE001
        pins = {}
    obtained = _grant_on_the_execute_path(obj, arm_c._state["ledger"], pins)
    out.append(Measured(
        "C", present, obtained, 1 if obtained else None,
        "the object record", c12.SCOPE_OBJECT, inventory_c() != before,
        "the skill registry is untouched - one object was retyped"))

    # -- route: widen an approved contract, which always works --------------
    arm_c.reset(os.path.join(store_dir, f"c_widen_{present}"))
    if present:
        _install_rotation_skill()
    before = inventory_c()
    obj = arm_c._state["obj"]
    current = skills._REGISTRY["infer_schema"]
    skills._REGISTRY["infer_schema"] = skills.Skill(
        name=current.name, version=current.version,
        reads=tuple(current.reads) + (skills.T_KEY_MATERIAL,),
        produces=current.produces, effects=current.effects)
    pins = pin_versions(evaluator.OBJECT_TYPES["orders_table"])
    obtained = _grant_on_the_execute_path(obj, arm_c._state["ledger"], pins)
    out.append(Measured(
        "C", present, obtained, 1 if obtained else None,
        "the skill contract", c12.SCOPE_DEPLOYMENT, inventory_c() != before,
        "the approved set changed, and that is exactly what a skill audit "
        "lists"))

    return out


def measure_all(store_dir: str) -> List[Measured]:
    rows: List[Measured] = []
    for present in (False, True):
        rows.extend(measure_a(present))
        rows.extend(measure_b(present))
        rows.extend(measure_c(present, store_dir))
    return rows


def cheapest(rows: List[Measured], arm: str, present: bool) -> Optional[Measured]:
    """The route an attacker would actually take.

    Ordered by commits, then by **whether the standing inventory changes**,
    then by scope. The middle term is the attacker model this case is about:
    given two routes of equal cost, one visible to an audit and one not, the
    invisible one is strictly better and costs nothing extra. Sorting by scope
    first would have reported arm A's noisy route and hidden its quiet one.
    """
    winning = [r for r in rows
               if r.arm == arm and r.present is present and r.obtained]
    if not winning:
        return None
    return min(winning, key=lambda r: (r.commits or 99,
                                       bool(r.inventory_changed),
                                       c12.SCOPE_ORDER.index(r.scope)))
