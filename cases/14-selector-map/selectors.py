"""Case 14 - what selects each authority premise, and which selectors pivot.

Case 13 found *a* premise that looks independent and is not. This enumerates
the selectors instead of finding another example, and answers the question the
manager put:

    What facts does authority depend on, and which of those facts can one
    attacker-controlled pivot change simultaneously?

A **premise** is a fact authority depends on. A **selector** is what that fact
is looked up by. Two premises are independent only if no attacker-alterable
selector reaches both - and the map below is worthless unless every "shares a
selector" claim is *executed*, so each one carries a pivot function that must
actually move both premises at once.

Arms are case 12's, frozen, reached through case 13's premise module. Nothing
in object_model or in either earlier case directory is modified.
"""

from __future__ import annotations

import importlib.util
import os
import sys
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Tuple

CASE_14 = os.path.dirname(os.path.abspath(__file__))
CASES = os.path.dirname(CASE_14)
CASE_13 = os.path.join(CASES, "13-second-premise")

for path in (CASE_13, os.path.dirname(CASES)):
    if path not in sys.path:
        sys.path.insert(0, path)


def _load13(name: str):
    spec = importlib.util.spec_from_file_location(
        f"case13_{name}", os.path.join(CASE_13, f"{name}.py"))
    module = importlib.util.module_from_spec(spec)
    sys.modules[f"case13_{name}"] = module
    spec.loader.exec_module(module)
    return module


p13 = _load13("premise")
c12 = p13.c12
arm_a, arm_b, arm_c = p13.arm_a, p13._load12("arm_b"), p13.arm_c

TARGET = c12.TARGET
STAGE = c12.ATTACK_STAGE


@dataclass(frozen=True)
class Premise:
    """One fact authority depends on, and what it is looked up by."""

    arm: str
    name: str
    stored_in: str
    selectors: Tuple[str, ...]
    note: str = ""


@dataclass
class Pivot:
    """A selector two or more premises share, and the edit that moves it.

    ``run`` performs the single edit and returns ``(obtained, moved)``. The two
    are reported separately on purpose: a pivot that shifts a premise and still
    fails to obtain the capability is a *different* result from one that shifts
    nothing, and collapsing them would hide which premise did the work. Arm C's
    object-type pivot is exactly that case and the distinction is its finding.
    """

    arm: str
    selector: str
    moves: Tuple[str, ...]
    edit: str
    run: Callable[[], Tuple[bool, str]]
    obtained: Optional[bool] = None
    moved: str = ""
    why: str = ""


# ---------------------------------------------------------------------------
# The map. Selector names are shared across arms where they mean the same
# thing, which is what makes the arms comparable at all.
# ---------------------------------------------------------------------------

SEL_SUBJECT = "the subject the stage runs as"
SEL_STAGE = "the stage/executable being run"
SEL_KEY = "the artifact key"
SEL_STEP = "the workflow step record"
SEL_CONNECTION = "the connection the step names"
SEL_OBJECT = "the object id"
SEL_OBJECT_TYPE = "the object type"
SEL_STATE = "the object state"
SEL_SKILL = "the skill name"
SEL_TYPE = "the artifact type"

PREMISES: List[Premise] = [
    # -- arm A ------------------------------------------------------------
    Premise("A", "may this subject read this key?", "permission table",
            (SEL_SUBJECT, SEL_KEY)),
    Premise("A", "may this domain meet this type? (case 13)", "label policy",
            (SEL_SUBJECT, SEL_KEY),
            "when the domain is keyed on the subject - the case 13 finding"),
    Premise("A", "may this domain meet this type? (case 13, stage-keyed)",
            "label policy", (SEL_STAGE, SEL_KEY),
            "the same record, looked up by something the attacker does not "
            "select"),

    # -- arm B ------------------------------------------------------------
    Premise("B", "does the step name this key?", "workflow definition",
            (SEL_STEP,)),
    Premise("B", "does the connection reach this key?", "connection scope",
            (SEL_STEP, SEL_CONNECTION),
            "the step record selects *which* connection is consulted, so the "
            "step is a selector for both premises"),

    # -- arm C ------------------------------------------------------------
    Premise("C", "which key holds this artifact type?", "production ledger",
            (SEL_OBJECT, SEL_TYPE)),
    Premise("C", "which types may this skill read?", "skill contract",
            (SEL_SKILL,)),
    Premise("C", "which skill does this object require?", "transition table",
            (SEL_OBJECT_TYPE, SEL_STATE),
            "governs which transformation runs, not what it may read - it is "
            "on the execute path, and the read grant does not consult it"),
    Premise("C", "does the artifact declare itself? (case 13)",
            "artifact declaration", (SEL_KEY,)),
    Premise("C", "may this object type have this type read? (case 13)",
            "object-type policy", (SEL_OBJECT_TYPE,)),
]

# Which selectors this adversary can alter. Level 1.5 writes persisted
# configuration and workflow records; it does not write code.
ALTERABLE: Dict[str, bool] = {
    SEL_SUBJECT: True,       # the stage->subject assignment is configuration
    SEL_STAGE: False,        # which stage is running is the work itself
    SEL_KEY: False,          # the key is what the premises resolve *to*
    SEL_STEP: True,          # the workflow definition is configuration
    SEL_CONNECTION: True,    # named by the step record
    SEL_OBJECT: True,        # persisted on the object
    SEL_OBJECT_TYPE: True,
    SEL_STATE: True,
    SEL_SKILL: False,        # derived from type+state, not written directly
    SEL_TYPE: False,         # declared by the skill contract
}


def shared_selectors() -> List[Tuple[str, str, List[str]]]:
    """(arm, selector, premises) for every alterable selector reaching 2+."""
    out: List[Tuple[str, str, List[str]]] = []
    for arm in ("A", "B", "C"):
        counts: Dict[str, List[str]] = {}
        for premise in PREMISES:
            if premise.arm != arm:
                continue
            for selector in premise.selectors:
                counts.setdefault(selector, []).append(premise.name)
        for selector, names in sorted(counts.items()):
            if len(names) > 1 and ALTERABLE.get(selector):
                out.append((arm, selector, names))
    return out


# ---------------------------------------------------------------------------
# The pivots, executed.
# ---------------------------------------------------------------------------

def _pivot_a_subject() -> Tuple[bool, str]:
    p13.reset_arm_a()
    arm_a.mutate_subject_assignment(TARGET)
    grant = p13.resolve_arm_a(STAGE, p13.BY_SUBJECT)
    return grant.permits_read(TARGET), "both the permission table's answer " \
                                       "and the domain used by the label policy"


def _pivot_a_subject_stage_keyed() -> Tuple[bool, str]:
    """The control: same edit, same records, domain keyed on the stage."""
    p13.reset_arm_a()
    arm_a.mutate_subject_assignment(TARGET)
    grant = p13.resolve_arm_a(STAGE, p13.BY_STAGE)
    return grant.permits_read(TARGET), "the permission table's answer only"


def _pivot_b_connection() -> Tuple[bool, str]:
    """Rebind the step's connection. Case 12 measured this failing - and it
    fails for a reason about the *inventory*, not the architecture."""
    arm_b.reset()
    arm_b.mutate_connection_binding(TARGET)
    try:
        return (arm_b.resolve(STAGE).permits_read(TARGET),
                "which connection scope is consulted")
    except c12.AuthorizationError:
        return False, "which connection scope is consulted - and the step " \
                      "then failed closed on its own legitimate inputs"


OVERSCOPED = "conn_ops"


def _write_step_record(connection: str) -> None:
    """One write to one record, setting both fields it carries.

    Case 12 counted field-level mutations and reported arm B's minimum tamper
    set as 2. Two of the three mutations it counted - the input list and the
    connection name - live in the *same* record, and an adversary with write
    access to the workflow definition sets both in one write. The unit matters
    and this case measures it in records rather than fields.
    """
    step = arm_b.WORKFLOW[STAGE]
    arm_b.WORKFLOW[STAGE] = arm_b.ConfiguredStep(
        name=step.name, action=step.action, connection=connection,
        inputs=tuple(step.inputs) + (TARGET,), output=step.output)


def _pivot_b_step_record() -> Tuple[bool, str]:
    """One write to the step record, in an ordinary tenant."""
    arm_b.reset()
    _write_step_record(arm_b.CONN_KEYS)
    try:
        return (arm_b.resolve(STAGE).permits_read(TARGET),
                "both premises in one record write - the input list and the "
                "connection name are fields of the same step record")
    except c12.AuthorizationError:
        return False, ("both premises in one record write - and the step then "
                       "failed closed, because conn_keys cannot reach its own "
                       "legitimate inputs")


def _pivot_b_connection_with_overscoped_credential() -> Tuple[bool, str]:
    """The same single record write, in a tenant that already holds one
    ordinary over-scoped credential.

    The credential is **pre-existing tenant state, not part of the attack** -
    it is established before the edit and is not counted as one. The
    competence checklist forbids it, and this measures what the checklist is
    buying rather than assuming it.
    """
    arm_b.reset()
    arm_b.CONNECTIONS[OVERSCOPED] = set(arm_b.CONNECTIONS[arm_b.CONN_ORDERS]) \
        | {TARGET}                                  # the tenant, before the attack
    _write_step_record(OVERSCOPED)                  # the attack: one write
    try:
        return (arm_b.resolve(STAGE).permits_read(TARGET),
                "both premises in one record write, and the pre-existing "
                "credential reaches both the legitimate inputs and the target")
    except c12.AuthorizationError:
        return False, "nothing"


def _pivot_c_object(store_dir: str) -> Tuple[bool, str]:
    p13.reset_arm_c(store_dir)
    arm_c._state["obj"].object_id = "obj_other"
    try:
        return (p13.resolve_arm_c(STAGE).permits_read(TARGET),
                "which object's bindings are read - to an empty set")
    except Exception:                                     # noqa: BLE001
        return False, "which object's bindings are read - to an empty set"


def _pivot_c_object_type(store_dir: str) -> Tuple[bool, str]:
    """One edit to object_type moves two premises, and does not obtain.

    This is the case's most useful negative. The pivot is real: after it, the
    object-type read policy genuinely admits key_material. It buys nothing
    because a *third* premise - the skill contract, keyed on the skill name -
    still says infer_schema reads table_preview and nothing else.

    So arm C's premises are keyed by genuinely different things, and case 13's
    "one premise per surface" is doing exactly the work it was supposed to.
    """
    from object_model import evaluator, skills

    p13.reset_arm_c(store_dir)
    # A second object type exists in the deployment, as one would: somebody's
    # workflow legitimately handles key material.
    evaluator._OBJECT_TYPES["key_rotation"] = ("infer_schema",)
    evaluator._TRANSITIONS[("key_rotation", "ingested")] = "infer_schema"
    evaluator._NEXT_STATE[("key_rotation", "ingested")] = "profiled"
    p13.TYPE_READABLE["key_rotation"] = {skills.T_TABLE_PREVIEW,
                                         skills.T_KEY_MATERIAL}
    arm_c._state["obj"].object_type = "key_rotation"

    admits = skills.T_KEY_MATERIAL in p13.TYPE_READABLE[
        arm_c._state["obj"].object_type]
    contract = skills.REGISTRY["infer_schema"].reads
    try:
        obtained = p13.resolve_arm_c(STAGE).permits_read(TARGET)
    except Exception:                                     # noqa: BLE001
        obtained = False
    return obtained, (
        f"the object-type read policy, which now admits key_material "
        f"({admits}) - and the skill contract still reads {list(contract)}, "
        "so a premise on a different selector held")


def build_pivots(store_dir: str) -> List[Pivot]:
    return [
        Pivot("A", SEL_SUBJECT,
              ("may this subject read this key?",
               "may this domain meet this type? (case 13)"),
              "reassign the stage to another subject", _pivot_a_subject,
              why="both premises are looked up by the subject, so one edit "
                  "moves both. Case 13's finding, now located on the map."),
        Pivot("A", SEL_STAGE,
              ("may this subject read this key?",
               "may this domain meet this type? (case 13, stage-keyed)"),
              "the same reassignment, against a stage-keyed domain",
              _pivot_a_subject_stage_keyed,
              why="the selector the attacker cannot alter does not pivot. "
                  "Same records, same edit, different lookup key."),
        Pivot("B", SEL_CONNECTION,
              ("does the step name this key?",
               "does the connection reach this key?"),
              "rebind the step to another connection", _pivot_b_connection,
              why="the pivot exists - the step record selects both premises - "
                  "and fails closed because no existing connection holds both "
                  "the legitimate inputs and the target."),
        Pivot("B", SEL_STEP,
              ("does the step name this key?",
               "does the connection reach this key?"),
              "one write to the step record, setting both fields",
              _pivot_b_step_record,
              why="case 12 counted fields and reported 2; two of those fields "
                  "are in one record. Counted in records, an ordinary tenant "
                  "still holds - for the inventory reason, not the count."),
        Pivot("B", SEL_STEP + " (over-scoped tenant)",
              ("does the step name this key?",
               "does the connection reach this key?"),
              "the same single record write, where one over-scoped "
              "credential already exists",
              _pivot_b_connection_with_overscoped_credential,
              why="arm B's independence is a property of the credential "
                  "inventory, not of the architecture - and once the "
                  "inventory supplies a target, its two premises collapse "
                  "into one record write."),
        Pivot("C", SEL_OBJECT,
              ("which key holds this artifact type?",),
              "point the object at another id",
              lambda: _pivot_c_object(os.path.join(store_dir, "obj")),
              why="selects the bindings, and fails closed: another object's "
                  "ledger holds nothing for this one."),
        Pivot("C", SEL_OBJECT_TYPE,
              ("which skill does this object require?",
               "may this object type have this type read? (case 13)"),
              "retype the object to a permissive type that exists",
              lambda: _pivot_c_object_type(os.path.join(store_dir, "otype")),
              why="the pivot is real and moves case 13's read policy, and a "
                  "third premise on a different selector - the skill contract, "
                  "keyed on the skill name - still holds. The clearest "
                  "measured example of premises being independently "
                  "*selected*."),
    ]
