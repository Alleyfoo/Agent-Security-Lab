"""Case 16 - authority reachability, in all three layers' idioms.

Case 15 found that the three models agree on something: once useful authority
exists in a deployment, an attacker need not create or widen anything. They
change what *points* at it, and the standing authority inventory does not move.

So an audit that asks "did anybody gain new permissions?" answers *no* while
effective access has changed completely. There are three questions, not one:

    what authority exists?          -> the inventory (case 15)
    what can currently reach it?    -> this case
    what does that combination permit?

The middle one is the whole attack, and nothing in this repository looked at it
until now.

Two views, and the distinction is the case:

    actual     work that reaches the authority as the deployment stands
    potential  work that could reach it through a **binding change alone** -
               no new authority created, nothing widened

`potential` is what makes this an audit rather than an alarm. It flags the
exposure *at rest*, before any attack, in exactly the situations case 15
measured as invisible.

The arms are case 12's, unchanged, reached through case 15. Each layer's idiom
expresses the same three-question structure differently, which is the point of
`docs/security-concepts.md` §0.
"""

from __future__ import annotations

import importlib.util
import os
import sys
from dataclasses import dataclass
from typing import Dict, List, Set, Tuple

CASE_16 = os.path.dirname(os.path.abspath(__file__))
CASES = os.path.dirname(CASE_16)
CASE_15 = os.path.join(CASES, "15-authority-inventory")

for path in (CASE_15, os.path.dirname(CASES)):
    if path not in sys.path:
        sys.path.insert(0, path)


def _load15(name: str):
    spec = importlib.util.spec_from_file_location(
        f"case15_{name}", os.path.join(CASE_15, f"{name}.py"))
    module = importlib.util.module_from_spec(spec)
    sys.modules[f"case15_{name}"] = module
    spec.loader.exec_module(module)
    return module


inv = _load15("inventory")
c12, arm_a, arm_b, arm_c = inv.c12, inv.arm_a, inv.arm_b, inv.arm_c
sel = inv.sel

TARGET = inv.TARGET


@dataclass(frozen=True)
class Path:
    """One way work can arrive at an authority. The hops are what an operator
    reads; the signature is what a diff compares."""

    arm: str
    work: str
    via: str
    authority: str

    def signature(self) -> Tuple[str, str, str, str]:
        return (self.arm, self.work, self.via, self.authority)

    def describe(self) -> str:
        return f"{self.work} --{self.via}--> {self.authority}"


# ---------------------------------------------------------------------------
# Arm A - work reaches authority through the subject it runs as.
# ---------------------------------------------------------------------------

def actual_a(target: str = TARGET) -> List[Path]:
    return [Path("A", f"stage {stage}", f"subject {subject}", target)
            for stage, subject in arm_a.SUBJECT_OF_STAGE.items()
            if arm_a.may(subject, target, arm_a.READ)]


def potential_a(target: str = TARGET) -> List[Path]:
    """Any stage can be pointed at any subject - the assignment is ordinary
    configuration - so every identity that already holds the authority is a
    path for every stage."""
    holders = [s for s in arm_a.PERMISSIONS
               if arm_a.may(s, target, arm_a.READ)]
    return [Path("A", f"stage {stage}", f"could run as {holder}", target)
            for stage in arm_a.SUBJECT_OF_STAGE for holder in holders]


# ---------------------------------------------------------------------------
# Arm B - work reaches authority through the credential its step names.
# ---------------------------------------------------------------------------

def actual_b(target: str = TARGET) -> List[Path]:
    out = []
    for name, step in arm_b.WORKFLOW.items():
        scope = arm_b.CONNECTIONS.get(step.connection, set())
        if target in step.inputs and target in scope:
            out.append(Path("B", f"step {name}", f"connection {step.connection}",
                            target))
    return out


def potential_b(target: str = TARGET) -> List[Path]:
    """A step could be rebound to any credential - but only a credential that
    also covers the step's own legitimate inputs and output is a usable path.
    Rebinding to one that does not breaks the step, which is exactly what case
    15 measured, so requiring the cover is what makes this view honest rather
    than alarmist."""
    out = []
    for name, step in arm_b.WORKFLOW.items():
        needed = set(step.inputs) | ({step.output} if step.output else set())
        for conn, scope in arm_b.CONNECTIONS.items():
            if target in scope and needed <= scope:
                out.append(Path("B", f"step {name}", f"could use {conn}",
                                target))
    return out


# ---------------------------------------------------------------------------
# Arm C - work reaches authority through the transformation its type requires.
# ---------------------------------------------------------------------------

def _types_bound_to(target: str) -> Set[str]:
    from object_model import evaluator
    obj = arm_c._state["obj"]
    binding = evaluator.artifact_map(obj, arm_c._state["ledger"])
    return {t for t, key in binding.items() if key == target}


def actual_c(target: str = TARGET) -> List[Path]:
    from object_model import evaluator, skills
    obj = arm_c._state["obj"]
    try:
        skill_name = evaluator.required_skill(obj)
    except Exception:                                     # noqa: BLE001
        return []
    skill = skills.REGISTRY.get(skill_name)
    if not skill:
        return []
    if set(skill.reads) & _types_bound_to(target):
        return [Path("C", f"object {obj.object_id} as {obj.object_type}",
                     f"skill {skill_name}", target)]
    return []


def potential_c(target: str = TARGET) -> List[Path]:
    """An object can be retyped - the type is ordinary persisted state - so
    every object type whose required transformation reads a type bound to the
    target is a path for every object."""
    from object_model import evaluator, skills
    bound = _types_bound_to(target)
    out = []
    for (object_type, state), skill_name in evaluator.TRANSITIONS.items():
        skill = skills.REGISTRY.get(skill_name)
        if skill and set(skill.reads) & bound:
            out.append(Path("C", "any object",
                            f"could be typed {object_type} -> {skill_name}",
                            target))
    return out


VIEWS = {
    "A": (actual_a, potential_a),
    "B": (actual_b, potential_b),
    "C": (actual_c, potential_c),
}


def snapshot(arm: str, which: str = "actual") -> Set[Tuple[str, str, str, str]]:
    actual, potential = VIEWS[arm]
    fn = actual if which == "actual" else potential
    return {p.signature() for p in fn()}


# ---------------------------------------------------------------------------
# The measurement: does a reachability diff see what an inventory diff missed?
# ---------------------------------------------------------------------------

@dataclass
class Detection:
    arm: str
    exposure_at_rest: int
    inventory_changed: bool
    reachability_changed: bool
    new_paths: List[str]


def measure(store_dir: str) -> List[Detection]:
    """Run case 15's *invisible* attack in each arm and compare both views."""
    out: List[Detection] = []

    # -- arm A ------------------------------------------------------------
    arm_a.reset()
    before_inv, before_reach = inv.inventory_a(), snapshot("A")
    exposure = len(snapshot("A", "potential"))
    arm_a.mutate_subject_assignment(TARGET)
    after = snapshot("A")
    out.append(Detection("A", exposure, inv.inventory_a() != before_inv,
                         after != before_reach,
                         sorted(f"{w} --{v}--> {k}" for _, w, v, k
                                in after - before_reach)))
    arm_a.reset()

    # -- arm B ------------------------------------------------------------
    arm_b.reset()
    arm_b.CONNECTIONS[sel.OVERSCOPED] = set(
        arm_b.CONNECTIONS[arm_b.CONN_ORDERS]) | {TARGET}
    before_inv, before_reach = inv.inventory_b(), snapshot("B")
    exposure = len(snapshot("B", "potential"))
    sel._write_step_record(sel.OVERSCOPED)
    after = snapshot("B")
    out.append(Detection("B", exposure, inv.inventory_b() != before_inv,
                         after != before_reach,
                         sorted(f"{w} --{v}--> {k}" for _, w, v, k
                                in after - before_reach)))
    arm_b.reset()

    # -- arm C ------------------------------------------------------------
    arm_c.reset(os.path.join(store_dir, "c"))
    inv._install_rotation_skill()
    before_inv, before_reach = inv.inventory_c(), snapshot("C")
    exposure = len(snapshot("C", "potential"))
    arm_c._state["obj"].object_type = inv.ROTATION_TYPE
    after = snapshot("C")
    out.append(Detection("C", exposure, inv.inventory_c() != before_inv,
                         after != before_reach,
                         sorted(f"{w} --{v}--> {k}" for _, w, v, k
                                in after - before_reach)))

    return out


def exposure_report(store_dir: str) -> Dict[str, Tuple[int, int]]:
    """(potential, actual) per arm, at rest, with the pre-existing authority
    present and nothing yet attacked. This is the audit product."""
    report: Dict[str, Tuple[int, int]] = {}

    arm_a.reset()
    report["A"] = (len(snapshot("A", "potential")), len(snapshot("A")))

    arm_b.reset()
    arm_b.CONNECTIONS[sel.OVERSCOPED] = set(
        arm_b.CONNECTIONS[arm_b.CONN_ORDERS]) | {TARGET}
    report["B"] = (len(snapshot("B", "potential")), len(snapshot("B")))
    arm_b.reset()

    arm_c.reset(os.path.join(store_dir, "exposure"))
    inv._install_rotation_skill()
    report["C"] = (len(snapshot("C", "potential")), len(snapshot("C")))

    return report
