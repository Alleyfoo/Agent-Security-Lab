"""Case 13 - does a second independent premise raise the cost?

Run it:

    python cases/13-second-premise/attack.py

The prediction was pre-registered in cases/REPORT.md before this was built:

    If the principle is architectural rather than incidental to arm B, then
    adding a second independent premise to arm A or arm C should raise that
    arm's minimum tamper set to 2 - without changing which model it is.

Same attacker as case 12, same target, same workflow position. The only change
is one added premise per arm, layered onto case 12's frozen arms.
"""

from __future__ import annotations

import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import premise as p  # noqa: E402

TARGET = p.TARGET
STAGE = p.STAGE


def _row(label: str, edits: int, obtained: bool, detail: str = "") -> tuple:
    mark = "!!" if obtained else "  "
    print(f"   {mark} {label:44s} {edits} edit(s)  "
          f"{'OBTAINED' if obtained else 'no':9s}")
    if detail:
        print(f"        {detail}")
    return edits, obtained


def arm_a_baseline() -> int:
    """Case 12's number, reproduced so the delta is visible here."""
    print("\n--- Arm A, one premise (case 12) ---")
    cells = []
    for surface in p.arm_a.surfaces():
        p.arm_a.reset()
        detail = p.arm_a.MUTATIONS[surface](TARGET)
        obtained = p.arm_a.resolve(STAGE).permits_read(TARGET)
        cells.append(_row(surface, 1, obtained, detail))
    p.arm_a.reset()
    return p.minimum_tamper_set(cells)


def arm_a_with_premise(variant: str) -> int:
    print(f"\n--- Arm A, two premises: DAC + label policy [{variant}] ---")
    cells = []

    p.reset_arm_a()
    d = p.arm_a.mutate_permission_table(TARGET)
    cells.append(_row("widen the permission table only", 1,
                      p.resolve_arm_a(STAGE, variant).permits_read(TARGET), d))

    p.reset_arm_a()
    d = p.mutate_a_label_policy(TARGET)
    cells.append(_row("widen the label policy only", 1,
                      p.resolve_arm_a(STAGE, variant).permits_read(TARGET), d))

    p.reset_arm_a()
    d = p.arm_a.mutate_subject_assignment(TARGET)
    cells.append(_row("reassign the subject only", 1,
                      p.resolve_arm_a(STAGE, variant).permits_read(TARGET), d))

    p.reset_arm_a()
    p.arm_a.mutate_permission_table(TARGET)
    p.mutate_a_label_policy(TARGET)
    cells.append(_row("widen both", 2,
                      p.resolve_arm_a(STAGE, variant).permits_read(TARGET)))

    p.reset_arm_a()
    return p.minimum_tamper_set(cells)


def arm_c_baseline(tmp: str) -> int:
    print("\n--- Arm C, one premise (case 12) ---")
    cells = []
    for index, surface in enumerate(("artifact binding record",
                                     "skill contract")):
        p.arm_c.reset(os.path.join(tmp, f"base{index}"))
        detail = p.arm_c.MUTATIONS[surface](TARGET)
        obtained = p.arm_c.resolve(STAGE).permits_read(TARGET)
        cells.append(_row(surface, 1, obtained, detail))
    return p.minimum_tamper_set(cells)


def arm_c_with_declares(tmp: str) -> int:
    """One added premise: artifacts declare what they are."""
    print("\n--- Arm C, two premises: binding + artifact declaration ---")
    cells = []

    p.reset_arm_c(os.path.join(tmp, "d0"))
    d = p.arm_c.mutate_artifact_binding(TARGET)
    cells.append(_row("overwrite the binding only", 1,
                      p.resolve_arm_c(STAGE, use_type_policy=False)
                      .permits_read(TARGET), d))

    p.reset_arm_c(os.path.join(tmp, "d1"))
    d = p.arm_c.mutate_skill_contract(TARGET)
    cells.append(_row("widen the skill contract only", 1,
                      p.resolve_arm_c(STAGE, use_type_policy=False)
                      .permits_read(TARGET), d))

    p.reset_arm_c(os.path.join(tmp, "d2"))
    p.arm_c.mutate_artifact_binding(TARGET)
    p.mutate_c_declaration(TARGET)
    cells.append(_row("overwrite the binding + rewrite the declaration", 2,
                      p.resolve_arm_c(STAGE, use_type_policy=False)
                      .permits_read(TARGET)))

    return p.minimum_tamper_set(cells)


def arm_c_with_both(tmp: str) -> int:
    """Both added premises: one per authority surface that yields."""
    print("\n--- Arm C, three premises: + object-type read policy ---")
    cells = []

    p.reset_arm_c(os.path.join(tmp, "b0"))
    d = p.arm_c.mutate_artifact_binding(TARGET)
    cells.append(_row("overwrite the binding only", 1,
                      p.resolve_arm_c(STAGE).permits_read(TARGET), d))

    p.reset_arm_c(os.path.join(tmp, "b1"))
    d = p.arm_c.mutate_skill_contract(TARGET)
    cells.append(_row("widen the skill contract only", 1,
                      p.resolve_arm_c(STAGE).permits_read(TARGET), d))

    p.reset_arm_c(os.path.join(tmp, "b2"))
    p.arm_c.mutate_skill_contract(TARGET)
    p.mutate_c_type_policy(TARGET)
    cells.append(_row("widen the skill contract + the type policy", 2,
                      p.resolve_arm_c(STAGE).permits_read(TARGET)))

    p.reset_arm_c(os.path.join(tmp, "b3"))
    p.arm_c.mutate_artifact_binding(TARGET)
    p.mutate_c_declaration(TARGET)
    cells.append(_row("overwrite the binding + rewrite the declaration", 2,
                      p.resolve_arm_c(STAGE).permits_read(TARGET)))

    return p.minimum_tamper_set(cells)


if __name__ == "__main__":
    print("Testing the principle, not the architectures.")
    print("Prediction: a second independent premise raises the minimum")
    print("tamper set to 2, in any model.")

    with tempfile.TemporaryDirectory() as tmp:
        a_before = arm_a_baseline()
        a_subject = arm_a_with_premise(p.BY_SUBJECT)
        a_stage = arm_a_with_premise(p.BY_STAGE)
        c_before = arm_c_baseline(tmp)
        c_one = arm_c_with_declares(tmp)
        c_both = arm_c_with_both(tmp)

    print("\n=== RESULT ===")
    print(f"{'configuration':<48s} {'min tamper set':>14s}")
    rows = [
        ("A  permission table only (case 12)", a_before),
        (f"A  + label policy [{p.BY_SUBJECT}]", a_subject),
        (f"A  + label policy [{p.BY_STAGE}]", a_stage),
        ("C  binding + skill contract (case 12)", c_before),
        ("C  + artifact declaration", c_one),
        ("C  + artifact declaration + type policy", c_both),
    ]
    for label, value in rows:
        print(f"{label:<48s} {str(value):>14s}")

    print()
    print("The prediction holds only under two conditions the prediction did")
    print("not state:")
    print()
    print(f"  1. the premises must not share an index the attacker can pivot.")
    print(f"     Keying the domain on the subject leaves the minimum at "
          f"{a_subject}:")
    print("     reassigning the subject moves BOTH premises at once.")
    print(f"     Keying it on the stage gives {a_stage}.")
    print()
    print(f"  2. a premise is needed per authority surface, not per model.")
    print(f"     One premise left arm C at {c_one} because it closed the")
    print(f"     binding route and not the skill-contract route. Two gave "
          f"{c_both}.")
    raise SystemExit(0)
