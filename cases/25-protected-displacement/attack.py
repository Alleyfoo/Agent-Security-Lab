"""Case 25 - can a worker displace a confirmed reservation on its own say-so?

Run it:

    python cases/25-protected-displacement/attack.py

This is demo step D lifted into the case registry, because unlike steps A-C, E
and F it has the shape the registry is for: an adversary, a protected outcome,
a bypass route, and a tamper cost in the settled unit.

The legacy profile is not a strawman. It is exactly what step C shipped.
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(
    os.path.dirname(os.path.abspath(__file__)))))

from demo_reservation.run_d import run  # noqa: E402

N = 1000
KIND = "facility_closed"


def _row(label: str, profile: str, approves: bool):
    out = run(N, KIND, profile, approves)
    runtime = out["runtime"]
    damaged = len(out["damaged"]) - len(out["disruption"].introduced)
    approvals = len(runtime.signoff.approvals) if runtime.signoff else 0
    print(f"--- {label} ---")
    print(f"    {damaged} confirmed reservations disrupted")
    print(f"    {out['moved']} displaced   approvals recorded: {approvals}")
    print(f"    final schedule: {out['final'].summary()}")
    return out["moved"], approvals


if __name__ == "__main__":
    print("Protected transformation: modifying somebody's CONFIRMED")
    print("reservation. Creating a new one is not protected. The rule binds to")
    print("the KIND of transformation, not to a risk score.\n")

    moved_ok, approvals_ok = _row(
        "protected profile, reviewer approves", "protected", True)
    moved_no, approvals_no = _row(
        "protected profile, no approval", "protected", False)
    moved_legacy, approvals_legacy = _row(
        "legacy profile: worker still holds move_reservation",
        "legacy", True)

    print("\n=== RESULT ===")
    print(f"{'profile':<44}{'displaced':>10}{'approvals':>11}")
    print(f"{'protected, approved':<44}{moved_ok:>10}{approvals_ok:>11}")
    print(f"{'protected, unapproved':<44}{moved_no:>10}{approvals_no:>11}")
    print(f"{'legacy (step C as shipped)':<44}"
          f"{moved_legacy:>10}{approvals_legacy:>11}")

    assert moved_no == 0, "unapproved displacement must not occur"
    assert approvals_legacy == 0, "the legacy route must record no approval"
    assert moved_legacy > 0, "the legacy route must actually work"

    print("\nThe legacy row is the finding, and case 22 predicted it.")
    print("One authorised invocation of an exported verb - minimum tamper")
    print("cost 1, one independently committed state change, the reservation")
    print("record - displaces a confirmed reservation with no approval in")
    print("existence. Adding a protected path while the unprotected verb is")
    print("still in the worker's hands protects nothing.")
    print("\nA boundary is only as narrow as the transformations it exports.")
    raise SystemExit(0)
