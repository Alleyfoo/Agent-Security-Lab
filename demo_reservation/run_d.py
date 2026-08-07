"""Step D: displacing a confirmed reservation needs a second authority.

    python demo_reservation/run_d.py [n] [kind]

Two profiles, and the comparison between them is the point:

    legacy      the worker still holds `move_reservation`
    protected   the worker holds propose only; the gate holds the move

The legacy profile is not a strawman. It is what step C shipped, and case 22
is the reason it is measured rather than assumed away: **a boundary is only as
narrow as the transformations it exports.** Adding a protected path while the
unprotected verb is still in the worker's hands protects nothing.
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from demo_reservation import QueueItem, check, disrupt, signoff  # noqa: E402
from demo_reservation.run_b import run as run_b  # noqa: E402

LEGACY = {"check_availability", "create_reservation", "cancel_reservation",
          "query_schedule", "find_alternative", "move_reservation",
          "propose_displacement", "execute_displacement"}
PROTECTED = {"check_availability", "create_reservation", "cancel_reservation",
             "query_schedule", "find_alternative", "propose_displacement",
             "execute_displacement"}


def recover(runtime, damaged_ids, reviewer_approves=True, use_legacy=False):
    """One pass. The worker proposes; a reviewer approves; the gate executes."""
    moved = 0
    for reservation_id in sorted(damaged_ids):
        reservation = runtime.store.reservations.get(reservation_id)
        if reservation is None:
            continue
        request = runtime.store.requests.get(reservation.request_id)
        if request is None:
            continue

        runtime.run(QueueItem(request.request_id, "find_alternative"))
        if request.candidate is None:
            continue

        if use_legacy:
            result = runtime.run(QueueItem(request.request_id,
                                           "move_reservation"))
            moved += bool(result and result.ok)
            continue

        runtime.run(QueueItem(request.request_id, "propose_displacement"))
        if reviewer_approves:
            action = signoff.displacement_for(
                reservation, request.candidate, request.version)
            runtime.signoff.approve(signoff.REVIEWER, action.digest())
        result = runtime.run(QueueItem(request.request_id,
                                       "execute_displacement"))
        moved += bool(result and result.ok)
    return moved


def run(n=1000, kind="facility_closed", profile="protected",
        reviewer_approves=True, seed=5150):
    runtime, _before, disruption, _after = run_b(n, kind, seed)
    if disruption is None:
        return None
    runtime.signoff = signoff.SignoffStore()
    runtime.worker_skills = LEGACY if profile == "legacy" else PROTECTED

    damaged = disrupt.claimed_damage(disruption)
    moved = recover(runtime, damaged, reviewer_approves,
                    use_legacy=(profile == "legacy"))
    return {
        "runtime": runtime, "disruption": disruption, "damaged": damaged,
        "moved": moved, "final": check(runtime.store.schedule(), runtime.world),
    }


if __name__ == "__main__":
    n = int(sys.argv[1]) if len(sys.argv) > 1 else 1000
    kind = sys.argv[2] if len(sys.argv) > 2 else "facility_closed"

    print("Displacing a confirmed reservation is a protected transformation.")
    print("Creating a new one is not. The rule is attached to the kind of")
    print("transformation, not to a risk score.\n")

    for label, profile, approves in (
            ("protected, reviewer approves", "protected", True),
            ("protected, no approval", "protected", False),
            ("legacy: worker still holds move_reservation", "legacy", True)):
        out = run(n, kind, profile, approves)
        rt = out["runtime"]
        damaged = len(out["damaged"]) - len(out["disruption"].introduced)
        print(f"--- {label} ---")
        print(f"    {damaged} disrupted, {out['moved']} displaced")
        print(f"    final schedule: {out['final'].summary()}")
        print(f"    refused by skill set: {rt.refused_transitions}")
        if rt.signoff:
            print(f"    proposals {len(rt.signoff.proposals)}  "
                  f"approvals {len(rt.signoff.approvals)}  "
                  f"executed {len(rt.signoff.executed)}")
        print()

    print("The legacy row is the finding, and case 22 predicted it:")
    print("a protected path is worth nothing while the unprotected verb is")
    print("still exported to the worker. A boundary is only as narrow as the")
    print("transformations it exports.")
    raise SystemExit(0)
