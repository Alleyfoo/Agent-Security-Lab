"""Step C end state: local resolution, judged by an oracle it cannot see.

    python demo_reservation/run_c.py [n] [kind]

The agents get `find_alternative` and `move_reservation` and nothing else. They
process the damaged set in the order it comes. When no candidate is found the
request becomes `unresolved` - which is a state, not a decision about who
should look at it.

Afterwards two independent things judge the run:

    invariants.check   is the resulting schedule valid at all?
    oracle.classify    did the unresolved ones have to be unresolved?

Nothing here is tuned after seeing the answer.
"""

from __future__ import annotations

import os
import sys
from copy import deepcopy

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from demo_reservation import QueueItem, check, disrupt, oracle  # noqa: E402
from demo_reservation.objects import UNRESOLVED  # noqa: E402
from demo_reservation.run_b import run as run_b  # noqa: E402


def recover(runtime, damaged_ids):
    """One pass over the damaged set. Two skills, no coordination."""
    queue = []
    for reservation_id in damaged_ids:
        reservation = runtime.store.reservations.get(reservation_id)
        if reservation is None:
            continue
        request_id = reservation.request_id
        if request_id not in runtime.store.requests:
            continue                       # the priority block has no request
        queue.append(QueueItem(request_id, "find_alternative"))
        queue.append(QueueItem(request_id, "move_reservation"))
    runtime.run_all(queue)
    return queue


def run(n: int = 1000, kind: str = None, seed: int = 5150):
    runtime, before, disruption, after = run_b(n, kind, seed)
    if disruption is None:
        return None

    damaged = disrupt.claimed_damage(disruption)
    # The evaluator's snapshot, taken before the agents touch anything.
    survivors_at_start = [deepcopy(r) for r in runtime.store.schedule()
                          if r.reservation_id not in damaged]
    damaged_at_start = [deepcopy(r) for r in runtime.store.schedule()
                        if r.reservation_id in damaged]

    queue = recover(runtime, sorted(damaged))

    final = check(runtime.store.schedule(), runtime.world)
    unresolved_ids = {
        r.reservation_id for r in runtime.store.schedule()
        if r.reservation_id in damaged
        and runtime.store.requests.get(r.request_id) is not None
        and runtime.store.requests[r.request_id].state == UNRESOLVED
    }
    unresolved = [r for r in runtime.store.schedule()
                  if r.reservation_id in unresolved_ids]
    survivors_now = [r for r in runtime.store.schedule()
                     if r.reservation_id not in unresolved_ids]

    outcome = oracle.classify(damaged_at_start, survivors_at_start,
                              unresolved, survivors_now, runtime.world)
    return {
        "runtime": runtime, "disruption": disruption, "damaged": damaged,
        "queue": queue, "final": final, "unresolved": unresolved_ids,
        "outcome": outcome,
        "recovered": len(damaged) - len(unresolved_ids) - len(
            disruption.introduced),
    }


if __name__ == "__main__":
    n = int(sys.argv[1]) if len(sys.argv) > 1 else 1000
    kind = sys.argv[2] if len(sys.argv) > 2 else None
    out = run(n, kind)
    if out is None:
        print("no disruption drawn")
        raise SystemExit(0)

    d, outcome = out["disruption"], out["outcome"]
    damaged = len(out["damaged"]) - len(d.introduced)

    print(f"disruption:\n    {d.describe()}")
    print()
    print(f"{damaged} reservations disrupted")
    print()
    print(f"{out['recovered']:>6d} recovered locally")
    print(f"{len(out['unresolved']):>6d} unresolved")
    print()
    if out["unresolved"]:
        print(f"of {len(out['unresolved'])} unresolved:")
        print(f"    {len(outcome.genuinely_impossible):>4d} genuinely impossible")
        print(f"    {len(outcome.false_escalations):>4d} false escalations")
        print(f"    {len(outcome.dead_ends):>4d} self-created dead ends")
        if outcome.undecided:
            print(f"    {len(outcome.undecided):>4d} undecided "
                  "(oracle budget exhausted)")
        print()
        print(f"    oracle: initial={outcome.initial.answer} "
              f"current={outcome.current.answer}")
    print()
    print(f"final schedule:\n    {out['final'].summary()}")
    print()
    calls = out["runtime"].skill_calls
    print("skill calls:")
    for name in sorted(calls):
        print(f"    {name:<22s} {calls[name]}")
    raise SystemExit(0)
