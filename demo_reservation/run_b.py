"""Step B end state. Damage reality, name the blast radius, stop.

    python demo_reservation/run_b.py [n] [kind]

No recovery is attempted and none is possible - step C does not exist yet.
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from demo_reservation import check  # noqa: E402
from demo_reservation import disrupt  # noqa: E402
from demo_reservation.run_a import run as run_a  # noqa: E402


def run(n: int = 1000, kind: str = None, seed: int = 5150):
    runtime, before, _queue = run_a(n)
    disruption = disrupt.draw(runtime.world, runtime.store, kind=kind,
                              seed=seed)
    after = check(runtime.store.schedule(), runtime.world)
    return runtime, before, disruption, after


if __name__ == "__main__":
    n = int(sys.argv[1]) if len(sys.argv) > 1 else 1000
    kind = sys.argv[2] if len(sys.argv) > 2 else None

    runtime, before, disruption, after = run(n, kind)

    print(f"schedule before:\n    {before.summary()}")
    print()
    if disruption is None:
        print("disruption:\n    none drawn")
        raise SystemExit(0)

    print(f"disruption:\n    {disruption.describe()}")
    print()
    print(f"affected reservations:\n    {len(disruption.affected)}")
    print()
    print(f"schedule after:\n    {after.summary()}")
    for invariant, violations in sorted(after.by_invariant().items()):
        print(f"    {invariant}: {len(violations)}  e.g. {violations[0].detail}")
    print()

    claimed = disrupt.claimed_damage(disruption)
    observed = after.reservation_ids()
    agree = claimed == observed
    print("cross-check (the checker decides, not the generator):")
    print(f"    generator says damaged:  {len(claimed)}"
          + (f"  ({len(disruption.affected)} existing + "
             f"{len(disruption.introduced)} introduced)"
             if disruption.introduced else ""))
    print(f"    checker says violating:  {len(observed)}")
    print(f"    agree: {agree}")
    if not agree:
        print(f"    only generator: {sorted(claimed - observed)[:5]}")
        print(f"    only checker:   {sorted(observed - claimed)[:5]}")
    print()
    print("recovery attempts:\n    0")
    raise SystemExit(0)
