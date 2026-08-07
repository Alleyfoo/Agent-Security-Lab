"""Step A end state. Boring on purpose.

    python demo_reservation/run_a.py [n]

The numbers are not interesting yet. Correct mechanics are.
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from demo_reservation import (  # noqa: E402
    Runtime, Store, check, default_world, generate_requests, straight_through,
)


def run(n: int = 1000):
    world = default_world()
    store = Store()
    requests = generate_requests(n, world)
    for request in requests:
        store.requests[request.request_id] = request

    runtime = Runtime(store=store, world=world)
    queue = straight_through(requests)
    runtime.run_all(queue)

    report = check(store.schedule(), world)
    return runtime, report, queue


if __name__ == "__main__":
    n = int(sys.argv[1]) if len(sys.argv) > 1 else 1000
    runtime, report, queue = run(n)
    summary = runtime.summary()

    print(f"{summary['requests']} requests submitted")
    print()
    print(f"{summary['booked']:>6d} booked")
    print(f"{summary['refused']:>6d} refused")
    if summary["pending"]:
        print(f"{summary['pending']:>6d} STILL PENDING")
    print()
    print("schedule invariants:")
    print(f"    {report.summary()}")
    if not report.ok:
        for invariant, violations in sorted(report.by_invariant().items()):
            print(f"    {invariant}: {violations[0].detail}")
    print()
    print(f"queue:  {'empty' if len(runtime.receipts) == len(queue) else 'INCOMPLETE'}")
    print(f"unauthorised transitions: {summary['refused_transitions']}")
    print()
    print("skill calls:")
    for name, count in summary["skill_calls"].items():
        print(f"    {name:<22s} {count}")
    booked = summary["booked"]
    if booked:
        print(f"\n{summary['total_skill_calls'] / booked:.2f} skill calls "
              "per completed reservation")
    raise SystemExit(0)
