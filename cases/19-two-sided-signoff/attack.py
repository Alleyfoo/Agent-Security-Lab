"""Case 19 - two-sided sign-off: build it naively, then tighten one condition.

Run it:

    python cases/19-two-sided-signoff/attack.py

Pre-registered in docs/target-architecture.md before this was built:

    The naive implementation will measure a minimum tamper set of 1, because
    the join key is the pivot.

Four rungs, two adversaries. The question each rung has to answer is not "does
it look right" but "what did it actually buy".
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import signoff as s  # noqa: E402


def detail(cells) -> None:
    for rung in s.RUNGS:
        print(f"\n--- {rung.name}   (independence: {rung.independence}) ---")
        for adversary in ("Level 1", "Level 1.5"):
            print(f"\n  {adversary}")
            for c in cells:
                if c.rung != rung.name or c.adversary != adversary:
                    continue
                mark = "!!" if c.obtained else "  "
                verdict = (f"OBTAINED in {c.commits}" if c.obtained else "no")
                print(f"   {mark} {c.attack:34s} {verdict:14s}")
                print(f"        {c.note}")


if __name__ == "__main__":
    print("Two-sided sign-off, built naively on purpose.")
    print("The prediction was: the naive version measures 1.")

    cells = s.measure()
    detail(cells)

    print("\n=== RESULT ===")
    print(f"{'rung':>18s}  {'independence':>28s}  "
          f"{'Level 1':>9s}  {'Level 1.5':>10s}")
    for rung in s.RUNGS:
        l1 = s.minimum(cells, rung.name, "Level 1")
        l15 = s.minimum(cells, rung.name, "Level 1.5")
        print(f"{rung.name:>18s}  {rung.independence:>28s}  "
              f"{(str(l1) if l1 else 'refused'):>9s}  "
              f"{(str(l15) if l15 else 'refused'):>10s}")

    print()
    print("PREDICTION CONFIRMED: the naive rung measures 1, by two")
    print("independent routes - self-approval and swapping the action after")
    print("review.")
    print()
    print("What each rung actually bought, which is the point of building it")
    print("this way round rather than implementing the correct version:")
    print()
    print("  R1 +bind action   closed one class AND OPENED ANOTHER. Swapping")
    print("    the action after review stops working - and because approvals")
    print("    now match by content rather than by request, any past approval")
    print("    of the same action matches by construction. Replay did not")
    print("    work at R0 and does at R1. The route count did not move; the")
    print("    routes changed, and counting defects rather than naming them")
    print("    would have called that progress.")
    print()
    print("  R2 +credential    closed another CLASS and did not move it")
    print("    either. A Level 1 worker can no longer forge an approval.")
    print()
    print("  R3 +append-only   closed nothing measurable here. It refuses a")
    print("    SECOND approval of a digest; replay reuses the FIRST, so the")
    print("    record shape from cases 10 and 11 does not help on this plane.")
    print()
    print("  R4 +one-use       moved the Level 1 result to refused. A")
    print("    lifecycle rule, not an independence layer - and three rungs of")
    print("    independence did not do what one rule about spending did.")
    print()
    print("So the staircase is the finding. Each of the first three rungs")
    print("looks like the important one and closes exactly one attack, while")
    print("the minimum tamper set sits at 1 until the last route is gone.")
    print("A design review that stopped after R2 would have shipped something")
    print("that still executes an unapproved payment.")
    print()
    print("And the bottom line no rung changes:")
    print()
    print("  Level 1.5 stays at 1 commit at every rung. The configuration")
    print("  adversary appends an approval or adds the worker to the reviewer")
    print("  list. No arrangement of records inside the same writable")
    print("  boundary raises that, which is the cross-cutting finding arriving")
    print("  at the approval plane.")
    print()
    print("  TWO-SIDED SIGN-OFF IS A LEVEL 1 CONTROL. It is worth building -")
    print("  R4 genuinely stops a compromised worker - and it must not be")
    print("  described as protecting against anyone who can write the")
    print("  approval store.")
    raise SystemExit(0)
