"""Case 14 - enumerate the pivots.

Run it:

    python cases/14-selector-map/attack.py

Case 13 found one premise that looks independent and is not. This does not look
for another; it enumerates what selects every authority premise in all three
arms, marks which selectors the Level 1.5 adversary can alter, and then
*executes* every shared-selector pivot, because a map of claimed dependencies
that nobody ran is prose.

Same adversary, same target, same workflow position as cases 12 and 13.
"""

from __future__ import annotations

import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import selectors as s  # noqa: E402


def show_map() -> None:
    print("\n--- What selects each authority premise ---")
    for arm in ("A", "B", "C"):
        print(f"\n  arm {arm}")
        for premise in s.PREMISES:
            if premise.arm != arm:
                continue
            marks = ", ".join(
                f"{sel}{'*' if s.ALTERABLE.get(sel) else ''}"
                for sel in premise.selectors)
            print(f"      {premise.name}")
            print(f"          stored in  {premise.stored_in}")
            print(f"          keyed by   {marks}")
    print("\n  * = the Level 1.5 adversary can alter this selector")


def show_shared() -> None:
    print("\n--- Alterable selectors reaching more than one premise ---")
    for arm, selector, names in s.shared_selectors():
        print(f"\n  arm {arm}: {selector}")
        for name in names:
            print(f"      moves: {name}")


def run_pivots(store_dir: str):
    print("\n--- Every shared selector, pivoted ---")
    pivots = s.build_pivots(store_dir)
    for pivot in pivots:
        pivot.obtained, pivot.moved = pivot.run()
        mark = "!!" if pivot.obtained else "  "
        print(f"\n   {mark} arm {pivot.arm}: {pivot.selector}")
        print(f"        edit      {pivot.edit}")
        print(f"        moved     {pivot.moved}")
        print(f"        result    "
              f"{'OBTAINED in 1 edit' if pivot.obtained else 'no'}")
        print(f"        why       {pivot.why}")
    return pivots


if __name__ == "__main__":
    print("Independent records are not independent premises.")
    print("This enumerates the difference instead of finding another example.")

    show_map()
    show_shared()
    with tempfile.TemporaryDirectory() as tmp:
        pivots = run_pivots(tmp)

    print("\n=== RESULT ===")
    print(f"{'arm':>4s}  {'selector':<44s} {'pivots?':>8s}")
    for pivot in pivots:
        print(f"{pivot.arm:>4s}  {pivot.selector:<44s} "
              f"{('YES' if pivot.obtained else 'no'):>8s}")

    winners = [p for p in pivots if p.obtained]
    print()
    print(f"{len(winners)} of {len(pivots)} shared selectors yield the "
          f"capability in one edit.")
    print()
    print("The ones that do not are instructive in different ways:")
    print("  - arm A stage-keyed: the selector is not attacker-alterable.")
    print("  - arm B ordinary tenant: the pivot exists, and fails closed")
    print("    because no credential holds both the legitimate inputs and")
    print("    the target. That is an inventory property, not architecture -")
    print("    the over-scoped row measures what happens when it is absent.")
    print("  - arm C object id: selects the bindings and finds nothing.")
    print("  - arm C object type: the pivot MOVED a premise and still lost,")
    print("    because the skill contract is keyed on something else. This")
    print("    is the clearest measured example of independent *selection*.")
    print()
    print("A premise is independent when no alterable selector reaches it")
    print("and another. Counting records does not tell you that.")
    raise SystemExit(0)
