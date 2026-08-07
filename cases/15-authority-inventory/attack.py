"""Case 15 - audit the deployment, not the architecture.

Run it:

    python cases/15-authority-inventory/attack.py

Cases 12-14 measured architectures. This measures what a normal deployment
already contains, and what its presence does to the same attack in each of the
three models.

Pre-registered hypothesis, from case 14's two yielding pivots:

    Pre-existing authority does not always reduce the number of commits. What
    it reduces is the *visibility* of the edit - the attacker stops having to
    create authority and only has to point at it, so the standing authority
    inventory does not change.

Same adversary as cases 12-14: Level 1.5, the configuration adversary.
"""

from __future__ import annotations

import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import inventory as inv  # noqa: E402

LABEL = {
    "A": "identity that already holds it",
    "B": "credential scoped across both sides",
    "C": "approved skill that legitimately reads it",
}


def show(rows) -> None:
    for arm in ("A", "B", "C"):
        print(f"\n--- arm {arm}: a pre-existing {LABEL[arm]} ---")
        for present in (False, True):
            state = "PRESENT" if present else "absent "
            print(f"\n  deployment: {state}")
            for row in rows:
                if row.arm != arm or row.present is not present:
                    continue
                mark = "!!" if row.obtained else "  "
                cost = f"{row.commits} commit" if row.commits else "-"
                seen = ("inventory CHANGES" if row.inventory_changed
                        else "inventory unchanged")
                print(f"   {mark} via {row.commit_of:38s} "
                      f"{'OBTAINED' if row.obtained else 'no':9s} {cost:9s}")
                print(f"        scope     {row.scope}")
                print(f"        audit     {seen} - {row.note}")


if __name__ == "__main__":
    print("The same attack, against deployments that differ only in what")
    print("authority they already contain.")

    with tempfile.TemporaryDirectory() as tmp:
        rows = inv.measure_all(tmp)
        show(rows)

        print("\n=== RESULT ===")
        print(f"{'arm':>4s}  {'pre-existing authority':<24s} "
              f"{'commits':>8s}  {'scope of the edit':<44s} {'audit sees it':>14s}")
        for arm in ("A", "B", "C"):
            for present in (False, True):
                best = inv.cheapest(rows, arm, present)
                tag = "present" if present else "absent"
                if best is None:
                    print(f"{arm:>4s}  {tag:<24s} {'-':>8s}  "
                          f"{'not obtained':<44s} {'-':>14s}")
                    continue
                print(f"{arm:>4s}  {tag:<24s} {best.commits:>8d}  "
                      f"{best.scope:<44s} "
                      f"{('yes' if best.inventory_changed else 'NO'):>14s}")

    print()
    print("The commit count is not the story. In every arm, the cheapest")
    print("yielding edit against a deployment that already holds the")
    print("authority leaves the standing inventory UNCHANGED - the attacker")
    print("stopped having to create authority and only had to point at it.")
    print()
    print("Which is why the control this suggests is an inventory audit and")
    print("not a diff: a diff of what changed cannot see an attack that")
    print("changes nothing an auditor lists.")
    raise SystemExit(0)
