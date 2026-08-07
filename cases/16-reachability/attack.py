"""Case 16 - audit authority reachability, not only the inventory.

Run it:

    python cases/16-reachability/attack.py

Case 15's finding was that all three models converge: once useful authority
exists, the attacker changes what points at it and the standing inventory does
not move. An audit asking "did anybody gain new permissions?" answers no while
effective access has changed completely.

This builds the missing middle question - **what can currently reach it** - and
measures two things:

  1. at rest, does the view flag the exposure an inventory calls legitimate?
  2. under case 15's invisible attack, does a reachability diff detect what an
     inventory diff missed?

Same adversary throughout: Level 1.5, the configuration adversary.
"""

from __future__ import annotations

import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import reach  # noqa: E402

QUESTION = {
    "A": "this identity is legitimate, but these stages could run as it",
    "B": "this credential is legitimate, but these steps could use it",
    "C": "this skill is approved, but these object types can cause it to run",
}


def show_exposure(store_dir: str) -> None:
    print("\n--- At rest: what could reach the authority, before any attack ---")
    report = reach.exposure_report(store_dir)
    for arm in ("A", "B", "C"):
        potential, actual = report[arm]
        print(f"\n  arm {arm}: {QUESTION[arm]}")
        print(f"      paths in effect now      {actual}")
        print(f"      paths one binding away   {potential}")
        if actual == 0 and potential:
            unit = "piece" if potential == 1 else "pieces"
            print(f"      -> nothing is wrong today, and {potential} {unit} of "
                  "ordinary work is one")
            print("         configuration change from this authority")


if __name__ == "__main__":
    print("Three questions, not one:")
    print("    what authority exists?        (the inventory - case 15)")
    print("    what can currently reach it?  (this case)")
    print("    what does that combination permit?")

    with tempfile.TemporaryDirectory() as tmp:
        show_exposure(os.path.join(tmp, "rest"))
        detections = reach.measure(os.path.join(tmp, "attack"))

        print("\n--- Under case 15's invisible attack ---")
        for det in detections:
            print(f"\n  arm {det.arm}")
            print(f"      inventory diff      "
                  f"{'sees it' if det.inventory_changed else 'sees NOTHING'}")
            print(f"      reachability diff   "
                  f"{'SEES IT' if det.reachability_changed else 'sees nothing'}")
            for path in det.new_paths:
                print(f"          new path: {path}")

        print("\n=== RESULT ===")
        print(f"{'arm':>4s}  {'exposure at rest':>17s}  "
              f"{'inventory diff':>15s}  {'reachability diff':>18s}")
        for det in detections:
            print(f"{det.arm:>4s}  {det.exposure_at_rest:>17d}  "
                  f"{('sees it' if det.inventory_changed else 'blind'):>15s}  "
                  f"{('detects' if det.reachability_changed else 'blind'):>18s}")

        blind = [d for d in detections if not d.inventory_changed]
        caught = [d for d in detections if d.reachability_changed]
        print()
        print(f"The inventory diff is blind in {len(blind)} of "
              f"{len(detections)} arms.")
        print(f"The reachability diff detects in {len(caught)} of "
              f"{len(detections)}.")
        print()
        print("And the more useful half is the first table, not this one: in")
        print("every arm the exposure was visible *at rest*, before anything")
        print("was attacked, in a deployment where an inventory audit reports")
        print("nothing wrong.")
    raise SystemExit(0)
