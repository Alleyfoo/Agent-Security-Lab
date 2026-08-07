"""Case 22 - does the boundary survive persistence?

Run it:

    python cases/22-durable-state/attack.py

Case 21 moved the gate's code and left its durable state on a filesystem the
worker's uid could write. This tests the part that did not move, and attacks
DELETION as hard as insertion - because after cases 19 and 20 the store holds
security state, and a consumption record is what makes a spent approval spent.
"""

from __future__ import annotations

import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import store as s  # noqa: E402


if __name__ == "__main__":
    print("Durable gate authority: can the worker create, modify or delete it?")

    with tempfile.TemporaryDirectory() as tmp:
        results = s.measure(tmp)

        for arm in s.ARMS:
            print(f"\n--- {arm.name} ---")
            for r in results:
                if r.arm != arm.name:
                    continue
                mark = "!!" if r.succeeded else "  "
                print(f"   {mark} {r.attack:30s} "
                      f"{'SUCCEEDS' if r.succeeded else 'no':9s}")
                print(f"        {r.note}")

        print("\n=== RESULT ===")
        print(f"{'attack':>30s}  {'D0':>6s}  {'D1':>6s}  {'D2':>6s}")
        for name in s.ATTACK_NAMES:
            row = [s.get(results, arm, name) for arm in s.ARMS]
            print(f"{name:>30s}  " + "  ".join(
                f"{('YES' if r.succeeded else 'no'):>6s}" for r in row))

        d1 = [r for r in results if r.arm == s.D1.name and r.succeeded]
        d2 = [r for r in results if r.arm == s.D2.name and r.succeeded]

        print()
        print("D0 loses everything, including the two deletion attacks case 21")
        print("never ran. Resurrecting a spent approval is the one to notice:")
        print("one legitimate review, two executions, and nothing in cases 19")
        print("or 20 detects it because both of those trusted the record.")
        print()
        print(f"D1 refuses all four ({len(d1)} succeeded).")
        print()
        print(f"D2 refuses insertion and loses to deletion ({len(d2)} "
              "succeeded) -")
        print("through the protocol's own vocabulary. One ordinary maintenance")
        print("operation, of the kind every persistent store eventually grows,")
        print("drops the consumption records and the approval is live again.")
        print()
        print("SO THE FINDING IS NOT 'MOVE THE STORE'. It is:")
        print()
        print("  moving the store behind a protocol moves the attack surface")
        print("  to the protocol's vocabulary, and a vocabulary that can")
        print("  forget is a vocabulary that can forge.")
        print()
        print("Which is case 09's lesson - an allowlist of names is not an")
        print("allowlist of transformations - arriving at the durable plane.")
        print("The store being unreachable is necessary and is not the claim;")
        print("the claim has to cover what the gate itself will do on request.")
    raise SystemExit(0)
