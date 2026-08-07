"""Case 21 - gate independence.

Run it:

    python cases/21-gate-independence/attack.py

Cases 19 and 20 both ended on the same sentence: the mechanism is a Level 1
control because a Level 1.5 adversary writes the approval store. This asks what
makes that boundary trusted.

The claim is deliberately tiny:

    Compromise of the worker's execution boundary cannot modify or invoke the
    approval gate except through its exposed protocol.
"""

from __future__ import annotations

import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import boundary as b  # noqa: E402


if __name__ == "__main__":
    print("Attacking the boundary, not the model.")

    with tempfile.TemporaryDirectory() as tmp:
        probes = b.measure(tmp)

        for arm, title in (("A", "worker and gate share the boundary"),
                           ("B", "gate in its own process, narrow protocol")):
            print(f"\n--- Arm {arm}: {title} ---")
            for p in probes:
                if p.arm != arm:
                    continue
                mark = "!!" if p.succeeded else "  "
                print(f"   {mark} {p.name:44s} "
                      f"{'SUCCEEDED' if p.succeeded else 'no':10s}")
                print(f"        {p.note}")

        print("\n=== RESULT ===")
        print(f"{'probe':>44s}  {'arm A':>7s}  {'arm B':>7s}")
        for name in b.PROBE_NAMES:
            a = b.get(probes, "A", name)
            bb = b.get(probes, "B", name)
            print(f"{name:>44s}  "
                  f"{('SUCCEEDS' if a.succeeded else 'no'):>7s}  "
                  f"{('SUCCEEDS' if bb.succeeded else 'no'):>7s}")

        persisted = b.get(probes, "B", "manipulate the gate's datastore "
                                       "(persisted)")
        a_wins = sum(1 for n in b.PROBE_NAMES
                     if b.get(probes, "A", n).succeeded)
        b_wins = sum(1 for n in b.PROBE_NAMES
                     if b.get(probes, "B", n).succeeded)

        print()
        print(f"Arm A: {a_wins} of {len(b.PROBE_NAMES)} probes succeed.")
        print(f"Arm B: {b_wins} of {len(b.PROBE_NAMES)}.")
        print()
        print("And then the seventh probe, which is the honest one:")
        print()
        print(f"   {'!!' if persisted.succeeded else '  '} "
              f"{persisted.name}: "
              f"{'SUCCEEDS' if persisted.succeeded else 'no'}")
        print(f"        {persisted.note}")
        print()
        print("So the claim holds, and only as far as it was written. A gate")
        print("in its own process cannot be patched, cannot have its reviewer")
        print("list edited, does not leak its credential through the protocol,")
        print("and ignores fields it did not ask for. Every arm A probe")
        print("succeeds because there is no boundary to cross - the")
        print("attributes are simply there.")
        print()
        print("What did NOT move: a gate that persists to a file the worker's")
        print("uid can write is separated in memory and not in storage. Case")
        print("06 measured the same thing about ambient authority and this is")
        print("that finding arriving at the approval plane. Level 1.5 still")
        print("wins against the persisted store, which means sign-off remains")
        print("a Level 1 control until the STORE moves too - not just the")
        print("code.")
    raise SystemExit(0)
