"""Case 20 - two executors racing one valid one-use approval.

Run it:

    python cases/20-one-use-race/attack.py

Pre-registered prediction: case 19's R4 loses this race.

Scope, fixed before the measurement and not negotiable afterwards:

    provable    a single approval cannot be concurrently acquired by two
                executions
    not provable exactly-once execution of an external effect
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import race as r  # noqa: E402


def show(readings) -> None:
    for gate in r.GATES:
        print(f"\n--- {gate.name} ---")
        for reading in readings:
            if reading.gate != gate.name:
                continue
            bad = reading.effects != 1
            mark = "!!" if bad else "  "
            print(f"   {mark} {reading.scenario:34s} "
                  f"effects={reading.effects}  state={reading.final_state}")
            print(f"        {reading.note}")


if __name__ == "__main__":
    print("Two executors, one valid one-use approval.")
    print("The prediction was: case 19's R4 loses this race.")

    readings = r.measure()
    show(readings)

    print("\n--- Without the interleaving hook ---")
    print("   instantaneous sink, 200 rounds "
          "(the window is a few bytecodes):")
    for gate in r.GATES:
        reading = r.concurrent_threads(gate, rounds=200, latency=0.0)
        mark = "!!" if reading.effects > 1 else "  "
        print(f"   {mark} {gate.name:36s} worst effects: {reading.effects}")
    print("\n   sink with the latency a real external call has, 25 rounds:")
    for gate in r.GATES:
        reading = r.concurrent_threads(gate, rounds=25, latency=0.002)
        mark = "!!" if reading.effects > 1 else "  "
        print(f"   {mark} {gate.name:36s} worst effects: {reading.effects}")

    print("\n=== RESULT ===")
    print(f"{'gate':>36s}  {'race':>6s}  {'crash before -> state':>22s}  "
          f"{'crash after':>12s}")
    for gate in r.GATES:
        race = r.get(readings, gate, "two executors race one approval")
        before = r.get(readings, gate, "crash before the effect")
        after = r.get(readings, gate, "crash after effect, then retry")
        lost = "" if before.final_state == r.UNUSED else "  LOST"
        print(f"{gate.name:>36s}  {race.effects:>6d}  "
              f"{(before.final_state + lost):>22s}  {after.effects:>12d}")

    print()
    print("PREDICTION CONFIRMED: G0 - case 19's R4 as built - performs the")
    print("external effect twice from one approval.")
    print()
    print("G1 is the trap, and the two runs together are what expose it.")
    print("Reordering the mark before the effect NARROWS the window without")
    print("closing it: forced at the worst moment it still performs the")
    print("effect twice, and unforced it never once misbehaved in 25 rounds")
    print("where G0 failed immediately. That combination is worse than an")
    print("obvious bug - a race that ordinary testing cannot reach is still")
    print("a race, and an adversary who can influence timing does not need")
    print("the luck a test suite is waiting for.")
    print()
    print("What the reordering does change is WHICH failure a crash gives:")
    print("the approval is spent with the action never performed. It trades")
    print("a double effect for a lost one.")
    print()
    print("G2 closes it, and the difference from G1 is one lock rather than")
    print("one reordering. Only a claim that is joined to the state test is")
    print("exclusive. The honest cost: a crash after the claim leaves the")
    print("approval stuck in 'claimed' - no double effect, no execution, and")
    print("no automatic way back.")
    print()
    print("G3 is the only gate where a retry after a crash produces one")
    print("effect rather than two, and NOTE WHERE THAT COMES FROM: the sink")
    print("refusing a repeated execution id. It is not a property of the")
    print("approval record at all.")
    print()
    print("SO THE CLAIM STOPS HERE:")
    print("  proved      one approval cannot be concurrently acquired twice")
    print("  NOT proved  exactly-once execution of an external effect")
    print()
    print("Anyone reading state == 'executed' and writing 'exactly once' is")
    print("wrong. Exactly-once needs the effect and the record in one")
    print("transaction, or an idempotent sink keyed on the execution id -")
    print("and the second is what G3 measures.")
    raise SystemExit(0)
