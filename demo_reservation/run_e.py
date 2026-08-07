"""Step E end state: prove observation, and nothing else.

    python demo_reservation/run_e.py [exchanges]

The monitor detects. It does not diagnose, retry, restart or reroute - step F
has to add every one of those explicitly.
"""

from __future__ import annotations

import os
import statistics
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from demo_reservation import comms_faults, monitor as monitor_mod  # noqa: E402
from demo_reservation.exchange import Bus  # noqa: E402


def run(exchanges: int = 1000, rate: float = 0.05, seed: int = 91100):
    watcher = monitor_mod.Monitor()
    bus = Bus(observers=[watcher])
    injector = comms_faults.Injector(rate=rate, seed=seed)
    injector.run(bus, exchanges)
    return watcher, injector, bus


def score(watcher, injector, exchanges: int):
    truth = injector.truth()
    flagged = watcher.faults_by_correlation()

    detected, missed, latencies, wrong_kind = [], [], [], []
    for correlation_id, kind in truth.items():
        observed = flagged.get(correlation_id)
        # wrong_correlation_id makes the response arrive under a fabricated id,
        # so the *original* exchange goes missing. Both observations are the
        # monitor doing its job; the ground truth is that this exchange broke.
        if not observed:
            missed.append(correlation_id)
            continue
        detected.append(correlation_id)
        latencies.append(observed[0].detected_tick
                         - injector.request_tick(correlation_id))
        # A single broken exchange can produce more than one honest
        # observation - a delayed response is legitimately "missing at the
        # deadline" and then "late when it arrives". The preregistered kind
        # must be AMONG them, not necessarily first.
        kinds = {f.kind for f in observed}
        if comms_faults.EXPECTED_FAULT[kind] not in kinds:
            wrong_kind.append((correlation_id, kind, sorted(kinds)))

    false_alarms = [cid for cid in flagged
                    if cid not in truth and cid < exchanges]
    return {
        "exchanges": exchanges,
        "clean": exchanges - len(truth),
        "disrupted": len(truth),
        "detected": len(detected),
        "missed": missed,
        "false_alarms": false_alarms,
        "wrong_kind": wrong_kind,
        "median_latency": (statistics.median(latencies) if latencies else 0),
    }


if __name__ == "__main__":
    n = int(sys.argv[1]) if len(sys.argv) > 1 else 1000
    watcher, injector, bus = run(n)
    s = score(watcher, injector, n)

    print(f"{s['exchanges']} communication exchanges")
    print()
    print(f"{s['clean']:>6d} clean")
    print(f"{s['disrupted']:>6d} disrupted")
    print()
    print(f"detected disruptions: {s['detected']}")
    print(f"missed: {len(s['missed'])}")
    print(f"false alarms on clean traffic: {len(s['false_alarms'])}")
    print(f"median detection latency: {s['median_latency']:.0f} ticks")
    print()
    print("by injected fault kind:")
    truth = injector.truth()
    flagged = watcher.faults_by_correlation()
    for kind in comms_faults.VOCABULARY:
        ids = [c for c, k in truth.items() if k == kind]
        hit = sum(1 for c in ids if c in flagged)
        print(f"    {kind:<26s} {hit}/{len(ids)} detected"
              f"  -> expected {comms_faults.EXPECTED_FAULT[kind]}")
    if s["wrong_kind"]:
        print(f"\n    classified differently than preregistered: "
              f"{len(s['wrong_kind'])}")
        for cid, injected, observed in s["wrong_kind"][:3]:
            print(f"        #{cid} {injected} -> {observed}")
    print()
    print("The monitor emitted only structured observations. It did not")
    print("conclude that any worker had crashed, and it holds no verb that")
    print("could have repaired anything - step F must add those explicitly.")
    raise SystemExit(0)
