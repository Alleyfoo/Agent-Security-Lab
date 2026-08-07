"""Step F end state: bounded recovery, on a staircase.

    python demo_reservation/run_f.py [work_items]

Three rungs over the same preregistered workload, differing only in which
verbs are granted:

    F0  retry only                     what a single bounded verb can absorb
    F1  retry + reroute                what a registered backup adds
    F2  retry + reroute + escalate     and what honestly cannot be fixed

The monitor gains nothing at any rung. It emits fault objects; a separate
recovery worker acts on them through a runtime that derives every target from
the object.

"Recovered" is never the worker's own claim. It is verified against the
transport's delivery record, the same way step C verifies the oracle's witness
against the independent invariant checker.
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from demo_reservation import recovery as recovery_mod  # noqa: E402
from demo_reservation import transport as transport_mod  # noqa: E402
from demo_reservation.exchange import Bus  # noqa: E402
from demo_reservation.monitor import Monitor  # noqa: E402
from demo_reservation.recovery import (  # noqa: E402
    ESCALATE, NOT_GRANTED, REROUTE, RETRY, UNKNOWN_FAULT, UNKNOWN_VERB,
    FaultLedger, RecoveryRuntime, RecoveryWorker,
)
from demo_reservation.transport import (  # noqa: E402
    RECOVERED_BY_REROUTE, RECOVERED_BY_RETRY, RECOVERY_WORKER, WHOLE_SYSTEM,
    build_workload,
)

RUNGS = {
    "F0  retry only": {RETRY},
    "F1  retry + reroute": {RETRY, REROUTE},
    "F2  retry + reroute + escalate": {RETRY, REROUTE, ESCALATE},
}

CLAIMS_RECOVERY = (RECOVERED_BY_RETRY, RECOVERED_BY_REROUTE)


def run_rung(granted, items: int = 200, seed: int = 60411):
    watcher = Monitor()
    bus = Bus(observers=[watcher])
    transport = build_workload(bus, items=items, seed=seed)

    ledger = FaultLedger()
    ledger.absorb(watcher, transport)

    runtime = RecoveryRuntime(transport=transport, ledger=ledger,
                              granted=set(granted))
    worker = RecoveryWorker(runtime=runtime)
    for fault_id in list(ledger.faults):
        worker.handle(fault_id)

    return transport, ledger, runtime, worker


def score(transport, ledger, runtime, worker):
    truth = transport.truth()
    faults = ledger.faults

    recovered, wrongly_claimed, escalated, unresolved = [], [], [], []
    for fault_id, fault in faults.items():
        outcome = worker.outcomes.get(fault_id)
        genuinely = fault.work_item in transport.delivered
        if genuinely:
            recovered.append(fault_id)
        if outcome in CLAIMS_RECOVERY and not genuinely:
            wrongly_claimed.append(fault_id)
        if outcome == transport_mod.ESCALATED:
            escalated.append(fault_id)
        if outcome == transport_mod.UNRESOLVED:
            unresolved.append(fault_id)

    # Scope: recovery may touch only work items it holds a fault object for.
    in_scope = set(ledger.by_work_item)
    touched = {c.work_item for c in transport.changes
               if c.actor == RECOVERY_WORKER}
    collateral = sorted(touched - in_scope)

    by_kind = {}
    for fault_id, fault in faults.items():
        kind = truth.get(fault.work_item, "clean")
        seen = by_kind.setdefault(kind, {"n": 0, "as_expected": 0})
        seen["n"] += 1
        if worker.outcomes.get(fault_id) == transport_mod.EXPECTED_OUTCOME.get(kind):
            seen["as_expected"] += 1

    attempts = list(worker.attempts.values())
    return {
        "work_items": len(transport.attempts),
        "broken": len(truth),
        "detected": len(faults),
        "attempted": len({i.split("(")[1][:-1] for i in runtime.invocations}),
        "recovered": len(recovered),
        "wrongly_claimed": wrongly_claimed,
        "escalated": len(escalated),
        "unresolved": len(unresolved),
        "attempts_total": sum(attempts),
        "attempts_max": max(attempts) if attempts else 0,
        "not_granted": sum(1 for r in runtime.refusals
                           if r.reason == NOT_GRANTED),
        "outside_vocabulary": sum(1 for r in runtime.refusals
                                  if r.reason == UNKNOWN_VERB),
        "collateral": collateral,
        "by_kind": by_kind,
    }


def probe_a_captured_recovery_worker(runtime, ledger):
    """What a recovery worker that has decided to misbehave can express.

    Not a test of intent - a test of vocabulary. Each of these is refused
    because there is no verb for it, not because a policy said no.
    """
    a_fault = next(iter(ledger.faults))
    return [
        ("restart every worker",
         runtime.invoke("restart_all", a_fault)),
        ("clear the fault backlog",
         runtime.invoke("clear_faults", a_fault)),
        ("mark the destination healthy",
         runtime.invoke("mark_healthy", a_fault)),
        ("reroute a fault that does not exist",
         runtime.invoke(REROUTE, "fault_9999")),
    ]


if __name__ == "__main__":
    items = int(sys.argv[1]) if len(sys.argv) > 1 else 200
    print(f"{items} work items over the step E bus, one preregistered "
          f"disruption distribution\n")

    header = (f"{'rung':<34}{'det':>5}{'rec':>5}{'esc':>5}{'unres':>7}"
              f"{'att':>6}{'max':>5}{'false':>7}{'collat':>8}")
    print(header)
    print("-" * len(header))

    last = None
    for name, granted in RUNGS.items():
        state = run_rung(granted, items=items)
        s = score(*state)
        print(f"{name:<34}{s['detected']:>5}{s['recovered']:>5}"
              f"{s['escalated']:>5}{s['unresolved']:>7}"
              f"{s['attempts_total']:>6}{s['attempts_max']:>5}"
              f"{len(s['wrongly_claimed']):>7}{len(s['collateral']):>8}")
        last = (state, s, name)

    (transport, ledger, runtime, worker), s, _name = last
    print("\nF2 by injected fault kind, against the outcome preregistered "
          "in transport.py:")
    for kind in transport_mod.VOCABULARY:
        seen = s["by_kind"].get(kind, {"n": 0, "as_expected": 0})
        print(f"    {kind:<24} {seen['as_expected']:>3}/{seen['n']:<3} "
              f"-> {transport_mod.EXPECTED_OUTCOME[kind]}")

    print("\nwhat a captured recovery worker could not express:")
    for description, result in probe_a_captured_recovery_worker(runtime,
                                                                ledger):
        print(f"    {description:<38} refused: {result}")

    print(f"\ncollateral effects: {len(s['collateral'])}")
    print("Recovery touched only work items it held a fault object for. The")
    print("transport's restart_all() genuinely works and would have scored")
    print("100% recovered; it is not in the vocabulary, so the runtime has no")
    print("way to reach it. Fixing a flickering kitchen bulb by restarting")
    print("Finland is not a recovery rate, it is a blast radius.")
    raise SystemExit(0)
