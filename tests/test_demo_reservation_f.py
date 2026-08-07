"""Reservation demo, step F: repair without general authority.

    Can a detected communication fault be recovered using only explicitly
    granted recovery functions, without giving the monitor general
    administrative authority?

Step E proved observation. This step proves bounded intervention, and the two
stay surgically separate: the monitor gains nothing here, and every recovery
verb had to be added explicitly.

Two metrics in this file are the kind that can pass by being decorative -
"nothing was falsely claimed recovered" and "there was no collateral damage"
are both satisfied by a system that never does anything. Each therefore has a
positive control that drives it above zero.
"""

from __future__ import annotations

import inspect

import pytest

from demo_reservation import monitor as monitor_mod
from demo_reservation import recovery as recovery_mod
from demo_reservation import transport as transport_mod
from demo_reservation.exchange import Bus
from demo_reservation.monitor import Monitor
from demo_reservation.recovery import (
    ESCALATE, NOT_GRANTED, RECOVERY_SKILLS, REROUTE, RETRY, UNKNOWN_FAULT,
    UNKNOWN_VERB, FaultLedger, FaultObject, RecoveryRuntime, RecoveryWorker,
)
from demo_reservation.run_f import RUNGS, run_rung, score
from demo_reservation.transport import (
    DESTINATION_DOWN, FLAPPING, ORPHANED_DESTINATION, RECOVERED_BY_REROUTE,
    RECOVERED_BY_RETRY, RECOVERY_WORKER, TRANSIENT_DROP, WHOLE_SYSTEM,
    build_workload,
)


@pytest.fixture(scope="module")
def f2():
    state = run_rung({RETRY, REROUTE, ESCALATE})
    return state, score(*state)


@pytest.fixture(scope="module")
def rungs():
    return {name: score(*run_rung(granted))
            for name, granted in RUNGS.items()}


# ---------------------------------------------------------------------------
# The staircase, against outcomes preregistered before recovery existed.
# ---------------------------------------------------------------------------

def test_every_fault_kind_reaches_its_preregistered_outcome(f2):
    """`transport.py` was committed before `recovery.py` and named the outcome
    each kind should reach. This is the whole measurement."""
    _state, s = f2
    for kind in transport_mod.VOCABULARY:
        seen = s["by_kind"][kind]
        assert seen["n"] > 0, f"{kind} never occurred"
        assert seen["as_expected"] == seen["n"], (
            kind, transport_mod.EXPECTED_OUTCOME[kind], seen)


def test_each_rung_absorbs_strictly_more_than_the_one_below(rungs):
    f0 = rungs["F0  retry only"]
    f1 = rungs["F1  retry + reroute"]
    f2 = rungs["F2  retry + reroute + escalate"]

    assert f0["recovered"] < f1["recovered"], "reroute must add something"
    assert f2["recovered"] == f1["recovered"], (
        "escalation is not recovery - it is admitting the bound")
    assert f2["unresolved"] == 0 and f0["unresolved"] > 0
    # At the top rung every detected fault ends in a named terminal state:
    # repaired, or reported. Nothing is left quietly unaccounted for.
    assert f2["recovered"] + f2["escalated"] == f2["detected"]


def test_escalation_converts_silence_into_a_statement(rungs):
    """The difference between F1 and F2 is not a better repair rate. It is that
    eight faults stop being quietly unresolved and start being reported."""
    f1 = rungs["F1  retry + reroute"]
    f2 = rungs["F2  retry + reroute + escalate"]
    assert f1["unresolved"] == f2["escalated"]
    assert f2["unresolved"] == 0


def test_recovery_is_bounded_rather_than_persistent(f2):
    """Retrying an unreachable destination forever is not recovery, it is a
    denial of service with good intentions."""
    _state, s = f2
    assert s["attempts_max"] <= 5   # 3 retries + one reroute + one escalation


def test_nothing_is_falsely_reported_recovered(f2):
    """The worker's claim is never taken at face value: 'recovered' means the
    transport recorded a genuine delivery, exactly as step C revalidates the
    oracle's witness through the independent invariant checker."""
    _state, s = f2
    assert s["wrongly_claimed"] == []


def test_the_false_recovery_metric_can_actually_fire():
    """Positive control. A metric that has never been above zero is not
    evidence - step E's diagnosis guard passed for a while while matching
    nothing at all."""
    state = run_rung({RETRY, REROUTE, ESCALATE})
    transport, ledger, runtime, worker = state
    liar = next(fid for fid, f in ledger.faults.items()
                if f.work_item not in transport.delivered)
    worker.outcomes[liar] = RECOVERED_BY_RETRY

    assert score(transport, ledger, runtime, worker)["wrongly_claimed"] == [liar]


# ---------------------------------------------------------------------------
# Scope: only the failed path, or its work item.
# ---------------------------------------------------------------------------

def test_recovery_touches_only_work_it_holds_a_fault_object_for(f2):
    _state, s = f2
    assert s["collateral"] == []


def test_the_collateral_metric_can_actually_fire():
    """Positive control, and the failure mode this step exists to forbid.

    `restart_all` genuinely works: it clears every fault and every broken item
    then recovers. 100% recovered, technically. Also rather like fixing a
    flickering kitchen bulb by restarting Finland."""
    state = run_rung({RETRY, REROUTE, ESCALATE})
    transport, ledger, runtime, worker = state
    assert score(*state)["collateral"] == []

    transport.restart_all(actor=RECOVERY_WORKER)
    assert score(*state)["collateral"] == [WHOLE_SYSTEM]


def test_a_reroute_reaches_only_the_registered_backup(f2):
    (transport, _ledger, _runtime, _worker), _s = f2
    destinations = {c.what for c in transport.changes
                    if c.actor == RECOVERY_WORKER}
    assert destinations <= {
        f"attempt via {transport_mod.AVAILABILITY_WORKER}",
        f"attempt via {transport_mod.AVAILABILITY_BACKUP}",
        f"attempt via {transport_mod.EQUIPMENT_WORKER}",
        "no registered backup",
    }, destinations


# ---------------------------------------------------------------------------
# THE AUTHORITY DIFF. Step F adds three verbs and no more.
# ---------------------------------------------------------------------------

def test_the_recovery_vocabulary_is_exactly_three_verbs():
    """Pinned so the diff stays visible. A later step wanting more must add it
    explicitly and rewrite this line, rather than acquiring authority by being
    useful."""
    assert RECOVERY_SKILLS == ("retry_exchange", "reroute_exchange",
                               "escalate_communication_fault")


@pytest.mark.parametrize("verb", ["restart_all", "restart_worker",
                                  "clear_faults", "mark_healthy",
                                  "reroute_all", "drain", "failover"])
def test_verbs_outside_the_vocabulary_are_refused(f2, verb):
    (_transport, ledger, runtime, _worker), _s = f2
    a_fault = next(iter(ledger.faults))
    assert runtime.invoke(verb, a_fault) == UNKNOWN_VERB


def test_a_fabricated_fault_id_is_refused(f2):
    """The recovery worker addresses objects it was handed. It cannot compose
    an identifier and have the runtime act on it."""
    (_transport, _ledger, runtime, _worker), _s = f2
    assert runtime.invoke(RETRY, "fault_9999") == UNKNOWN_FAULT


def test_an_ungranted_verb_is_refused_and_counted(rungs):
    """Refusals are counted rather than merely prevented. A silent guard is
    indistinguishable from a system nobody attacked."""
    assert rungs["F0  retry only"]["not_granted"] > 0


def test_no_recovery_skill_accepts_a_destination():
    """The reason `reroute_exchange(fault_4812)` beats
    `reroute_exchange(exchange_id, backup_worker_id)`: a captured worker can
    say 'reroute everything to attacker_worker' only if the verb has somewhere
    to put the words."""
    for name in RECOVERY_SKILLS:
        params = set(inspect.signature(getattr(recovery_mod, name)).parameters)
        assert params == {"transport", "fault", "escalations"}, name
    invoke = set(inspect.signature(RecoveryRuntime.invoke).parameters)
    assert invoke == {"self", "skill", "fault_id"}


def test_the_recovery_worker_holds_no_transport():
    """It has a runtime and a bound, and nothing it could act through
    directly."""
    worker = RecoveryWorker(runtime=RecoveryRuntime(
        transport=None, ledger=FaultLedger()))
    assert set(vars(worker)) == {"runtime", "retry_budget", "outcomes",
                                 "attempts"}
    assert not hasattr(worker, "transport")
    assert not hasattr(worker, "bus")


# ---------------------------------------------------------------------------
# The monitor gained nothing.
# ---------------------------------------------------------------------------

def test_the_monitor_still_holds_no_recovery_verb():
    """Step E's guard, re-run against step F's vocabulary. Observation creates
    an object; a separate authorised function acts on it. Without this the
    architecture drifts to sees everything -> understands everything ->
    controls everything."""
    names = [n.lower() for n in dir(Monitor) if not n.startswith("__")]
    for verb in ("retry", "reroute", "escalate", "restart", "repair", "heal",
                 "recover"):
        assert not any(verb in n for n in names), verb


def test_the_monitor_module_is_untouched_by_step_f():
    source = open(monitor_mod.__file__, encoding="utf-8").read()
    for name in RECOVERY_SKILLS + ("Transport", "RecoveryRuntime",
                                   "demo_reservation.transport",
                                   "demo_reservation.recovery"):
        assert name not in source, name


def test_a_fault_object_carries_an_observation_not_a_cause(f2):
    """Handing recovery a diagnosis the stream could not prove would smuggle
    step E's forbidden conclusion back in through the side door."""
    (_transport, ledger, _runtime, _worker), _s = f2
    assert ledger.faults
    for fault in ledger.faults.values():
        assert fault.observed in monitor_mod.FAULT_KINDS
    assert set(vars(next(iter(ledger.faults.values())))) == {
        "fault_id", "work_item", "correlation_id", "observed"}


def test_one_fault_object_per_work_item(f2):
    """A failed retry produces a fresh monitor observation under a new
    correlation id. Opening a second fault object for it would make
    'attempts per fault' meaningless."""
    (_transport, ledger, _runtime, _worker), _s = f2
    work_items = [f.work_item for f in ledger.faults.values()]
    assert len(work_items) == len(set(work_items))


# ---------------------------------------------------------------------------
# The recovery layer cannot read what it is being measured against.
# ---------------------------------------------------------------------------

def test_recovery_cannot_read_the_injected_fault_kind():
    """Otherwise the staircase measures a lookup table. Same rule as step C's
    hidden oracle witness and step E's unreadable injector."""
    import ast
    source = open(recovery_mod.__file__, encoding="utf-8").read()
    tree = ast.parse(source)
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef)):
            if (node.body and isinstance(node.body[0], ast.Expr)
                    and isinstance(node.body[0].value, ast.Constant)
                    and isinstance(node.body[0].value.value, str)):
                node.body.pop(0)
    code = ast.unparse(tree)
    for forbidden in ("injected_kind", "truth", "_kind", "_drops",
                      "_unreachable", "restart_all", "VOCABULARY",
                      "EXPECTED_OUTCOME", TRANSIENT_DROP, FLAPPING,
                      DESTINATION_DOWN, ORPHANED_DESTINATION):
        assert forbidden not in code, forbidden


def test_recovery_reaches_no_business_state():
    """Communication recovery is not authority over the calendar. A recovery
    worker that could edit reservations would have acquired step D's
    displacement power by way of a retry button."""
    source = open(recovery_mod.__file__, encoding="utf-8").read()
    for module in ("demo_reservation.skills", "demo_reservation.runtime",
                   "demo_reservation.objects", "demo_reservation.signoff",
                   "demo_reservation.world", "demo_reservation.invariants"):
        assert module not in source, module
