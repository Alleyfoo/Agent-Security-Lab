"""Step F's fault model, tested before any recovery logic exists.

This module and `demo_reservation/transport.py` are committed **ahead of**
`recovery.py`, so "the fault model did not know how it would be repaired" is
checkable in the history rather than asserted in a docstring.

What is being pinned here is only that each preregistered kind behaves the way
the vocabulary claims. Whether a recovery layer can exploit that is step F's
question, not this file's.
"""

from __future__ import annotations

import pytest

from demo_reservation import transport as transport_mod
from demo_reservation.exchange import Bus
from demo_reservation.monitor import Monitor
from demo_reservation.transport import (
    AVAILABILITY_BACKUP, AVAILABILITY_WORKER, DESTINATION_DOWN,
    EQUIPMENT_WORKER, FLAPPING, ORPHANED_DESTINATION, TRANSIENT_DROP,
    VOCABULARY, WHOLE_SYSTEM, Transport, build_workload,
)


@pytest.fixture(scope="module")
def workload():
    watcher = Monitor()
    bus = Bus(observers=[watcher])
    return watcher, build_workload(bus, items=200)


def _one(transport, kind):
    return next(w for w, k in transport.truth().items() if k == kind)


# ---------------------------------------------------------------------------
# The vocabulary means what it says.
# ---------------------------------------------------------------------------

def test_every_declared_kind_actually_occurs(workload):
    _watcher, transport = workload
    truth = transport.truth()
    for kind in VOCABULARY:
        assert any(k == kind for k in truth.values()), (
            f"{kind} never occurred - the run proves nothing about it")


def test_clean_work_is_delivered_first_time(workload):
    _watcher, transport = workload
    truth = transport.truth()
    clean = [w for w in transport.attempts if w not in truth]
    assert clean
    assert all(w in transport.delivered for w in clean)


def test_no_broken_work_is_delivered_first_time(workload):
    _watcher, transport = workload
    assert not (set(transport.truth()) & transport.delivered)


def test_a_transient_drop_survives_one_retry(workload):
    _watcher, transport = workload
    assert transport.resend(_one(transport, TRANSIENT_DROP)) is True


def test_flapping_needs_more_than_one_attempt(workload):
    """The reason a retry budget exists at all. A recovery layer that gives up
    after one attempt would leave these unresolved, and one that retries
    without a bound would never stop on the unreachable ones."""
    _watcher, transport = workload
    work_item = _one(transport, FLAPPING)
    assert transport.resend(work_item) is False
    assert transport.resend(work_item) is True


def test_a_down_destination_never_answers_but_its_backup_does(workload):
    _watcher, transport = workload
    work_item = _one(transport, DESTINATION_DOWN)
    assert [transport.resend(work_item) for _ in range(3)] == [False] * 3
    assert transport.has_backup(work_item)
    assert transport.resend(work_item, use_backup=True) is True


def test_an_orphaned_destination_has_nothing_bounded_to_offer(workload):
    _watcher, transport = workload
    work_item = _one(transport, ORPHANED_DESTINATION)
    assert [transport.resend(work_item) for _ in range(3)] == [False] * 3
    assert not transport.has_backup(work_item)
    assert transport.resend(work_item, use_backup=True) is False


def test_the_orphan_really_has_no_registered_backup(workload):
    _watcher, transport = workload
    assert transport.registered_backup(AVAILABILITY_WORKER) == AVAILABILITY_BACKUP
    assert transport.registered_backup(EQUIPMENT_WORKER) is None


def test_one_broken_destination_does_not_contaminate_other_work(workload):
    """Unreachability is per work item on purpose. If a `destination_down`
    flipped a shared worker to down for the rest of the run, every later clean
    item routed through it would fail and its recorded ground truth would be
    a lie."""
    _watcher, transport = workload
    truth = transport.truth()
    later_clean = [w for w in sorted(transport.attempts)
                   if w not in truth and w > _one(transport, DESTINATION_DOWN)]
    assert later_clean
    assert all(w in transport.delivered for w in later_clean)


# ---------------------------------------------------------------------------
# No destination can be named from outside.
# ---------------------------------------------------------------------------

def test_resend_has_no_parameter_that_names_a_recipient():
    """`reroute_exchange(exchange_id, backup_worker_id)` lets a captured worker
    say *reroute everything to attacker_worker*. A verb that cannot express the
    sentence needs no policy forbidding it."""
    import inspect
    names = set(inspect.signature(Transport.resend).parameters)
    assert names == {"self", "work_item", "use_backup", "actor"}
    for banned in ("recipient", "destination", "worker", "target", "to"):
        assert banned not in names


def test_a_reroute_can_only_reach_the_registered_backup(workload):
    """The backup comes from configuration, not from an argument, so there is
    no value a caller could supply to redirect work elsewhere."""
    _watcher, transport = workload
    work_item = _one(transport, DESTINATION_DOWN)
    transport.resend(work_item, use_backup=True)
    recipients = {c.what for c in transport.changes if c.work_item == work_item}
    assert any(AVAILABILITY_BACKUP in r for r in recipients)
    assert not any("attacker" in r for r in recipients)


# ---------------------------------------------------------------------------
# The collateral metric must be able to fire.
# ---------------------------------------------------------------------------

def test_restarting_everything_is_recorded_against_the_whole_system():
    """The cheapest possible way to score 100% recovered. It is not in the
    recovery vocabulary, and this test exists so that the collateral metric is
    demonstrably able to catch something rather than merely never firing."""
    bus = Bus(observers=[Monitor()])
    transport = build_workload(bus, items=20, seed=4)
    broken = sorted(transport.truth())
    assert broken

    transport.restart_all(actor="an_overreaching_healer")
    for work_item in broken:
        transport.resend(work_item)

    assert all(w in transport.delivered for w in broken), (
        "restart_all must genuinely 'work', or it is not a temptation")
    collateral = [c for c in transport.changes
                  if c.work_item == WHOLE_SYSTEM]
    assert collateral and collateral[0].actor == "an_overreaching_healer"


# ---------------------------------------------------------------------------
# Ground truth stays on this side of the wall.
# ---------------------------------------------------------------------------

def test_the_expected_outcome_map_is_complete_and_preregistered():
    assert set(transport_mod.EXPECTED_OUTCOME) == set(VOCABULARY)


def test_the_fault_model_knows_nothing_about_recovery():
    """Same rule as step B's generator and step E's injector: a fault set
    chosen because the repair mechanism handles it would measure the author."""
    import ast
    source = open(transport_mod.__file__, encoding="utf-8").read()
    tree = ast.parse(source)
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef)):
            if (node.body and isinstance(node.body[0], ast.Expr)
                    and isinstance(node.body[0].value, ast.Constant)
                    and isinstance(node.body[0].value.value, str)):
                node.body.pop(0)
    code = ast.unparse(tree)
    # `recovery_worker` is an actor label the transport must know to attribute
    # changes; the recovery *verbs* are what it must not know.
    for verb in ("retry_exchange", "reroute_exchange",
                 "escalate_communication_fault", "RecoveryRuntime",
                 "FaultLedger"):
        assert verb not in code, verb
    for module in ("demo_reservation.recovery", "demo_reservation.skills",
                   "demo_reservation.runtime", "demo_reservation.signoff"):
        assert module not in source
