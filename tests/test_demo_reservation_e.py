"""Reservation demo, step E: prove observation, and nothing else.

    Can an independent observer detect that an expected communication did not
    complete correctly, without possessing authority to repair it?

Not self-healing. Not diagnosis. The scope guards at the end are the point of
the step as much as the detection numbers are: step F must add every recovery
verb explicitly, so the authority the monitor gains is visible as a diff rather
than acquired by being useful.
"""

from __future__ import annotations

import pytest

from demo_reservation import comms_faults, monitor as monitor_mod
from demo_reservation.exchange import Bus, Event, Exchange
from demo_reservation.monitor import (
    DUPLICATE, LATE, MISSING, UNEXPECTED_IDENTITY, Monitor,
)
from demo_reservation.run_e import run, score


@pytest.fixture(scope="module")
def measured():
    watcher, injector, bus = run(600)
    return watcher, injector, score(watcher, injector, 600)


# ---------------------------------------------------------------------------
# Detection, against ground truth the monitor cannot read.
# ---------------------------------------------------------------------------

def test_every_injected_fault_is_detected(measured):
    _watcher, _injector, s = measured
    assert s["disrupted"] > 0
    assert s["missed"] == [], f"missed {s['missed'][:5]}"


def test_no_false_alarms_on_clean_traffic(measured):
    _watcher, _injector, s = measured
    assert s["false_alarms"] == [], s["false_alarms"][:5]


def test_each_fault_is_classified_as_preregistered(measured):
    """The expected observation for each injected fault was written in
    `comms_faults.py` before the detector existed. A broken exchange may
    produce more than one honest observation - a delayed response is
    legitimately *missing at the deadline* and then *late when it arrives* -
    so the preregistered kind must be among them rather than first."""
    _watcher, _injector, s = measured
    assert s["wrong_kind"] == [], s["wrong_kind"][:5]


@pytest.mark.parametrize("kind", list(comms_faults.VOCABULARY))
def test_every_fault_kind_actually_occurs_and_is_caught(measured, kind):
    watcher, injector, _s = measured
    ids = [c for c, k in injector.truth().items() if k == kind]
    assert ids, f"{kind} never occurred - the run proves nothing about it"
    flagged = watcher.faults_by_correlation()
    assert all(c in flagged for c in ids)


def test_detection_latency_is_measured_in_ticks(measured):
    """Logical ticks, never wall-clock. A deadline in seconds would measure
    Windows scheduling rather than communication detection."""
    _watcher, _injector, s = measured
    assert isinstance(s["median_latency"], (int, float))
    assert 0 < s["median_latency"] < 20


# ---------------------------------------------------------------------------
# What the monitor is allowed to say.
# ---------------------------------------------------------------------------

def test_the_monitor_only_emits_the_four_provable_kinds(measured):
    watcher, _injector, _s = measured
    assert {f.kind for f in watcher.faults} <= set(monitor_mod.FAULT_KINDS)


def test_the_monitor_never_diagnoses_a_cause(measured):
    """`missing_expected_response` is provable from the stream.
    `availability_worker_crashed` is not - the worker may be alive and the
    message dropped. A monitor that infers causes from absences is grading its
    own homework about a system it can only see the outside of."""
    import re
    watcher, _injector, _s = measured
    # Word boundaries, because "dead" is a substring of "deadline" and an
    # earlier version of this test flagged the monitor for correctly saying
    # what the deadline was.
    banned = re.compile(
        r"\b(crash(ed|ing)?|down|dead|died|unhealthy|offline|"
        r"failed_worker)\b")
    for fault in watcher.faults:
        blob = (fault.kind + " " + fault.detail).lower()
        assert not banned.search(blob), fault.describe()
    # ...and the guard must be able to fire, or it proves nothing.
    assert banned.search("availability_worker crashed")
    assert not banned.search("missing_expected_response deadline was t12")


def test_a_late_arrival_is_not_reported_as_a_duplicate():
    """A delayed response is missing at the deadline and late when it arrives.
    Calling the arrival a duplicate would be wrong: nothing arrived twice."""
    watcher = Monitor()
    bus = Bus(observers=[watcher])
    exchange = Exchange(correlation_id=1)
    bus.emit(exchange.request(bus.tick))
    for _ in range(exchange.slack + 2):
        bus.advance()
    bus.emit(exchange.response(bus.tick))

    kinds = [f.kind for f in watcher.faults]
    assert MISSING in kinds and LATE in kinds
    assert DUPLICATE not in kinds


def test_a_genuine_duplicate_is_reported_as_one():
    watcher = Monitor()
    bus = Bus(observers=[watcher])
    exchange = Exchange(correlation_id=2)
    bus.emit(exchange.request(bus.tick))
    bus.advance()
    bus.emit(exchange.response(bus.tick))
    bus.emit(exchange.response(bus.tick))

    assert [f.kind for f in watcher.faults] == [DUPLICATE]


def test_a_response_from_the_wrong_party_is_an_identity_fault():
    watcher = Monitor()
    bus = Bus(observers=[watcher])
    exchange = Exchange(correlation_id=3)
    bus.emit(exchange.request(bus.tick))
    bus.advance()
    bus.emit(exchange.response(bus.tick, sender="stranger_worker"))

    fault = watcher.faults[0]
    assert fault.kind == UNEXPECTED_IDENTITY
    assert "stranger_worker" in fault.detail


def test_a_clean_exchange_produces_no_fault():
    watcher = Monitor()
    bus = Bus(observers=[watcher])
    exchange = Exchange(correlation_id=4)
    bus.emit(exchange.request(bus.tick))
    bus.advance()
    bus.emit(exchange.response(bus.tick))
    for _ in range(5):
        bus.advance()

    assert watcher.faults == []


# ---------------------------------------------------------------------------
# THE SCOPE GUARD. Observation creates knowledge, not authority.
# ---------------------------------------------------------------------------

def test_the_monitor_holds_no_verb_that_could_repair_anything():
    """may:  observe, correlate, detect, emit a communication fault
       NOT:  mutate the calendar, mutate the queue, invoke a worker skill,
             restart a worker, reroute work, change routing

    Step F must add every one of those explicitly. Without this guard the
    architecture drifts the way observability always drifts - sees everything,
    understands everything, controls everything."""
    forbidden = ("restart", "reroute", "retry", "cancel", "move", "create",
                 "mutate", "invoke", "execute", "repair", "heal")
    names = [n for n in dir(Monitor) if not n.startswith("__")]
    for name in names:
        for verb in forbidden:
            assert verb not in name.lower(), (name, verb)


def test_the_monitor_imports_nothing_it_could_act_through():
    source = open(monitor_mod.__file__, encoding="utf-8").read()
    for module in ("demo_reservation.skills", "demo_reservation.runtime",
                   "demo_reservation.objects", "demo_reservation.signoff",
                   "demo_reservation.world"):
        assert f"from {module}" not in source and f"import {module}" not in source


def test_the_monitor_cannot_read_the_injectors_ground_truth():
    source = open(monitor_mod.__file__, encoding="utf-8").read()
    assert "comms_faults" not in source
    assert "Injector" not in source
    assert "truth" not in source


def test_observers_receive_copies_rather_than_the_log():
    """An observer that could edit the stream could hide its own misses -
    the audit-plane mistake case 00 exists to prevent."""
    seen = []

    class Grabber:
        def observe(self, event):
            seen.append(event)

    bus = Bus(observers=[Grabber()])
    exchange = Exchange(correlation_id=5)
    bus.emit(exchange.request(bus.tick))

    assert seen and seen[0] is not bus.log()[0]
    assert isinstance(seen[0], Event)


def test_the_fault_vocabulary_was_fixed_before_the_detector():
    """Same rule as step B's disruption generator: the injector and the
    expected classification live together, written first."""
    import ast
    tree = ast.parse(open(comms_faults.__file__, encoding="utf-8").read())
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef)):
            if (node.body and isinstance(node.body[0], ast.Expr)
                    and isinstance(node.body[0].value, ast.Constant)
                    and isinstance(node.body[0].value.value, str)):
                node.body.pop(0)
    code = ast.unparse(tree).lower()
    assert "monitor" not in code, "the injector must not consult the detector"
    assert set(comms_faults.EXPECTED_FAULT) == set(comms_faults.VOCABULARY)
