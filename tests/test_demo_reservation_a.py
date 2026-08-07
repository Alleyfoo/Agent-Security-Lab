"""Reservation demo, step A: the boring foundation.

Contract: `docs/demo-reservation-queue.md`. Step A freezes the world, the queue
semantics, the bounded skill set and an independent invariant checker, and
implements nothing that resolves a problem.

The scope guards at the end matter as much as the mechanics. Step A drifting
into step C would mean the eventual local-resolution rate measures code that
was written before the disruption generator existed - which is the failure case
18 had to unpick.
"""

from __future__ import annotations

import pytest

from demo_reservation import (
    QueueItem, Reservation, Runtime, Store, check, default_world,
    generate_requests, straight_through,
)
from demo_reservation import invariants, runtime as runtime_mod, skills
from demo_reservation.objects import BOOKED, PENDING, REFUSED
from demo_reservation.world import DAYS


@pytest.fixture
def world():
    return default_world()


@pytest.fixture
def loaded(world):
    store = Store()
    requests = generate_requests(200, world)
    for request in requests:
        store.requests[request.request_id] = request
    return Runtime(store=store, world=world), requests


# ---------------------------------------------------------------------------
# The end state: correct mechanics, uninteresting numbers.
# ---------------------------------------------------------------------------

def test_a_clean_run_leaves_a_valid_schedule(loaded, world):
    rt, requests = loaded
    rt.run_all(straight_through(requests))

    report = check(rt.store.schedule(), world)
    assert report.ok, report.summary()


def test_every_request_reaches_a_terminal_state(loaded):
    rt, requests = loaded
    rt.run_all(straight_through(requests))

    states = {r.state for r in rt.store.requests.values()}
    assert PENDING not in states, "the queue drained"
    assert states <= {BOOKED, REFUSED}


def test_the_queue_drains_and_every_item_leaves_a_receipt(loaded):
    rt, requests = loaded
    queue = straight_through(requests)
    rt.run_all(queue)
    assert len(rt.receipts) == len(queue)


def test_a_clean_run_makes_no_unauthorised_transition(loaded):
    rt, requests = loaded
    rt.run_all(straight_through(requests))
    assert rt.refused_transitions == 0


def test_refusals_come_from_contention_not_from_the_generator(loaded):
    """The generator produces physically plausible requests, so a refusal means
    two requests wanted the same room at the same time.

    An early version chose facilities at random and produced 342 refusals for
    missing features against 98 from contention - the signal steps B and C need
    was drowned by noise the generator invented. Nothing here consults the
    schedule, which is the line between *plausible* and *aimed*.
    """
    rt, requests = loaded
    rt.run_all(straight_through(requests))

    refusals = [r for r in rt.receipts
                if r.skill == "create_reservation" and not r.ok]
    assert refusals, "a full month should produce contention"
    assert all("occupied" in r.detail for r in refusals), (
        {r.detail for r in refusals}
    )


# ---------------------------------------------------------------------------
# The architectural claim: permission comes from the object, not the queue.
# ---------------------------------------------------------------------------

def test_a_skill_the_object_state_forbids_is_refused_and_counted(loaded):
    rt, requests = loaded
    rt.run_all(straight_through(requests))

    booked = next(r for r in rt.store.requests.values() if r.state == BOOKED)
    before = rt.refused_transitions

    # create_reservation is permitted only for a pending request.
    result = rt.run(QueueItem(booked.request_id, "create_reservation"))

    assert result is None
    assert rt.refused_transitions == before + 1
    assert rt.receipts[-1].refused_transition is True
    assert "not permitted" in rt.receipts[-1].detail


def test_the_refused_transition_changes_nothing(loaded):
    rt, requests = loaded
    rt.run_all(straight_through(requests))

    booked = next(r for r in rt.store.requests.values() if r.state == BOOKED)
    before = len(rt.store.schedule())
    rt.run(QueueItem(booked.request_id, "create_reservation"))
    assert len(rt.store.schedule()) == before


def test_an_unapproved_skill_is_absent_rather_than_denied(loaded):
    """`find_alternative` was the example here until step C approved it, which
    is the guard doing its job rather than failing. The claim is unchanged:
    a name that is not in the registry produces an absence, not a denial."""
    rt, _requests = loaded
    with pytest.raises(runtime_mod.UnknownSkill):
        rt.run(QueueItem("req_00000", "delete_everything"))


def test_an_unknown_object_is_refused(loaded):
    rt, _requests = loaded
    with pytest.raises(runtime_mod.UnknownObject):
        rt.run(QueueItem("req_99999", "check_availability"))


def test_create_rechecks_rather_than_trusting_the_queue(loaded, world):
    """The advisory check may be stale. If `create_reservation` trusted it the
    queue would be authoritative about the outcome, which is the shape this
    architecture exists to avoid."""
    rt, requests = loaded
    first = requests[0]

    rt.run(QueueItem(first.request_id, "check_availability"))
    assert first.last_check is True

    # Someone else takes the slot between the check and the attempt.
    rt.store.reservations["res_squat"] = Reservation(
        reservation_id="res_squat", request_id="other",
        facility_id=first.facility_id, day=first.day,
        start=first.start, end=first.end, activity="squatter",
        participants=1)

    result = rt.run(QueueItem(first.request_id, "create_reservation"))
    assert result.ok is False
    assert "occupied" in result.detail
    assert first.state == REFUSED


def test_cancelling_frees_the_slot(loaded):
    rt, requests = loaded
    rt.run_all(straight_through(requests))
    booked = next(r for r in rt.store.requests.values() if r.state == BOOKED)

    result = rt.run(QueueItem(booked.request_id, "cancel_reservation"))
    assert result.ok is True
    assert rt.store.reservations[booked.reservation_id].state == "cancelled"
    assert all(r.reservation_id != booked.reservation_id
               for r in rt.store.schedule())


# ---------------------------------------------------------------------------
# The invariant checker, and its independence.
# ---------------------------------------------------------------------------

def test_the_checker_imports_neither_the_skills_nor_the_runtime():
    """THE LOAD-BEARING ONE. A checker that went through the code which
    produced the schedule would confirm the producer agrees with itself."""
    source = open(invariants.__file__, encoding="utf-8").read()
    assert "demo_reservation.skills" not in source
    assert "demo_reservation.runtime" not in source
    assert "import skills" not in source and "import runtime" not in source


@pytest.mark.parametrize("invariant,mutate", [
    ("no_overlap", lambda r: None),
    ("inside_opening_hours", lambda r: setattr(r, "start", 2 * 60)),
    ("capacity_sufficient", lambda r: setattr(r, "participants", 9999)),
    ("features_satisfied", lambda r: setattr(r, "requires",
                                             frozenset({"helipad"}))),
    ("facility_exists", lambda r: setattr(r, "facility_id", "hall_z")),
    ("start_before_end", lambda r: setattr(r, "end", r.start)),
    ("day_in_range", lambda r: setattr(r, "day", DAYS + 5)),
])
def test_the_checker_catches_each_violation(loaded, world, invariant, mutate):
    rt, requests = loaded
    rt.run_all(straight_through(requests))
    schedule = rt.store.schedule()
    assert check(schedule, world).ok

    victim = schedule[0]
    if invariant == "no_overlap":
        schedule.append(Reservation(
            reservation_id="res_clash", request_id="clash",
            facility_id=victim.facility_id, day=victim.day,
            start=victim.start, end=victim.end, activity="clash",
            participants=1, requires=frozenset()))
    else:
        mutate(victim)

    report = check(schedule, world)
    assert not report.ok
    assert invariant in report.by_invariant(), report.summary()


def test_an_empty_schedule_is_valid(world):
    assert check([], world).ok


# ---------------------------------------------------------------------------
# Scope guards. Step A must not drift into step C.
# ---------------------------------------------------------------------------

STEP_A_SKILLS = {
    "check_availability": ("pending",),
    "create_reservation": ("pending",),
    "cancel_reservation": ("booked",),
    "query_schedule": ("pending", "booked", "refused"),
}


def test_step_as_four_skills_are_present_and_unchanged():
    """Step C added two skills, which is legitimate and is asserted in that
    step's own file. What must not drift is step A's four: the same names with
    the same permitted states, so a later step cannot quietly widen when a
    worker may create or cancel a booking."""
    for name, states in STEP_A_SKILLS.items():
        assert name in skills.REGISTRY, name
        assert skills.REGISTRY[name].permitted_states == states, name


def test_no_step_beyond_c_has_added_a_skill_without_saying_so():
    """The registry is shared, so this is where an unannounced seventh skill
    would show up first."""
    assert set(skills.REGISTRY) == set(STEP_A_SKILLS) | {
        "find_alternative", "move_reservation",
    }


def test_the_resolution_logic_arrived_after_the_disruption_generator():
    """Step A's version of this guard forbade `find_alternative` outright, and
    step C approved it - so the guard is rewritten rather than deleted.

    What it protects is unchanged and is the reason the ordering mattered:
    `disrupt.py` was written before any resolution logic existed, so the
    disruption set cannot have been chosen to be survivable. The guard is now
    on the generator rather than on the skills, and lives in step B's file.
    Here it remains true that the *checker* and the *runtime* search for
    nothing.
    """
    for module in (runtime_mod, invariants):
        source = open(module.__file__, encoding="utf-8").read().lower()
        for forbidden in ("def find_alternative", "def escalate",
                          "def raise_exception", "class exception"):
            assert forbidden not in source, (module.__name__, forbidden)


def test_the_demo_does_not_import_the_object_model():
    """Cases 10 and 11 published tables against object_model's registry. The
    idioms are shared; the code is not."""
    import demo_reservation
    for module in (demo_reservation, skills, runtime_mod, invariants):
        source = open(module.__file__, encoding="utf-8").read()
        assert "from object_model" not in source
        assert "import object_model" not in source


def test_generated_requests_are_well_formed():
    for request in generate_requests(300):
        assert request.start < request.end
        assert 0 <= request.day < DAYS
        assert request.participants > 0
        assert request.state == PENDING
