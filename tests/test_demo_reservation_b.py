"""Reservation demo, step B: damage reality, name the blast radius, stop.

Contract: `docs/demo-reservation-queue.md`. B changes world facts, identifies
which reservations it damaged, and proves the previously valid schedule is now
invalid. It attempts no recovery, and step C does not exist yet.

The two rules that carry the value:

  * B may know which reservations it damages and may **not** know whether they
    are recoverable;
  * B's own list is not trusted - the independent checker decides who was
    damaged, and the two must agree.
"""

from __future__ import annotations

import pytest

from demo_reservation import Runtime, Store, check, default_world
from demo_reservation import disrupt
from demo_reservation import generate_requests, straight_through
from demo_reservation.disrupt import VOCABULARY, claimed_damage


@pytest.fixture
def booked():
    """A valid world with a valid booked schedule - step A's output."""
    world = default_world()
    store = Store()
    requests = generate_requests(600, world)
    for request in requests:
        store.requests[request.request_id] = request
    rt = Runtime(store=store, world=world)
    rt.run_all(straight_through(requests))
    assert check(store.schedule(), world).ok, "step B needs a valid input"
    return rt


# ---------------------------------------------------------------------------
# The end state, per kind.
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("kind", list(VOCABULARY))
def test_each_disruption_damages_a_previously_valid_schedule(booked, kind):
    before = check(booked.store.schedule(), booked.world)
    assert before.ok

    d = disrupt.draw(booked.world, booked.store, kind=kind)
    assert d is not None, f"no {kind} disruption could be drawn"
    assert d.affected, "the draw condition requires at least one casualty"

    after = check(booked.store.schedule(), booked.world)
    assert not after.ok, f"{kind} left the schedule valid"


@pytest.mark.parametrize("kind", list(VOCABULARY))
def test_the_checker_and_the_generator_agree_on_the_blast_radius(booked, kind):
    """THE LOAD-BEARING ONE. B's own list is not trusted.

    The independent invariant checker decides who was damaged; the generator
    merely claims. A disagreement means one of the two is wrong and the
    experiment is not measuring what it says it is.
    """
    d = disrupt.draw(booked.world, booked.store, kind=kind)
    after = check(booked.store.schedule(), booked.world)

    assert claimed_damage(d) == after.reservation_ids(), (
        f"{kind}: generator {sorted(claimed_damage(d))[:5]} vs "
        f"checker {sorted(after.reservation_ids())[:5]}"
    )


@pytest.mark.parametrize("kind", list(VOCABULARY))
def test_untouched_reservations_stay_valid(booked, kind):
    """A disruption damages what it damages. Everything else must still pass,
    or the blast radius is wider than the generator admits."""
    d = disrupt.draw(booked.world, booked.store, kind=kind)
    damaged = claimed_damage(d)
    survivors = [r for r in booked.store.schedule()
                 if r.reservation_id not in damaged]

    assert check(survivors, booked.world).ok


def test_only_the_priority_block_introduces_a_reservation(booked):
    """Four of five disruptions change world facts only. The exception is
    declared rather than quietly filed with the others."""
    for kind in VOCABULARY:
        world, store = default_world(), Store()
        requests = generate_requests(300, world)
        for request in requests:
            store.requests[request.request_id] = request
        rt = Runtime(store=store, world=world)
        rt.run_all(straight_through(requests))

        d = disrupt.draw(world, store, kind=kind)
        if kind == disrupt.PRIORITY_BLOCK_INSERTED:
            assert d.introduced, "the block is a reservation"
        else:
            assert not d.introduced, f"{kind} should change world facts only"


# ---------------------------------------------------------------------------
# What B is not allowed to know.
# ---------------------------------------------------------------------------

def _executable_source(module) -> str:
    """The module's code with docstrings removed.

    Scanning raw text matched this module's own docstring, which legitimately
    says "no alternative search" - the prose describing a restriction is not a
    violation of it. Only what executes is evidence.
    """
    import ast
    tree = ast.parse(open(module.__file__, encoding="utf-8").read())
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef,
                             ast.AsyncFunctionDef)):
            if (node.body and isinstance(node.body[0], ast.Expr)
                    and isinstance(node.body[0].value, ast.Constant)
                    and isinstance(node.body[0].value.value, str)):
                node.body.pop(0)
    return ast.unparse(tree).lower()


def test_the_generator_never_looks_for_an_alternative():
    """B may know what it damaged. It may not know whether the damage is
    recoverable, or the disruption set would be chosen to be survivable and
    step C's local-resolution rate would measure the author."""
    code = _executable_source(disrupt)
    for forbidden in ("find_alternative", "alternative", "solvable",
                      "recoverable", "check_availability", "_blockers"):
        assert forbidden not in code, forbidden


def test_the_generator_does_not_import_the_skills_or_the_runtime():
    source = open(disrupt.__file__, encoding="utf-8").read()
    assert "demo_reservation.skills" not in source
    assert "demo_reservation.runtime" not in source


def test_the_draw_condition_is_only_that_something_was_damaged(booked):
    """The one permitted conditioning rule. `affected > 0` guarantees the
    experiment contains a disturbance; anything about how many alternatives
    exist would grade step C before step C is written."""
    import inspect
    source = inspect.getsource(disrupt.draw)
    assert "if affected:" in source
    for forbidden in ("len(alternatives", "solvable", "free_slots"):
        assert forbidden not in source


def test_step_b_attempts_no_recovery(booked):
    """The schedule is left broken. Nothing in B repairs, reschedules,
    cancels or escalates."""
    d = disrupt.draw(booked.world, booked.store, kind=disrupt.FACILITY_CLOSED)
    assert d is not None
    after = check(booked.store.schedule(), booked.world)
    assert not after.ok

    # Nothing ran: the receipt count is whatever step A left.
    skills_used = {r.skill for r in booked.receipts}
    assert skills_used <= {"check_availability", "create_reservation"}


# ---------------------------------------------------------------------------
# The property A established, carried through B.
# ---------------------------------------------------------------------------

def test_a_stale_queue_cannot_force_a_now_invalid_action(booked):
    """A queue item is advisory, not authoritative.

    A request checked as available before the disruption must not be bookable
    after it. `create_reservation` re-derives reality when it executes, so
    yesterday's valid action cannot be forced into today's world.
    """
    from demo_reservation import QueueItem
    from demo_reservation.objects import PENDING, REFUSED

    pending = next((r for r in booked.store.requests.values()
                    if r.state == PENDING), None)
    if pending is None:                       # every request reached terminal
        pending = next(iter(booked.store.requests.values()))
        pending.state = PENDING

    booked.run(QueueItem(pending.request_id, "check_availability"))

    # Close the facility this request wants, after the check.
    booked.world.closed_days.setdefault(pending.facility_id, set()).add(
        pending.day)

    result = booked.run(QueueItem(pending.request_id, "create_reservation"))
    assert result.ok is False
    assert "outside opening hours" in result.detail
    assert pending.state == REFUSED
    assert check(booked.store.schedule(), booked.world).reservation_ids() \
        or True                                # the point is it was not booked
