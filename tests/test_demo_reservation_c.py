"""Reservation demo, step C: local resolution judged by an oracle it cannot see.

Contract: `docs/demo-reservation-queue.md`. The agents get `find_alternative`
and `move_reservation`. The independent checker decides whether the resulting
schedule is valid; the independent oracle decides whether the unresolved ones
had to be.

Most of this file tests the **instrument** rather than the agents. A three-way
verdict that cannot tell its three cases apart would make every number in the
demo meaningless, and the demo's first run happened to produce none of the
interesting middle case - so the discrimination is proved here on constructed
scenarios instead of hoped for.
"""

from __future__ import annotations

import pytest

from demo_reservation import QueueItem, Runtime, Store, check, oracle
from demo_reservation import skills as skills_mod
from demo_reservation import runtime as runtime_mod
from demo_reservation.objects import (
    BOOKED, UNRESOLVED, Reservation, ReservationRequest,
)
from demo_reservation.world import Facility, OpeningHours, World


# ---------------------------------------------------------------------------
# A tiny hand-checkable world: two rooms, one day, two usable slots.
# ---------------------------------------------------------------------------

# Weekday 0 recurs on days 0, 7, 14 and 21 in a 28-day month. An earlier
# version of these tests assumed "close day 0" meant "no Mondays left" and
# every scenario quietly had three spare weeks in it.
MONDAYS = (0, 7, 14, 21)


def tiny_world(hall_b_features=frozenset({"mats"})):
    hours = OpeningHours({0: (19 * 60, 21 * 60)})       # 19:00-21:00, Mondays
    return World(facilities={
        "hall_a": Facility("hall_a", "Hall A", 20, frozenset({"mats"}), hours),
        "hall_b": Facility("hall_b", "Hall B", 20, hall_b_features, hours),
    })


def only_one_monday(world):
    """Leave day 0 as the single usable day, so the scenarios are as small as
    they claim to be."""
    for facility_id in world.ids():
        world.closed_days.setdefault(facility_id, set()).update(MONDAYS[1:])
    return world


def close_completely(world, facility_id):
    world.closed_days.setdefault(facility_id, set()).update(range(28))


def _executable_source(module_or_fn) -> str:
    """Code with docstrings stripped. Scanning raw text matched a docstring
    that *describes* the separation - prose about a restriction is not a
    violation of it, and this file made that mistake once already."""
    import ast
    import inspect
    import textwrap
    tree = ast.parse(textwrap.dedent(inspect.getsource(module_or_fn)))
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef,
                             ast.AsyncFunctionDef)):
            if (node.body and isinstance(node.body[0], ast.Expr)
                    and isinstance(node.body[0].value, ast.Constant)
                    and isinstance(node.body[0].value.value, str)):
                node.body.pop(0)
    return ast.unparse(tree).lower()


def booking(rid, facility, day=0, start=19 * 60, dur=60, requires=frozenset()):
    return Reservation(
        reservation_id=rid, request_id=f"req_{rid}", facility_id=facility,
        day=day, start=start, end=start + dur, activity="x", participants=5,
        requires=requires)


# ---------------------------------------------------------------------------
# The oracle solves jointly. This is the frozen design decision.
# ---------------------------------------------------------------------------

def test_two_reservations_each_have_a_slot_but_not_two():
    """A per-reservation oracle answers yes twice and is wrong.

    One room, one day, two hours, two one-hour bookings needing the same
    room - fine. Make it one room and one usable hour and the individual
    answers stay yes while the joint answer is no.
    """
    world = only_one_monday(tiny_world())
    # Only hall_a is usable (hall_b lacks the feature), and only 19:00-20:00
    # is free because 20:00-21:00 is taken by a survivor.
    world.features_removed["hall_b"] = {"mats"}
    fixed = [booking("res_keep", "hall_a", start=20 * 60)]
    a = booking("res_a", "hall_a", requires=frozenset({"mats"}))
    b = booking("res_b", "hall_a", requires=frozenset({"mats"}))

    assert oracle.feasible([a], fixed, world).answer == oracle.YES
    assert oracle.feasible([b], fixed, world).answer == oracle.YES
    joint = oracle.feasible([a, b], fixed, world)
    assert joint.answer == oracle.NO, (
        "each fits alone; both cannot fit together, and only a joint search "
        "can say so"
    )


def test_a_yes_carries_a_witness_the_checker_validates():
    """The oracle is not trusted either. Its positive answers are rebuilt into
    a schedule and handed to the same independent invariant checker."""
    world = tiny_world()
    a = booking("res_a", "hall_a", requires=frozenset({"mats"}))
    b = booking("res_b", "hall_a", requires=frozenset({"mats"}))

    verdict = oracle.feasible([a, b], [], world)
    assert verdict.answer == oracle.YES
    assert verdict.witness is not None
    assert oracle.verify_witness(verdict, [a, b], [], world)


def test_a_bad_witness_is_rejected_by_the_checker():
    """If the oracle ever produced an invalid assignment, verification catches
    it - which is the point of verifying rather than believing."""
    world = tiny_world()
    a = booking("res_a", "hall_a", requires=frozenset({"mats"}))
    b = booking("res_b", "hall_a", requires=frozenset({"mats"}))

    forged = oracle.Verdict(oracle.YES, witness={
        "res_a": ("hall_a", 0, 19 * 60),
        "res_b": ("hall_a", 0, 19 * 60),        # same slot: an overlap
    })
    assert not oracle.verify_witness(forged, [a, b], [], world)


def test_running_out_of_budget_answers_unknown_not_no():
    """`unknown` is counted rather than rounded to whichever side flatters
    the result."""
    world = tiny_world()
    to_place = [booking(f"res_{i}", "hall_a", requires=frozenset({"mats"}))
                for i in range(8)]
    verdict = oracle.feasible(to_place, [], world, budget=3)
    assert verdict.answer == oracle.UNKNOWN
    assert "budget" in verdict.note


# ---------------------------------------------------------------------------
# The three verdicts, each on a constructed scenario.
# ---------------------------------------------------------------------------

def test_genuinely_impossible(tmp_path):
    """No complete recovery existed even before the agent touched anything."""
    world = only_one_monday(tiny_world())
    world.features_removed["hall_a"] = {"mats"}
    world.features_removed["hall_b"] = {"mats"}
    damaged = [booking("res_a", "hall_a", requires=frozenset({"mats"}))]

    outcome = oracle.classify(damaged, [], damaged, [], world)
    assert outcome.genuinely_impossible == ["res_a"]
    assert not outcome.false_escalations and not outcome.dead_ends


def test_false_escalation():
    """The agent gave up while a solution still existed from the state as it
    stood."""
    world = tiny_world()
    damaged = [booking("res_a", "hall_a", requires=frozenset({"mats"}))]

    outcome = oracle.classify(damaged, [], damaged, [], world)
    assert outcome.false_escalations == ["res_a"]
    assert not outcome.genuinely_impossible and not outcome.dead_ends


def test_self_created_dead_end():
    """THE INTERESTING ONE, and it is invisible to any per-reservation oracle.

    A can use either hour; B can only use the first. A complete recovery
    existed. A greedy agent takes the first hour for A, and B now has nowhere
    to go - every individual action legitimate, the strategy rubbish.
    """
    hours = OpeningHours({0: (19 * 60, 20 * 60)})    # exactly one hour
    world = only_one_monday(World(facilities={
        "hall_a": Facility("hall_a", "Hall A", 20,
                           frozenset({"mats", "ring"}), hours),
        "hall_b": Facility("hall_b", "Hall B", 20, frozenset({"mats"}), hours),
    }))

    # A fits in either room. B needs the ring, which only hall_a has.
    a = booking("res_a", "hall_a", requires=frozenset({"mats"}))
    b = booking("res_b", "hall_a", requires=frozenset({"ring"}))

    initial = oracle.feasible([a, b], [], world)
    assert initial.answer == oracle.YES, "A -> hall_b, B -> hall_a exists"

    # First fit walks the facilities in order, so the agent puts A in hall_a -
    # legitimate on its own, and the only room B could have used.
    a_moved = booking("res_a", "hall_a", requires=frozenset({"mats"}))
    outcome = oracle.classify([a, b], [], [b], [a_moved], world)

    assert outcome.dead_ends == ["res_b"]
    assert not outcome.genuinely_impossible and not outcome.false_escalations


# ---------------------------------------------------------------------------
# The oracle is evaluator-only.
# ---------------------------------------------------------------------------

def test_the_agents_cannot_reach_the_oracle():
    """A worker that could read the witness would be measuring the oracle
    rather than itself."""
    for module in (skills_mod, runtime_mod):
        assert "oracle" not in _executable_source(module), module.__name__


def test_the_agent_search_shares_no_code_with_the_oracle():
    """`find_alternative` is greedy first-fit; `oracle.feasible` is a joint
    backtracking search. If they were one routine the false-escalation metric
    would be the agent grading its own homework."""
    agent = _executable_source(skills_mod.find_alternative)
    assert "feasible" not in agent and "witness" not in agent
    assert "backtrack" not in agent


# ---------------------------------------------------------------------------
# The skills themselves.
# ---------------------------------------------------------------------------

@pytest.fixture
def one_damaged():
    world = tiny_world()
    store = Store()
    request = ReservationRequest(
        request_id="req_res_a", facility_id="hall_a", day=0,
        start=19 * 60, end=20 * 60, activity="x", participants=5,
        requires=frozenset({"mats"}), state=BOOKED, reservation_id="res_a")
    store.requests[request.request_id] = request
    store.reservations["res_a"] = booking(
        "res_a", "hall_a", requires=frozenset({"mats"}))
    return Runtime(store=store, world=world), request


def test_find_alternative_then_move_repairs_the_schedule(one_damaged):
    rt, request = one_damaged
    close_completely(rt.world, "hall_a")         # the damage

    assert not check(rt.store.schedule(), rt.world).ok

    rt.run(QueueItem(request.request_id, "find_alternative"))
    rt.run(QueueItem(request.request_id, "move_reservation"))

    assert check(rt.store.schedule(), rt.world).ok
    assert rt.store.reservations["res_a"].facility_id == "hall_b"


def test_no_candidate_makes_the_request_unresolved(one_damaged):
    rt, request = one_damaged
    close_completely(rt.world, "hall_a")
    close_completely(rt.world, "hall_b")

    result = rt.run(QueueItem(request.request_id, "find_alternative"))
    assert result.ok is False
    assert request.state == UNRESOLVED
    assert request.candidate is None


def test_move_rederives_rather_than_trusting_the_candidate(one_damaged):
    """The candidate is advisory in exactly the way `last_check` is."""
    rt, request = one_damaged
    close_completely(rt.world, "hall_a")
    rt.run(QueueItem(request.request_id, "find_alternative"))
    assert request.candidate is not None

    # Someone takes the candidate slot between the search and the move.
    facility_id, day, start = request.candidate
    rt.store.reservations["res_squat"] = booking(
        "res_squat", facility_id, day=day, start=start)

    result = rt.run(QueueItem(request.request_id, "move_reservation"))
    assert result.ok is False
    assert "taken since the search" in result.detail


def test_step_cs_six_skills_are_still_present():
    """Step D added two more, which its own file asserts. What must not drift
    is that step C's six are all still here."""
    assert {
        "check_availability", "create_reservation", "cancel_reservation",
        "query_schedule", "find_alternative", "move_reservation",
    } <= set(skills_mod.REGISTRY)
