"""Reservation demo, step D: displacing a confirmed reservation needs a second
authority.

The rule is attached to the **kind of transformation**, not to a risk score:
creating a new booking stays local; modifying somebody's confirmed one is
protected.

Design and limits inherited from cases 19-22 rather than re-derived. In
particular this is a **Level 1 control** and the store and gate boundaries are
**modelled**, not enforced - case 23 is blocked, and nothing here upgrades that.
"""

from __future__ import annotations

import pytest

from demo_reservation import QueueItem, Runtime, Store, check, signoff
from demo_reservation import skills as skills_mod
from demo_reservation.objects import BOOKED, Reservation, ReservationRequest
from demo_reservation.run_d import LEGACY, PROTECTED
from demo_reservation.world import Facility, OpeningHours, World


def small_world():
    hours = OpeningHours({d: (19 * 60, 22 * 60) for d in range(7)})
    return World(facilities={
        "hall_a": Facility("hall_a", "Hall A", 20, frozenset({"mats"}), hours),
        "hall_b": Facility("hall_b", "Hall B", 20, frozenset({"mats"}), hours),
    })


@pytest.fixture
def displaceable():
    """One confirmed booking in hall_a whose room has just closed."""
    world = small_world()
    store = Store()
    request = ReservationRequest(
        request_id="req_a", facility_id="hall_a", day=0, start=19 * 60,
        end=20 * 60, activity="x", participants=5,
        requires=frozenset({"mats"}), state=BOOKED, reservation_id="res_a")
    store.requests["req_a"] = request
    store.reservations["res_a"] = Reservation(
        reservation_id="res_a", request_id="req_a", facility_id="hall_a",
        day=0, start=19 * 60, end=20 * 60, activity="x", participants=5,
        requires=frozenset({"mats"}))
    world.closed_days["hall_a"] = set(range(28))

    rt = Runtime(store=store, world=world, worker_skills=set(PROTECTED),
                 signoff=signoff.SignoffStore())
    rt.run(QueueItem("req_a", "find_alternative"))
    assert request.candidate is not None
    return rt, request


def _action(rt, request):
    return signoff.displacement_for(
        rt.store.reservations[request.reservation_id],
        request.candidate, request.version)


# ---------------------------------------------------------------------------
# The three paths the direction named.
# ---------------------------------------------------------------------------

def test_valid_proposal_and_valid_approval_displaces(displaceable):
    rt, request = displaceable
    rt.run(QueueItem("req_a", "propose_displacement"))
    rt.signoff.approve(signoff.REVIEWER, _action(rt, request).digest())

    result = rt.run(QueueItem("req_a", "execute_displacement"))
    assert result.ok is True
    assert rt.store.reservations["res_a"].facility_id == "hall_b"
    assert check(rt.store.schedule(), rt.world).ok


def test_a_proposal_without_an_approval_cannot_displace(displaceable):
    rt, request = displaceable
    rt.run(QueueItem("req_a", "propose_displacement"))

    result = rt.run(QueueItem("req_a", "execute_displacement"))
    assert result.ok is False
    assert "no approval attests" in result.detail
    assert rt.store.reservations["res_a"].facility_id == "hall_a"


def test_an_approval_for_one_action_cannot_execute_another(displaceable):
    """Case 19's R1 in the demo: authority binds to action content.

    The reviewer approves a move to hall_b day 0. The worker then aims at a
    different day, which is a different action and a different digest.
    """
    rt, request = displaceable
    rt.run(QueueItem("req_a", "propose_displacement"))
    approved = _action(rt, request)
    rt.signoff.approve(signoff.REVIEWER, approved.digest())

    facility_id, _day, start = request.candidate
    request.candidate = (facility_id, 3, start)          # a different action

    result = rt.run(QueueItem("req_a", "execute_displacement"))
    assert result.ok is False
    assert ("no proposal attests" in result.detail
            or "no approval attests" in result.detail)
    assert rt.store.reservations["res_a"].day == 0


# ---------------------------------------------------------------------------
# Inherited from cases 19 and 20.
# ---------------------------------------------------------------------------

def test_the_worker_cannot_approve_its_own_displacement(displaceable):
    """Credential independence - case 19's R2, the rung that made the
    mechanism mean anything."""
    rt, request = displaceable
    rt.run(QueueItem("req_a", "propose_displacement"))

    with pytest.raises(signoff.SignoffRefused) as exc:
        rt.signoff.approve(signoff.WORKER, _action(rt, request).digest())
    assert "not an authorised reviewer" in str(exc.value)


def test_an_approval_is_spent_by_one_execution(displaceable):
    """Case 19's R4 and case 20's claim: one occurrence, not one action."""
    rt, request = displaceable
    rt.run(QueueItem("req_a", "propose_displacement"))
    action = _action(rt, request)
    rt.signoff.approve(signoff.REVIEWER, action.digest())
    assert rt.run(QueueItem("req_a", "execute_displacement")).ok

    # Aim at the same action again and replay the spent approval.
    request.candidate = action.to_slot
    result = rt.run(QueueItem("req_a", "execute_displacement"))
    assert result.ok is False
    assert "already spent" in result.detail or "no proposal" in result.detail


def test_the_version_moves_with_the_reservation(displaceable):
    """An approval naming the slot a reservation used to be in cannot
    authorise a move from where it is now."""
    rt, request = displaceable
    before = request.version
    rt.run(QueueItem("req_a", "propose_displacement"))
    rt.signoff.approve(signoff.REVIEWER, _action(rt, request).digest())
    rt.run(QueueItem("req_a", "execute_displacement"))
    assert request.version == before + 1


def test_the_gate_still_applies_the_physical_checks(displaceable):
    """An approval authorises an action; it cannot conjure a free room."""
    rt, request = displaceable
    rt.run(QueueItem("req_a", "propose_displacement"))
    rt.signoff.approve(signoff.REVIEWER, _action(rt, request).digest())

    facility_id, day, start = request.candidate
    rt.store.reservations["res_squat"] = Reservation(
        reservation_id="res_squat", request_id="other",
        facility_id=facility_id, day=day, start=start, end=start + 60,
        activity="squat", participants=1)

    result = rt.run(QueueItem("req_a", "execute_displacement"))
    assert result.ok is False
    assert "taken since the search" in result.detail


# ---------------------------------------------------------------------------
# Case 22's finding, in the demo.
# ---------------------------------------------------------------------------

def test_the_protected_profile_refuses_the_unprotected_verb(displaceable):
    rt, request = displaceable
    before = rt.refused_transitions

    result = rt.run(QueueItem("req_a", "move_reservation"))

    assert result is None
    assert rt.refused_transitions == before + 1
    assert "not in this worker's skill set" in rt.receipts[-1].detail
    assert rt.store.reservations["res_a"].facility_id == "hall_a"


def test_leaving_the_unprotected_verb_exported_defeats_the_whole_thing():
    """THE FINDING, and case 22 predicted it: a boundary is only as narrow as
    the transformations it exports.

    Same world, same damage, same sign-off store - and a worker that still
    holds `move_reservation` displaces a confirmed booking with no proposal
    and no approval in existence.
    """
    world = small_world()
    store = Store()
    request = ReservationRequest(
        request_id="req_a", facility_id="hall_a", day=0, start=19 * 60,
        end=20 * 60, activity="x", participants=5,
        requires=frozenset({"mats"}), state=BOOKED, reservation_id="res_a")
    store.requests["req_a"] = request
    store.reservations["res_a"] = Reservation(
        reservation_id="res_a", request_id="req_a", facility_id="hall_a",
        day=0, start=19 * 60, end=20 * 60, activity="x", participants=5,
        requires=frozenset({"mats"}))
    world.closed_days["hall_a"] = set(range(28))

    rt = Runtime(store=store, world=world, worker_skills=set(LEGACY),
                 signoff=signoff.SignoffStore())
    rt.run(QueueItem("req_a", "find_alternative"))
    result = rt.run(QueueItem("req_a", "move_reservation"))

    assert result.ok is True, "the old verb still works"
    assert rt.store.reservations["res_a"].facility_id == "hall_b"
    assert rt.signoff.proposals == [] and rt.signoff.approvals == []
    assert rt.signoff.executed == [], "sign-off was never involved"


# ---------------------------------------------------------------------------
# The comparison the rule exists to make.
# ---------------------------------------------------------------------------

def test_creating_a_new_reservation_is_not_protected():
    """Authority is attached to the kind of transformation. A worker may make
    a new booking alone; it may not modify somebody else's."""
    world = small_world()
    store = Store()
    request = ReservationRequest(
        request_id="req_new", facility_id="hall_a", day=0, start=19 * 60,
        end=20 * 60, activity="x", participants=5,
        requires=frozenset({"mats"}))
    store.requests["req_new"] = request

    rt = Runtime(store=store, world=world, worker_skills=set(PROTECTED),
                 signoff=signoff.SignoffStore())
    result = rt.run(QueueItem("req_new", "create_reservation"))

    assert result.ok is True
    assert rt.signoff.approvals == [], "no sign-off was needed or used"


def test_step_d_added_exactly_two_skills():
    assert {"propose_displacement", "execute_displacement"} <= set(
        skills_mod.REGISTRY)
    assert "move_reservation" not in PROTECTED
    assert "move_reservation" in LEGACY
