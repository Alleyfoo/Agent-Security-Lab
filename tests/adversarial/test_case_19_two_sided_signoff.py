"""Case 19 - two-sided sign-off, built naively and then tightened one rung.

The first slice of the target architecture, built the way this repository
requires: start with the version that looks correct, prove it fails, then add
one condition at a time and measure what each buys.

The prediction was written into docs/target-architecture.md before any of this
existed: the naive implementation measures a minimum tamper set of 1.
"""

from __future__ import annotations

import importlib.util
import os
import sys

import pytest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))
CASE_DIR = os.path.join(REPO_ROOT, "cases", "19-two-sided-signoff")

if CASE_DIR not in sys.path:
    sys.path.insert(0, CASE_DIR)


def _load(name: str):
    spec = importlib.util.spec_from_file_location(
        f"case19_{name}", os.path.join(CASE_DIR, f"{name}.py"))
    module = importlib.util.module_from_spec(spec)
    sys.modules[f"case19_{name}"] = module
    spec.loader.exec_module(module)
    return module


s = _load("signoff")


@pytest.fixture
def cells():
    return s.measure()


# ---------------------------------------------------------------------------
# The pre-registered prediction.
# ---------------------------------------------------------------------------

def test_the_naive_implementation_measures_one(cells):
    """PRE-REGISTERED. Written into the design document before the code."""
    assert s.minimum(cells, s.R0.name, "Level 1") == 1


def test_the_naive_implementation_fails_two_independent_ways(cells):
    """A single route would be a bug. Two independent routes is a design that
    looks like two-sided sign-off and proves almost nothing."""
    routes = {c.attack for c in cells
              if c.rung == s.R0.name and c.adversary == "Level 1" and c.obtained}
    assert routes == {"worker signs its own approval",
                      "action swapped after approval"}


def test_binding_the_action_opens_a_route_the_naive_version_did_not_have(cells):
    """THE CASE'S BEST FINDING, and the reason for building it naively first.

    R0 matches an approval by request id, so replaying an old approval under a
    new request finds nothing. R1 matches by *content* - which is the design
    document's own recommendation - and any past approval of the same action
    now matches by construction.

    So the rung that closes swapping simultaneously opens replay. The route
    count does not move at R1; the routes are simply different ones, and a
    review that counted defects rather than naming them would have called that
    progress.
    """
    assert _cell(cells, s.R0, "Level 1", "old approval replayed").obtained is False
    assert _cell(cells, s.R1, "Level 1", "old approval replayed").obtained is True


# ---------------------------------------------------------------------------
# What each rung actually bought.
# ---------------------------------------------------------------------------

def _cell(cells, rung, adversary, attack):
    return next(c for c in cells if c.rung == rung.name
                and c.adversary == adversary and c.attack == attack)


def test_binding_the_action_closes_swapping_and_nothing_else(cells):
    """R1 closes a class and does not move the number. Binding says what was
    agreed, not who agreed to it."""
    assert _cell(cells, s.R0, "Level 1",
                 "action swapped after approval").obtained is True
    assert _cell(cells, s.R1, "Level 1",
                 "action swapped after approval").obtained is False
    assert _cell(cells, s.R1, "Level 1",
                 "worker signs its own approval").obtained is True
    assert s.minimum(cells, s.R1.name, "Level 1") == 1


def test_credential_independence_closes_self_approval_and_nothing_else(cells):
    assert _cell(cells, s.R2, "Level 1",
                 "worker signs its own approval").obtained is False
    assert _cell(cells, s.R2, "Level 1",
                 "old approval replayed").obtained is True
    assert s.minimum(cells, s.R2.name, "Level 1") == 1


def test_append_only_closes_nothing_on_this_plane(cells):
    """The honest negative. Cases 10 and 11's record shape refuses a *second*
    approval of a digest; replay reuses the *first*, so it does not help.

    This was mis-stated in a first draft of the case summary, which claimed
    R3 closed replay. It does not, and the measurement said so.
    """
    for attack in ("worker signs its own approval",
                   "action swapped after approval", "old approval replayed"):
        assert (_cell(cells, s.R2, "Level 1", attack).obtained
                == _cell(cells, s.R3, "Level 1", attack).obtained)
    assert s.minimum(cells, s.R3.name, "Level 1") == 1


def test_one_use_is_what_finally_moves_the_level_1_result(cells):
    """A lifecycle rule, not an independence layer. Three rungs of
    independence did not do what one rule about spending did."""
    assert s.minimum(cells, s.R4.name, "Level 1") is None
    assert _cell(cells, s.R4, "Level 1",
                 "old approval replayed").obtained is False


@pytest.mark.parametrize("rung", list(s.RUNGS))
def test_every_refusal_names_its_reason(cells, rung):
    """Assert on the denial reason, not merely that something raised - the
    repository's adversarial-test-first rule."""
    for c in cells:
        if c.rung == rung.name and not c.obtained:
            assert c.note.startswith("REFUSED: "), c
            assert len(c.note) > 20


# ---------------------------------------------------------------------------
# The bottom line no rung changes.
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("rung", list(s.RUNGS))
def test_level_1_5_stays_at_one_commit_at_every_rung(cells, rung):
    """THE RESULT. Two-sided sign-off is a Level 1 control.

    The configuration adversary appends an approval or adds the worker to the
    reviewer list. No arrangement of records inside the same writable boundary
    raises that, which is the cross-cutting finding arriving at the approval
    plane.

    If this ever fails, something has moved a record outside the adversary's
    reach and the case's conclusion needs rewriting - not this assertion.
    """
    assert s.minimum(cells, rung.name, "Level 1.5") == 1


def test_no_rung_has_gate_independence():
    """Stated so a reader cannot infer it from the independence column. The
    gate is ordinary in-process code at every rung."""
    for rung in s.RUNGS:
        assert "gate" not in rung.independence


# ---------------------------------------------------------------------------
# Properties of the design itself.
# ---------------------------------------------------------------------------

def test_request_id_is_not_security_sensitive():
    """The design condition from the target architecture: authority binds to
    action content, and the request id is a correlation identifier only."""
    import dataclasses
    fields = {f.name for f in dataclasses.fields(s.Action)}
    assert "request_id" not in fields

    a = s.action("release_payment", amount="1", destination="x")
    b = s.action("release_payment", amount="1", destination="x")
    assert a.digest() == b.digest(), "the digest depends on content alone"


def test_the_digest_covers_every_part_of_the_action():
    """Skill, object, parameters and object version must all change it, or a
    class the design claims to close is open."""
    base = s.action("release_payment", "obj_1", 1, amount="1")
    assert base.digest() != s.action("other_skill", "obj_1", 1,
                                     amount="1").digest()
    assert base.digest() != s.action("release_payment", "obj_2", 1,
                                     amount="1").digest()
    assert base.digest() != s.action("release_payment", "obj_1", 2,
                                     amount="1").digest()
    assert base.digest() != s.action("release_payment", "obj_1", 1,
                                     amount="2").digest()


def test_an_honest_run_still_executes_at_every_rung():
    """A gate that refuses everything is not a control, it is an outage."""
    for rung in s.RUNGS:
        s.reset()
        s.propose(s.WORKER, "req-ok", s.DANGEROUS)
        s.approve(s.REVIEWER, "req-ok", s.DANGEROUS.digest(), rung)
        assert s.execute("req-ok", rung) == s.DANGEROUS
