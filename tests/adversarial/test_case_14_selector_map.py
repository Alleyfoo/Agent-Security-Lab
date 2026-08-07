"""Case 14 - the selector map, and every pivot in it.

An enumeration is only worth something if it is executed. Each claim that two
premises share an attacker-alterable selector carries a pivot that must
actually move both, and each claim that a pivot does not yield must say which
premise held instead. Both directions are pinned here.

Adversary: Level 1.5, the configuration adversary, unchanged from cases 12
and 13.
"""

from __future__ import annotations

import importlib.util
import os
import sys

import pytest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))
CASE_DIR = os.path.join(REPO_ROOT, "cases", "14-selector-map")

if CASE_DIR not in sys.path:
    sys.path.insert(0, CASE_DIR)


def _load(name: str):
    spec = importlib.util.spec_from_file_location(
        f"case14_{name}", os.path.join(CASE_DIR, f"{name}.py"))
    module = importlib.util.module_from_spec(spec)
    sys.modules[f"case14_{name}"] = module
    spec.loader.exec_module(module)
    return module


s = _load("selectors")

TARGET = s.TARGET
STAGE = s.STAGE


@pytest.fixture
def pivots(tmp_path):
    built = s.build_pivots(str(tmp_path))
    for pivot in built:
        pivot.obtained, pivot.moved = pivot.run()
    return {f"{p.arm}:{p.selector}": p for p in built}


# ---------------------------------------------------------------------------
# The map itself.
# ---------------------------------------------------------------------------

def test_every_premise_names_at_least_one_selector():
    """A premise nothing looks up is not a premise."""
    for premise in s.PREMISES:
        assert premise.selectors, premise.name
        for selector in premise.selectors:
            assert selector in s.ALTERABLE, (
                f"{selector!r} is used but not classified as alterable or not"
            )


def test_all_three_arms_are_mapped():
    assert {p.arm for p in s.PREMISES} == {"A", "B", "C"}


def test_shared_selectors_are_all_pivoted(tmp_path):
    """Every shared alterable selector in the map must carry an executed
    pivot. A claimed dependency nobody ran is prose."""
    claimed = {(arm, selector) for arm, selector, _ in s.shared_selectors()}
    pivoted = {(p.arm, p.selector.split(" (")[0])
               for p in s.build_pivots(str(tmp_path))}
    missing = claimed - pivoted
    assert not missing, f"shared selectors with no executed pivot: {missing}"


# ---------------------------------------------------------------------------
# Arm A - the pivot that works, and the one-word difference that stops it.
# ---------------------------------------------------------------------------

def test_arm_a_subject_pivot_yields_in_one_edit(pivots):
    pivot = pivots[f"A:{s.SEL_SUBJECT}"]
    assert pivot.obtained is True
    assert "label policy" in pivot.moved


def test_arm_a_stage_keyed_does_not_yield(pivots):
    """Same records, same edit, different lookup key."""
    assert pivots[f"A:{s.SEL_STAGE}"].obtained is False


# ---------------------------------------------------------------------------
# Arm B - independence that is a property of the credential inventory.
# ---------------------------------------------------------------------------

def test_arm_b_connection_pivot_fails_closed_in_an_ordinary_tenant(pivots):
    assert pivots[f"B:{s.SEL_CONNECTION}"].obtained is False


def test_arm_b_two_premises_live_in_one_record(pivots):
    """A unit-of-measurement finding that refines case 12's headline.

    Case 12 counted field-level mutations and reported a minimum tamper set of
    2 for arm B. Two of the three fields it counted - the input list and the
    connection name - are fields of the same step record, and an adversary
    with write access to the workflow definition sets both in one write. In an
    ordinary tenant it still fails, but for the inventory reason rather than
    the count.
    """
    pivot = pivots[f"B:{s.SEL_STEP}"]
    assert pivot.obtained is False
    assert "one record write" in pivot.moved
    assert "failed closed" in pivot.moved


def test_arm_b_one_overscoped_credential_collapses_it_to_one_edit(pivots):
    """THE FINDING FOR ARM B. Case 12 measured a minimum tamper set of 2 and
    credited the architecture. This locates the credit correctly: it belongs
    to the absence of a credential spanning both scopes, which is a property
    of the deployment, and the competence checklist is what was enforcing it."""
    pivot = pivots[f"B:{s.SEL_STEP} (over-scoped tenant)"]
    assert pivot.obtained is True
    assert "one record write" in pivot.moved


def test_the_overscoped_credential_would_fail_case_12s_checklist():
    """Stated so the previous test cannot be read as arm B being incompetent.
    The over-scoped credential is exactly what case 12's checklist forbids;
    this measures what that checklist is buying rather than assuming it."""
    s.arm_b.reset()
    everything = {s.c12.KEY_RAW, s.c12.KEY_SCHEMA, s.c12.KEY_CLEANED, TARGET}
    for scope in s.arm_b.CONNECTIONS.values():
        assert not everything.issubset(scope), "the clean tenant is competent"

    s.arm_b.CONNECTIONS[s.OVERSCOPED] = set(
        s.arm_b.CONNECTIONS[s.arm_b.CONN_ORDERS]) | {TARGET}
    assert everything.issubset(s.arm_b.CONNECTIONS[s.OVERSCOPED]), (
        "and the over-scoped one is precisely what the checklist rejects"
    )
    s.arm_b.reset()


# ---------------------------------------------------------------------------
# Arm C - a pivot that moves a premise and still loses.
# ---------------------------------------------------------------------------

def test_arm_c_object_id_pivot_finds_nothing(pivots):
    assert pivots[f"C:{s.SEL_OBJECT}"].obtained is False


def test_arm_c_object_type_pivot_moves_a_premise_and_still_loses(pivots):
    """THE FINDING FOR ARM C, and the clearest measured example of the
    principle. The pivot is real - after it the object-type read policy
    genuinely admits key_material - and a third premise keyed on the skill
    name still holds, so nothing is obtained.

    'Moved' and 'obtained' are reported separately for exactly this cell.
    """
    pivot = pivots[f"C:{s.SEL_OBJECT_TYPE}"]
    assert pivot.obtained is False
    assert "admits key_material (True)" in pivot.moved, (
        "the pivot must be shown to have moved something, or this is not a "
        "finding about independent selection - it is a pivot that did nothing"
    )
    assert "skill contract still reads" in pivot.moved


# ---------------------------------------------------------------------------
# The headline.
# ---------------------------------------------------------------------------

def test_two_of_six_shared_selectors_yield(pivots):
    yielding = {k for k, p in pivots.items() if p.obtained}
    assert yielding == {
        f"A:{s.SEL_SUBJECT}",
        f"B:{s.SEL_STEP} (over-scoped tenant)",
    }


def test_the_transition_table_is_not_on_the_read_grant_path():
    """Pinned because the map says so and a reader would reasonably assume
    otherwise. Arm C's read grant derives from the skill contract and the
    artifact binding; which skill is *required* governs the execute path."""
    premise = next(p for p in s.PREMISES
                   if p.name == "which skill does this object require?")
    assert "execute path" in premise.note
