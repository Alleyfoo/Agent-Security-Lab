"""Case 15 - what a normal deployment already contains.

Cases 12-14 measured architectures. This measures deployments: one piece of
plausible pre-existing authority per model, present and absent, against the
same attack.

The pre-registered hypothesis was that pre-existing authority reduces the
*visibility* of the edit rather than its cost. It holds in all three arms, and
in one of them it reduces the cost as well.

Adversary: Level 1.5, the configuration adversary, unchanged.
"""

from __future__ import annotations

import importlib.util
import os
import sys

import pytest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))
CASE_DIR = os.path.join(REPO_ROOT, "cases", "15-authority-inventory")

if CASE_DIR not in sys.path:
    sys.path.insert(0, CASE_DIR)


def _load(name: str):
    spec = importlib.util.spec_from_file_location(
        f"case15_{name}", os.path.join(CASE_DIR, f"{name}.py"))
    module = importlib.util.module_from_spec(spec)
    sys.modules[f"case15_{name}"] = module
    spec.loader.exec_module(module)
    return module


inv = _load("inventory")


@pytest.fixture
def rows(tmp_path):
    return inv.measure_all(str(tmp_path))


def _cheapest(rows, arm, present):
    return inv.cheapest(rows, arm, present)


# ---------------------------------------------------------------------------
# The headline: the same finding in three architectures.
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("arm", ["A", "B", "C"])
def test_preexisting_authority_makes_the_attack_invisible_to_an_audit(rows, arm):
    """THE FINDING, and it is architecture-independent.

    With the authority already in the deployment, the cheapest yielding edit
    leaves the standing authority inventory unchanged in every arm - the
    attacker stops having to *create* authority and only has to *point* at it.
    Without it, the cheapest yielding edit is visible in every arm.
    """
    absent = _cheapest(rows, arm, False)
    present = _cheapest(rows, arm, present=True)

    assert absent is not None and absent.inventory_changed is True, (
        f"arm {arm}: without pre-existing authority the attacker must create "
        "some, and that is what an audit lists"
    )
    assert present is not None and present.inventory_changed is False, (
        f"arm {arm}: with it, nothing an auditor lists changes"
    )


def test_the_benefit_to_the_attacker_takes_three_different_shapes(rows):
    """Cost, scope and visibility move differently per model, and reporting
    only one of them would hide two of the findings."""
    a_absent, a_present = _cheapest(rows, "A", False), _cheapest(rows, "A", True)
    b_absent, b_present = _cheapest(rows, "B", False), _cheapest(rows, "B", True)
    c_absent, c_present = _cheapest(rows, "C", False), _cheapest(rows, "C", True)

    # arm A: cost and scope unchanged; only visibility moves.
    assert a_absent.commits == a_present.commits == 1
    assert a_absent.scope == a_present.scope

    # arm B: the cost halves.
    assert b_absent.commits == 2
    assert b_present.commits == 1

    # arm C: the cost is the same and the scope collapses.
    assert c_absent.commits == c_present.commits == 1
    assert inv.c12.SCOPE_ORDER.index(c_present.scope) < \
        inv.c12.SCOPE_ORDER.index(c_absent.scope), (
        "retyping one object replaces a deployment-wide contract edit"
    )


# ---------------------------------------------------------------------------
# Arm A - the identity that already holds it.
# ---------------------------------------------------------------------------

def test_arm_a_the_substitution_route_needs_the_identity_to_exist(rows):
    """Remove the identity and the route disappears entirely - the model
    refuses a subject it does not know. The route was never about the
    permission table; it was about the deployment."""
    substitutions = [r for r in rows if r.arm == "A"
                     and "subject" in r.commit_of]
    absent = next(r for r in substitutions if not r.present)
    present = next(r for r in substitutions if r.present)

    assert present.obtained is True
    assert absent.obtained is False


def test_arm_a_widening_always_works_and_is_always_visible(rows):
    widenings = [r for r in rows if r.arm == "A"
                 and "permission table" in r.commit_of]
    assert all(r.obtained for r in widenings)
    assert all(r.inventory_changed for r in widenings)


# ---------------------------------------------------------------------------
# Arm B - the credential scoped across both sides.
# ---------------------------------------------------------------------------

def test_arm_b_one_overscoped_credential_halves_the_cost(rows):
    """The sharpest single number in the case. Case 12 credited arm B's 2 to
    the architecture; it belongs to the deployment not containing this."""
    assert _cheapest(rows, "B", False).commits == 2
    assert _cheapest(rows, "B", True).commits == 1


def test_arm_b_without_it_the_credential_scope_itself_must_change(rows):
    absent = _cheapest(rows, "B", False)
    assert "connection scope" in absent.commit_of
    assert absent.inventory_changed is True


# ---------------------------------------------------------------------------
# Arm C - the approved skill that legitimately reads the target.
# ---------------------------------------------------------------------------

def test_arm_c_retyping_needs_the_skill_to_already_exist(rows):
    retypes = [r for r in rows if r.arm == "C" and "object record" in r.commit_of]
    assert next(r for r in retypes if r.present).obtained is True
    assert next(r for r in retypes if not r.present).obtained is False


def test_arm_c_the_contract_edit_always_works_and_is_deployment_wide(rows):
    """The route that needs no pre-existing authority is the loud one: it is
    visible to a skill audit and it reaches every object until redeployment."""
    widenings = [r for r in rows if r.arm == "C"
                 and "skill contract" in r.commit_of]
    assert all(r.obtained for r in widenings)
    assert all(r.inventory_changed for r in widenings)
    assert all(r.scope == inv.c12.SCOPE_DEPLOYMENT for r in widenings)


# ---------------------------------------------------------------------------
# The instrument itself.
# ---------------------------------------------------------------------------

def test_the_inventories_actually_list_the_target_authority():
    """An inventory that cannot see the authority in question would report
    'unchanged' for every attack and prove nothing."""
    inv.arm_a.reset()
    assert any(key == inv.TARGET for _, key, _ in inv.inventory_a())

    inv.arm_b.reset()
    inv.arm_b.CONNECTIONS[inv.sel.OVERSCOPED] = {inv.TARGET}
    assert any(key == inv.TARGET for _, key in inv.inventory_b())
    inv.arm_b.reset()

    from object_model import skills
    inv._install_rotation_skill()
    assert any(t == skills.T_KEY_MATERIAL for _, t in inv.inventory_c())
    skills.reset_registry()


def test_the_cheapest_route_prefers_invisibility_over_narrow_scope():
    """Pins the attacker model in `cheapest`. Given equal cost, an attacker
    takes the route an audit cannot see; ordering by scope first would have
    reported arm A's noisy route and hidden its quiet one."""
    import inspect
    source = inspect.getsource(inv.cheapest)
    assert "inventory_changed" in source
    assert source.index("inventory_changed") < source.index("SCOPE_ORDER")
