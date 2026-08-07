"""Case 13 - does a second independent premise raise the cost?

A pre-registered prediction, tested. The prediction was written into
cases/REPORT.md before this code existed:

    If the principle is architectural rather than incidental to arm B, then
    adding a second independent premise to arm A or arm C should raise that
    arm's minimum tamper set to 2 - without changing which model it is.

It holds, under two conditions the prediction did not state. Both conditions
are pinned below, because both are the actual finding and a later change that
quietly removes either would leave the review's principle overclaimed.

Case 12's arms are frozen and this case layers onto them. A test asserts that.
"""

from __future__ import annotations

import importlib.util
import os
import sys

import pytest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))
CASE_DIR = os.path.join(REPO_ROOT, "cases", "13-second-premise")

if CASE_DIR not in sys.path:
    sys.path.insert(0, CASE_DIR)


def _load(name: str):
    spec = importlib.util.spec_from_file_location(
        f"case13_{name}", os.path.join(CASE_DIR, f"{name}.py"))
    module = importlib.util.module_from_spec(spec)
    sys.modules[f"case13_{name}"] = module
    spec.loader.exec_module(module)
    return module


premise = _load("premise")

TARGET = premise.TARGET
STAGE = premise.STAGE


@pytest.fixture(autouse=True)
def _fresh(tmp_path):
    premise.reset_arm_a()
    premise.reset_arm_c(str(tmp_path / "c"))
    yield
    premise.arm_a.reset()


# ---------------------------------------------------------------------------
# Fairness: the premises must be real, and case 12 must be untouched.
# ---------------------------------------------------------------------------

def test_case_12s_arms_are_not_modified(tmp_path):
    """Case 12 published a table. This case layers; it does not edit."""
    premise.arm_a.reset()
    assert premise.arm_a.resolve(STAGE).permits_read(TARGET) is False
    premise.arm_a.mutate_permission_table(TARGET)
    assert premise.arm_a.resolve(STAGE).permits_read(TARGET), (
        "case 12's arm A must still measure 1 edit on its own"
    )


def test_the_added_premises_are_actually_consulted(tmp_path):
    """A premise no runtime path reads is the anti-pattern this project bans.

    Each premise must be able to *deny* something the other would allow, or it
    is decorative and the measurement below is a lie rather than an error.
    """
    premise.reset_arm_a()
    premise.arm_a.mutate_permission_table(TARGET)
    assert premise.arm_a.resolve(STAGE).permits_read(TARGET), "DAC allows"
    assert not premise.resolve_arm_a(STAGE, premise.BY_STAGE).permits_read(
        TARGET), "the label policy denies what DAC allowed"

    premise.reset_arm_c(str(tmp_path / "consulted"))
    premise.arm_c.mutate_artifact_binding(TARGET)
    assert premise.arm_c.resolve(STAGE).permits_read(TARGET), "binding allows"
    assert not premise.resolve_arm_c(STAGE).permits_read(TARGET), (
        "the artifact's own declaration denies what the binding allowed"
    )


def test_the_premises_do_not_break_the_honest_run(tmp_path):
    """A premise that denies legitimate work is not a premise, it is a bug."""
    for variant in (premise.BY_SUBJECT, premise.BY_STAGE):
        premise.reset_arm_a()
        grant = premise.resolve_arm_a(STAGE, variant)
        assert grant.read_keys == ["artifact.raw_input"], variant

    premise.reset_arm_c(str(tmp_path / "honest"))
    assert premise.resolve_arm_c(STAGE).read_keys == ["artifact.raw_input"]


# ---------------------------------------------------------------------------
# Condition 1: the premises must not share an index the attacker can pivot.
# ---------------------------------------------------------------------------

def test_a_second_premise_keyed_on_the_subject_does_not_help():
    """THE FINDING. Independence of records is not enough.

    Both premises answer a question about *the subject*, so one edit that
    changes which subject the stage runs as moves both at once. The label
    policy is genuinely a separate record, genuinely consulted, and worth
    nothing against this route.
    """
    premise.reset_arm_a()
    premise.arm_a.mutate_subject_assignment(TARGET)
    assert premise.resolve_arm_a(STAGE, premise.BY_SUBJECT).permits_read(TARGET)


def test_the_same_premise_keyed_on_the_stage_does_help():
    """The only difference is what the domain is looked up by - which is how
    SELinux actually does it, deriving the domain from a transition on the
    executable rather than from the uid."""
    premise.reset_arm_a()
    premise.arm_a.mutate_subject_assignment(TARGET)
    assert not premise.resolve_arm_a(STAGE, premise.BY_STAGE).permits_read(
        TARGET)


@pytest.mark.parametrize("variant", [premise.BY_SUBJECT, premise.BY_STAGE])
def test_neither_single_widening_obtains_it_in_either_variant(variant):
    for mutate in (lambda: premise.arm_a.mutate_permission_table(TARGET),
                   lambda: premise.mutate_a_label_policy(TARGET)):
        premise.reset_arm_a()
        mutate()
        assert not premise.resolve_arm_a(STAGE, variant).permits_read(TARGET)


def test_arm_a_two_edits_obtain_it():
    premise.reset_arm_a()
    premise.arm_a.mutate_permission_table(TARGET)
    premise.mutate_a_label_policy(TARGET)
    assert premise.resolve_arm_a(STAGE, premise.BY_STAGE).permits_read(TARGET)


# ---------------------------------------------------------------------------
# Condition 2: one premise per authority surface, not per model.
# ---------------------------------------------------------------------------

def test_one_premise_closes_one_surface_and_leaves_the_other(tmp_path):
    """THE SECOND FINDING, and the one that costs the object model most.

    The artifact declaration closes the binding route completely and does
    nothing about the skill-contract route, which still obtains at one edit.
    An arm with more authority surfaces needs more premises to reach the same
    cost - so expressiveness is paid for twice.
    """
    premise.reset_arm_c(str(tmp_path / "one_a"))
    premise.arm_c.mutate_artifact_binding(TARGET)
    assert not premise.resolve_arm_c(STAGE, use_type_policy=False).permits_read(
        TARGET), "the binding route is closed"

    premise.reset_arm_c(str(tmp_path / "one_b"))
    premise.arm_c.mutate_skill_contract(TARGET)
    assert premise.resolve_arm_c(STAGE, use_type_policy=False).permits_read(
        TARGET), "and the skill-contract route is untouched"


def test_a_premise_per_surface_raises_the_minimum_to_two(tmp_path):
    premise.reset_arm_c(str(tmp_path / "both_a"))
    premise.arm_c.mutate_artifact_binding(TARGET)
    assert not premise.resolve_arm_c(STAGE).permits_read(TARGET)

    premise.reset_arm_c(str(tmp_path / "both_b"))
    premise.arm_c.mutate_skill_contract(TARGET)
    assert not premise.resolve_arm_c(STAGE).permits_read(TARGET)


@pytest.mark.parametrize("pair", ["binding", "skill"])
def test_arm_c_two_edits_obtain_it(pair, tmp_path):
    premise.reset_arm_c(str(tmp_path / f"two_{pair}"))
    if pair == "binding":
        premise.arm_c.mutate_artifact_binding(TARGET)
        premise.mutate_c_declaration(TARGET)
    else:
        premise.arm_c.mutate_skill_contract(TARGET)
        premise.mutate_c_type_policy(TARGET)
    assert premise.resolve_arm_c(STAGE).permits_read(TARGET)


# ---------------------------------------------------------------------------
# The headline.
# ---------------------------------------------------------------------------

def test_the_prediction_holds_only_under_both_conditions(tmp_path):
    """The whole case in one assertion.

    The pre-registered prediction said a second premise raises the minimum to
    2 in any model. It does - when the premises do not share a pivotable index
    and when there is one per surface. Two of the four configurations measured
    still sit at 1.
    """
    def arm_a_min(variant):
        cells = []
        for mutate in (lambda: premise.arm_a.mutate_permission_table(TARGET),
                       lambda: premise.mutate_a_label_policy(TARGET),
                       lambda: premise.arm_a.mutate_subject_assignment(TARGET)):
            premise.reset_arm_a()
            mutate()
            cells.append(
                (1, premise.resolve_arm_a(STAGE, variant).permits_read(TARGET)))
        premise.reset_arm_a()
        premise.arm_a.mutate_permission_table(TARGET)
        premise.mutate_a_label_policy(TARGET)
        cells.append(
            (2, premise.resolve_arm_a(STAGE, variant).permits_read(TARGET)))
        return premise.minimum_tamper_set(cells)

    assert arm_a_min(premise.BY_SUBJECT) == 1
    assert arm_a_min(premise.BY_STAGE) == 2

    def arm_c_min(use_type_policy, tag):
        cells = []
        for index, mutate in enumerate(
                (premise.arm_c.mutate_artifact_binding,
                 premise.arm_c.mutate_skill_contract)):
            premise.reset_arm_c(str(tmp_path / f"{tag}{index}"))
            mutate(TARGET)
            cells.append((1, premise.resolve_arm_c(
                STAGE, use_type_policy=use_type_policy).permits_read(TARGET)))
        premise.reset_arm_c(str(tmp_path / f"{tag}pair"))
        premise.arm_c.mutate_artifact_binding(TARGET)
        premise.mutate_c_declaration(TARGET)
        cells.append((2, premise.resolve_arm_c(
            STAGE, use_type_policy=use_type_policy).permits_read(TARGET)))
        return premise.minimum_tamper_set(cells)

    assert arm_c_min(False, "one") == 1
    assert arm_c_min(True, "both") == 2
