"""The applied programme's results, and the schema boundary that keeps them
from being mistaken for attack evidence.

The central test in this file is `test_no_programme_result_carries_a_tamper_
cost`. Everything else supports it. The point is not tidiness: a
`minimum_tamper_cost` invented for step E's detection rate would be a number
with no referent, and this repository has already measured what happens to
numbers with no referent.
"""

from __future__ import annotations

import os

import pytest

from cases.programme import (
    CORRECTNESS_ORACLE, FORBIDDEN_ON_PROGRAMME, OPERATIONAL_RESILIENCE,
    PROGRAMME, PROGRAMME_FAMILIES, REQUIRED_MEASUREMENTS, SECURITY_CASE,
    ProgrammeResult, by_family,
)
from cases.registry import EVIDENCE_STATUSES, all_cases

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
IDS = [r.step for r in PROGRAMME]


# ---------------------------------------------------------------------------
# THE SCHEMA BOUNDARY. Not every piece of evidence is attack evidence.
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("result", PROGRAMME, ids=IDS)
def test_no_programme_result_carries_a_tamper_cost(result: ProgrammeResult):
    """F0's 17 unresolved is not a successful attack route. F2's 8 escalated
    is not a prevention whose tamper cost is some number. They are operational
    outcomes under a preregistered fault distribution, and giving them a
    tamper set because `CaseResult` has the field would repeat the measurement
    mistake the first twenty-four cases exist to eliminate."""
    for forbidden in FORBIDDEN_ON_PROGRAMME:
        assert not hasattr(result, forbidden), forbidden
        assert forbidden not in result.measurements, forbidden


def test_the_schema_boundary_is_enforced_not_documented():
    """Positive control. A rule that only exists in a docstring is a rule the
    next person will not notice they broke."""
    with pytest.raises(ValueError, match="attack-evidence vocabulary"):
        ProgrammeResult(
            step="X", title="t", question="q", family=OPERATIONAL_RESILIENCE,
            claim="c", non_claims=["n"], residual="r",
            measurements={"detected": 1, "missed": 0, "false_alarms": 0,
                          "minimum_commits": 1},
            method="m", source_commit="s", exercises={}, run="r",
            test_module="t")


def test_a_programme_result_cannot_claim_to_be_a_security_case():
    with pytest.raises(ValueError, match="cases/registry.py"):
        ProgrammeResult(
            step="X", title="t", question="q", family=SECURITY_CASE,
            claim="c", non_claims=["n"], residual="r",
            measurements={}, method="m", source_commit="s", exercises={},
            run="r", test_module="t")


@pytest.mark.parametrize("result", PROGRAMME, ids=IDS)
def test_each_family_reports_the_measurements_it_must(result: ProgrammeResult):
    """So a step cannot quietly omit the measurement that would have been
    inconvenient."""
    for required in REQUIRED_MEASUREMENTS[result.family]:
        assert required in result.measurements, required


def test_a_missing_required_measurement_is_refused():
    with pytest.raises(ValueError, match="missing measurements"):
        ProgrammeResult(
            step="X", title="t", question="q", family=OPERATIONAL_RESILIENCE,
            claim="c", non_claims=["n"], residual="r",
            measurements={"detected": 1}, method="m", source_commit="s",
            exercises={}, run="r", test_module="t")


# ---------------------------------------------------------------------------
# Step D is the only one that belongs in the case table.
# ---------------------------------------------------------------------------

def test_step_d_is_a_case_and_the_others_are_not():
    """Step D has an adversary, a protected outcome, a bypass route and a cost
    in the settled unit. That is what `CaseResult` is for, and it is the only
    step that has it."""
    assert "D" not in {r.step for r in PROGRAMME}
    assert [r.step for r in PROGRAMME] == ["A", "B", "C", "E", "F",
                                           "BOX-model"], (
        "the programme's step list changed. If a new step was added, say "
        "which family it belongs to and why it is not a CaseResult - do not "
        "edit this list first")
    case_ids = {c.case_id for c in all_cases()}
    assert "case-25" in case_ids


def test_case_25_declares_its_tamper_cost_and_routes():
    """The counterpart of the test above: the one step that IS a case must
    carry the attack-evidence fields, or the split would be an excuse rather
    than a distinction."""
    from cases.registry import TAMPER_UNIT, get
    case = get("case-25")
    assert case.extra["tamper_unit"] == TAMPER_UNIT
    assert case.extra["minimum_commits"]["legacy Level 1"] == 1
    assert case.extra["routes"]["legacy Level 1"]
    assert case.extra["routes"]["protected Level 1"] == [], (
        "no route achieves unapproved displacement at Level 1 - that is the "
        "result, and an empty list is how it is stated")


# ---------------------------------------------------------------------------
# Ordinary hygiene, matching what the case registry already demands.
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("result", PROGRAMME, ids=IDS)
def test_every_step_states_what_it_does_not_claim(result: ProgrammeResult):
    assert result.non_claims
    assert result.residual and len(result.residual) > 40


@pytest.mark.parametrize("result", PROGRAMME, ids=IDS)
def test_every_step_names_a_runnable_reproduction(result: ProgrammeResult):
    script = result.run.split()[-1]
    assert os.path.isfile(os.path.join(REPO_ROOT, script)), script
    assert os.path.isfile(os.path.join(REPO_ROOT, result.test_module))


@pytest.mark.parametrize("result", PROGRAMME, ids=IDS)
def test_every_step_declares_its_evidence_status(result: ProgrammeResult):
    assert result.evidence_status in EVIDENCE_STATUSES


@pytest.mark.parametrize("result", PROGRAMME, ids=IDS)
def test_every_step_links_back_to_the_concepts_it_exercises(
        result: ProgrammeResult):
    """Cross-linking is what stops the programme reading as a self-contained
    toy. Each step has to say which security concept it bears on."""
    assert result.exercises, result.step
    for concept, why in result.exercises.items():
        assert len(why) > 20, (result.step, concept)


def test_steps_are_unique_and_the_families_are_populated():
    steps = [r.step for r in PROGRAMME]
    assert len(steps) == len(set(steps))
    for family in PROGRAMME_FAMILIES:
        assert by_family(family), family


def test_no_vague_result_language_in_programme_claims():
    """The same rule the case registry applies to `*_result` fields. 'The
    system handled it' is not a measurement."""
    vague = ("handled", "secure", "mitigated", "hardened", "robust",
             "best practice", "bulletproof")
    for result in PROGRAMME:
        blob = f"{result.claim} {result.residual}".lower()
        for word in vague:
            assert word not in blob, (result.step, word)


# ---------------------------------------------------------------------------
# The report must actually show them.
# ---------------------------------------------------------------------------

def test_the_report_renders_every_programme_step():
    """The failure this section exists to prevent: a reader six months from
    now concluding the reservation programme never got past step C, because
    the strongest applied results lived only in commit messages."""
    from cases import report
    text = report.render()
    assert "## Applied architecture programme" in text
    for result in PROGRAMME:
        assert f"Step {result.step} — {result.title}" in text, result.step
    assert "Not every piece of evidence here is attack evidence" in text
    assert "Step D is case-25" in text


def test_the_report_shows_the_headline_numbers():
    from cases import report
    text = report.render()
    for number in ("348", "652", "46", "47", "39", "17 unresolved"):
        assert number in text, number
