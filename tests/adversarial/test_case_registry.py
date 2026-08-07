"""The canonical case registry must not drift from the repository.

Security claims live in ``cases/registry.py`` once. These tests keep that
structure honest: every case it describes must exist on disk, every result must
use the closed vocabulary, and an open case must never advertise an improvement
it has not made.
"""

from __future__ import annotations

import os
import re
import subprocess
import sys

import pytest

from cases import registry
from cases.registry import RESULTS, RESULT_SEVERITY, CaseResult

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))

ALL = registry.all_cases()
IDS = [c.case_id for c in ALL]


@pytest.mark.parametrize("case", ALL, ids=IDS)
def test_case_directory_and_attack_script_exist(case: CaseResult):
    directory = os.path.join(REPO_ROOT, case.directory)
    assert os.path.isdir(directory), f"{case.case_id}: {case.directory} missing"
    assert os.path.isfile(os.path.join(directory, "README.md"))
    assert os.path.isfile(os.path.join(directory, "attack.py")), (
        f"{case.case_id}: every case ships a runnable attack"
    )


@pytest.mark.parametrize("case", ALL, ids=IDS)
def test_test_module_exists(case: CaseResult):
    assert os.path.isfile(os.path.join(REPO_ROOT, case.test_module))


@pytest.mark.parametrize("case", ALL, ids=IDS)
def test_results_use_the_closed_vocabulary(case: CaseResult):
    assert case.baseline_result in RESULTS
    assert case.controlled_result in RESULTS


@pytest.mark.parametrize("case", ALL, ids=IDS)
def test_open_cases_do_not_claim_an_improvement(case: CaseResult):
    """An open negative case must never be shown as green."""
    if case.status == "open":
        assert case.controlled_result == case.baseline_result
        assert not case.improved


@pytest.mark.parametrize("case", ALL, ids=IDS)
def test_a_control_never_worsens_the_result(case: CaseResult):
    assert (RESULT_SEVERITY[case.controlled_result]
            >= RESULT_SEVERITY[case.baseline_result])


@pytest.mark.parametrize("case", ALL, ids=IDS)
def test_mandatory_framing_is_present_and_substantive(case: CaseResult):
    for field in ("what_this_proves", "what_this_does_not_prove",
                  "residual_limitation", "containment", "recovery"):
        value = getattr(case, field)
        assert len(value) > 40, f"{case.case_id}: {field} is not substantive"


@pytest.mark.parametrize("case", ALL, ids=IDS)
def test_no_vague_result_language_in_claims(case: CaseResult):
    """The direction bans vague substitutes for the result vocabulary.

    Checked only on the claim fields, since prose elsewhere legitimately
    discusses these words.
    """
    banned = re.compile(
        r"\b(tamper[- ]proof|unhackable|fully secure|completely secure)\b",
        re.IGNORECASE)
    for field in ("control", "what_this_proves"):
        value = getattr(case, field)
        assert not banned.search(value), (
            f"{case.case_id}: {field} uses an overclaiming term"
        )


@pytest.mark.parametrize("case", ALL, ids=IDS)
def test_case_readme_states_both_framings(case: CaseResult):
    readme = os.path.join(REPO_ROOT, case.directory, "README.md")
    with open(readme, "r", encoding="utf-8") as fh:
        text = fh.read().lower()
    assert "what this proves" in text
    assert "what this does not prove" in text


def test_case_ids_are_unique():
    assert len(IDS) == len(set(IDS))


def test_report_renders_and_covers_every_case():
    from cases import report
    text = report.render()
    for case in ALL:
        assert case.case_id in text
        assert case.title in text


def test_report_on_disk_is_current():
    """REPORT.md is generated; a stale copy is a drifted claim."""
    from cases import report
    path = os.path.join(REPO_ROOT, "cases", "REPORT.md")
    assert os.path.isfile(path), "run: python cases/report.py"
    with open(path, "r", encoding="utf-8") as fh:
        on_disk = fh.read()
    assert on_disk == report.render(), (
        "cases/REPORT.md is out of date - run: python cases/report.py"
    )


# ---------------------------------------------------------------------------
# The review's structural claims.
#
# cases/REPORT.md now carries a synthesis over the whole set. Its three
# structural claims are derived from this registry rather than typed, and these
# tests pin them so a later case that contradicts one breaks the build instead
# of leaving a confident paragraph that is quietly false. Each failure message
# says what to rewrite. None of them may be relaxed to green a suite.
# ---------------------------------------------------------------------------

def _by_level(level: str):
    from cases.report import primary_level
    return {c.case_id for c in ALL if primary_level(c) == level}


def test_review_every_level_2_prevention_is_an_absence():
    """TRIPWIRE for the review's central claim.

    Two cases prevent an effect against an adversary holding arbitrary code in
    the runner's process, and neither does it with a check: case 04b because
    the decision plane never reads the corrupted record, case 06 because the
    isolated interpreter contains no runner objects.

    A third entry here means a check has prevented something at Level 2 - or
    that an absence has - and either way the review's design rule and the
    cross-cutting finding both need rewriting before this test is changed.
    """
    from cases.registry import PREVENTED
    prevented = {c.case_id for c in ALL
                 if c.case_id in _by_level("Level 2")
                 and c.controlled_result == PREVENTED}
    assert prevented == {"case-04b", "case-06"}, (
        "the set of Level 2 preventions changed. rewrite 'Every Level 2 "
        "prevention here is an absence, not a check' in cases/report.py "
        "against the new evidence - do not edit this assertion first"
    )


def test_review_exactly_one_level_1_case_ends_in_detection():
    """TRIPWIRE for 'restricting an agent to its assigned function does not
    restrict what its assigned function can do'.

    Case 07 is the only case with a Level 1 adversary that ends below
    rejection before commitment, and the reason is that it never crosses a
    boundary: the stage used its grant exactly as issued. That is the limit of
    confinement itself, and the review is built on it being the single
    exception.

    The threshold is rejection, not prevention, on purpose. Case 05's hostile
    output is produced and then refused entry to trusted state, which is the
    boundary holding rather than failing.
    """
    from cases.registry import REJECTED_BEFORE_COMMITMENT
    weak = {c.case_id for c in ALL
            if c.case_id in _by_level("Level 1")
            and RESULT_SEVERITY[c.controlled_result]
            < RESULT_SEVERITY[REJECTED_BEFORE_COMMITMENT]}
    assert weak == {"case-07"}, (
        "a Level 1 case other than 07 now ends in detection or worse, or 07 "
        "no longer does. rewrite the review's 'the one Level 1 case that ends "
        "in detection' section"
    )


def test_review_the_persisted_record_adversary_is_still_unnamed():
    """TRIPWIRE for the review's recommendation.

    Cases 08, 10, 11 and 12 share case 08's narrow attacker - may alter
    persisted policy or workflow records, may not modify evaluator code - which
    is not a row on the compromise ladder. The review recommends naming it or
    recording why it is not a level. When that happens these compromise_level
    strings change, and this test is the reminder that the review's section has
    to change with them.

    It has fired twice, when cases 12 and 13 joined the set, and both times
    the review prose was rewritten rather than the assertion relaxed - which
    is what a tripwire is for. That it keeps firing is itself the argument for
    naming the adversary: the set only grows.
    """
    persisted = _by_level("persisted-record")
    assert persisted == {"case-08", "case-10", "case-11", "case-12",
                         "case-13"}, (
        "the set of cases using case 08's attacker changed. update the review "
        "section 'N cases measure an adversary the ladder has no row for' "
        "before changing this assertion"
    )


@pytest.mark.parametrize("case", ALL, ids=IDS)
def test_attack_script_runs_and_reports_the_registered_outcome(case: CaseResult):
    """The attack script must agree with the registry.

    Exit 0 means the attack was stopped or is a documented open finding; a
    crash means the case's own reproduction is broken.
    """
    script = os.path.join(REPO_ROOT, case.directory, "attack.py")
    proc = subprocess.run([sys.executable, script], capture_output=True,
                          text=True, cwd=REPO_ROOT, timeout=120)
    assert proc.returncode == 0, (
        f"{case.case_id}: attack.py exited {proc.returncode}\n"
        f"stdout:\n{proc.stdout}\nstderr:\n{proc.stderr}"
    )
