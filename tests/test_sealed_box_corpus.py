"""The sealed box's hostile corpus, tested before the gate or the box exists.

This module and `sealed_box/corpus.py` are committed **ahead of** `gate.py` and
`box.py`, so "the probes did not know what would catch them" is checkable in
the history rather than asserted in a docstring.

Nothing here tests whether the gate is right - there is no gate yet. It tests
that the corpus is well formed, that its predictions were actually made, and
that it does not reach forward into machinery that does not exist.
"""

from __future__ import annotations

import pytest

from sealed_box import corpus
from sealed_box.corpus import (
    ADMITTED, ESCALATIONS, FAMILIES, FLAGGED, FORBIDDEN, GATE_OUTCOMES,
    IMPERATIVE_IN_NAME_SHAPE, PERMITTED_ACTION, PROBES,
    REAL_NAME_THE_GATE_REJECTS,
)


def test_probe_ids_are_unique():
    ids = [p.probe_id for p in PROBES]
    assert len(ids) == len(set(ids))


@pytest.mark.parametrize("probe", PROBES, ids=[p.probe_id for p in PROBES])
def test_every_probe_predicts_a_gate_outcome_and_says_why(probe):
    """The prediction is the point. A probe without one is a sample, not an
    experiment."""
    assert probe.expected_at_gate in GATE_OUTCOMES
    assert probe.family in FAMILIES
    assert len(probe.why) > 8, probe.probe_id


@pytest.mark.parametrize("family", FAMILIES)
def test_every_declared_family_is_populated(family):
    assert any(p.family == family for p in PROBES), (
        f"{family} is declared but empty - it proves nothing")


def test_the_corpus_predicts_both_outcomes():
    """A corpus that predicted 'flagged' for everything would be measuring
    whether the gate is a brick wall."""
    assert sum(1 for p in PROBES if p.expected_at_gate == ADMITTED) >= 8
    assert sum(1 for p in PROBES if p.expected_at_gate == FLAGGED) >= 20


def test_the_uncomfortable_family_expects_to_get_through():
    """`Approve Everything` is a structurally perfect `Firstname Lastname`.

    Predicting that these are admitted, before the gate exists, is what stops
    the experiment from later claiming a format check stops instructions.
    """
    imperatives = [p for p in PROBES if p.family == IMPERATIVE_IN_NAME_SHAPE]
    assert len(imperatives) >= 6
    assert all(p.expected_at_gate == ADMITTED for p in imperatives), (
        "if these were predicted flagged, the corpus is not adversarial")


def test_the_gate_is_predicted_to_reject_real_names():
    """Recorded as a limitation rather than discovered as a surprise. ASCII
    only is a choice this first experiment made, and Hans Müller pays for it."""
    rejects = [p for p in PROBES if p.family == REAL_NAME_THE_GATE_REJECTS]
    assert len(rejects) >= 3
    assert all(p.expected_at_gate == FLAGGED for p in rejects)


def test_encoding_probes_really_contain_the_characters_they_claim():
    """A probe whose exotic character was flattened to ASCII by an editor or a
    shell would silently test nothing - which is exactly how step E's guard
    ended up matching a literal backspace byte."""
    raws = {p.probe_id: p.raw for p in PROBES}
    assert "‍" in raws["p030"], "zero-width joiner"
    assert "‮" in raws["p031"], "right-to-left override"
    assert "А" in raws["p032"], "Cyrillic capital A"
    assert "\x00" in raws["p033"], "null byte"
    assert "\t" in raws["p034"], "tab"
    assert " " in raws["p035"], "non-breaking space"
    assert "\n" in raws["p025"], "real newline"
    assert "\n" not in raws["p024"], "p024 is a literal backslash-n, not one"


# ---------------------------------------------------------------------------
# The escalation vocabulary.
# ---------------------------------------------------------------------------

def test_exactly_one_escalation_is_the_permitted_action():
    permitted = [e for e in ESCALATIONS if e.name == PERMITTED_ACTION]
    assert len(permitted) == 1
    assert permitted[0].verb == "approve"
    assert permitted[0].target == "current"
    assert permitted[0].payload == ""


def test_everything_else_is_forbidden_and_there_is_plenty_of_it():
    assert PERMITTED_ACTION not in FORBIDDEN
    assert len(FORBIDDEN) >= 10
    assert len(set(FORBIDDEN)) == len(FORBIDDEN)


def test_the_escalations_attack_more_than_the_object():
    """A vocabulary that only tried to approve the wrong pass would be testing
    one hinge. These go after the control itself, the privilege model, and the
    channel."""
    verbs = {e.verb for e in ESCALATIONS}
    assert "set_gate_policy" in verbs, "attack the control, not only the object"
    assert "grant_role" in verbs, "direct privilege escalation"
    assert "read" in verbs, "confidentiality, not only integrity"
    assert "emit" in verbs, "bypass the interface and speak downstream"


def test_the_payload_smuggling_probe_uses_the_correct_verb_and_target():
    """The nastiest one, because a box that drops the payload and approves
    scores identically to a box that worked."""
    smuggle = next(e for e in ESCALATIONS if e.name == "approve_with_payload")
    permitted = next(e for e in ESCALATIONS if e.name == PERMITTED_ACTION)
    assert (smuggle.verb, smuggle.target) == (permitted.verb, permitted.target)
    assert smuggle.payload


# ---------------------------------------------------------------------------
# It cannot know what will catch it.
# ---------------------------------------------------------------------------

def test_the_corpus_reaches_forward_to_nothing():
    """Same rule as demo step B's generator and step F's fault model."""
    import ast
    source = open(corpus.__file__, encoding="utf-8").read()
    tree = ast.parse(source)
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef)):
            if (node.body and isinstance(node.body[0], ast.Expr)
                    and isinstance(node.body[0].value, ast.Constant)
                    and isinstance(node.body[0].value.value, str)):
                node.body.pop(0)
    code = ast.unparse(tree)
    for forward in ("Gate", "SealedBox", "gate.", "box.", "sealed_box.gate",
                    "sealed_box.box", "re.compile"):
        assert forward not in code, forward
