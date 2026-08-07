"""Case 20 - two executors racing one valid one-use approval.

Pre-registered after case 19: R4 marks `consumed` only after its checks, so it
should lose this race.

Scope, fixed before measuring:

    provable     one approval cannot be concurrently acquired twice
    NOT provable exactly-once execution of an external effect

The second line is enforced by a test, because the failure mode of this case is
somebody reading `state == 'executed'` and writing "exactly once".
"""

from __future__ import annotations

import importlib.util
import os
import sys

import pytest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))
CASE_DIR = os.path.join(REPO_ROOT, "cases", "20-one-use-race")

if CASE_DIR not in sys.path:
    sys.path.insert(0, CASE_DIR)


def _load(name: str):
    spec = importlib.util.spec_from_file_location(
        f"case20_{name}", os.path.join(CASE_DIR, f"{name}.py"))
    module = importlib.util.module_from_spec(spec)
    sys.modules[f"case20_{name}"] = module
    spec.loader.exec_module(module)
    return module


r = _load("race")

RACE = "two executors race one approval"
BEFORE = "crash before the effect"
AFTER = "crash after effect, then retry"


@pytest.fixture(scope="module")
def readings():
    return r.measure()


# ---------------------------------------------------------------------------
# The pre-registered prediction.
# ---------------------------------------------------------------------------

def test_case_19s_gate_loses_the_race(readings):
    """PRE-REGISTERED in docs/target-architecture.md before this existed."""
    assert r.get(readings, r.G0, RACE).effects == 2


def test_the_atomic_claim_closes_it(readings):
    assert r.get(readings, r.G2, RACE).effects == 1
    assert r.get(readings, r.G3, RACE).effects == 1


# ---------------------------------------------------------------------------
# G1, the trap.
# ---------------------------------------------------------------------------

def test_reordering_narrows_the_window_without_closing_it(readings):
    """THE FINDING. Marking before executing looks like the fix.

    Forced at the worst moment it still performs the effect twice. What it
    changes is how hard the failure is to reach, which is worse than an
    obvious bug: ordinary testing stops finding it while an adversary who can
    influence timing still does not need luck.
    """
    assert r.get(readings, r.G1, RACE).effects == 2


def test_the_unforced_race_finds_g0_and_not_g1():
    """The measurement behind the sentence above.

    G0's window spans the external call and reproduces immediately once the
    sink takes the time a real one takes. G1's window is a couple of
    bytecodes and does not reproduce at all. Both are racy; only one is
    findable by running the tests.
    """
    assert r.concurrent_threads(r.G0, rounds=25, latency=0.002).effects == 2
    assert r.concurrent_threads(r.G1, rounds=25, latency=0.002).effects == 1


def test_an_instantaneous_sink_hides_the_race_entirely():
    """Why the interleaving hook exists. With no latency even G0 survives 200
    rounds, so a test suite that measured only this would report the gate as
    correct."""
    assert r.concurrent_threads(r.G0, rounds=200, latency=0.0).effects == 1


# ---------------------------------------------------------------------------
# What each ordering costs on a crash.
# ---------------------------------------------------------------------------

def test_the_naive_gate_loses_nothing_on_a_crash(readings):
    """G0's failure is duplication, not loss: it writes nothing before the
    effect, so a crash leaves the approval spendable."""
    before = r.get(readings, r.G0, BEFORE)
    assert before.effects == 0
    assert before.final_state == r.UNUSED


@pytest.mark.parametrize("gate", [r.G1, r.G2, r.G3])
def test_writing_before_the_effect_can_lose_the_action(readings, gate):
    """The cost of every fix. The approval is spent and the action never
    happened - and for the atomic gates it is stuck in `claimed` with no
    automatic way back."""
    before = r.get(readings, gate, BEFORE)
    assert before.effects == 0
    assert before.final_state != r.UNUSED


def test_only_the_naive_gate_double_pays_on_retry(readings):
    """G0 never recorded anything, so a retry after a crash performs the
    effect again."""
    assert r.get(readings, r.G0, AFTER).effects == 2
    for gate in (r.G1, r.G2, r.G3):
        assert r.get(readings, gate, AFTER).effects == 1


# ---------------------------------------------------------------------------
# The scope limit, enforced.
# ---------------------------------------------------------------------------

def test_exactly_once_comes_from_the_sink_not_from_the_approval():
    """THE CLAIM LIMIT. The approval record cannot deliver exactly-once for an
    effect outside its transaction.

    G3 differs from G2 only in the sink refusing a repeated execution id. If
    this ever became a property of the approval record instead, the case's
    scope statement would need rewriting - not this test.
    """
    assert r.G2.atomic_claim and r.G3.atomic_claim
    assert not r.G2.idempotent_sink and r.G3.idempotent_sink

    sink = r.Sink(idempotent=True)
    assert sink.perform("d", "exec-1") == "performed"
    assert sink.perform("d", "exec-1") == "deduplicated"
    assert sink.effects == 1

    plain = r.Sink(idempotent=False)
    plain.perform("d", "exec-1")
    plain.perform("d", "exec-1")
    assert plain.effects == 2, "without the sink's help the effect repeats"


def test_an_idempotent_sink_keys_on_execution_id_not_on_content():
    """Two legitimately identical actions must both go through. A sink that
    deduplicated on the action digest would silently drop the second of two
    real payments."""
    sink = r.Sink(idempotent=True)
    sink.perform("same-digest", "exec-1")
    sink.perform("same-digest", "exec-2")
    assert sink.effects == 2


def test_no_gate_claims_exactly_once():
    """A naming guard. If a gate is ever called something with 'exactly' in
    it, the scope statement is being overrun."""
    for gate in r.GATES:
        assert "exactly" not in gate.name.lower()
