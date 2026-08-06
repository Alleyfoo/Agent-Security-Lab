"""Case 07 - corrupting downstream artifacts through your own.

Adversary: **Level 1**, and unusually cheap even by that standard. A hostile
schema agent writes one well-formed artifact to the key it was granted. The
next stage is not hostile - it is the ordinary TransformAgent doing its job
correctly with an input that is a lie.

Central claim under test:

    The run's derived conclusion compares the output's content shape back to
    the source artifact, not only to other derived artifacts.

This does NOT make the runner a data validator. It compares structure. The
residual tests below pin what that leaves untouched, including a fidelity loss
that the honest pipeline causes all by itself.
"""

from __future__ import annotations

import pytest

from agent_network_demo.agents import (
    AgentResult, KEY_CLEANED, KEY_RAW_INPUT, KEY_SCHEMA, SchemaAgent,
)
from agent_network_demo.demo_runner import RunSession
from agent_network_demo.verdict import (
    CHECK_OUTPUT_MATCHES_SOURCE, CHECK_ROW_COUNTS_CONSISTENT,
    CHECK_SCHEMA_MATCHES_OUTPUT, derive_verdict,
)


class PoisoningSchemaAgent(SchemaAgent):
    """Writes a schema profile that does not describe the source.

    Legal in every respect: one write, to the granted key, of a well-formed
    artifact of the declared contract type.
    """

    def __init__(self, columns=None, rename=None, drop=None) -> None:
        self.columns = columns
        self.rename = rename
        self.drop = drop

    def run(self, envelope, view, log):
        preview = view.get(KEY_RAW_INPUT)
        columns = list(preview["columns"])
        if self.columns is not None:
            columns = list(self.columns)
        if self.drop is not None:
            columns = [c for c in columns if c != self.drop]
        if self.rename is not None:
            old, new = self.rename
            columns = [new if c == old else c for c in columns]

        view.register(KEY_SCHEMA, {
            "type": "schema_profile", "status": "ok", "columns": columns,
            "fields": [{"name": c, "type": "string"} for c in columns],
            "row_count": preview["row_count"],
        })
        self._emit(log, action="write_artifact", input_keys=[KEY_RAW_INPUT],
                   output_keys=[KEY_SCHEMA], status="ok", checks={},
                   message=f"Inferred schema over {len(columns)} columns.")
        return AgentResult([KEY_SCHEMA], "Inferred schema from raw artifact.", {})


def _derive(artifacts, receipts=None):
    return derive_verdict(
        artifacts, receipts if receipts is not None else [PASSING],
        KEY_RAW_INPUT, KEY_SCHEMA, KEY_CLEANED)


PASSING = {"agent": "schema_agent", "status": "ok", "contract_result": "passed"}


def _chain(source_cols, output_cols, rows=20):
    return {
        KEY_RAW_INPUT: {"row_count": rows, "columns": list(source_cols)},
        KEY_SCHEMA: {"columns": list(output_cols)},
        KEY_CLEANED: {"row_count": rows, "columns": list(output_cols)},
    }


@pytest.fixture
def poisoned(data_dir, key_file_path):
    sessions = []

    def _factory(**kwargs):
        s = RunSession(data_dir=str(data_dir))
        s.start_run(key_file_path)
        s._agents[1] = PoisoningSchemaAgent(**kwargs)
        while not s.done and not s.quarantined and not s.error:
            s.step()
        sessions.append(s)
        return s

    yield _factory
    for s in sessions:
        if s.log is not None:
            s.log.close()


@pytest.fixture
def honest(data_dir, key_file_path):
    s = RunSession(data_dir=str(data_dir))
    s.start_run(key_file_path)
    while not s.done:
        s.step()
    yield s
    s.log.close()


# ---------------------------------------------------------------------------
# The check itself.
# ---------------------------------------------------------------------------

def test_a_chain_that_preserves_the_source_columns_passes():
    derived = _derive(_chain(["a", "b"], ["a", "b"]))

    assert derived["checks"][CHECK_OUTPUT_MATCHES_SOURCE] is True
    assert derived["verdict"] == "ok"


@pytest.mark.parametrize("source, output, missing, added", [
    pytest.param(["a", "b"], ["fabricated"], ["a", "b"], ["fabricated"],
                 id="fabricated"),
    pytest.param(["a", "b"], ["a"], ["b"], [], id="dropped"),
    pytest.param(["a", "b"], ["a", "bb"], ["b"], ["bb"], id="renamed"),
    pytest.param(["a", "b"], ["b", "a"], [], [], id="reordered"),
])
def test_divergence_from_the_source_is_named(source, output, missing, added):
    derived = _derive(_chain(source, output))

    assert derived["checks"][CHECK_OUTPUT_MATCHES_SOURCE] is False
    assert derived["verdict"] == "warn"
    reason = next(r for r in derived["reasons"]
                  if r.startswith("output columns do not match the source"))
    assert f"missing {missing}" in reason
    assert f"added {added}" in reason


def test_a_missing_source_is_not_treated_as_a_match():
    """Fail-closed on absent evidence, like every other check here."""
    artifacts = _chain(["a"], ["a"])
    del artifacts[KEY_RAW_INPUT]

    derived = _derive(artifacts)
    assert derived["checks"][CHECK_OUTPUT_MATCHES_SOURCE] is False


def test_the_check_is_independent_of_the_derived_to_derived_ones():
    """Its whole reason to exist: the other checks agree while it does not."""
    derived = _derive(_chain(["a", "b"], ["fabricated"]))
    checks = derived["checks"]

    assert checks[CHECK_SCHEMA_MATCHES_OUTPUT] is True, (
        "schema and cleaned output agree - that is the laundering"
    )
    assert checks[CHECK_ROW_COUNTS_CONSISTENT] is True
    assert checks[CHECK_OUTPUT_MATCHES_SOURCE] is False


# ---------------------------------------------------------------------------
# The three attacks, end to end.
# ---------------------------------------------------------------------------

def test_a_fabricated_schema_is_detected(poisoned):
    session = poisoned(columns=["fabricated"])
    report = session.report()
    cleaned = session.store.get(KEY_CLEANED)

    assert cleaned["columns"] == ["fabricated"]
    assert all(row == {"fabricated": None} for row in cleaned["rows_data"]), (
        "the run must really have destroyed the data, or this proves nothing"
    )
    assert report["verdict"]["verdict"] == "warn"
    assert report["checks"][CHECK_OUTPUT_MATCHES_SOURCE] is False


def test_a_dropped_column_is_detected(poisoned):
    """The subtlest structurally and the worst operationally."""
    session = poisoned(drop="Total")
    report = session.report()
    cleaned = session.store.get(KEY_CLEANED)

    assert "Total" not in cleaned["columns"]
    assert cleaned["row_count"] == session.store.get(KEY_RAW_INPUT)["row_count"], (
        "row counts still agree - the loss is invisible to that check"
    )
    assert report["verdict"]["verdict"] == "warn"
    assert "missing ['Total']" in " ".join(report["reasons"])


def test_a_renamed_column_is_detected(poisoned):
    session = poisoned(rename=("Total", "Totl"))
    report = session.report()
    cleaned = session.store.get(KEY_CLEANED)

    assert all(row.get("Totl") is None for row in cleaned["rows_data"])
    assert report["verdict"]["verdict"] == "warn"
    assert report["checks"][CHECK_OUTPUT_MATCHES_SOURCE] is False


def test_the_corruption_still_happened(poisoned):
    """`detected_after_occurrence`, not `prevented`. The artifacts are written
    and stay written; nothing stops a stage writing inside its own grant."""
    session = poisoned(drop="Total")

    assert session.store.has(KEY_CLEANED)
    assert "Total" not in session.store.get(KEY_CLEANED)["columns"]
    assert session.quarantined is False
    assert session.done is True


def test_the_honest_run_is_unaffected(honest):
    """No false positives, on the fixture the whole suite uses."""
    report = honest.report()

    assert report["checks"][CHECK_OUTPUT_MATCHES_SOURCE] is True
    assert report["verdict"]["verdict"] == "ok"
    assert report["review_required"] is False


def test_the_poisoning_agent_broke_no_other_control(poisoned):
    """Level 1 through the front door: every other control holds throughout."""
    session = poisoned(drop="Total")

    assert session.store.verify_all() == []          # case 02
    assert session.quarantined is False              # cases 02, 03, 04
    assert all(r["contract_result"] == "passed"
               for r in session.receipts())          # case 00
    assert session.report()["verdict_source"] == "runner_derived"   # case 05


# ---------------------------------------------------------------------------
# Residual limitations - executable.
# ---------------------------------------------------------------------------

def test_residual_the_honest_pipeline_already_loses_identifier_fidelity(honest):
    """RESIDUAL, and it is a property of the baseline rather than of any attack.

    ``"1001"`` is a string in the source and an integer in the output, because
    the schema stage infers "integer" for a column of digit strings and the
    transform coerces it. Every column matches, every count matches, and no
    check looks at a value - so this is invisible to all five.

    This is the concept note's section 9 sitting in the fixture. Closing it
    needs the canonical artifact to carry field semantics, so that "identifier"
    is a fact about the data rather than a guess made from its shape. That is a
    different and larger claim.
    """
    source = honest.store.get(KEY_RAW_INPUT)["rows_data"][0]
    output = honest.store.get(KEY_CLEANED)["rows_data"][0]

    assert source["Order ID"] == "1001"
    assert output["Order ID"] == 1001, (
        "if this now fails, the pipeline gained value-level fidelity - update "
        "case 07's residual-limitation section and this test"
    )
    assert honest.report()["verdict"]["verdict"] == "ok", (
        "and no check noticed"
    )


def test_residual_row_content_is_not_compared(data_dir, key_file_path):
    """RESIDUAL. Structure is compared; values are not.

    A stage that keeps every column name and mistypes every one of them passes
    the check: the shape is preserved, the content is coerced away.
    """
    class MistypingSchemaAgent(SchemaAgent):
        def run(self, envelope, view, log):
            preview = view.get(KEY_RAW_INPUT)
            columns = list(preview["columns"])
            view.register(KEY_SCHEMA, {
                "type": "schema_profile", "status": "ok", "columns": columns,
                "fields": [{"name": c, "type": "integer"} for c in columns],
                "row_count": preview["row_count"],
            })
            self._emit(log, action="write_artifact", input_keys=[KEY_RAW_INPUT],
                       output_keys=[KEY_SCHEMA], status="ok", checks={},
                       message="Inferred schema.")
            return AgentResult([KEY_SCHEMA], "Inferred schema.", {})

    session = RunSession(data_dir=str(data_dir))
    session.start_run(key_file_path)
    session._agents[1] = MistypingSchemaAgent()
    while not session.done and not session.error:
        session.step()
    report = session.report()
    source = session.store.get(KEY_RAW_INPUT)
    cleaned = session.store.get(KEY_CLEANED)
    session.log.close()

    assert cleaned["columns"] == source["columns"], "the shape is preserved"
    # Declaring the money column an integer truncates every amount. Text
    # columns survive, because coercion that fails leaves the value alone -
    # so the damage is silent and selective, which is worse.
    assert source["rows_data"][0]["Total"] == "42.50"
    assert cleaned["rows_data"][0]["Total"] == 42, (
        "the content must actually have changed, or this proves nothing"
    )
    assert report["checks"][CHECK_OUTPUT_MATCHES_SOURCE] is True, (
        "if this now fails, values became part of the comparison - update "
        "case 07's residual-limitation section and this test"
    )
