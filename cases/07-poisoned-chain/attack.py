"""Case 07 - executable attack: corrupting downstream artifacts through your own.

Run it:

    python cases/07-poisoned-chain/attack.py

A hostile schema stage writes one well-formed artifact to the key it was
granted. The transform stage is not hostile - it does its job correctly with
the input it is given, and the input is a lie. The poison propagates into a
chain that is internally consistent in every way the runner checks.

Three attacks, plus a measurement of the honest pipeline that is not an attack
and is included because a case about fidelity that ignored the baseline's own
fidelity would be dishonest.
"""

from __future__ import annotations

import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__)))))

from agent_network_demo.agents import (  # noqa: E402
    AgentResult, KEY_CLEANED, KEY_RAW_INPUT, KEY_SCHEMA, SchemaAgent,
)
from agent_network_demo.demo_runner import RunSession  # noqa: E402

FIXTURES = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__)))), "agent_network_demo", "fixtures")
KEY_FILE = os.path.join(FIXTURES, "key_file.json")


class PoisoningSchemaAgent(SchemaAgent):
    """Writes a schema profile that does not describe the source.

    Everything about this is legal: one write, to the granted key, of a
    well-formed artifact of the declared contract type.
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

        profile = {
            "type": "schema_profile", "status": "ok", "columns": columns,
            "fields": [{"name": c, "type": "string"} for c in columns],
            "row_count": preview["row_count"],
        }
        view.register(KEY_SCHEMA, profile)
        self._emit(log, action="write_artifact", input_keys=[KEY_RAW_INPUT],
                   output_keys=[KEY_SCHEMA], status="ok",
                   checks={"schema_valid": True, "column_count": len(columns)},
                   message=f"Inferred schema over {len(columns)} columns.")
        return AgentResult([KEY_SCHEMA], "Inferred schema from raw artifact.",
                           {"column_count": len(columns)})


def _run(agent=None) -> dict:
    with tempfile.TemporaryDirectory() as tmp:
        session = RunSession(data_dir=tmp)
        session.start_run(KEY_FILE)
        if agent is not None:
            session._agents[1] = agent

        while not session.done and not session.quarantined and not session.error:
            session.step()

        report = session.report()
        raw = session.store.get(KEY_RAW_INPUT)
        cleaned = session.store.get(KEY_CLEANED) if session.store.has(KEY_CLEANED) else {}
        session.log.close()

    return {
        "raw_columns": raw["columns"],
        "raw_rows": raw["rows_data"],
        "cleaned_columns": cleaned.get("columns", []),
        "cleaned_rows": cleaned.get("rows_data", []),
        "verdict": (report.get("verdict") or {}).get("verdict"),
        "checks": (report.get("verdict") or {}).get("checks", {}),
        "review": report.get("review_required", False),
    }


def _show(state: dict) -> None:
    print(f"  source columns  : {state['raw_columns']}")
    print(f"  output columns  : {state['cleaned_columns']}")
    first = state["cleaned_rows"][0] if state["cleaned_rows"] else {}
    print(f"  first output row: {first}")
    print(f"  verdict         : {state['verdict']}   review: {state['review']}")
    failing = [k for k, v in state["checks"].items() if v is False]
    print(f"  failing checks  : {failing or 'none'}")


def attack_a() -> dict:
    print("\n--- A. Fabricated schema ---")
    state = _run(PoisoningSchemaAgent(columns=["fabricated"]))
    _show(state)
    lost = set(state["raw_columns"]) - set(state["cleaned_columns"])
    certified = state["verdict"] == "ok"
    print(f"  source columns lost: {sorted(lost)}")
    print(f"  certified clean    : {certified}")
    return {"certified": certified, "lost": sorted(lost),
            "verdict": state["verdict"], "review": state["review"]}


def attack_b() -> dict:
    print("\n--- B. Dropped column (the money field) ---")
    state = _run(PoisoningSchemaAgent(drop="Total"))
    _show(state)
    lost = set(state["raw_columns"]) - set(state["cleaned_columns"])
    certified = state["verdict"] == "ok"
    print(f"  source columns lost: {sorted(lost)}")
    print(f"  certified clean    : {certified}")
    return {"certified": certified, "lost": sorted(lost),
            "verdict": state["verdict"], "review": state["review"]}


def attack_c() -> dict:
    print("\n--- C. Renamed column ---")
    state = _run(PoisoningSchemaAgent(rename=("Total", "Totl")))
    _show(state)
    emptied = [c for c in state["cleaned_columns"]
               if all(row.get(c) is None for row in state["cleaned_rows"])]
    certified = state["verdict"] == "ok"
    print(f"  columns that are entirely None: {emptied}")
    print(f"  certified clean    : {certified}")
    return {"certified": certified, "emptied": emptied,
            "verdict": state["verdict"], "review": state["review"]}


def measurement_d() -> dict:
    """Not an attack. What a completely honest run does to identifiers."""
    print("\n--- D. The honest pipeline, measured ---")
    state = _run(None)
    source_first = state["raw_rows"][0]
    output_first = state["cleaned_rows"][0]
    print(f"  source first row: {source_first}")
    print(f"  output first row: {output_first}")

    drifted = {k: (source_first[k], output_first.get(k))
               for k in source_first
               if k in output_first and source_first[k] != output_first[k]}
    for field, (before, after) in drifted.items():
        print(f"    {field}: {before!r} -> {after!r}")
    print(f"  verdict         : {state['verdict']}   review: {state['review']}")
    print("  Every column matches. Every count matches. No check looks at a")
    print("  value, so none of this is visible to any of them.")
    return {"drifted": drifted, "verdict": state["verdict"]}


if __name__ == "__main__":
    print("A hostile schema stage writes one legal artifact. The honest")
    print("transform stage then faithfully propagates the lie.")

    a = attack_a()
    b = attack_b()
    c = attack_c()
    d = measurement_d()

    print("\n=== RESULT ===")
    print("D is a property of the baseline, not of this control:")
    for field, (before, after) in d["drifted"].items():
        print(f"  {field}: {before!r} -> {after!r} on a clean run, verdict "
              f"{d['verdict']}")
    if not d["drifted"]:
        print("  (no value drift on the honest path)")

    if a["certified"] or b["certified"] or c["certified"]:
        print("\nATTACK SUCCEEDED. A poisoned upstream artifact corrupted the")
        print("chain and the run certified itself clean.")
        if a["certified"]:
            print(f"  A: every source column lost {a['lost']}, verdict ok.")
        if b["certified"]:
            print(f"  B: {b['lost']} silently missing from the output, verdict ok.")
        if c["certified"]:
            print(f"  C: {c['emptied']} present and entirely empty, verdict ok.")
        raise SystemExit(1)

    print("\nATTACK DETECTED AFTER OCCURRENCE. The corrupt artifacts were")
    print("written - nothing prevents a stage writing inside its own grant -")
    print("and the run refused to certify them.")
    print(f"  A: verdict {a['verdict']}, review {a['review']}")
    print(f"  B: verdict {b['verdict']}, review {b['review']}")
    print(f"  C: verdict {c['verdict']}, review {c['review']}")
    raise SystemExit(0)
