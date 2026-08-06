"""Deterministic derivation of a run's conclusion from its evidence.

The validation agent used to read the evidence, draw the conclusion, and
publish it — one untrusted component doing all three, with nothing comparing
its answer to anything. Protecting the *input* to a computation says nothing
about the output when the adversary owns the computation (case 05).

So the derivation lives here, as a pure function, and it is called twice:

* by ``ValidationAgent``, whose result is a **recommendation**;
* by ``RunSession``, over its own store and its own receipt ledger, whose
  result is the run's **conclusion**.

Both callers use the same implementation on purpose. A second, independently
written implementation would drift, and drift shows up as disagreement on
honest runs — false positives in the one signal that has to stay meaningful.
The security property is not that two implementations agree; it is that the
trusted side computes the answer itself instead of accepting one.

Scope, stated plainly: these are four structural checks over metadata the
pipeline's own agents wrote. A hostile stage that drops a row *and* decrements
``row_count`` is self-consistent and passes. Case 02's hash proves an artifact
has not changed since registration; it does not prove it was truthful then.
This module supervises a workflow; it does not validate data.
"""

from __future__ import annotations

from typing import Any, Dict, List, Mapping, Optional, Sequence

# The check names, in the order they are computed. Named here so the runner,
# the agent and the tests refer to one list rather than four string literals.
CHECK_CHAIN_COMPLETE = "chain_complete"
CHECK_ALL_WRITES_ALLOWED = "all_writes_allowed"
CHECK_SCHEMA_MATCHES_OUTPUT = "schema_matches_output"
CHECK_ROW_COUNTS_CONSISTENT = "row_counts_consistent"
CHECK_OUTPUT_MATCHES_SOURCE = "output_matches_source"

CHECKS = (CHECK_CHAIN_COMPLETE, CHECK_ALL_WRITES_ALLOWED,
          CHECK_SCHEMA_MATCHES_OUTPUT, CHECK_ROW_COUNTS_CONSISTENT,
          CHECK_OUTPUT_MATCHES_SOURCE)


def derive_verdict(artifacts: Mapping[str, Any],
                   receipts: Sequence[Mapping[str, Any]],
                   raw_key: str, schema_key: str, cleaned_key: str,
                   ) -> Dict[str, Any]:
    """Evidence in, conclusion out. No agent-authored conclusion reaches this.

    ``artifacts`` holds only the chain artifacts actually present — absence is
    itself evidence, and is what ``chain_complete`` reports on. The key names
    are parameters rather than imports so this module depends on nothing in the
    agent layer.
    """
    checks: Dict[str, Any] = {}
    reasons: List[str] = []

    expected = [raw_key, schema_key, cleaned_key]
    present = [k for k in expected if k in artifacts]
    checks[CHECK_CHAIN_COMPLETE] = len(present) == len(expected)
    if not checks[CHECK_CHAIN_COMPLETE]:
        missing = [k for k in expected if k not in present]
        reasons.append(f"chain incomplete: missing {missing}")

    # Authorization comes from the runner's receipts, never from anything an
    # agent said about itself (control B18, measured in case 04b).
    bad_receipts = [r for r in receipts
                    if r.get("status") != "ok"
                    or r.get("contract_result") != "passed"]
    checks[CHECK_ALL_WRITES_ALLOWED] = bool(receipts) and not bad_receipts
    if bad_receipts:
        reasons.append("runner receipts contain authorization failures")

    if schema_key in artifacts and cleaned_key in artifacts:
        schema_cols = artifacts[schema_key].get("columns", [])
        cleaned_cols = artifacts[cleaned_key].get("columns", [])
        matches = schema_cols == cleaned_cols
        checks[CHECK_SCHEMA_MATCHES_OUTPUT] = matches
        if not matches:
            reasons.append("schema columns != cleaned output columns")
    else:
        checks[CHECK_SCHEMA_MATCHES_OUTPUT] = False
        reasons.append("schema or cleaned output missing")

    # Case 07. The three checks above compare derived artifacts to each other,
    # so a poisoned upstream stage is laundered by an honest downstream one
    # into a chain that agrees with itself. This is the only check that looks
    # back at the artifact the chain started from.
    if raw_key in artifacts and cleaned_key in artifacts:
        source_cols = artifacts[raw_key].get("columns", [])
        output_cols = artifacts[cleaned_key].get("columns", [])
        preserved = source_cols == output_cols
        checks[CHECK_OUTPUT_MATCHES_SOURCE] = preserved
        if not preserved:
            missing = [c for c in source_cols if c not in output_cols]
            added = [c for c in output_cols if c not in source_cols]
            reasons.append(
                f"output columns do not match the source: missing {missing}, "
                f"added {added}"
            )
    else:
        checks[CHECK_OUTPUT_MATCHES_SOURCE] = False
        reasons.append("source or cleaned output missing")

    counts = [artifacts[k].get("row_count")
              for k in (raw_key, cleaned_key) if k in artifacts]
    checks[CHECK_ROW_COUNTS_CONSISTENT] = (
        len(set(counts)) <= 1 and None not in counts
    )
    if not checks[CHECK_ROW_COUNTS_CONSISTENT] and counts:
        reasons.append(f"inconsistent row counts: {counts}")

    ok = bool(checks) and all(checks.values()) and not reasons
    return {
        "type": "validation_verdict",
        "status": "ok" if ok else "warn",
        "verdict": "ok" if ok else "warn",
        "checks": checks,
        "reasons": reasons if reasons else ["all checks passed"],
    }


def verdict_disagreement(derived: Mapping[str, Any],
                         recommendation: Optional[Mapping[str, Any]],
                         ) -> List[str]:
    """Name every decision field on which the two conclusions differ.

    Only the *decision* is compared — the verdict value and each named check.
    ``reasons`` and ``message`` are prose and are not bound, so a validator can
    still attach a misleading narrative to a recommendation whose decision
    agrees. That residual is recorded in case 05 rather than half-closed by
    comparing strings.

    Symmetric on purpose. An optimistic lie and a pessimistic one both have to
    surface: a control that resolved disagreement by taking the worse verdict
    would let a compromised validator condemn every run.
    """
    if recommendation is None:
        return ["no recommendation was produced"]

    differences: List[str] = []
    claimed = recommendation.get("verdict")
    if claimed != derived.get("verdict"):
        differences.append(
            f"verdict: recommended {claimed!r}, derived {derived.get('verdict')!r}"
        )

    claimed_checks = recommendation.get("checks") or {}
    derived_checks = derived.get("checks") or {}
    for name in sorted(set(derived_checks) | set(claimed_checks)):
        if claimed_checks.get(name) != derived_checks.get(name):
            differences.append(
                f"check {name}: recommended {claimed_checks.get(name)!r}, "
                f"derived {derived_checks.get(name)!r}"
            )
    return differences
