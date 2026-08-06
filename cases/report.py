"""Render the canonical case registry as a Markdown report.

    python cases/report.py            # write cases/REPORT.md
    python cases/report.py --stdout   # print instead

Satisfies acceptance criterion 7 ("the result is visible in the demo or
report") from the same structure the tests assert against, so a claim cannot
be true in one surface and stale in another.
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cases.registry import (  # noqa: E402
    DETECTED_AFTER_OCCURRENCE, PREVENTED, RESULT_LABELS, RESULT_SEVERITY,
    UNDETECTED, all_cases,
)

BADGE = {
    UNDETECTED: "🔴",
    DETECTED_AFTER_OCCURRENCE: "🟠",
    "rejected_before_commitment": "🟡",
    PREVENTED: "🟢",
}


def _result(value: str) -> str:
    return f"{BADGE[value]} {RESULT_LABELS[value]}"


def render() -> str:
    cases = all_cases()
    out: list[str] = []
    w = out.append

    w("# Case results")
    w("")
    w("Generated from `cases/registry.py` — the canonical source. Do not edit "
      "this file by hand; run `python cases/report.py`.")
    w("")
    w("Every attack outcome is exactly one of **prevented**, **rejected before "
      "commitment**, **detected after occurrence**, or **undetected**. Vague "
      "terms are not results. For confidentiality attacks, detection after the "
      "read is not prevention — once secret content reaches the compromised "
      "agent, the loss has already occurred.")
    w("")

    # -- comparison surface ------------------------------------------------
    w("## Comparison")
    w("")
    w("| Case | Attack | Baseline | Controlled | Control | Remaining limitation |")
    w("|---|---|---|---|---|---|")
    for c in cases:
        link = f"[{c.case_id}]({os.path.relpath(c.directory, 'cases')}/README.md)"
        w(f"| {link}<br>{c.title} | {c.attack} | {_result(c.baseline_result)} "
          f"| {_result(c.controlled_result)} | {c.control} "
          f"| {c.residual_limitation} |")
    w("")

    # -- scoreboard --------------------------------------------------------
    closed = [c for c in cases if c.status == "closed"]
    open_ = [c for c in cases if c.status == "open"]
    improved = [c for c in cases if c.improved]
    w(f"**{len(cases)} cases** — {len(closed)} with a control, {len(open_)} "
      f"open by design. {len(improved)} moved to a better result class.")
    w("")
    if open_:
        w("Open cases are not failures of the project; they are findings whose "
          "control belongs to a later phase. Their controlled result is "
          "deliberately identical to their baseline result — an open case must "
          "never be shown as green.")
        w("")

    # -- detail ------------------------------------------------------------
    w("## Detail")
    w("")
    for c in cases:
        flag = "✅" if c.status == "closed" else "⚠️"
        w(f"### {flag} {c.case_id} — {c.title}")
        w("")
        w(f"**Compromise level:** {c.compromise_level}  ")
        w(f"**Attack:** {c.attack}  ")
        w(f"**Baseline:** {_result(c.baseline_result)} → "
          f"**Controlled:** {_result(c.controlled_result)}")
        w("")
        w(f"**Control.** {c.control}")
        w("")
        w("**Evidence**")
        w("")
        for item in c.evidence:
            w(f"- {item}")
        w("")
        w(f"**What this proves.** {c.what_this_proves}")
        w("")
        w(f"**What this does not prove.** {c.what_this_does_not_prove}")
        w("")
        w(f"**Residual limitation.** {c.residual_limitation}")
        w("")
        w(f"**Containment.** {c.containment}")
        w("")
        w(f"**Recovery.** {c.recovery}")
        w("")
        if c.blast_radius:
            w(f"**Blast radius.** {c.blast_radius}")
            w("")
        if c.notes:
            w(f"**Notes.** {c.notes}")
            w("")
        w(f"Reproduce: `python {c.directory}/attack.py` · Tests: `{c.test_module}`")
        w("")

    # -- what the map says so far -----------------------------------------
    w("## Where the boundary stands")
    w("")
    w("The near-term milestone is a verified map of what a malicious agent can "
      "and cannot do inside the baseline process.")
    w("")
    w("| Question | Answer so far |")
    w("|---|---|")
    w("| Which interface controls genuinely work? | Scoped reads/writes through "
      "`StoreView`, contract-to-action binding, the read-only receipt handle "
      "(case 00), and the read-only routing table with per-run pinning "
      "(case 03). |")
    w("| Which attacks remain possible through shared memory? | Ungranted "
      "reads by three independent paths (case 01); in-place mutation itself, "
      "which is detected but not prevented (case 02); rewriting the private "
      "routing table before a run starts, which is not detected at all "
      "(case 03 residual). |")
    w("| Which unauthorized writes can be detected? | New-key writes, via the "
      "runner's store diff. In-place mutation, via hash verification (case 02). |")
    w("| Which unauthorized reads remain invisible? | All of them. Bypassed "
      "reads leave `view.read_keys` empty (case 01). |")
    w("| Which runner-owned structures can agents affect? | None through the "
      "documented interface: the receipt ledger (case 00) and the routing "
      "table (case 03) are both read-only to agents. Both remain reachable by "
      "a Level 2 adversary via private attributes. |")
    w("| Which conclusions remain agent-authored? | The validation verdict "
      "(case 00 residual, to be closed by case 05). |")
    w("| Which evidence remains trustworthy? | Runner receipts. The event log "
      "still accepts forged runner-labelled events (case 04, not yet run). |")
    w("")
    w("### The cross-cutting finding")
    w("")
    w("Cases 02 and 03 arrived at the same wall from different directions:")
    w("")
    w("> An integrity check whose expected value is stored where the adversary "
      "can reach it detects careless tampering, not careful tampering.")
    w("")
    w("Case 02's `source_hash` sits in the same dict as the data it protects. "
      "Case 03's route fingerprint sits on the same session object as the "
      "routes it protects. In both, an adversary who updates the reference "
      "value alongside the data passes verification, and both residuals are "
      "pinned by executable tests.")
    w("")
    w("Neither is fixable by a better check. Both need the expected value held "
      "outside the adversary's reach, which means changing the trust boundary "
      "rather than adding another comparison inside it.")
    w("")
    return "\n".join(out) + "\n"


if __name__ == "__main__":
    text = render()
    if "--stdout" in sys.argv:
        print(text)
    else:
        path = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                            "REPORT.md")
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(text)
        print(f"wrote {path}")
