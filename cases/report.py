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
      "(case 00), the read-only routing table with per-run pinning (case 03), "
      "and the author-bound event-log handle (case 04). |")
    w("| Which attacks remain possible through shared memory? | Ungranted "
      "reads by three independent paths (case 01); in-place mutation itself, "
      "which is detected but not prevented (case 02); rewriting the private "
      "routing table before a run starts, which is not detected at all "
      "(case 03 residual); appending a log event under another agent's "
      "identity, which the runner cannot tally (case 04a residual). |")
    w("| Which unauthorized writes can be detected? | New-key writes, via the "
      "runner's store diff. In-place mutation, via hash verification (case 02). "
      "Events forged under the runner's own identity, via the runner's tally "
      "(case 04a). |")
    w("| Which unauthorized reads remain invisible? | All of them. Bypassed "
      "reads leave `view.read_keys` empty (case 01). |")
    w("| Which runner-owned structures can agents affect? | None through the "
      "documented interface: the receipt ledger (case 00), the routing table "
      "(case 03) and the identity an event is attributed to (case 04) are all "
      "runner-assigned. All remain reachable by a Level 2 adversary via "
      "private attributes. |")
    w("| Which conclusions remain agent-authored? | None that the workflow "
      "acts on. The validator still *authors* a conclusion — authorship is not "
      "constrainable from outside the component that authors — but the run's "
      "conclusion is derived by the runner and disagreement is flagged "
      "(case 05). |")
    w("| Which evidence remains trustworthy? | Runner receipts. The event log "
      "is a *narrative record*, not evidence of authorization: nothing derives "
      "an authorization decision from it, which case 04b measured rather than "
      "assumed. Its attribution is now runner-assigned and runner-labelled "
      "forgery is detected (case 04a), but it is still not tamper-evident — "
      "no chain, and the file is rewritable (L5, Phase 7). |")
    w("")
    w("**All seven entries are now answered.** The map is the gate to Phase 5, "
      "and it is met.")
    w("")
    w("### The cross-cutting finding")
    w("")
    w("Four cases arrived at the same wall from four directions:")
    w("")
    w("> An integrity check whose expected value is stored where the adversary "
      "can reach it detects careless tampering, not careful tampering.")
    w("")
    w("| Case | The check | Where its reference value lives |")
    w("|---|---|---|")
    w("| 02 | artifact hash | the same dict as the data it protects |")
    w("| 03 | route fingerprint | the same session object as the routes |")
    w("| 04a | runner event tally | an ordinary attribute on the session |")
    w("| 05 | derived verdict | a module the adversary can patch, and an "
      "attribute it can rewrite |")
    w("")
    w("In each one an adversary who updates the reference alongside the data "
      "passes verification, and each residual is pinned by an executable test "
      "rather than left as prose.")
    w("")
    w("None is fixable by a better check. All four need the expected value "
      "held outside the adversary's reach, which means changing the trust "
      "boundary rather than adding another comparison inside it.")
    w("")

    # -- the gate ---------------------------------------------------------
    w("## The transition statement")
    w("")
    w("The boundary map above is the gate to Phase 5. With every entry "
      "answered, the statement the project reserved is now earned:")
    w("")
    w("> The remaining attacks cannot be closed honestly while agent and "
      "trusted infrastructure share a Python process. The next control changes "
      "the trust boundary rather than hiding references inside the same "
      "boundary.")
    w("")
    w("The evidence for it is specific, not rhetorical: one case is wholly "
      "open with no in-process control available (case 01, three independent "
      "reach-around read paths that share no mechanism), and every closed "
      "case's residual is the same shape — the reference value sits inside the "
      "adversary's reach. Those are not four problems with four fixes. They "
      "are one problem, and it is the boundary.")
    w("")
    w("What Phase 5 must **not** claim on arrival is set out in "
      "`cases/README.md`: a separate process prevents direct inspection and "
      "modification of the runner's memory and object graph, and nothing more "
      "until each further claim is measured on its own.")
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
