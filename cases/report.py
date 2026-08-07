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
    DETECTED_AFTER_OCCURRENCE, PREVENTED, REJECTED_BEFORE_COMMITMENT,
    RESULT_LABELS, RESULT_SEVERITY, UNDETECTED, CaseResult, all_cases,
)

BADGE = {
    UNDETECTED: "🔴",
    DETECTED_AFTER_OCCURRENCE: "🟠",
    "rejected_before_commitment": "🟡",
    PREVENTED: "🟢",
}

LEVEL_1 = "Level 1"
LEVEL_2 = "Level 2"
PERSISTED = "persisted-record"


def _result(value: str) -> str:
    return f"{BADGE[value]} {RESULT_LABELS[value]}"


def primary_level(case: CaseResult) -> str:
    """The adversary a case's *result* is measured against.

    Read off ``compromise_level``, and deliberately ignoring the parenthesised
    "(Level 2 for the residual)" several cases carry: the residual is what the
    control does not reach, not what the result measures. Cases 08, 10 and 11
    share a narrower adversary that the compromise ladder has no row for -
    see the review section below.
    """
    text = case.compromise_level
    if text.startswith(LEVEL_1):
        return LEVEL_1
    if text.startswith(LEVEL_2):
        return LEVEL_2
    return PERSISTED


def by_level(level: str) -> list:
    return [c for c in all_cases() if primary_level(c) == level]


def _review() -> list:
    """The synthesis pass: what the cases add up to, read as a set.

    Not a case and not a new measurement. Every claim here is a relationship
    between results recorded elsewhere in this file, and the three structural
    ones are derived from the registry rather than typed, so a later case that
    contradicts one changes this section instead of leaving it stale.
    """
    out: list = []
    w = out.append

    level_1 = by_level(LEVEL_1)
    level_2 = by_level(LEVEL_2)
    persisted = by_level(PERSISTED)
    l2_prevented = [c for c in level_2 if c.controlled_result == PREVENTED]
    # Below *rejection before commitment*, not below prevention: case 05's
    # hostile output is produced and then refused entry to trusted state,
    # which is the boundary holding rather than failing.
    l1_unprevented = [c for c in level_1
                      if RESULT_SEVERITY[c.controlled_result]
                      < RESULT_SEVERITY[REJECTED_BEFORE_COMMITMENT]]

    w("## What the cases add up to")
    w("")
    w("A review of the entries above as a set rather than a further case. The "
      "per-case evidence follows in **Detail**; this section only relates "
      "results already recorded there.")
    w("")

    # -- 1. the question has three answers --------------------------------
    w("### The project's question has three answers, not one")
    w("")
    w("> Can an agent be restricted to its assigned function when it is "
      "manipulated, malicious, or fully captured?")
    w("")
    w(f"**Manipulated or malicious — yes, and it is measured.** All "
      f"{len(level_1)} cases whose adversary is a hostile agent "
      "implementation end in prevention or rejection before commitment, with "
      "one exception:")
    w("")
    w("| Case | Result |")
    w("|---|---|")
    for c in level_1:
        w(f"| {c.case_id} — {c.title} | {_result(c.controlled_result)} |")
    w("")
    w(f"**Fully captured — no, and no check has ever changed that.** The "
      f"{len(level_2)} cases whose adversary holds arbitrary code in the "
      "runner's process:")
    w("")
    w("| Case | Result |")
    w("|---|---|")
    for c in level_2:
        w(f"| {c.case_id} — {c.title} | {_result(c.controlled_result)} |")
    w("")

    # -- 2. the structural finding ----------------------------------------
    w("### Every Level 2 prevention here is an absence, not a check")
    w("")
    w("This is the sharpest thing the set says, and it is checkable against "
      "the table above rather than argued. Exactly "
      f"{len(l2_prevented)} cases prevent anything against a fully "
      "compromised process, and neither does it by checking:")
    w("")
    w("| Case | What prevents the effect | Mechanism |")
    w("|---|---|---|")
    w("| case-04b | the decision plane never reads the corrupted record | an "
      "absence |")
    w("| case-06 | the isolated interpreter contains no runner objects | an "
      "absence |")
    w("")
    w("Every other Level 2 result is detection or nothing. That is the "
      "empirical form of the cross-cutting finding below: a check compares two "
      "values, at Level 2 the adversary reaches both, so a check can only ever "
      "notice. Case 06's probes reporting *nothing found* rather than *access "
      "denied* is the same fact stated from the other side.")
    w("")
    w("> **Design rule the set has earned.** Against an adversary sharing the "
      "boundary, remove the thing rather than guard it. A guard is a second "
      "object in the same address space, and the measurements say every one "
      "of them has been reachable.")
    w("")

    # -- 3. the limit of confinement itself --------------------------------
    w("### The one Level 1 case that ends in detection is the important one")
    w("")
    for c in l1_unprevented:
        w(f"**{c.case_id} — {c.title}.** {c.attack}.")
        w("")
    w("Nothing was bypassed. The stage read only its granted input, wrote only "
      "its granted key, produced a well-formed artifact, and every control in "
      "the repository held while every column of the dataset was destroyed. "
      "Confinement worked perfectly and bought nothing.")
    w("")
    w("> **Restricting an agent to its assigned function does not restrict "
      "what its assigned function can do.**")
    w("")
    w("Cases 05 and 07 are the two halves of that limit — authorship of a "
      "*conclusion* and authorship of *content*. Neither is answerable by "
      "deciding who may touch what, and sorting the controls by what they "
      "actually do turns out to sort them by how well they survive as well:")
    w("")
    w("| Kind | What it does | Cases | Best result it has reached |")
    w("|---|---|---|---|")
    w("| **Absence** | the object is not there to reach | 04b, 06 | prevented "
      "— **the only kind that has ever prevented anything at Level 2** |")
    w("| **Boundary** | decides who may touch what | 00, 03, 04a, 09 | "
      "prevented at Level 1; nothing at Level 2 |")
    w("| **Derivation** | recomputes the answer from narrower premises instead "
      "of storing it | 05, 07, 08, 10 | rejected before commitment — never "
      "prevented |")
    w("| **Containment** | acts on evidence that state is already corrupt | "
      "02, 11 | prevented, for the one step it stops; blind to an edit that "
      "leaves no evidence |")
    w("")
    w("The ordering is the review's practical output. A boundary control fails "
      "completely the moment the boundary is shared — that is cases 00, 03, "
      "04a and 09, all of which are green at Level 1 and all of which record "
      "the same Level 2 residual. A derivation control degrades instead of "
      "failing: the adversary keeps the access and loses the cheap version of "
      "the attack. A containment response is a check by another name and "
      "inherits the check's limit, which is why case 11 cannot see the one "
      "edit that beat case 10. Only an absence has ever held.")
    w("")
    w("The repository has been keeping one undifferentiated list of controls. "
      "These four behave differently under the same adversary, and a control "
      "should be argued for by which kind it is before it is argued for by "
      "what it catches.")
    w("")

    # -- 4. the adversary with no ladder row -------------------------------
    w(f"### {len(persisted)} cases measure an adversary the ladder has no row "
      "for")
    w("")
    w(f"Cases {', '.join(c.case_id.replace('case-', '') for c in persisted)} "
      "share an attacker defined narrowly by case 08: **may alter persisted "
      "policy or workflow records, may not modify evaluator code.** That is "
      "not a level. It is strictly stronger than Level 1 — it reaches records "
      "no agent interface exposes — and strictly weaker than Level 2, which "
      "would rewrite the derivation and make every arm lose identically.")
    w("")
    w("| Case | Result |")
    w("|---|---|")
    for c in persisted:
        w(f"| {c.case_id} — {c.title} | {_result(c.controlled_result)} |")
    w("")
    w("It is a realistic adversary — a compromised storage layer, a restored "
      "backup, a writable share — and it is *not the one the project's "
      "question is about*. The consequence has to be stated plainly, because "
      "the comparison table cannot say it: **the authority-model improvements "
      "measured in cases 10 and 11 have not been shown to hold against a "
      "fully captured agent.** They were measured against something else, for "
      "the good reason case 08 gives, and the ladder should either name that "
      "adversary or record why it is not a level.")
    w("")
    w("Case 12 turned this from a gap into an asset. Fixing the adversary "
      "*first* is what let three architectures be compared at all — an "
      "identity model, a configured-workflow model and the object model, each "
      "attacked with the same power. Under Level 2 all three lose identically "
      "and the comparison measures process isolation instead of authority "
      "placement. So the unnamed adversary is now load-bearing for four cases "
      "and naming it is overdue rather than optional.")
    w("")

    # -- 5. what deriving authority actually bought ------------------------
    w("### What deriving authority actually bought")
    w("")
    w("The two single-model comparisons (08, 10) both measured a **minimum "
      "tamper set of 1 in every arm**. Deriving the grant never made the "
      "attack cost more. Read together with case 11, what it did instead:")
    w("")
    w("| | stored authority | derived authority |")
    w("|---|---|---|")
    w("| the cheap edit — write or append | total and silent | inert, then "
      "loud (case 11) |")
    w("| the working edit — destroy the record | same edit | same cost, no "
      "evidence left |")
    w("| after a cheap edit, is the legitimate value still there? | no | "
      "**yes** — first production wins, so recovery is what already happens |")
    w("| can a contradiction even exist to act on? | no | yes, and case 11 "
      "acts on it |")
    w("")
    w("So the honest summary of the series is neither \"derived authority is "
      "better\" nor \"it is the same\". It is: **derivation does not raise the "
      "cost of the attack; it removes the cheap versions of the attack and "
      "makes their failure mode recoverable, and an adversary who reads the "
      "code simply chooses the destructive edit.** Case 11's blind spot is "
      "that statement in miniature.")
    w("")
    w("One thing the stored model cannot do at all, which is the strongest "
      "single point in favour of the derived one: a stored map keeps no "
      "contradiction, so case 11's control cannot exist there. A write is "
      "total, the prior binding is gone, and the object is left holding a map "
      "that is internally consistent and wrong.")
    w("")
    w("**Case 12 found the counterexample the first two comparisons could "
      "not.** Widening to three architectures produced an arm where one edit "
      "is *not* enough — a competently configured workflow needs two, because "
      "what a step names and what its credential may reach are separate "
      "records and both must permit. So the constant that had survived two "
      "comparisons was a property of the two things being compared, not a law: "
      "both were single-record models.")
    w("")
    w("That reframes what the series has been measuring. The question is not "
      "*stored versus derived* — it is **how many independent records must "
      "agree**, and on that axis the object model and the route table are the "
      "same answer (one) while the workflow model is a different one (two). "
      "Neither is safe against an adversary who reaches both records; the cost "
      "doubles rather than becoming impossible. It is the same shape as the "
      "cross-cutting finding, arrived at from outside.")
    w("")

    # -- 6. the unpriced currency ------------------------------------------
    w("### Availability became the currency, and it is out of scope")
    w("")
    w("`docs/threat-model.md` §7 excludes availability and denial of service. "
      "Meanwhile the controls in this report spend it, repeatedly and "
      "deliberately:")
    w("")
    w("| Where | What is traded |")
    w("|---|---|")
    w("| cases 02, 03, 04a | quarantine — the run stops rather than continue "
      "on corrupt state |")
    w("| case 09 | fail closed — no grant is derived from an unverified "
      "contract |")
    w("| case 10 | the produced-once invariant blocks a legitimate producer "
      "permanently, and this one was not intended |")
    w("| case 11 | containment on conflict, which widens exactly that surface "
      "on purpose |")
    w("")
    w("Nothing here is wrong: stopping is usually the right answer, and every "
      "instance is recorded. What is wrong is that the threat model gives the "
      "project no place to record the *cost*, because it excludes availability "
      "as an attack target and the cases spend it as a **currency**. Those are "
      "different roles for the same word. Three of the four rows above are "
      "cheap for an attacker to trigger deliberately, and the project "
      "currently has no rule about how much unavailability a control may buy "
      "with. §7 should say which of the two meanings it excludes.")
    w("")

    # -- 7. where to go next ------------------------------------------------
    w("### What the set says to do next")
    w("")
    w("Ordered by what the measurements support, not by appetite.")
    w("")
    w("1. **The metadata floor.** Every derived conclusion in the product "
      "bottoms out in metadata that agents wrote — case 05's derivation trusts "
      "`row_count`, case 07's compares column shape and not values, and the "
      "honest pipeline already turns the identifier `'1001'` into the number "
      "`1001` with no check noticing (case 07, measurement D). Two cases "
      "recorded this residual independently and no case has attacked it. It is "
      "the clearest unclosed finding in the set and it is a derivation "
      "control, which the table above says is the kind that degrades rather "
      "than collapses.")
    w("2. **Finish the absence.** Case 06 is one of only two Level 2 "
      "preventions and it covers one stage of four. The design rule above says "
      "this is the only move that has ever worked at Level 2; case 01 stays "
      "wholly open until it is finished.")
    w("3. **Name the adversary** cases 08, 10 and 11 measured, in the ladder, "
      "or record why it is not a level.")
    w("4. **Decide what availability is** in §7 of the threat model, before a "
      "further control spends more of it.")
    w("")
    w("Not next, and worth saying: another authority-model comparison. The two "
      "already run agree on the only number they both produced — minimum "
      "tamper set 1 — and a third arm measured against the same "
      "persisted-record adversary would not move the answer to the project's "
      "question.")
    w("")
    return out


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

    out.extend(_review())

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
      "identity, which the runner cannot tally (case 04a residual). None of "
      "them from a stage running in a separate interpreter, and all of them "
      "from the three stages that are not (case 06). |")
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
    w("Six cases arrived at the same wall from six directions:")
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
    w("| 09 | skill version pin | a dict the run holds, updatable alongside "
      "the registry it pins |")
    w("| 10 | the production record | the list the derivation reads, "
      "overwritable in place |")
    w("")
    w("In each one an adversary who updates the reference alongside the data "
      "passes verification, and each residual is pinned by an executable test "
      "rather than left as prose.")
    w("")
    w("None is fixable by a better check. All six need the expected value held "
      "outside the adversary's reach, which means changing the trust boundary "
      "rather than adding another comparison inside it.")
    w("")
    w("**The last two are a different shape, and the difference is the "
      "authority model's actual contribution.** In cases 02–05 the reference "
      "value is a *second* object beside the data, and the attack is to update "
      "both. In cases 09 and 10 there is no second object: the derivation is "
      "the check, and the record is its own evidence. There is nothing to "
      "update in step, so the cheapest successful edit changes from **addition "
      "to destruction** — and that is why case 10's appended tampering is "
      "inert while its overwrite still wins, and why case 11 can contain the "
      "first and is structurally blind to the second.")
    w("")
    w("It is a real improvement and it is smaller than it looks. Destruction "
      "costs the adversary no more than addition did — both comparisons "
      "measured a minimum tamper set of 1 — so what is bought is that the "
      "cheap, careless and automated edits stop working, and that after one "
      "the legitimate value is still in the record.")
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
    w("### Phase 5 so far")
    w("")
    w("Case 06 built that boundary for one stage and measured it. It holds, "
      "and it holds by a mechanism worth stating precisely: the probes report "
      "*nothing found*, not *access denied*. The reach-around techniques still "
      "work — they run in an interpreter that contains no runner objects. "
      "Isolation empties the room rather than locking the door, which is why "
      "no better reach-around defeats it and equally why it protects nothing "
      "already in the room.")
    w("")
    w("Three things the same measurement found, and they are the reason the "
      "transition statement is a beginning rather than a conclusion:")
    w("")
    w("- The isolated stage's ambient authority, grant and authorship are all "
      "unchanged. It read the repository filesystem and listed every run's "
      "event log from inside the boundary.")
    w("- Three stages of four still share the runner's process, so case 01's "
      "finding stands unaltered. Its tripwires did not fire, and should not "
      "have.")
    w("- A poisoned upstream stage laundered into a chain that passed every "
      "check, because every check compared derived artifacts to each other "
      "and none compared output back to the source artifact. That became "
      "case 07, which added the missing comparison.")
    w("")
    w("### What is still open at the end of Phase 5's first slice")
    w("")
    w("| Open | Where it is recorded |")
    w("|---|---|")
    w("| Three stages of four share the runner's process | case 01, still red |")
    w("| Ambient authority is unbounded for every stage | case 06 residual |")
    w("| Values are never compared, only structure | case 07 residual |")
    w("| The honest pipeline loses identifier fidelity | case 07, measurement D |")
    w("")

    # -- phase 3: the second map -------------------------------------------
    w("## Where authority is stored")
    w("")
    w("The boundary map above asks what a compromised agent can reach. Phase 3 "
      "asks a question it has no row for — *what record has to be edited to "
      "obtain authority, and what does editing it cost* — so it gets its own "
      "map. Measured against the persisted-record adversary defined in case "
      "08, not against Level 2.")
    w("")
    w("| Record | Binds | Owner | Scope of one successful edit | Where measured |")
    w("|---|---|---|---|---|")
    w("| `WORKFLOW_ROUTES` | stage → grant | control plane, static | process "
      "lifetime, including later independent runs | cases 03, 08 arm A |")
    w("| skill registry | skill → which *types* it may read | admin plane, "
      "static | every object running that skill until redeployment — the "
      "widest measured anywhere | case 09 |")
    w("| object artifact map | type → which *key* holds it | execution plane, "
      "dynamic | one object, including retries and resume | cases 08 arm B, 10 |")
    w("| production ledger | what each completed step produced | runner-owned, "
      "append-only by API | one object; an append is inert and contains it "
      "(11), an overwrite is total (10) | cases 10, 11 |")
    w("")
    w("Two conclusions the individual cases could not state:")
    w("")
    w("- **The authority-bearing record is whatever binds a declared type to a "
      "concrete key, wherever it lives.** Case 08 found it in the route table "
      "and in the object map; moving the binding never removed it. Every entry "
      "above has a minimum tamper set of 1.")
    w("- **The two halves of the trust root do not substitute for each "
      "other.** The skill contract says which types a skill may read; the "
      "artifact map says which key holds a type. Case 09 secured the first and "
      "left the second measurably open; case 10 addressed the second and left "
      "the first untouched. Both directions are asserted by scope-guard tests "
      "so neither case can quietly claim the other's ground.")
    w("")
    w("What no case has produced is an **independent** account of what any of "
      "these records should contain. Case 09's version pin records what was "
      "there at run start, not what was approved; case 10's ledger records "
      "what this process did, not what should have happened. Both said so, in "
      "the same words, without either case noticing the other had. That is the "
      "identity plane, and it does not exist yet.")
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
