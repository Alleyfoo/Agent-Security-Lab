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
LEVEL_1_5 = "Level 1.5"
LEVEL_2 = "Level 2"
PERSISTED = "persisted-record"
NOT_AN_ATTACK = "not an attack case"


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
    # 1.5 must be tested first - it startswith "Level 1" too, and getting that
    # ordering wrong silently files the configuration adversary's cases under
    # Level 1 and rewrites three tables in this report.
    if text.startswith(LEVEL_1_5):
        return PERSISTED
    if text.startswith(LEVEL_1):
        return LEVEL_1
    if text.startswith(LEVEL_2):
        return LEVEL_2
    # Some cases measure an input or a report rather than an adversary. They
    # must not fall through into the configuration adversary's bucket, which
    # would put them in three of this report's tables and one tripwire.
    if text.startswith("Not an attack"):
        return NOT_AN_ATTACK
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
      "compromised process, and not one does it by checking:")
    w("")
    w("| Case | What prevents the effect | Mechanism |")
    w("|---|---|---|")
    w("| case-04b | the decision plane never reads the corrupted record | "
      "**dependency** absence |")
    w("| case-06 | the isolated interpreter contains no runner objects | "
      "**ambient** absence |")
    w("| case-21 | the approval gate's code, state and credential are not in "
      "the worker's process | **ambient** absence |")
    w("| case-22 | the gate's protocol has no operation that removes a record "
      "| **capability** absence |")
    w("")
    w("Case 22's refusal is the cleanest statement of the pattern in the "
      "whole set. Asked to compact its store, the gate answers **no such "
      "operation** - not *you may not*. The verb is absent, and that is the "
      "entire control.")
    w("")

    # -- 2b. absence had been one word for three mechanisms ----------------
    w("#### But \"absence\" was carrying three different mechanisms")
    w("")
    w("This came out of integrating the applied programme, and it is a "
      "correction to how the finding above had been stated rather than a new "
      "case. The word was doing three jobs, and the three degrade "
      "differently, so a reader given one word cannot tell which guarantee "
      "they are being offered.")
    w("")
    w("| Kind | What it means | Fails when | Cases |")
    w("|---|---|---|---|")
    w("| **ambient** | the adversary's boundary cannot reach the thing at "
      "all - it is not in the interpreter, the process or the address space "
      "| only if the boundary itself fails | 06, 21 |")
    w("| **capability** | the system *can* perform the operation and the code "
      "works; the adversary's invocation vocabulary has no word that "
      "addresses it | anything widens the vocabulary - a "
      "configuration-adversary problem (case 15), not a boundary problem "
      "| 22, and demo step F |")
    w("| **dependency** | the operation is reachable and its output "
      "corruptible, but no security decision consumes it | some later feature "
      "decides the corruptible record would be convenient to read | 04b |")
    w("")
    w("The uncomfortable one is case 22. `Gate.compact` and "
      "`DurableStore.rewrite` are both implemented and both work; an arm flag "
      "is what refuses. That is a real control at the protocol boundary and "
      "the Level 2 adversary is not inside the gate's process - but it is "
      "**not** case 06's control, where the objects genuinely do not exist in "
      "the address space the adversary occupies. Filing both under one word "
      "flattered the weaker of the two.")
    w("")
    w("Demo step F is the same shape, which is how the distinction surfaced: "
      "`Transport.restart_all()` exists, works, clears every fault and would "
      "score 100% recovered. The recovery worker simply holds no verb that "
      "names it. That is a genuine control and it is worth exactly as much as "
      "the vocabulary is stable - which is the point of stating the kind "
      "instead of the word.")
    w("")
    w("The design rule survives unchanged. What changes is that a case "
      "claiming an absence must now say **which kind**, and a test enforces "
      "it.")
    w("")
    w("**Case 21 is the first one the rule predicted rather than explained.** "
      "The design rule below was written after cases 04b and 06; case 21 was "
      "then built by applying it to the approval plane, and it produced the "
      "third absence and the third Level 2 prevention. Five of its six probes "
      "land on nothing for the same reason case 06 gave - the room is empty, "
      "not the door locked. Its sixth is the instructive one: the gate's "
      "*persisted store* stayed in the worker's reach, so that probe still "
      "succeeds. Moving the code is half an absence.")
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

    # -- 3b. the principle, and its measured bound -------------------------
    w("### The principle case 12 produced, stated with its bound")
    w("")
    w("Case 12 found the mechanism the *derivation* row above was groping at, "
      "and it is not \"derive rather than store\":")
    w("")
    w("> **Authority is harder to forge when it must be derived from "
      "independent premises than when it is read from one writable "
      "conclusion.**")
    w("")
    w("This is **architecture-neutral**. It is not a property of objects. The "
      "arm that had it in case 12 was the conventional workflow model, which "
      "acquired it by ordinary competent configuration rather than by design "
      "intent: what a step names and what its credential may reach are "
      "separate records, and both must permit.")
    w("")
    w("Two things have to be said about it in the same breath, because the "
      "measurement supports one and not the other.")
    w("")
    w("**What was measured: the count sets the cost.** Two independent "
      "premises cost two edits. That is a real and reproducible doubling, and "
      "it is the only arm in three where a single edit was not enough.")
    w("")
    w("**What was not measured: the count does not set the possibility.** "
      "Both of arm B's records sit inside the same adversary's reach, so two "
      "edits is a price, not a wall. An adversary who can edit one can edit "
      "the other.")
    w("")
    w("Put beside the cross-cutting finding, the two compose into one "
      "statement the series can actually stand behind:")
    w("")
    w("| Property | Sets | Evidence |")
    w("|---|---|---|")
    w("| how many independent premises must agree | the **cost** of forging "
      "authority | case 12: 1 premise → 1 edit, 2 premises → 2 edits |")
    w("| whether any premise is outside the adversary's reach | whether "
      "forging is **possible at all** | the cross-cutting finding, six cases: "
      "every reference value inside the reach has fallen |")
    w("")
    w("So multiplying premises inside one trust boundary buys a linear price "
      "increase, and moving one premise outside it is the only thing that has "
      "ever bought more than a price increase. The first is cheap to do and "
      "worth doing; it should not be mistaken for the second.")
    w("")
    w("**The falsifiable prediction, and its result.** Pre-registered here "
      "before case 13 existed: *adding a second independent premise to arm A "
      "or arm C should raise that arm's minimum tamper set to 2, without "
      "changing which model it is.* Case 13 tested it. **Confirmed — under "
      "two conditions the prediction did not state**, and two of its four "
      "measured configurations still sit at 1.")
    w("")
    w("| Configuration | Minimum tamper set |")
    w("|---|---|")
    w("| A — permission table only (case 12) | 1 |")
    w("| A — + label policy, domain keyed on the **subject** | **1** |")
    w("| A — + label policy, domain keyed on the **stage** | **2** |")
    w("| C — binding + skill contract (case 12) | 1 |")
    w("| C — + artifact declaration | **1** |")
    w("| C — + artifact declaration + object-type policy | **2** |")
    w("")
    w("**Condition 1 — the premises must not be functions of the same "
      "attacker-controlled key.** Arm A's label policy is a genuinely separate "
      "record, genuinely consulted, and worth nothing when the domain is keyed "
      "on the subject: reassigning which subject the stage runs as moves both "
      "premises at once. Keyed on the stage instead — which is how SELinux "
      "actually derives a domain — the identical attack fails. This is the "
      "confused-deputy shape arriving in the authority model: the attacker "
      "does not forge a permission, it changes which principal the question is "
      "asked about.")
    w("")
    w("**Condition 2 — a premise raises the cost of the surface it covers and "
      "no other.** Arm C's artifact declarations closed case 10's surviving "
      "overwrite route completely and did nothing at all about the "
      "skill-contract route, which still obtained at one edit. An arm with "
      "more authority-bearing surfaces needs more premises to reach the same "
      "minimum — which is the compounding cost of expressiveness, and it cost "
      "the object model two premises where arm A needed one.")
    w("")
    w("So the principle is usable rather than merely true:")
    w("")
    w("> To raise the cost of forging authority, add a premise that is **(a)** "
      "consulted at use time, **(b)** not a function of an index the attacker "
      "can change, and **(c)** on the specific surface being defended. Missing "
      "any of the three buys nothing. The subject-keyed variant is the one to "
      "remember: it looks exactly like defence in depth and measures as no "
      "defence at all.")
    w("")

    # -- 4. the adversary with no ladder row -------------------------------
    w(f"### Level 1.5, the configuration adversary — named after "
      f"{len(persisted)} cases had measured it")
    w("")
    w(f"Cases {', '.join(c.case_id.replace('case-', '') for c in persisted)} "
      "share an attacker defined narrowly by case 08: **may alter persisted "
      "policy or workflow records, may not modify evaluator code.** For most "
      "of that time it had no rung on the compromise ladder. It has one now — "
      "`Level 1.5`, numbered so Levels 2–7 and every case README citing them "
      "keep their numbers.")
    w("")
    w("It is defined by **reach, not by which component is captured**, which "
      "is why it was awkward to place: it need not control any agent at all. "
      "A compromised storage layer, a restored backup, a writable config "
      "share or a deploy pipeline is Level 1.5 while every worker is honest. "
      "It is stronger than Level 1 — it reaches records no agent interface "
      "exposes — and weaker than Level 2, which would rewrite the derivation "
      "and make every arm of a comparison lose identically.")
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
      "placement.")
    w("")
    w("Full definition, blast radius, detection and containment: "
      "`docs/compromise-ladder.md`. The honest summary of what is known about "
      "defending against it is short — version pinning detects an edit made "
      "during a run and not one made before it, in all three architectures; "
      "no architecture measured holds an independent account of what its own "
      "authority records should contain; and raising the premise count raises "
      "price, not possibility.")
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
    w("| case 12, arm B | the cheapest edit against the workflow model obtains "
      "nothing and stops the step — the first instance found *outside* the "
      "object model, so it is a property of authority configuration rather "
      "than of one candidate |")
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

    # -- 5b. the unit ------------------------------------------------------
    w("### The unit tamper cost is measured in")
    w("")
    w("Settled after case 14 found it ambiguous, and stated once in "
      "`cases/registry.py` beside the result vocabulary, for the same reason.")
    w("")
    w("> **Primary unit: the minimum number of state changes that must be "
      "committed independently.** One commit is one write the adversary must "
      "perform as a separate act. Two fields of one record set in one write "
      "are 1. Two records that cannot be written together are 2.")
    w("")
    w("Fields and records touched are reported alongside as *descriptive* "
      "data. They describe the shape of an edit; they are not its cost.")
    w("")
    w("**And the number is never reported alone.** Case 19 measured two "
      "consecutive rungs at 1, which a scalar would have called no "
      "improvement — while mechanically R1 closed the swap-after-approval "
      "route and *opened* the replay route, because approvals began matching "
      "by content. The count did not move; the routes changed, and it was a "
      "different system.")
    w("")
    w("| | Tells you |")
    w("|---|---|")
    w("| minimum tamper set | how **hard** the remaining attack is |")
    w("| route enumeration | what **kind** of failure remains |")
    w("")
    w("Both are required, and a test enforces it: a case declaring a tamper "
      "cost must name the routes that achieve it. That test immediately "
      "caught case 14 claiming a cost of 1 for two pivots that obtained "
      "nothing — one commit *spent* is not one commit *sufficing*.")
    w("")
    w("This mattered: case 12 counted fields without saying so, and arm B's "
      "input list and connection name are two fields of one record. Restated "
      "in commits, **every published number is unchanged** — and arm B's 2 is "
      "now true for a better reason. Its two commits are the workflow "
      "definition and the connection scope, which are separate stores that "
      "cannot be written together; a test asserts they are distinct objects, "
      "so if they ever merged the table would have to be re-measured.")
    w("")

    # -- 6b. what the thesis cannot be --------------------------------------
    w("### What the eventual thesis cannot be")
    w("")
    w("Recorded because a dead hypothesis is worth as much as a live one, and "
      "because this repository's rule is that a refuted belief is written "
      "down rather than quietly dropped.")
    w("")
    w("> ~~The object model is safer than an identity model or a workflow "
      "model.~~ **Dead.** Case 12 measured the opposite for the one property "
      "family it covers: the object model has the most authority-bearing "
      "records of the three, the same minimum tamper set as the identity "
      "model, and a one-edit route whose scope is wider than either other "
      "arm's.")
    w("")
    w("The result worth keeping, stated as narrowly as it was measured:")
    w("")
    w("> **For fixed workflows, conventional workflow orchestration may be "
      "structurally better than the candidate object model at resisting "
      "single-record authority tampering.**")
    w("")
    w("The three models are not a ladder from old to modern to futuristic. "
      "They are three trade-offs:")
    w("")
    w("| Model | Strength | Cost |")
    w("|---|---|---|")
    w("| identity | simple and powerful; its real strength is OS and process "
      "enforcement, which case 12's miniature does **not** reproduce | "
      "standing authority, broad scope, and every identity that already holds "
      "a permission is a route to it |")
    w("| configured workflow | strong for predictable processes, because "
      "configuration can require independent pieces to line up | authority is "
      "the least specific of the three — every run of the definition, with no "
      "notion of which object is being worked on |")
    w("| object | dynamic and expressive | flexibility creates more "
      "authority-bearing surfaces; a shared skill definition has very broad "
      "consequences |")
    w("")
    w("What the object model's advantage has to come from instead, none of "
      "which case 12 measured: dynamic task composition, canonical artifacts, "
      "less data movement, provenance and replay, narrower per-object "
      "bindings, disposable workers, and behaviour under a hostile worker. "
      "Each needs its own comparison and its own instrument.")
    w("")
    w("So the honest form of the project's claim is not a ranking:")
    w("")
    w("> Different orchestration models attach authority and state "
      "differently. This laboratory is experimentally identifying which "
      "properties actually improve under each model, and at which threat "
      "level.")
    w("")
    w("Cases 13–15 sharpened it once more, and this is the form to use now:")
    w("")
    w("> Unix, workflow automation and object-centric orchestration each "
      "provide different ways to **structure** authority. Their practical "
      "security depends not only on the model but on whether deployment "
      "choices preserve or collapse the independence those models are capable "
      "of expressing.")
    w("")
    w("Three measurements stand behind that sentence, and none of them is "
      "about a diagram:")
    w("")
    w("- **independence is a property of selectors, not of records** — two "
      "files, tables or checks buy nothing if one editable reference changes "
      "what both mean (case 13, mapped in case 14);")
    w("- **architecture establishes possibilities; deployment decides whether "
      "they collapse** — arm B looked separated until one credential spanned "
      "both sides, arm A had layered policy until an already-powerful identity "
      "was substituted, arm C had narrow bindings until a broadly applicable "
      "skill existed (cases 14, 15);")
    w("- **the object model's one structural advantage, kept narrow** — its "
      "selectors were the hardest to pivot together (case 14, no yielding "
      "pivot). That is not global safety: case 12 measured cheap, broad "
      "authority surfaces elsewhere in the same model. \"Expressiveness "
      "creates more surfaces while allowing cleaner separation between their "
      "selectors\" is the defensible form.")
    w("")
    w("Cases 15 and 16 give it one more turn, and this is the form that "
      "travels furthest — it holds whether the layer underneath is Unix, a "
      "workflow engine, Kubernetes, an agent framework or the object model:")
    w("")
    w("> **Agent security depends not just on what authority exists, but on "
      "how dynamic work can become connected to that authority.**")
    w("")

    # -- 6c. the reachability turn ------------------------------------------
    w("### The question none of the cases were asking")
    w("")
    w("Case 15's convergence has a sharper statement than the one that case "
      "made. It is not only that pre-existing authority is dangerous — it is "
      "that **existing authority is dangerous even when nobody changes it**. "
      "Once useful authority exists somewhere in a deployment, an attacker may "
      "not need to create or widen anything at all. They change what points at "
      "it.")
    w("")
    w("Which means the conventional audit question — *did anybody gain new "
      "permissions?* — can answer **no** while effective access has changed "
      "completely. There are three questions and this repository had been "
      "asking two of them:")
    w("")
    w("```text")
    w("what authority exists?              the inventory      (case 15)")
    w("what can currently point at it?    the binding        (case 16)")
    w("what does that combination permit? the grant          (cases 08-13)")
    w("```")
    w("")
    w("> **Audit authority reachability, not only authority inventory or "
      "changes to it.**")
    w("")
    w("This has relatives worth naming rather than reinventing. It is the "
      "shape of **ambient authority** — powerful credentials existing in an "
      "environment and usable from contexts that never requested that power — "
      "and of the **confused deputy**, where the attacker never acquires the "
      "authority and instead arranges for something that already holds it to "
      "act in the wrong context. Case 13's subject-keyed premise was the same "
      "pattern seen from the other side.")
    w("")
    w("It also explains the convergence. A legitimate powerful service "
      "identity, a legitimate powerful connection and a legitimate powerful "
      "skill are none of them evidence of compromise. The dangerous fact is "
      "the same in all three: **can an untrusted change redirect ordinary work "
      "through that existing authority?**")
    w("")
    w("### What kind of thing said no")
    w("")
    w("A distinction case 23 forced by being **blocked** rather than faked, "
      "and now a field on every case:")
    w("")
    w("| | |")
    w("|---|---|")
    w("| `untested` | nobody has got around to it |")
    w("| `modeled` | the boundary is represented in code — the case's own "
      "Python is what refuses |")
    w("| `blocked` | the experiment needs a boundary this environment cannot "
      "provide, and the blocker is recorded |")
    w("| `measured` | a real external mechanism was exercised and it refused |")
    w("")
    modeled = [c.case_id for c in all_cases()
               if c.evidence_status == "modeled"]
    w(f"Currently `modeled`: {', '.join(modeled)}. Everything else exercised "
      "real Python objects, real subprocesses or real threads.")
    w("")
    w("The line that matters is between the middle two and the last, and case "
      "23 states it as a pass condition: **the attack must fail for a reason "
      "the case did not implement.** If the repository's own code is what says "
      "no, the case has rebuilt the application claim with another coat of "
      "paint — which is why cases 21 and 22 are process and protocol results "
      "and not isolation results, and why they say so.")
    w("")
    w("### The reusable principles")
    w("")
    w("What the series has produced is not one proposed architecture. It is a "
      "set of principles that survive being moved between layers, which is the "
      "test a principle has to pass to be worth anything.")
    w("")
    w("| Principle | What the measurement says |")
    w("|---|---|")
    w("| **Least privilege** | minimise the authority that exists — case 15 "
      "measures what each surviving piece costs |")
    w("| **Independent premises** | important authority should depend on facts "
      "that cannot all be moved by one pivot (cases 13, 14) |")
    w("| **Complete mediation** | resolve authority at the actual point of use "
      "(cases 08, 10) |")
    w("| **Reachability awareness** | inventory not only authority but the "
      "paths by which work can reach it (cases 15, 16) |")
    w("| **Absence over guarding** | where deep compromise is in scope, "
      "unavailable authority beats another colocated check — the only Level 2 "
      "preventions measured here are absences |")
    w("| **Canonical state and provenance** | keep enough trusted history to "
      "tell legitimate progression from redirected work (cases 05, 07, 10) |")
    w("| **Exported transformations** | a boundary is only as narrow as the "
      "verbs it offers across it (cases 09, 22) |")
    w("")
    w("The last one is the newest and it connects the others rather than "
      "sitting beside them. Cases 09 and 22 found the same thing two planes "
      "apart:")
    w("")
    w("> **A protection boundary is only as narrow as the transformations it "
      "exports.**")
    w("")
    w("Case 09: an allowlist of *names* is not an allowlist of "
      "*transformations*. Case 22: a store behind a service is not protected "
      "if the service offers `compact()`. Names, endpoints, services and "
      "processes buy nothing by themselves — what matters is which state "
      "transitions the other side can cause. So the independence layers are "
      "not five parallel properties with a sixth called *protocol "
      "independence*; the exported verbs are the rule that decides how much "
      "of every other layer leaks back out.")
    w("")
    w("Which gives the boundary condition its full form. Not *the gate owns "
      "the database*, but:")
    w("")
    w("```text")
    w("the worker cannot reach storage")
    w("AND")
    w("the protocol exposes only transformations that preserve the security")
    w("invariants")
    w("```")
    w("")
    w("Integrity can fail by **subtraction** as easily as by addition, which "
      "is case 22's resurrection result: any maintenance verb that can "
      "delete, compact, rewrite, merge, prune, repair or rebase "
      "security-relevant history is an authority operation however much it "
      "sounds like housekeeping.")
    w("")
    w("And one property to keep separate, because arm C made them look "
      "identical: **a narrow blast radius is not detectability.** Case 15 "
      "measured the object model's per-object binding as the narrowest "
      "exposure and the quietest attack in the same breath; case 16 detected "
      "it without changing either fact.")
    w("")
    w("### The reachability subsystem's contract")
    w("")
    w("Cases 16 to 18 and 24 collapse into one sentence, and it is the one "
      "worth carrying rather than the journey:")
    w("")
    w("> **Exposure is derived from the authority graph; severity is supplied "
      "from an independent source.**")
    w("")
    w("Which fixes what each layer is allowed to answer:")
    w("")
    w("| | |")
    w("|---|---|")
    w("| **the graph answers** | which authority is reachable, through which "
      "intermediaries, which endpoints are exposed, how many paths lead there |")
    w("| **the graph does not answer** | how important that authority is, or "
      "how urgently anyone should look at it |")
    w("")
    w("And what a finding is made of:")
    w("")
    w("```text")
    w("identity     the intermediary")
    w("attributes   the endpoints it exposes, the path evidence")
    w("enrichment   severity / business value / sensitivity - from outside")
    w("")
    w("reporting    group by the structural finding")
    w("             rank by the supplied severity")
    w("```")
    w("")
    w("The practical payoff is that an organisation can change what it calls "
      "critical without touching the reachability computation. Same graph, "
      "same causes, same findings, different prioritisation — this year the "
      "production database, next year the training corpus. Case 24's "
      "structural test is what keeps that true: `by_sensitivity` may take a "
      "severity map because ranking is where supplied knowledge belongs, "
      "while `causes`, `findings`, `endpoints_exposed` and `path_count` may "
      "not mention it. Severity reaching the presentation layer is not "
      "contamination; severity reaching discovery would be.")
    w("")
    w("The conditional that produced this, stated with the assumption it "
      "depends on rather than as a law:")
    w("")
    w("> When high-value authority is **rare**, exposure frequency may be "
      "*anti-correlated* with severity. Severity therefore cannot safely be "
      "inferred from reachability prevalence without an independently "
      "justified relationship between prevalence and value.")
    w("")
    w("Case 24 measured that anti-correlation at ρ = −0.995, and case 17 "
      "showed what it costs: ranked by prevalence, none of the planted "
      "needles reached the top ten.")
    w("")

    w("### Where the reachability line actually stands")
    w("")
    w("Case 17 was the gate case 16 set for itself, and it split cleanly:")
    w("")
    w("| | Result |")
    w("|---|---|")
    w("| does the reduction survive scale? | **yes** — 320,000 paths become 16 "
      "causes, and the reading load tracks how much sensitive authority "
      "exists rather than estate size |")
    w("| does it hide dangerous paths? | **no** — every planted needle "
      "survives grouping |")
    w("| does the obvious presentation hide them? | **yes** — ranked by blast "
      "radius, 0% of the needles are in the top 10 |")
    w("")
    w("So the hard part was not the reduction. It was that a correct "
      "reduction, presented the obvious way, is still wallpaper with the "
      "dangerous findings underneath it. And the fix is not in the graph: "
      "**severity is a property of the authority that an operator supplies**, "
      "and with no severity map the ranking collapses back to blast radius and "
      "needle recall returns to zero. That is the distance between what this "
      "series has measured and something deployable.")
    w("")
    w("This line of work has a recognisable family — attack-path analysis, "
      "entitlement analysis, graph-based exposure analysis — and the graph "
      "concept is not the contribution. Applying it to *dynamic workflow and "
      "agent authority*, where the bindings change as work runs, is the part "
      "that would be new, and only if it survives a real distribution.")
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
    w("3. **Decide what availability is** in §7 of the threat model, before a "
      "further control spends more of it. The last open direction question "
      "from this review's first pass — naming the adversary and enumerating "
      "the pivots are both done, in the ladder and in case 14.")
    w("4. **A severity source.** Case 17 measured the view as usable *given* a "
      "severity map and unusable without one — with no severities the ranking "
      "collapses to blast radius and every planted needle sits below the fold. "
      "Producing that map is real work nothing here has done, and it is now "
      "the gap between a measurement and a tool.")
    w("5. **Measure interactions between several pieces of pre-existing "
      "authority**, and reachability at more than one hop. Case 15 took one "
      "item per model in isolation and case 16 computes direct paths only; a "
      "real deployment is neither.")
    w("6. **Sample a real distribution.** Case 17's deployments are argued "
      "rather than sampled, and it names the shape that would break the "
      "reduction: sensitive authority that is not rare. That is the one "
      "assumption the whole reachability line rests on and nobody has checked "
      "it against reality.")
    w("")
    w("Then the two families case 12 could not measure, each blocked on an "
      "instrument rather than on appetite: **data movement and fidelity**, "
      "which needs observation of a running system rather than the "
      "whole-payload strawman `key_vs_paste.py` assumes; and "
      "**compromise and failure behaviour**, which is where real OS "
      "isolation, real workflow credentials and disposable workers actually "
      "differ, and where the identity arm would stop being a miniature.")
    w("")
    w("Not next, and worth saying: a fourth arm, or another authority-model "
      "comparison against the same adversary. Case 12 answered that question "
      "for this property family, and the answer does not improve by adding "
      "models to it.")
    w("")
    return out


def _programme() -> list:
    """The applied programme, and why most of it is not in the case table.

    Without this section a reader six months from now would conclude the
    reservation programme never got past step C, because the strongest applied
    results would live only in commit messages.
    """
    from cases.programme import (
        CORRECTNESS_ORACLE, FAMILY_LABELS, OPERATIONAL_RESILIENCE, PROGRAMME,
        by_family,
    )

    out: list = []
    w = out.append

    w("## Applied architecture programme")
    w("")
    w("A reservation queue, built in six steps, each asking a different "
      "architectural question. It is not a calendar simulation with security "
      "bolted on - the steps were sequenced so that each one measures "
      "something the previous one could not.")
    w("")
    w("```text")
    w("A-C  can agents perform and recover business work?")
    w("D    can consequential transformations require independent authority?")
    w("E    can failure be observed without inventing causes?")
    w("F    can failure be repaired without granting general authority?")
    w("```")
    w("")

    # -- the schema finding ------------------------------------------------
    w("### Not every piece of evidence here is attack evidence")
    w("")
    w("Only **step D** is a case. It is registered as case-25 because it has "
      "the shape the registry is for: an adversary, a protected outcome, a "
      "bypass route, and a cost in the settled tamper unit. The rest are "
      "recorded in `cases/programme.py` as `ProgrammeResult`, which "
      "deliberately has **no tamper-cost field at all**.")
    w("")
    w("That is a structural decision, not a filing convenience. Inventing a "
      "`minimum_tamper_cost` for step E's detection rate because `CaseResult` "
      "happens to have the field would repeat the measurement mistake the "
      "first twenty-four cases exist to eliminate:")
    w("")
    w("> F0's *17 unresolved* is not a successful attack route. F2's *8 "
      "escalated* is not a prevention whose tamper cost is some number. They "
      "are operational outcomes under a preregistered fault distribution.")
    w("")
    w("So the repository holds three families of evidence, and a scalar model "
      "that swallowed all three would be exactly the kind of security score "
      "this project exists to distrust:")
    w("")
    w("| Family | Where | What it measures |")
    w("|---|---|---|")
    w("| Adversarial security | cases 00-25, `CaseResult` | what an adversary "
      "achieves, and what it costs in independently committed state changes |")
    w("| Correctness / oracle | steps A-C, `ProgrammeResult` | whether work "
      "completes and whether an independent evaluator agrees it had to fail |")
    w("| Operational resilience | steps E-F, `ProgrammeResult` | what is "
      "detected, repaired, escalated, and damaged in passing |")
    w("")
    w("`ProgrammeResult.__post_init__` raises if a measurement dictionary "
      "contains attack-evidence vocabulary, so the distinction is enforced "
      "rather than documented.")
    w("")

    # -- the steps ---------------------------------------------------------
    for family in (CORRECTNESS_ORACLE, OPERATIONAL_RESILIENCE):
        w(f"### {FAMILY_LABELS[family]}")
        w("")
        for r in by_family(family):
            w(f"#### Step {r.step} — {r.title}")
            w("")
            w(f"> {r.question}")
            w("")
            w(f"**Claim.** {r.claim}")
            w("")
            w("**Measured**")
            w("")
            for key, value in r.measurements.items():
                if isinstance(value, dict):
                    w(f"- {key}:")
                    for sub, subvalue in value.items():
                        w(f"    - {sub}: `{subvalue}`")
                else:
                    w(f"- {key}: `{value}`")
            w("")
            w(f"**Method.** {r.method}")
            w("")
            w("**What it does not claim**")
            w("")
            for item in r.non_claims:
                w(f"- {item}")
            w("")
            w(f"**Residual.** {r.residual}")
            w("")
            w("**Exercises**")
            w("")
            for concept, why in r.exercises.items():
                w(f"- *{concept}* — {why}")
            w("")
            if r.notes:
                w(f"**Notes.** {r.notes}")
                w("")
            w(f"Reproduce: `{r.run}` · Tests: `{r.test_module}` · Measured at "
              f"`{r.source_commit}`")
            w("")

    # -- step D's pointer --------------------------------------------------
    w("### Step D is case-25")
    w("")
    w("Displacing a confirmed reservation is a protected transformation; "
      "creating a new one is not. The rule binds to the **kind of "
      "transformation**, not to a risk score. The legacy row — the worker "
      "still holding `move_reservation`, which is exactly what step C shipped "
      "— displaces five confirmed reservations with zero approvals in "
      "existence, at a minimum tamper cost of 1. See the case table above.")
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
    out.extend(_programme())

    # -- detail ------------------------------------------------------------
    w("## Detail")
    w("")
    for c in cases:
        flag = "✅" if c.status == "closed" else "⚠️"
        w(f"### {flag} {c.case_id} — {c.title}")
        w("")
        w(f"**Compromise level:** {c.compromise_level}  ")
        if c.evidence_status != "measured":
            w(f"**Evidence:** `{c.evidence_status}` — the boundary this case "
              "relies on is drawn by its own code, not enforced by anything "
              "underneath it  ")
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
