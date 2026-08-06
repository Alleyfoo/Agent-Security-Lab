"""Canonical case-result registry.

One structure, rendered in several places: the generated report, the Streamlit
comparison surface, and assertions in the adversarial tests. Security claims
are written here **once**. Do not restate a result in test code, README prose,
report code and UI code independently - they drift, and a drifted claim is
worse than no claim.

Result vocabulary is closed. Every attack outcome is exactly one of:

``prevented``                the unauthorized effect never occurred
``rejected_before_commitment`` hostile output produced but never accepted into
                             trusted state
``detected_after_occurrence`` the effect occurred and was noticed later
``undetected``               the effect occurred and no trusted observation
                             identified it

Vague terms - "handled", "protected", "secure", "mitigated" - are not results
and must not appear in a ``*_result`` field.

For confidentiality attacks, detection after the read is NOT prevention. Once
secret content reaches the compromised agent the loss has already occurred.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List

# ---------------------------------------------------------------------------
# Closed result vocabulary.
# ---------------------------------------------------------------------------

PREVENTED = "prevented"
REJECTED_BEFORE_COMMITMENT = "rejected_before_commitment"
DETECTED_AFTER_OCCURRENCE = "detected_after_occurrence"
UNDETECTED = "undetected"

RESULTS = (PREVENTED, REJECTED_BEFORE_COMMITMENT,
           DETECTED_AFTER_OCCURRENCE, UNDETECTED)

RESULT_LABELS = {
    PREVENTED: "Prevented",
    REJECTED_BEFORE_COMMITMENT: "Rejected before commitment",
    DETECTED_AFTER_OCCURRENCE: "Detected after occurrence",
    UNDETECTED: "Undetected",
}

# Ordered worst -> best, for sorting and for colouring a comparison surface.
RESULT_SEVERITY = {UNDETECTED: 0, DETECTED_AFTER_OCCURRENCE: 1,
                   REJECTED_BEFORE_COMMITMENT: 2, PREVENTED: 3}


@dataclass(frozen=True)
class CaseResult:
    case_id: str
    title: str
    compromise_level: str
    attack: str
    baseline_result: str
    controlled_result: str
    control: str
    evidence: List[str]
    what_this_proves: str
    what_this_does_not_prove: str
    residual_limitation: str
    containment: str
    recovery: str
    status: str                      # "closed" | "open"
    directory: str
    test_module: str
    notes: str = ""
    blast_radius: str = ""
    extra: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        for value, name in ((self.baseline_result, "baseline_result"),
                            (self.controlled_result, "controlled_result")):
            if value not in RESULTS:
                raise ValueError(
                    f"{self.case_id}: {name}={value!r} is not one of {RESULTS}. "
                    "Vague terms are not results."
                )
        if self.status not in ("closed", "open"):
            raise ValueError(f"{self.case_id}: status must be closed|open")
        # An open case must not advertise an improvement it has not made.
        if self.status == "open" and self.controlled_result != self.baseline_result:
            raise ValueError(
                f"{self.case_id}: an open case must not claim a changed result"
            )

    @property
    def improved(self) -> bool:
        return (RESULT_SEVERITY[self.controlled_result]
                > RESULT_SEVERITY[self.baseline_result])

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


CASES: List[CaseResult] = [
    CaseResult(
        case_id="case-00",
        title="Audited component edits its own evidence",
        compromise_level="Level 1: malicious agent implementation",
        attack="A hostile ValidationAgent deletes failing receipts from the "
               "runner's record through the handle it was given",
        baseline_result=UNDETECTED,
        controlled_result=PREVENTED,
        control="Runner-owned append-only ReceiptLedger; agents receive a "
                "read-only ReceiptView with no mutation surface",
        evidence=[
            "ReceiptIntegrityError naming the attempted operation",
            "runner receipt record unchanged after the attack",
            "final verdict still 'warn'",
            "tests/adversarial/test_case_00_receipt_handle.py",
        ],
        what_this_proves=(
            "An agent going through the interfaces it is given cannot alter "
            "the trusted runner's record of what happened. Corrupting that "
            "evidence now requires Level 2 in-process compromise instead of "
            "merely a hostile agent implementation."),
        what_this_does_not_prove=(
            "It does not stop a compromised validator authoring a false "
            "conclusion - authorship is not constrainable from outside the "
            "component that authors, and case 05 had to make the conclusion "
            "come from somewhere else rather than constrain the artifact. It "
            "does not contain a Level 2 adversary, and it does not make the "
            "receipt record tamper-evident: there is no hash chain, signature "
            "or external anchor."),
        residual_limitation=(
            "Closed by case 05. The validator still controls its own output "
            "artifact and may state a false conclusion; what changed is that "
            "the artifact is now a recommendation and the run's conclusion is "
            "derived by the runner from this same protected evidence. Case "
            "00's tripwire test was written to fail when that happened, and "
            "was rewritten when it did."),
        containment="Agent contract violation -> reject the operation and stop "
                    "the workflow (existing runner behaviour).",
        recovery="Treat the verdict artifact as untrusted and read the "
                 "runner-derived conclusion from RunSession.report() instead "
                 "(case 05 makes that the default); re-run validation with a "
                 "known-good build.",
        status="closed",
        directory="cases/00-receipt-handle",
        test_module="tests/adversarial/test_case_00_receipt_handle.py",
        blast_radius="One workflow's audit record and its verdict artifact. No "
                     "data-plane artifact, no other run, no policy, no grant.",
        notes="Prevented, not merely detected: the mutation never reaches the "
              "ledger. The residual false-conclusion problem is a separate "
              "claim and is deliberately not counted here.",
    ),
    CaseResult(
        case_id="case-01",
        title="Reading artifacts the grant excludes",
        compromise_level="Level 2: fully compromised agent process",
        attack="Read artifact.cleaned_output from a stage granted only "
               "artifact.raw_input, via view._store, a sys._getframe() walk, "
               "and a gc.get_objects() scan",
        baseline_result=UNDETECTED,
        controlled_result=UNDETECTED,
        control="None at this phase. Control is process isolation (Phase 5).",
        evidence=[
            "all three paths return the ungranted artifact",
            "view.read_keys empty after every bypass",
            "ClosureStoreView closes path 1 only - refused as cosmetic",
            "tests/adversarial/test_case_01_ungranted_read.py",
        ],
        what_this_proves=(
            "The scoped view enforces exactly one thing - reads that go "
            "through its interface - and closing individual reach-around paths "
            "is not progress, because the three demonstrated paths share no "
            "mechanism and only the first involves the view."),
        what_this_does_not_prove=(
            "Nothing about a Level 1 adversary, who is genuinely constrained "
            "by the view. It does not show the store is easy to reach in a "
            "hardened deployment, and it says nothing about whether process "
            "isolation will hold - that belongs to Phase 5 and must be "
            "measured there."),
        residual_limitation=(
            "The entire case is open. StoreView does not contain arbitrary "
            "hostile Python sharing the process, interpreter, object graph, "
            "memory, module namespace and OS identity. Case 06 built the "
            "control and measured it working - for one stage. The tripwires "
            "here did not fire and should not have: three stages of four still "
            "share the runner's process, and this case closes when every stage "
            "is isolated, not when the first one is."),
        containment="None automatic - there is no detection. The honest "
                    "posture is that a compromised agent process has read "
                    "every artifact in its run.",
        recovery="Treat every artifact in the affected run as disclosed. "
                 "Nothing narrower is evidenced.",
        status="open",
        directory="cases/01-ungranted-read",
        test_module="tests/adversarial/test_case_01_ungranted_read.py",
        blast_radius="Every artifact in the process, for every run it has "
                     "handled - stores from earlier sessions stay reachable "
                     "via gc until collected.",
        notes="Confidentiality loss occurs at the read. Detection after the "
              "fact would not be prevention, and no detection exists anyway. "
              "Tests assert the attack SUCCEEDS and are tripwires for Phase 5.",
    ),
    CaseResult(
        case_id="case-02",
        title="In-place mutation of a registered artifact",
        compromise_level="Level 2: fully compromised agent process",
        attack="A hostile schema stage rewrites one cell of artifact.raw_input "
               "after doing its legitimate work - no new key, no row-count "
               "change, no column change",
        baseline_result=UNDETECTED,
        controlled_result=DETECTED_AFTER_OCCURRENCE,
        control="Trusted hash verification in two places: ArtifactStore.get() "
                "at the read boundary (C1) and ArtifactStore.verify_all() as a "
                "runner post-step sweep (C2), plus fail-closed quarantine",
        evidence=[
            "stored source_hash 16879f03... vs recomputed 8194315c...",
            "ArtifactIntegrityError naming the affected key",
            "runner receipt status 'error', contract_result 'failed'",
            "cleaned_output never produced - corruption did not propagate",
            "tests/adversarial/test_case_02_artifact_mutation.py",
        ],
        what_this_proves=(
            "The baseline's immutability guarantee covered key rebinding but "
            "not content mutation, and the gap was silently exploitable end to "
            "end. With the control, unauthorized in-place mutation is detected "
            "before the workflow accepts or consumes the altered state, by "
            "trusted code that never asks the agent to vouch for the artifact "
            "it may have modified."),
        what_this_does_not_prove=(
            "It does not prove prevention: the mutation occurs and the control "
            "observes it afterwards. It does not create memory isolation - an "
            "adversary that updates content and hash together passes "
            "verification. It restores nothing and undoes no confidentiality "
            "loss from case 01."),
        residual_limitation=(
            "Same-process hostile code may still mutate memory. Hash "
            "verification detects divergence but does not create memory "
            "isolation or undo confidentiality loss. The hash lives in the "
            "same dict as the data it protects, so an attacker who updates "
            "both passes; and the sweep runs at step boundaries, so an "
            "attacker who restores the original bytes first is not caught."),
        containment="Agent contract violation -> reject the operation and stop "
                    "the workflow, extended with a quarantine flag so a store "
                    "known to be corrupt is never retried.",
        recovery="Not implemented in this slice. Abort and quarantine are "
                 "implemented; discarding the store destroys evidence, and "
                 "snapshot restoration needs its own specification and tests. "
                 "Operationally: re-run from intake in a clean session.",
        status="closed",
        directory="cases/02-artifact-mutation",
        test_module="tests/adversarial/test_case_02_artifact_mutation.py",
        blast_radius="One workflow's artifacts, plus anything derived from the "
                     "tampered one. Without the control, cleaned_output "
                     "inherited the forged value and the verdict certified it. "
                     "There is no provenance graph yet, so identifying derived "
                     "outputs after the fact is not possible (Phase 8).",
        notes="Classified Level 2, deviating from the direction's example "
              "metadata: measured, there is no Level 1 path to in-place "
              "mutation. Verification cost measured at 71 us per read and 69 "
              "us per sweep at fixture scale; O(artifact size) and O(store "
              "size) respectively, so not free asymptotically.",
    ),
    CaseResult(
        case_id="case-03",
        title="Altering runner-owned routing data",
        compromise_level="Level 1: malicious agent implementation "
                         "(Level 2 for the residual)",
        attack="A hostile agent rebinds WORKFLOW_ROUTES entries to widen the "
               "next stage's grant, to delete the validation stage, and - "
               "persistently - to contaminate later runs in the same process",
        baseline_result=UNDETECTED,
        controlled_result=PREVENTED,
        control="Read-only MappingProxyType over a private table (C1), a "
                "per-run private copy pinned at start_run (C2), and a route "
                "fingerprint verified before and after every step (C3), with "
                "fail-closed quarantine on mismatch",
        evidence=[
            "TypeError: 'mappingproxy' object does not support item assignment",
            "issued grant matches policy - no smuggled action",
            "all 4 agents run and the verdict artifact is produced",
            "next run in the same process inherits a clean table",
            "RouteIntegrityError + quarantine on mid-run copy tampering",
            "tests/adversarial/test_case_03_mutable_route_table.py",
        ],
        what_this_proves=(
            "That 'runner-owned routing' described the control flow but not "
            "the policy state, and that the gap was exploitable by an agent "
            "using nothing but an ordinary import. With the control, an agent "
            "using the documented interface cannot alter routing at all, a "
            "run's policy is fixed at start_run, and mid-run modification of "
            "the copy actually in use is detected before the runner acts."),
        what_this_does_not_prove=(
            "It does not prove hostile same-process Python is contained: a "
            "Level 2 adversary reaches the private table behind the proxy, and "
            "if it does so before start_run the tampering is undetected. It "
            "does not prove the fingerprint is trustworthy evidence, since the "
            "fingerprint and the data it protects share an address space."),
        residual_limitation=(
            "The reference value lives inside the adversary's reach. "
            "MappingProxyType is a view, not a freeze, so the private dict is "
            "still writable; pre-run tampering is pinned rather than caught; "
            "and an adversary updating both the routes and the fingerprint "
            "passes verification. Closing these needs the expected policy held "
            "outside the process - a different boundary, not a different check."),
        containment="Route fingerprint mismatch -> RouteIntegrityError, "
                    "quarantine the run, refuse further steps rather than "
                    "issuing grants derived from unverified policy.",
        recovery="Not implemented. Restoring routes from the module table or a "
                 "same-module constant would launder the tampering, since that "
                 "is what the adversary rewrote. Restart the process: attack C "
                 "shows tampering outlives a session, so a fresh RunSession in "
                 "a contaminated process is not a clean state.",
        status="closed",
        directory="cases/03-mutable-route-table",
        test_module="tests/adversarial/test_case_03_mutable_route_table.py",
        blast_radius="Process lifetime, not run lifetime. Without the control "
                     "one hostile agent silently reconfigured every subsequent "
                     "run in the same interpreter, including runs whose agents "
                     "were entirely honest.",
        notes="The smuggled action in attack A did not by itself yield a "
              "usable capability, because StoreView's write grant derives from "
              "output_contract rather than allowed_actions - real defence in "
              "depth, recorded rather than claimed as the control. The "
              "persistence finding (attack C) was noticed by accident when one "
              "attack contaminated the next, then measured deliberately.",
    ),
    # Case 04 is registered as two entries on purpose. Forging the audit record
    # and corrupting the authorization decision are different effects with
    # different results, and one row saying "the audit log was forged" would
    # hide the only operationally useful fact - which of them changed a
    # decision. See cases/04-forged-runner-event/README.md.
    CaseResult(
        case_id="case-04a",
        title="Forged runner-labelled audit event - the record",
        compromise_level="Level 1: malicious agent implementation "
                         "(Level 2 for the residual)",
        attack="A hostile agent appends an event carrying the trusted runner's "
               "identity through the log handle it was given, and - separately "
               "- renames itself 'trusted_runner' so the runner writes the "
               "identity into the receipt ledger on its behalf",
        baseline_result=UNDETECTED,
        controlled_result=PREVENTED,
        control="An author-bound EventLogView minted from the routing table, "
                "not from agent.name (C1+C2), plus a runner-owned tally of "
                "runner-labelled events verified after every step (C3), with "
                "fail-closed quarantine on mismatch",
        evidence=[
            "5 events labelled trusted_runner against 4 receipts at baseline",
            "AuditIntegrityError naming the claimed and the assigned identity",
            "receipt ledger no longer adopts a renamed agent's identity",
            "Level 2 append quarantines the run: 2 written, 3 in the log",
            "tests/adversarial/test_case_04_forged_runner_event.py",
        ],
        what_this_proves=(
            "The agent field in the audit log recorded a claim, not an "
            "observation, and two independent Level 1 routes could set it to "
            "the trusted runner's identity - one through the handle the runner "
            "passed in, one by renaming the agent so the runner wrote the lie "
            "itself. With the control the identity in the trusted record is "
            "assigned by runner-owned policy, an agent cannot append under "
            "another identity through the interfaces it is given, and a "
            "runner-labelled event the runner did not write is detected before "
            "the workflow advances."),
        what_this_does_not_prove=(
            "It does not make the log tamper-evident: no hash chain, no "
            "signature, no external anchor, and the on-disk file is still "
            "rewritable (L5). It does not contain a Level 2 adversary, who "
            "reaches the EventLog through the object graph and can update the "
            "runner's tally alongside a forged event. It binds attribution, "
            "not content, and it says nothing about the authorization "
            "decision - that is case-04b."),
        residual_limitation=(
            "Attribution is bound; content is not, so an agent may still write "
            "receipt-shaped prose under its own honest identity. The tally "
            "covers the runner's label only, because the runner has no "
            "independent record of what an agent legitimately wrote, so Level "
            "2 forgery under another agent's label is undetected. And the "
            "tally is an ordinary attribute on the session: an adversary who "
            "forges and increments it passes."),
        containment="Attribution denied at the handle -> ContractError, the "
                    "step fails and the workflow halts (Level 1 path, nothing "
                    "corrupt entered the record). Attribution mismatch found "
                    "by the sweep -> AuditIntegrityError and quarantine.",
        recovery="Not implemented. Deleting the forged event is the attack, "
                 "not the remedy, and the ledger cannot reconstruct agent work "
                 "events. Treat the run's log as untrusted narrative and read "
                 "RunSession.receipts() instead.",
        status="closed",
        directory="cases/04-forged-runner-event",
        test_module="tests/adversarial/test_case_04_forged_runner_event.py",
        blast_radius="One run's narrative record - the log file is per-run, so "
                     "unlike case 03 the tampering does not reach another run. "
                     "What is lost is the ability to answer 'who did this?' for "
                     "the whole run, since one entry indistinguishable from a "
                     "real one devalues every entry beside it.",
        notes="A2 was the cheaper and the worse of the two routes: one renamed "
              "attribute put the runner's identity into the receipt ledger, "
              "the record case 00 had made read-only so it could serve as "
              "evidence. Noticed and recorded rather than fixed: _emit_error "
              "attributes runner-authored error events to the acting agent.",
    ),
    CaseResult(
        case_id="case-04b",
        title="Forged runner-labelled audit event - the decision",
        compromise_level="Level 2: fully compromised agent process",
        attack="The same forged events, measured against the authorization "
               "decision rather than the record: does a run under forged "
               "permission claims reach a different verdict?",
        baseline_result=PREVENTED,
        controlled_result=PREVENTED,
        control="None added by this case. Pre-existing baseline control B18: "
                "ValidationAgent derives all_writes_allowed from the "
                "runner-owned receipt ledger and never reads log events",
        evidence=[
            "verdict under forged events is field-for-field identical to a "
            "clean run",
            "with ledger and log in direct contradiction the verdict follows "
            "the ledger: warn, all_writes_allowed False",
            "test_forged_events_do_not_change_the_verdict",
            "test_the_validator_follows_the_ledger_not_the_log",
        ],
        what_this_proves=(
            "That corrupting the audit record and corrupting the authorization "
            "decision are separate incidents in this system, by measurement "
            "rather than by assertion. The decision plane does not read the "
            "narrative log at all, so a forged event - including one in the "
            "runner's own voice - changes nothing about what the workflow "
            "authorizes."),
        what_this_does_not_prove=(
            "It does not make the log trustworthy evidence of authorization - "
            "it is not evidence of authorization at all, which is the point. "
            "It does not defend the receipt ledger, which is case 00's claim, "
            "and it does not show the verdict itself is trustworthy: the "
            "validator still authors its own conclusion (case 05)."),
        residual_limitation=(
            "The separation holds because one consumer happens to read the "
            "right source. Nothing structurally prevents a future reader - a "
            "UI panel, a report, an operator - from deriving an authorization "
            "conclusion from the log, and no type or interface marks the log "
            "as narrative rather than evidence."),
        containment="Not applicable: no unauthorized effect occurs on the "
                    "decision plane. The containment for the forged event "
                    "itself is case-04a's.",
        recovery="Not applicable. The decision was never derived from the "
                 "corrupted source, so there is nothing to recompute. The "
                 "record still needs case-04a's response.",
        status="closed",
        directory="cases/04-forged-runner-event",
        test_module="tests/adversarial/test_case_04_forged_runner_event.py",
        blast_radius="None on the decision plane. Stated as a measured result "
                     "rather than an absence of findings.",
        notes="Registered green at the baseline, which is unusual here and "
              "deliberate: the entry records a containment that already "
              "existed and that this case measured. An unmeasured containment "
              "is indistinguishable from luck, and the collapse of these two "
              "effects into one sentence is what the case exists to prevent.",
    ),
    CaseResult(
        case_id="case-05",
        title="A conclusion the agent authors is not evidence",
        compromise_level="Level 1: malicious agent implementation "
                         "(Level 2 for the residual)",
        attack="A hostile ValidationAgent writes a conclusion the evidence "
               "does not support: clean over a failed receipt, clean over a "
               "chain missing a row, clean on the basis of no checks at all, "
               "and - the symmetric direction - a false alarm on a healthy run",
        baseline_result=UNDETECTED,
        controlled_result=REJECTED_BEFORE_COMMITMENT,
        control="A deterministic derive_verdict() in verdict.py, called by the "
                "runner over its own ArtifactStore and ReceiptLedger at the "
                "terminal step (C1+C2); the agent's artifact becomes a "
                "recommendation, and any disagreement on the decision fields "
                "sets review_required and emits a verdict_disagreement event "
                "naming each differing field (C3)",
        evidence=[
            "report()['verdict'] is runner-derived; verdict_source says so",
            "clean recommendation over a failed receipt -> published 'warn'",
            "clean recommendation over a 20->19 row chain -> published 'warn'",
            "empty checks -> all four named individually as differences",
            "false alarm on a healthy run -> published 'ok', still flagged",
            "tests/adversarial/test_case_05_false_verdict.py",
        ],
        what_this_proves=(
            "That protecting the evidence a component reads says nothing about "
            "the conclusion it writes, and that the two must be separated even "
            "when the same component legitimately does both. Case 00 made the "
            "receipt ledger read-only and case 04b showed the decision does "
            "not come from the event log - and a validator could still certify "
            "a failed run as clean by four routes with no contradiction "
            "recorded anywhere. With the control the run's conclusion is "
            "computed by the runner from its own evidence, the agent's "
            "conclusion is a recommendation, and disagreement is recorded and "
            "routed to review rather than resolved in either direction."),
        what_this_does_not_prove=(
            "It does not prove the derived verdict is correct: it is four "
            "structural checks over metadata the pipeline's own agents wrote, "
            "and a self-consistent lie in the data plane passes both the "
            "recommendation and the derivation. It does not contain a Level 2 "
            "adversary, who rewrites the derived verdict after the comparison "
            "or patches the derivation before the run. It does not make review "
            "a workflow: nothing routes a flagged run to a human or stops its "
            "outputs being used."),
        residual_limitation=(
            "The derivation trusts artifact metadata that agents wrote, so a "
            "transform that drops a row and decrements row_count passes both "
            "sides. Only the decision is compared - reasons and message are "
            "prose and are not bound. And the reference computation lives "
            "inside the adversary's reach: rewriting _derived_verdict or "
            "patching derive_verdict defeats it, though patching only one side "
            "still surfaces as disagreement with the other."),
        containment="Disagreement -> the agent's conclusion is not adopted, "
                    "review_required is set, and a verdict_disagreement event "
                    "names every differing field. Deliberately not quarantine: "
                    "nothing is corrupt and the derived conclusion is sound.",
        recovery="Implemented, uniquely among the closed cases: nothing was "
                 "lost, because the conclusion was never taken from the agent. "
                 "The runner-derived verdict is served and the run is flagged; "
                 "re-running validation with a known-good build changes only "
                 "the recommendation.",
        status="closed",
        directory="cases/05-false-verdict",
        test_module="tests/adversarial/test_case_05_false_verdict.py",
        blast_radius="One run's conclusion and everything downstream that "
                     "trusted it - not the validator's own output. Without the "
                     "control a compromised validator certifies any run as "
                     "clean, including runs whose other stages were caught "
                     "failing. There is no provenance graph, so identifying "
                     "what consumed a false verdict is not possible (Phase 8).",
        notes="First case closed by a later case's control: it resolves case "
              "00's recorded residual, and case 00's tripwire test was written "
              "to fail when that happened. Both callers share one derivation "
              "on purpose - a second implementation would drift, and drift is "
              "a false positive in the one signal that must stay meaningful. "
              "Attack C exists because 'resolve disagreement by taking the "
              "worse verdict' would let a compromised validator condemn every "
              "run; the two conclusions are compared, never reconciled.",
    ),
    CaseResult(
        case_id="case-06",
        title="What process separation actually buys",
        compromise_level="Level 2: fully compromised agent process",
        attack="The same hostile stage runs in the runner's process and in a "
               "spawned interpreter, probing for the artifact store, the "
               "RunSession, ungranted artifact content from an earlier run, "
               "and the host filesystem",
        baseline_result=UNDETECTED,
        controlled_result=PREVENTED,
        control="The stage executes in a separate interpreter reached only by "
                "line-delimited JSON, with the parent acting as a trusted "
                "resolver that answers one read request at a time against the "
                "grant it issued; returned artifacts and events re-enter "
                "through the existing write contract, hash registration and "
                "attribution binding",
        evidence=[
            "5 memory paths reached in-process, 0 from the spawned interpreter",
            "every isolated probe reports 'nothing found', not 'denied'",
            "workflow completes with verdict ok and read log "
            "['artifact.raw_input']",
            "an edited child-side grant is still refused by the parent resolver",
            "a forged trusted_runner event returns stamped 'schema_agent'",
            "tests/adversarial/test_case_06_process_isolation.py",
        ],
        what_this_proves=(
            "That process separation removes exactly one thing and removes it "
            "completely: a stage in another interpreter has no path to the "
            "runner's Python objects, because there are none there to find. "
            "The probes report 'nothing found' rather than 'denied' - the "
            "techniques still work, the room is empty. It also proves the "
            "boundary can be crossed without giving up the enforcement point: "
            "resolving reads one at a time keeps view.read_keys meaningful, "
            "which an eager payload handoff would have made vacuous."),
        what_this_does_not_prove=(
            "It does not prove the isolated stage is contained. Its ambient "
            "authority, its grant and its authorship are all unchanged and "
            "measured so. It does not prove the system is isolated - three "
            "stages of four still share the runner's process, so case 01 "
            "stands. It says nothing about host compromise, resource "
            "exhaustion or a determined sandbox escape, none of which were "
            "tested."),
        residual_limitation=(
            "Ambient authority is untouched: same uid, same filesystem, same "
            "network, no resource limits. The grant is untouched. Output "
            "honesty is untouched. And three of four stages remain "
            "in-process, which is the residual an 'isolation landed' headline "
            "would hide."),
        containment="Two failure modes kept apart: a ContractError raised in "
                    "the child re-raises on the parent as a contract violation "
                    "(Level 1, workflow halts); a crash, timeout or protocol "
                    "violation raises IsolationError, reported as an isolated "
                    "stage failure. Neither quarantines.",
        recovery="Re-run the stage. The first case where recovery is genuinely "
                 "cheap: the child holds no state and a fresh interpreter is "
                 "clean by construction, so nothing must be restored from a "
                 "place the adversary could also reach.",
        status="closed",
        directory="cases/06-process-isolation",
        test_module="tests/adversarial/test_case_06_process_isolation.py",
        blast_radius="For the isolated stage: its own grant, its own output, "
                     "and whatever the uid reaches on the host - not the "
                     "runner's memory and not other runs' artifacts, since the "
                     "interpreter is new per invocation. For the system: "
                     "unchanged.",
        notes="Measuring this turned up a finding no case covers: an isolated "
              "stage wrote a fabricated schema, the honest transform built the "
              "cleaned output from it, and the poison laundered into a chain "
              "that is internally consistent - every column of real data gone, "
              "verdict ok, no review flag. Every check compares derived "
              "artifacts to each other; nothing compares output back to the "
              "source artifact. Pinned by a test, recorded rather than fixed, "
              "and it is the recommended next case.",
    ),
    CaseResult(
        case_id="case-07",
        title="Corrupting downstream artifacts through your own",
        compromise_level="Level 1: malicious agent implementation",
        attack="A hostile schema stage writes one well-formed artifact to the "
               "key it was granted - a fabricated column set, a dropped "
               "column, a renamed column - and the honest transform stage "
               "builds the cleaned output from it",
        baseline_result=UNDETECTED,
        controlled_result=DETECTED_AFTER_OCCURRENCE,
        control="A fifth derived check, output_matches_source: the cleaned "
                "output's columns must equal the source artifact's columns, "
                "naming what went missing and what was added. It is the only "
                "check that looks back at the artifact the chain started from",
        evidence=[
            "fabricated schema: 20 rows of {'fabricated': None}, verdict ok "
            "at the baseline",
            "dropped money column: row counts still agree, verdict ok",
            "renamed column: present, entirely None, verdict ok",
            "with the control all three report warn and name the divergence",
            "the honest run is unaffected",
            "tests/adversarial/test_case_07_poisoned_chain.py",
        ],
        what_this_proves=(
            "That deriving a conclusion from trustworthy evidence is not "
            "enough if the evidence only describes derived state. Three of "
            "case 05's four checks compared artifacts the pipeline produced "
            "against each other, so an honest downstream stage laundered a "
            "poisoned upstream artifact into a chain that agreed with itself, "
            "and the lie became the standard everything after it was measured "
            "against. It also shows how cheap this class is: no control was "
            "defeated, and a single legal write destroyed every column of a "
            "dataset while every other control held."),
        what_this_does_not_prove=(
            "It does not prove the output is correct - the check compares "
            "column shape, and a mistyped schema silently truncates money "
            "while passing. It does not address the identifier fidelity the "
            "honest pipeline already loses. It does not generalise to a longer "
            "chain, since only the raw-to-cleaned pair is compared. And it "
            "prevents nothing."),
        residual_limitation=(
            "Structure is compared; values are not. A stage that keeps every "
            "column name and mistypes them all passes, and the damage is "
            "selective because a failed coercion leaves the value alone. "
            "Identifier fidelity is lost on the honest path already - '1001' "
            "becomes 1001 - and closing that needs the canonical artifact to "
            "carry field semantics rather than have them guessed from shape."),
        containment="The run completes and reports warn with the divergence "
                    "named. No quarantine: the artifacts are exactly what "
                    "their producer wrote and their hashes verify. The "
                    "workflow's own conclusion is the containment.",
        recovery="Re-run from intake with a known-good schema stage. The case "
                 "where the immutable canonical artifact earns its keep: the "
                 "thing to recover from is provably the thing the run started "
                 "with.",
        status="closed",
        directory="cases/07-poisoned-chain",
        test_module="tests/adversarial/test_case_07_poisoned_chain.py",
        blast_radius="Every artifact downstream of the poisoned one, which "
                     "here is all of them, plus anything that consumed the "
                     "run's output - and there is no provenance graph to "
                     "identify what did (Phase 8). Bounded by the run: the "
                     "source artifact is untouched and the poison does not "
                     "persist into later runs.",
        notes="Found while measuring case 06, not by looking for it. "
              "Deliberately extends case 05's derivation rather than adding a "
              "parallel mechanism, for the reason case 05 recorded - a second "
              "derivation would drift. The cost was four tests elsewhere that "
              "pinned a four-check vocabulary; all four are listed in the "
              "case README and none was weakened. Measurement D is not an "
              "attack: it records that the honest pipeline turns the "
              "identifier '1001' into the number 1001 and no check notices.",
    ),
    CaseResult(
        case_id="case-08",
        title="Stored grant versus grant derived at use time",
        compromise_level="Narrow by design: may alter persisted policy or "
                         "workflow records before execution; may not modify "
                         "evaluator code or the administrative trust root",
        attack="Obtain a named unauthorized read at the schema step in each of "
               "two authority models, attacking every stored "
               "authority-bearing record independently: a future artifact "
               "(cleaned_output) and an existing unrelated one (key_material)",
        baseline_result=UNDETECTED,
        controlled_result=UNDETECTED,
        control="None. This case is a comparison and changes nothing in the "
                "product; both models are measured as they are. Arm A is the "
                "production Route table, arm B a candidate object-and-skill "
                "model living in the case directory per concept note 24",
        evidence=[
            "minimum tamper set 1 in both arms, for both capabilities",
            "arm A: 1 stored surface, yields both targets, additive",
            "arm B: 5 stored surfaces, 2 yield - skill contract and "
            "artifact map",
            "arm B transition, object-state and queue edits yield no key "
            "authority",
            "scope differs sharply: object lifetime vs deployment lifetime",
            "tests/adversarial/test_case_08_derived_authority.py",
        ],
        what_this_proves=(
            "That the authority-bearing record is whatever binds a declared "
            "type to a concrete key, wherever it lives. Arm A keeps that "
            "binding in the policy table and arm B in the object's artifact "
            "map; neither removes it, and one edit to it suffices in both. "
            "Deriving the grant does bound what state, transition and queue "
            "lies obtain - three of arm B's five surfaces yielded nothing, "
            "because the grant still has to resolve through the artifact map "
            "and none of them touches it."),
        what_this_does_not_prove=(
            "It does not show arm A is preferable: arm A's single surface is "
            "broader in scope and its edit is purely additive, so the "
            "tampering leaves the legitimate work intact and invisible. It "
            "does not generalise beyond one workflow position, one object "
            "type and one registry. And it says nothing about whether the "
            "skill registry is trustworthy - it attacks the registry as data "
            "and reports the radius. Case 09 owns that."),
        residual_limitation=(
            "Arm B's artifact map is unprotected, persisted, and reads as "
            "bookkeeping rather than policy - cheapest to reach, survives "
            "resume, and the surface this case nearly failed to test. The "
            "skill-contract edit has the widest scope in the whole table, "
            "every object until redeployment, and arm B has no answer to it."),
        containment="None in either arm. Arm A's pre-run edit is case 03's "
                    "unclosed residual; arm B has no independent account of "
                    "what an object's state or artifact map should be.",
        recovery="Not applicable - no control was applied. Operationally, "
                 "neither model can distinguish a tampered record from a "
                 "legitimate one without an external account of what the "
                 "premises should be.",
        status="open",
        directory="cases/08-derived-authority",
        test_module="tests/adversarial/test_case_08_derived_authority.py",
        blast_radius="Recorded per surface rather than per case, on a scope "
                     "scale. Arm A route edit: process lifetime and future "
                     "independent runs. Arm B map edit: one object, including "
                     "retries and resume. Arm B skill edit: deployment "
                     "lifetime, every object running that skill.",
        notes="The hypothesis was that arm B would require two mutations. It "
              "was written into an early draft of the contract as an "
              "acceptance condition, corrected to a metric before "
              "measurement, and refuted: one edit is enough in both arms. "
              "'Bounded by workflow progress' was also refuted, and only "
              "because the case tested two capabilities - arm B refused the "
              "future artifact through the transition and state surfaces, "
              "which looked like progress bounding until the artifact-map "
              "edit obtained it anyway. A single-probe case would have "
              "claimed object-centred authorization for what was timing.",
    ),
]

CASES_BY_ID = {case.case_id: case for case in CASES}


def all_cases() -> List[CaseResult]:
    return list(CASES)


def get(case_id: str) -> CaseResult:
    return CASES_BY_ID[case_id]


def to_json_dicts() -> List[Dict[str, Any]]:
    return [case.to_dict() for case in CASES]
