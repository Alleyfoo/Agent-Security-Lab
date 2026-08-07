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
        compromise_level="Level 1.5: the configuration adversary - may alter "
                         "persisted policy or workflow records before "
                         "execution; may not modify evaluator code or the "
                         "administrative trust root",
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
    CaseResult(
        case_id="case-09",
        title="Can the execution plane mint a transformation?",
        compromise_level="Level 1: a worker using the execution plane's "
                         "interfaces (Level 2 for the residual)",
        attack="Create, modify, replace and select an unapproved skill "
               "definition - four verbs measured separately - then rewrite the "
               "private registry in three placements: before the run pins, "
               "mid-run, and mid-run with the pin updated",
        baseline_result=UNDETECTED,
        controlled_result=PREVENTED,
        control="A read-only MappingProxyType registry over frozen Skill "
                "records with no mutation operation on the execution path "
                "(C1), plus per-run version pinning: each skill carries a "
                "content digest, a run pins the digests it may use at start "
                "and re-verifies before deriving any grant (C2)",
        evidence=[
            "create, update, setdefault, remove and clear all refused",
            "no create_skill / publish_skill / disable_review anywhere on the "
            "execution path - absent, not denied",
            "replacement between steps: baseline OBTAINED, pinned detected "
            "with both digests named",
            "selection refused for an unregistered name and for a name the "
            "object's state does not require",
            "Level 2: before-pin OBTAINED, mid-run detected, pin-updated "
            "OBTAINED",
            "tests/adversarial/test_case_09_skill_registry.py",
        ],
        what_this_proves=(
            "That an allowlist of names is not an allowlist of "
            "transformations. Selection was already sound before this case - "
            "an unregistered name and a name the object type does not permit "
            "were both refused - while the contents of an approved entry could "
            "be rewritten and the run would use them without comment. With the "
            "control a worker cannot create, modify or select through any "
            "interface it holds, and a definition replaced after the run "
            "started is detected before a grant is derived from it. It also "
            "establishes what a version pin is worth, which is less than it "
            "looks: continuity across one window, not legitimacy."),
        what_this_does_not_prove=(
            "It does not prove the registry is trustworthy. There is no "
            "independent account of what the approved set should be, so "
            "tampering before a run pins is undetected and tampering with the "
            "pin alongside the registry passes. It implements no part of the "
            "concept note's administrative lifecycle - no proposal, review, "
            "approval, signing or versioned release. And it does not secure "
            "the type-to-key binding: case 08's artifact-map edit still works "
            "with every control here active, which a scope-guard test pins."),
        residual_limitation=(
            "Replacement before the run pins is undetected - the pin records "
            "what was there, not what should have been. Updating the pin "
            "alongside the registry passes, the fifth instance of the "
            "cross-cutting finding. MappingProxyType is a view, not a freeze. "
            "And removal mid-run is misreported as a selection failure, "
            "because validate runs before verify_pins and shadows the message "
            "that would name the real incident."),
        containment="A version mismatch raises SkillRegistryError, distinct "
                    "from AuthorizationError, and the run refuses to derive a "
                    "grant from a definition it did not start with. Fails "
                    "closed: there is no sound conclusion available from an "
                    "unapproved contract.",
        recovery="Restart the run - the pin is taken at start, so a fresh run "
                 "over an untampered registry is clean, and unlike cases 02, "
                 "03 and 05 there is nothing to reconstruct because a skill "
                 "definition is not run state. Restoring the registry itself "
                 "is out of scope and would be unsound: the process holds no "
                 "record of what the approved set was.",
        status="closed",
        directory="cases/09-skill-registry",
        test_module="tests/adversarial/test_case_09_skill_registry.py",
        blast_radius="A successful registry edit reaches every object running "
                     "that skill until redeployment - the widest scope "
                     "measured anywhere here. C2 narrows it to runs starting "
                     "after the edit; runs in flight detect it and stop. A "
                     "real reduction, and not containment: the edit is still "
                     "there and every later run picks it up silently.",
        notes="The candidate model moved to object_model/ this slice, because "
              "cases 08, 09 and 10 share it and loading it across case "
              "directories by file path was worse. It is not the product and "
              "agent_network_demo does not import it. Case 08's own copy is "
              "deliberately left frozen at what it measured - retrofitting "
              "these controls into it would have changed a published table. "
              "The independent-authority question is answered 'there is none', "
              "which is the honest answer at this phase.",
    ),
    CaseResult(
        case_id="case-10",
        title="The type-to-key binding",
        compromise_level="Level 1.5: the configuration adversary - may alter "
                         "persisted policy or workflow records, may not "
                         "modify evaluator code",
        attack="Rebind an artifact type to a different key mid-workflow - "
               "through the API, appended past it, and by overwriting the "
               "record - plus pre-seeding a type before its producer runs, and "
               "tampering after completion to hit resume",
        baseline_result=UNDETECTED,
        controlled_result=DETECTED_AFTER_OCCURRENCE,
        control="Derive the map instead of storing it: a runner-owned "
                "append-only ProductionLedger records what each completed step "
                "produced, the binding is computed from it with first "
                "production winning, and an artifact type may be produced at "
                "most once per object",
        evidence=[
            "map maintenance implemented first - both arms run the same "
            "three-step workflow and resolve identical grants untampered",
            "stored map: rebinding succeeds by every route, silently",
            "derived: refused through the API, inert when appended past it, "
            "and the conflict stays in the record",
            "derived: tampering is inert across reload and resume",
            "residual: overwriting a production record still works",
            "tests/adversarial/test_case_10_type_to_key_binding.py",
        ],
        what_this_proves=(
            "That the shape of a record decides what tampering with it costs, "
            "independently of how well it is protected. The stored map and the "
            "derived ledger are both unprotected in-process data with a "
            "minimum tamper set of one, and they behave completely "
            "differently: a dictionary write is total and silent, while an "
            "append-only record with a produced-once invariant makes the cheap "
            "edits inert and leaves the contradiction in place. First case in "
            "the comparison series where the derived model is materially "
            "better rather than merely different."),
        what_this_does_not_prove=(
            "It does not close the surface: overwriting a production record "
            "obtains the capability at the same cost as before, and the ledger "
            "is append-only by API rather than tamper-evident. It does not "
            "come free - the produced-once invariant introduces a denial of "
            "service the stored map does not have. And it does not touch the "
            "skill registry, which case 09 measured as the wider-scope half."),
        residual_limitation=(
            "Overwriting an existing production record still works, with the "
            "same tamper set as the stored map - the sixth appearance of the "
            "cross-cutting finding. One forged append for a type not yet "
            "produced permanently blocks its legitimate producer, so the "
            "object cannot complete. The last clause - that conflicts_for() "
            "reported contradictions nothing acted on - was closed by case 11, "
            "which made the step lifecycle read it; the overwrite residual is "
            "untouched by that and is structurally invisible to it."),
        containment="Superseded by case 11 for appended conflicts, which now "
                    "contain the object before the next step. As measured "
                    "here: none automatic. The API refusal stops the ordinary "
                    "path; past it the derivation makes tampering ineffective "
                    "rather than detected-and-halted, and the conflict sits in "
                    "the record until something looks.",
        recovery="Better than the stored map, and the derived arm's clearest "
                 "practical advantage: the original binding is still in the "
                 "record, so first-production-wins means recovery is already "
                 "what happens. In the stored map the original key is gone and "
                 "there is nothing to recover it from.",
        status="closed",
        directory="cases/10-type-to-key-binding",
        test_module="tests/adversarial/test_case_10_type_to_key_binding.py",
        blast_radius="Unchanged in reach, changed in durability. One object "
                     "including its retries and resume. In the derived arm an "
                     "append-shaped edit affects nothing and a DoS-shaped edit "
                     "stops that object permanently.",
        notes="Map maintenance was implemented before any attack, because case "
              "08's arm B never changed its map and tampering with a record "
              "nothing maintains would have measured nothing. The "
              "denial-of-service finding was not predicted - it fell out of "
              "attack B, where the invariant that makes rebinding hard also "
              "makes one forged append fatal to the object. A ledger with no "
              "records was falsy because __len__ was defined without "
              "__bool__, and the first harness run silently measured the "
              "stored arm twice; both the class and the test now pin it.",
    ),
    CaseResult(
        case_id="case-11",
        title="Contain a contradiction the moment it appears",
        compromise_level="Level 1.5: the configuration adversary - may alter "
                         "persisted policy or workflow records, may not "
                         "modify evaluator code",
        attack="Leave a contradiction in the production record - case 10's "
               "appended rebinding, measured there as inert - and let the "
               "object keep working; then retry, reload and resume it, then "
               "overwrite instead of appending",
        baseline_result=DETECTED_AFTER_OCCURRENCE,
        controlled_result=PREVENTED,
        control="check_containment() in the step lifecycle: before validation "
                "and before any grant is derived, an object whose production "
                "record contradicts itself raises ObjectContainedError and "
                "runs no further step. No new record and no new state - the "
                "check reads the record the lifecycle already has",
        evidence=[
            "uncontained: two more steps run and the object reaches "
            "'validated' with its record contradicting itself",
            "contained: stopped at 'profiled', no grant derived, nothing "
            "produced, the refusal naming both bindings",
            "3/3 retries refused, and a reloaded ledger contains a resumed "
            "object again with no flag anywhere",
            "an overwritten record leaves no conflict: the read is OBTAINED "
            "and containment never fires",
            "cost: one forged append is now a permanent object-level denial "
            "of service; a conflict about a type no step reads stops it too",
            "tests/adversarial/test_case_11_conflict_containment.py",
        ],
        what_this_proves=(
            "That the derived model can hold a control the stored model cannot "
            "have at all. Containment needs a contradiction to find, and a "
            "stored map keeps none - a write is total, the previous binding is "
            "gone, and the object is left with a map that is internally "
            "consistent and wrong. Case 10 showed the two records behave "
            "differently under tampering; this shows the difference is usable "
            "rather than merely observable. It also shows quarantine did not "
            "need new state here: the corrupt record is its own marker, so the "
            "refusal survives reload and resume with nothing added to remember "
            "it."),
        what_this_does_not_prove=(
            "It does not close case 10's residual - overwriting still works "
            "and containment is structurally blind to it, because a "
            "contradiction is what an append leaves behind and only appends "
            "leave one. It moves no confidentiality result: the rebinding it "
            "now stops was already inert. It does not come free, and the cost "
            "runs opposite to the benefit. And it says nothing about the skill "
            "registry, case 09's half of the trust root."),
        residual_limitation=(
            "The one attack that works is invisible to the check. It is an "
            "availability trade, not a free improvement: the cheapest forgery "
            "in the model - one appended line - now guarantees an object never "
            "completes, and the check is object-scoped, so a contradiction "
            "about a type no step reads stops it as surely as a relevant one. "
            "check_containment is ordinary in-process code reading an ordinary "
            "in-process list, so the cross-cutting finding applies unchanged. "
            "And containment sits at the lifecycle, not at the derivation: "
            "derive_grant still answers on a contradicted record, deliberately, "
            "because case 10's published measurement is taken there."),
        containment="ObjectContainedError, a subclass of LedgerIntegrityError - "
                    "the same corruption, a different response: the ledger "
                    "refusing to write versus the lifecycle refusing to run. "
                    "Fails closed, and scoped to one object; others in the same "
                    "ledger complete, which is asserted rather than assumed.",
        recovery="Not implemented, and it is the honest gap. Deleting the "
                 "forged record is indistinguishable from the attack: the "
                 "ledger holds no independent account of which of two "
                 "contradicting entries is legitimate, even though "
                 "first-production-wins makes the derivation behave as though "
                 "it does. An operator must reconstruct outside the model - "
                 "the same wall case 09 hit with the registry.",
        status="closed",
        directory="cases/11-conflict-containment",
        test_module="tests/adversarial/test_case_11_conflict_containment.py",
        blast_radius="One object, permanently, including retries and resume. "
                     "Not the run, not other objects, not later deployments. "
                     "Wider than case 10 in duration and narrower in effect: "
                     "the object stops instead of finishing on a corrupt "
                     "record.",
        notes="Closes the last clause of case 10's residual and nothing else, "
              "under an explicit instruction not to expand the model again. "
              "The finding that made that possible was not planned: quarantine "
              "needed no flag, because unlike case 02 the corruption lives in "
              "the record the lifecycle already reads. The blind spot is the "
              "case's most useful output - containment stops the attack that "
              "was already inert and cannot see the attack that works, which "
              "is one fact stated twice rather than two limitations.",
    ),
    CaseResult(
        case_id="case-12",
        title="Three models, one workflow",
        compromise_level="Level 1.5: the configuration adversary, generalized per "
                         "arm - may alter persisted configuration or workflow "
                         "records, may not modify executable code or the "
                         "trust root",
        attack="Obtain a read of artifact.key_material at the schema step in "
               "three architectures running the same workload - authority "
               "following the subject, the configured workflow step, and the "
               "transformation of one object - attacking every stored "
               "authority-bearing record in each",
        baseline_result=UNDETECTED,
        controlled_result=UNDETECTED,
        control="None. This case is a comparison and changes nothing in the "
                "product or in object_model; all three arms are measured as "
                "they are. Version pinning is implemented once and shared, "
                "because the contract adjudicated it as not "
                "architecture-specific",
        evidence=[
            "equivalence asserted first: same artifacts, same schema-step "
            "grant, in all three arms before any tampering",
            "arm A identity: 2 stored records, both yield, minimum tamper "
            "set 1, scope every future run by that subject",
            "arm B workflow: 3 stored records, none yields alone, minimum "
            "tamper set 2, scope every run of the definition",
            "arm C object: 5 stored records, 2 yield, minimum tamper set 1, "
            "scope one object or the whole deployment by surface",
            "pinning detects a mid-run edit in all three arms and a pre-run "
            "edit in none",
            "tests/adversarial/test_case_12_three_models.py",
        ],
        what_this_proves=(
            "That the three models put authority in measurably different "
            "places, and that the difference which mattered was not the one "
            "predicted. What separates the arms is not how many "
            "authority-bearing records they hold - the object model has the "
            "most and is among the cheapest to attack - but whether two "
            "independent records must agree. Arm B is the only arm where they "
            "must, and the only one where a single edit is not enough. It also "
            "shows the comparison can be run fairly: the arms do the same "
            "work, resolve the same grant untampered, and each carries an "
            "executable competence checklist whose violation voids its own "
            "numbers."),
        what_this_does_not_prove=(
            "It does not show the object model is better or worse overall: one "
            "property family of three was measured, and data flow and failure "
            "behaviour were not. It does not show arm B is a better "
            "architecture - its authority is the least specific of the three, "
            "scoped to every run of the definition with no notion of which "
            "object is being worked on. Arm A is not Unix and arm B is not "
            "Power Automate; they are reference models, and arm A in "
            "particular models permission checks and not ambient authority or "
            "kernel enforcement, which is where a real Unix arm would be "
            "strongest."),
        residual_limitation=(
            "One workflow position, one capability, one attacker - the same "
            "narrowness case 08 recorded, and a different target might rank "
            "the arms differently. Arm C's intake is a seed rather than a "
            "transition because object_model's workflow table is frozen at "
            "what cases 10 and 11 measured, so the arms are compared on "
            "artifacts produced and grant resolved rather than on step count. "
            "Nothing here measures ambient authority, process boundaries, data "
            "movement, provenance, replay, or availability under attack."),
        containment="None in any arm. Arm B refuses at use time when the two "
                    "records disagree, but the message is identical to a "
                    "misconfiguration - refusal, not detection of tampering. "
                    "No arm has an independent account of what its own "
                    "authority records should contain.",
        recovery="Not applicable - no control was applied. Operationally none "
                 "of the three arms can distinguish a tampered authority "
                 "record from a legitimate administrative change, which is the "
                 "same wall cases 09 and 11 hit from inside one model.",
        status="open",
        directory="cases/12-three-models",
        test_module="tests/adversarial/test_case_12_three_models.py",
        blast_radius="Recorded per arm on the shared scope scale rather than "
                     "per case. Arm A: every future run by that subject and "
                     "every resource it may touch. Arm B: every run of that "
                     "workflow definition. Arm C: one object for the artifact "
                     "binding, every object until redeployment for the skill "
                     "contract - the same one-edit cost for both.",
        notes="Kills the project's easy story, and that is the value of it: "
              "'the object model is safer than an identity model or a "
              "workflow model' is refuted for this property family. The "
              "result to keep is narrower and more useful - for fixed "
              "workflows, conventional workflow orchestration may be "
              "structurally better than the candidate object model at "
              "resisting single-record authority tampering. The principle "
              "that survives is architecture-neutral and belongs to no arm: "
              "authority is harder to forge when derived from independent "
              "premises than when read from one writable conclusion - with "
              "the bound that the premise count sets the cost, not the "
              "possibility, since both of arm B's records sit inside the same "
              "adversary's reach. "
              "Both pre-registered predictions were refuted, which is the "
              "point of pre-registering them. Minimum tamper set is not 1 "
              "everywhere: a competently configured workflow needs 2. And the "
              "object model is not narrowest at minimum cost - its "
              "skill-contract route is deployment-wide, wider than either "
              "other arm, so conclusion 4 cannot be claimed without naming the "
              "surface. Arm A's second route creates no new authority "
              "anywhere: it reassigns the stage to an identity that already "
              "holds it, and the audit record afterwards is correct and "
              "useless. A collision found while building this: case 08 owns "
              "the bare module name 'common', so case 12's helper is "
              "case12_common - a plain import bound case 08's module and the "
              "test file failed to collect.",
    ),
    CaseResult(
        case_id="case-13",
        title="Does a second independent premise raise the cost?",
        compromise_level="Level 1.5: the configuration adversary, unchanged from "
                         "case 12 - may alter persisted configuration or "
                         "workflow records, may not modify executable code or "
                         "the trust root",
        attack="The same read of artifact.key_material at the schema step, "
               "against case 12's arm A and arm C after one additional "
               "independent premise is layered onto each - a MAC-style label "
               "policy over the permission table, and artifacts that declare "
               "what they are",
        baseline_result=UNDETECTED,
        controlled_result=UNDETECTED,
        control="None in the product. An experiment on laboratory reference "
                "arms, testing a prediction pre-registered in the report "
                "before the code existed. object_model is untouched and case "
                "12's arms are frozen; this case layers onto them",
        evidence=[
            "arm A + label policy keyed on the stage: minimum tamper set "
            "rises 1 -> 2, prediction confirmed",
            "arm A + the same policy keyed on the subject: stays 1, because "
            "reassigning the subject moves both premises at once",
            "arm C + artifact declaration: closes case 10's surviving "
            "overwrite route completely, and the skill-contract route still "
            "obtains at one edit",
            "arm C + a premise per surface: rises to 2",
            "each added premise is asserted to be genuinely consulted and to "
            "leave the honest run intact",
            "tests/adversarial/test_case_13_second_premise.py",
        ],
        what_this_proves=(
            "That case 12's principle is architecture-neutral as claimed - it "
            "worked in an identity model and in an object model, neither of "
            "which had it before - and that it is conditional in two ways "
            "nobody had stated. A second premise buys nothing if it is a "
            "function of an index the attacker can pivot, which is the "
            "confused-deputy shape arriving in the authority model: the "
            "attacker does not forge a permission, it changes which principal "
            "the question is asked about. And a premise raises the cost only "
            "of the surface it covers, so an arm with more authority-bearing "
            "surfaces needs more premises to reach the same minimum - which "
            "cost the object model two where arm A needed one."),
        what_this_does_not_prove=(
            "It does not show any arm is secure. Every premise here sits "
            "inside the same adversary's reach, so two edits is a price and "
            "not a wall, and the cross-cutting finding is untouched. It does "
            "not show the object model is worse - expressiveness is paid for "
            "in premises, which is a cost a designer may choose to pay. And it "
            "tests one capability at one workflow position; a surface no "
            "premise covers is unaffected by any of it."),
        residual_limitation=(
            "The premises are laboratory constructs layered onto laboratory "
            "arms, and none of them exists in the product. Arm A's label "
            "policy models the *structure* of MAC over DAC and not kernel "
            "enforcement, which is the dimension case 12 already recorded its "
            "identity arm cannot reproduce. Both of arm C's premises are "
            "in-process data the same attacker reaches."),
        containment="None. Refusals here are ordinary authorization denials - "
                    "the premise disagrees and the key is not in the grant. No "
                    "arm records that a disagreement happened, so a tamper "
                    "that fails is as silent as one that succeeds.",
        recovery="Not applicable - no control was applied. The finding that "
                 "matters operationally is negative: an added premise keyed on "
                 "an attacker-controlled index gives the appearance of defence "
                 "in depth and none of the substance.",
        status="open",
        directory="cases/13-second-premise",
        test_module="tests/adversarial/test_case_13_second_premise.py",
        blast_radius="Unchanged from case 12 in every configuration. Adding "
                     "premises changes the price of a successful edit, not "
                     "what a successful edit reaches.",
        notes="Written to test a prediction rather than to build a control, "
              "and the prediction survived in a more useful form than it was "
              "stated. The rule it produces is applicable rather than "
              "admirable: a premise must be consulted at use time, must not be "
              "a function of an index the attacker can change, and must sit on "
              "the surface being defended - missing any of the three buys "
              "nothing. The subject-keyed variant is the one to remember, "
              "because it looks exactly like defence in depth and measures as "
              "no defence at all.",
    ),
    CaseResult(
        case_id="case-14",
        title="The selector map",
        compromise_level="Level 1.5: the configuration adversary - named in "
                         "this slice after five cases had measured it "
                         "unnamed",
        attack="Enumerate what selects every authority premise in all three "
               "arms, mark which selectors this adversary can alter, and "
               "execute every pivot the map implies - one edit to a shared "
               "selector, measured for whether it moved a premise and "
               "separately for whether it obtained the capability",
        baseline_result=UNDETECTED,
        controlled_result=UNDETECTED,
        control="None. An enumeration, not a control: no arm is changed and "
                "no product code is touched. The map's completeness is "
                "enforced by a test requiring every shared alterable selector "
                "to carry an executed pivot",
        evidence=[
            "10 premises mapped across 3 arms, each with its store and its "
            "selectors",
            "7 shared-selector pivots executed; 2 yield in one edit",
            "arm A: both premises keyed on the subject, so one reassignment "
            "moves both - stage-keyed, the identical edit yields nothing",
            "arm B: the input list and the connection name are fields of the "
            "same step record, so case 12's 2 fields are 1 record write",
            "arm B: one ordinary over-scoped credential, pre-existing and not "
            "counted as an edit, collapses it to one write",
            "arm C: retyping the object moves the read policy and obtains "
            "nothing, because the skill contract is keyed on the skill name",
            "tests/adversarial/test_case_14_selector_map.py",
        ],
        what_this_proves=(
            "That independent records and independent premises are different "
            "things, and that the difference is measurable rather than "
            "rhetorical. Seven shared selectors were executed; two collapse "
            "two premises into one edit, and the five that do not fail for "
            "four distinguishable reasons - an unalterable selector, an absent "
            "target in the deployment, an empty lookup, and a third premise "
            "keyed on something else. It also converts case 12's arm B result "
            "from an architectural claim into a conditional one: two premises, "
            "one record, and an advantage that depends on the credential "
            "inventory rather than on the architecture."),
        what_this_does_not_prove=(
            "It does not show arm C is secure: it has no yielding pivot on "
            "this path for this capability, which is narrower than it sounds, "
            "and case 12 measured its minimum tamper set at 1 by two routes "
            "that need no pivot at all. It does not close anything - every "
            "premise remains inside the adversary's reach, and this case adds "
            "no control, no detection and no containment. And it does not "
            "establish that the premise list is complete for any arm."),
        residual_limitation=(
            "The map is hand-built and its completeness is asserted rather "
            "than derived: a test requires every shared alterable selector to "
            "carry an executed pivot, which caught one missing pivot while the "
            "case was being written, but a premise nobody wrote down has no "
            "selector on the map. Whether a selector is alterable is a "
            "judgement recorded as data so it can be argued with - the "
            "artifact key and the skill name are classified as not directly "
            "writable, and both are derived from records that are."),
        containment="None, and the case records why that is the honest answer: "
                    "a pivot is an ordinary configuration change. Nothing in "
                    "any arm distinguishes retyping an object or reassigning a "
                    "subject from an administrative decision to do exactly "
                    "that.",
        recovery="Not applicable - no control was applied. The operationally "
                 "useful output is a checklist rather than a remedy: for each "
                 "premise, name its selector, and check whether any other "
                 "premise shares it.",
        status="open",
        directory="cases/14-selector-map",
        test_module="tests/adversarial/test_case_14_selector_map.py",
        blast_radius="Unchanged - the case measures reachability, not effect. "
                     "What it adds is that a pivot's radius is the radius of "
                     "the widest premise the selector reaches, which is not "
                     "visible from any single record.",
        notes="Produced an inversion worth keeping: on selector hygiene the "
              "ordering of the three models reverses. The simplest "
              "architecture has the most yielding pivots and the most "
              "expressive has none, while case 12 measured the reverse on "
              "record count and tamper set. Not a contradiction - how many "
              "records hold authority is not how many of them one edit can "
              "move. The unit-of-measurement finding is the one most likely to "
              "matter elsewhere: counting fields and counting records give "
              "different tamper sets for the same attack, and case 12 counted "
              "fields.",
    ),
]

CASES_BY_ID = {case.case_id: case for case in CASES}


def all_cases() -> List[CaseResult]:
    return list(CASES)


def get(case_id: str) -> CaseResult:
    return CASES_BY_ID[case_id]


def to_json_dicts() -> List[Dict[str, Any]]:
    return [case.to_dict() for case in CASES]
