"""Applied-programme results: the evidence that is NOT attack evidence.

Why this file exists instead of more `CaseResult` rows
------------------------------------------------------

`CaseResult` describes an adversary, a protected outcome, a bypass route and a
cost in the settled tamper unit. Demo step D has exactly that shape and is
registered as **case 25**. Steps A-C, E and F do not, and forcing them into the
same structure because the dataclass has a `minimum_commits` field would repeat
the measurement mistake the first twenty-four cases exist to eliminate.

Concretely:

    F0's "17 unresolved" is not a successful attack route.
    F2's "8 escalated" is not a prevention whose tamper cost is some number.

They are operational outcomes under a preregistered fault distribution. A
`minimum_tamper_cost` invented for them would be a number with no referent, and
this repository already knows what happens to numbers with no referent - case
19 measured two mechanically different systems at 1 and 1, and case 24 measured
what severity looks like when it is derived from the same graph as exposure.

So the repository now holds three families of evidence:

    adversarial security   cases 00-25          CaseResult
    correctness / oracle   demo steps A-C       ProgrammeResult
    operational resilience demo steps E-F       ProgrammeResult

The common fields are genuinely common - a claim, its non-claims, its residual,
its evidence status, the commit it was measured at. The measurements are not,
and `REQUIRED_MEASUREMENTS` says so per family rather than pretending one schema
fits all three.

The architectural finding is the split itself: **not every piece of evidence in
an agent-security system is attack evidence**, and a scalar model that swallowed
all three would be the kind of security score this project exists to distrust.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List

from cases.registry import EVIDENCE_STATUSES, MEASURED

# ---------------------------------------------------------------------------
# Families. `security_case` is named here for completeness but lives in
# registry.py - a ProgrammeResult may not claim it.
# ---------------------------------------------------------------------------

SECURITY_CASE = "security_case"
CORRECTNESS_ORACLE = "correctness_oracle"
OPERATIONAL_RESILIENCE = "operational_resilience"

FAMILIES = (SECURITY_CASE, CORRECTNESS_ORACLE, OPERATIONAL_RESILIENCE)
PROGRAMME_FAMILIES = (CORRECTNESS_ORACLE, OPERATIONAL_RESILIENCE)

FAMILY_LABELS = {
    SECURITY_CASE: "Adversarial security evidence",
    CORRECTNESS_ORACLE: "Correctness / oracle evidence",
    OPERATIONAL_RESILIENCE: "Operational resilience evidence",
}

# What each family must report. Enforced by a test, so a step cannot quietly
# omit the measurement that would have been inconvenient.
REQUIRED_MEASUREMENTS = {
    CORRECTNESS_ORACLE: (
        "work_completed", "refused", "schedule_valid",
        "unauthorised_transitions",
    ),
    OPERATIONAL_RESILIENCE: (
        "detected", "missed", "false_alarms",
    ),
}

# Fields that belong to attack evidence and must never appear on a programme
# result. This is the distinction made structural rather than described.
FORBIDDEN_ON_PROGRAMME = (
    "tamper_unit", "minimum_commits", "commits", "routes",
    "minimum_tamper_cost", "attack_routes", "baseline_result",
    "controlled_result", "compromise_level",
)


@dataclass(frozen=True)
class ProgrammeResult:
    step: str
    title: str
    question: str
    family: str
    claim: str
    non_claims: List[str]
    residual: str
    measurements: Dict[str, Any]
    method: str
    source_commit: str
    exercises: Dict[str, str]        # concept -> why this step bears on it
    run: str
    test_module: str
    evidence_status: str = MEASURED
    notes: str = ""

    def __post_init__(self) -> None:
        if self.family not in PROGRAMME_FAMILIES:
            raise ValueError(
                f"{self.step}: family={self.family!r} is not one of "
                f"{PROGRAMME_FAMILIES}. Attack evidence belongs in "
                "cases/registry.py as a CaseResult.")
        if self.evidence_status not in EVIDENCE_STATUSES:
            raise ValueError(
                f"{self.step}: evidence_status={self.evidence_status!r}")
        for forbidden in FORBIDDEN_ON_PROGRAMME:
            if forbidden in self.measurements:
                raise ValueError(
                    f"{self.step}: {forbidden!r} is attack-evidence "
                    "vocabulary. An operational experiment has no tamper set; "
                    "inventing one because the field exists is the "
                    "measurement mistake this split was made to prevent.")
        missing = [m for m in REQUIRED_MEASUREMENTS[self.family]
                   if m not in self.measurements]
        if missing:
            raise ValueError(f"{self.step}: missing measurements {missing}")
        if not self.non_claims:
            raise ValueError(f"{self.step}: must state what it does not claim")

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


PROGRAMME: List[ProgrammeResult] = [
    ProgrammeResult(
        step="A",
        title="Bounded queue mechanics",
        question="Does routine work complete, and is the resulting schedule "
                 "valid according to a checker that knows nothing about the "
                 "agents?",
        family=CORRECTNESS_ORACLE,
        claim="A worker restricted to a fixed skill set, validated against "
              "each object's current state rather than the queue's opinion of "
              "it, completes ordinary work and produces a schedule an "
              "independent checker accepts.",
        non_claims=[
            "nothing about natural language - there is none in the demo",
            "nothing about adversarial behaviour; the worker is not hostile "
            "at this step",
            "nothing about scale - one venue for 28 days is not a deployment",
        ],
        residual="A valid schedule under a benign workload says nothing about "
                 "what the same skill set permits a hostile worker. That is "
                 "case 25's question, and it needed a different experiment.",
        measurements={
            "requests": 1000,
            "work_completed": 348,
            "refused": 652,
            "refusal_causes": {"contention": 652},
            "schedule_valid": True,
            "unauthorised_transitions": 0,
        },
        method="Frozen world model, bounded skill registry, runtime validating "
               "each skill against object state, and a schedule-invariant "
               "checker that imports neither the skills nor the runtime.",
        source_commit="demo step A",
        exercises={
            "restriction by function": "the runtime refuses a skill the "
                                       "object's state does not permit, and "
                                       "counts the refusal rather than "
                                       "silently dropping it",
            "independent verification": "the invariant checker shares no code "
                                        "with the thing it checks",
        },
        run="python demo_reservation/run_a.py",
        test_module="tests/test_demo_reservation_a.py",
        notes="All 652 refusals are contention. An earlier generator produced "
              "342 feature-mismatch and 296 hours refusals; that was "
              "physically implausible demand, and removing it was removing "
              "noise rather than removing difficulty.",
    ),
    ProgrammeResult(
        step="B",
        title="Independent disruptions",
        question="What actually breaks, when the generator is written before "
                 "any resolution logic exists?",
        family=CORRECTNESS_ORACLE,
        claim="A disruption generator committed before the recovery code can "
              "damage a running schedule in ways the recovery code did not "
              "get to choose.",
        non_claims=[
            "nothing about how hard the damage is to repair - conditioning on "
            "solvability is exactly what was forbidden",
            "nothing about realistic disruption frequency in a real venue",
        ],
        residual="The distribution is preregistered, not representative. Case "
                 "18 is the standing reminder of what a distribution "
                 "assumption costs, and step C's finding turned out to be a "
                 "property of THIS distribution rather than of scheduling.",
        measurements={
            "disruption_kinds": 5,
            "work_completed": 348,
            "refused": 652,
            "schedule_valid": True,
            "unauthorised_transitions": 0,
            "damage_independently_verified": True,
        },
        method="Generator conditioned only on affecting at least one existing "
               "reservation. Explicitly NOT conditioned on the number of "
               "alternatives, conflict complexity, or future solvability.",
        source_commit="demo step B",
        exercises={
            "preregistration": "a fault set chosen because the system handles "
                               "it measures the author, not the system",
        },
        run="python demo_reservation/run_b.py",
        test_module="tests/test_demo_reservation_b.py",
        notes="B1 is frozen. A scarce-resource workload would be a separate "
              "preregistered B2; modifying B to make C more interesting was "
              "explicitly refused.",
    ),
    ProgrammeResult(
        step="C",
        title="Local resolution and the joint oracle",
        question="How much damage absorbs locally, and how many of the "
                 "escalations were false?",
        family=CORRECTNESS_ORACLE,
        claim="An evaluator solving the affected reservations JOINTLY - not "
              "one at a time - can distinguish genuine impossibility from a "
              "false escalation and from a dead end the agent's own valid "
              "choices created.",
        non_claims=[
            "nothing about coordination mechanisms, because this workload "
            "never generated coordination pressure",
            "nothing that a per-reservation oracle could have told you - the "
            "self-created dead end is invisible to one",
            "no claim that zero dead ends is a property of the architecture; "
            "it is a property of this distribution",
        ],
        residual="Recoverability under B1 is bimodal: damage is either "
                 "locally trivial or structurally impossible. That is a "
                 "finding about the workload, and it means C did not get to "
                 "test the interesting middle. B1 stays untouched anyway.",
        measurements={
            "work_completed": 348,
            "refused": 652,
            "schedule_valid": True,
            "unauthorised_transitions": 0,
            "false_escalations": 0,
            "self_created_dead_ends": 0,
            "undecided": 0,
            "oracle_values": "yes / no / unknown, three-valued",
            "witness_verified_independently": True,
        },
        method="Joint backtracking feasibility oracle with a search budget. A "
               "`yes` always carries a witness assignment revalidated by the "
               "same independent invariant checker; a `no` is only sound if "
               "the search completed, otherwise `unknown`. The witness is "
               "never visible to the agents, enforced by a structural test.",
        source_commit="demo step C",
        exercises={
            "the oracle is not trusted either": "a three-valued answer with a "
                                                "verified witness, rather "
                                                "than a boolean to believe",
            "independent verification": "the oracle's positive claims go "
                                        "through the same checker the "
                                        "schedule does",
        },
        run="python demo_reservation/run_c.py",
        test_module="tests/test_demo_reservation_c.py",
        notes="Frozen exactly as first run. Nothing was optimised afterwards, "
              "which is why the bimodality is reported as a result rather "
              "than tuned away.",
    ),
    ProgrammeResult(
        step="E",
        title="Communication detection",
        question="Can an independent observer detect that an expected "
                 "communication did not complete correctly, WITHOUT "
                 "possessing authority to repair it?",
        family=OPERATIONAL_RESILIENCE,
        claim="Detection and repair are separable. An observer holding no "
              "verb that could change anything detects every injected "
              "communication fault, classifies each as preregistered, and "
              "raises no false alarm on clean traffic.",
        non_claims=[
            "nothing about diagnosis - `missing_expected_response` is "
            "provable from the stream, `worker_crashed` is not",
            "nothing about self-healing; the monitor cannot repair and that "
            "is the point of the step",
            "nothing about wall-clock behaviour - the deadlines are logical "
            "ticks, because a deadline in seconds would measure Windows "
            "scheduling",
        ],
        residual="The monitor sees a bus that hands it copies. A monitor "
                 "reading a stream it could edit would be able to hide its "
                 "own misses, which is case 00's audit-plane mistake; that is "
                 "prevented here by construction rather than measured against "
                 "an adversary who tries.",
        measurements={
            "exchanges": 1000,
            "clean": 954,
            "faults_injected": 46,
            "detected": 46,
            "missed": 0,
            "false_alarms": 0,
            "classified_as_preregistered": 46,
            "detection_latency_median_ticks": 4,
            "by_kind": {
                "drop_response": "5/5", "delay_past_deadline": "9/9",
                "wrong_correlation_id": "13/13",
                "wrong_sender_or_recipient": "14/14",
                "duplicate_response": "5/5",
            },
            "recovery_verbs_held_by_observer": 0,
        },
        method="Fault vocabulary and expected classification fixed in "
               "`comms_faults.py` before the detector existed. The injector "
               "holds ground truth and the monitor cannot read it, enforced "
               "structurally. Logical ticks throughout.",
        source_commit="0791d36",
        exercises={
            "observation is not diagnosis": "the stream can prove an absence; "
                                            "it cannot prove a cause, and a "
                                            "monitor inferring one is grading "
                                            "its own homework",
            "lowest necessary authority": "the observer imports no store, no "
                                          "runtime and no skills, and holds "
                                          "no verb that could repair anything",
            "case 00 - the audit plane": "observers receive copies, so an "
                                         "observer cannot edit the record of "
                                         "what it failed to notice",
        },
        run="python demo_reservation/run_e.py",
        test_module="tests/test_demo_reservation_e.py",
        notes="The diagnosis guard passed for a while while matching nothing "
              "at all - a literal backspace byte had turned \\b into a regex "
              "that checked nothing. That is why every absence guard in this "
              "repository now carries a positive control.",
    ),
    ProgrammeResult(
        step="F",
        title="Bounded recovery",
        question="Can a detected communication fault be recovered using only "
                 "explicitly granted recovery functions, without giving the "
                 "monitor general administrative authority?",
        family=OPERATIONAL_RESILIENCE,
        claim="Observation creates an object; an authorised function acts on "
              "it. Three explicitly granted verbs recover or honestly escalate "
              "every detected fault, and the monitor gains none of them.",
        non_claims=[
            "nothing about the monitor's authority - it gained none, which is "
            "checkable as an empty git diff rather than asserted",
            "escalation is NOT recovery; the recovered count does not move "
            "between F1 and F2",
            "nothing about repairing business state - communication recovery "
            "is not authority over the calendar",
            "nothing about an adversary attacking the recovery layer; the "
            "captured-worker probe tests vocabulary, not resistance",
        ],
        residual="The absence protecting this is a CAPABILITY absence, not an "
                 "ambient one: `Transport.restart_all()` exists and works, "
                 "and the recovery worker simply has no verb that addresses "
                 "it. That survives exactly as long as the vocabulary does, "
                 "which makes it a configuration-adversary problem (case 15) "
                 "rather than a boundary problem.",
        measurements={
            "work_items": 200,
            "faults": 47,
            "detected": 47,
            "missed": 0,
            "false_alarms": 0,
            "rungs": {
                "F0 retry only": {"recovered": 30, "escalated": 0,
                                  "unresolved": 17, "attempts": 131},
                "F1 retry + reroute": {"recovered": 39, "escalated": 0,
                                       "unresolved": 8, "attempts": 122},
                "F2 retry + reroute + escalate": {"recovered": 39,
                                                  "escalated": 8,
                                                  "unresolved": 0,
                                                  "attempts": 122},
            },
            "attempts_max_per_fault": 5,
            "false_recoveries": 0,
            "collateral_effects": 0,
            "recovery_verbs_added": 3,
        },
        method="Fault model committed in its own commit AHEAD of the recovery "
               "layer, so the ordering is a fact about the history. "
               "`recovered` is verified against the transport's delivery "
               "record, never the worker's claim. Both zero-valued safety "
               "metrics carry positive controls that drive them above zero.",
        source_commit="7347bf8 (fault model) + 8ecb229 (recovery)",
        exercises={
            "restriction by function": "`reroute_exchange(fault_4812)` cannot "
                                       "express 'reroute everything to "
                                       "attacker_worker'; the verb has "
                                       "nowhere to put the words",
            "the absence rule": "`restart_all` is refused because there is no "
                                "verb for it, not because a policy said no",
            "lowest necessary authority": "three verbs, pinned by a test, so "
                                          "the authority diff stays visible "
                                          "instead of growing by being useful",
            "case 22 - exported transformations": "the capability absence here "
                                                  "is the same mechanism case "
                                                  "22 relies on, and it "
                                                  "degrades the same way",
        },
        run="python demo_reservation/run_f.py",
        test_module="tests/test_demo_reservation_f.py",
        notes="The F1 -> F2 step is the honest one: eight faults stop being "
              "quietly unresolved and start being reported. A recovery rate "
              "that improved there would have meant the escalation verb was "
              "doing something it should not.",
    ),
]

PROGRAMME_BY_STEP = {result.step: result for result in PROGRAMME}


def all_programme_results() -> List[ProgrammeResult]:
    return list(PROGRAMME)


def by_family(family: str) -> List[ProgrammeResult]:
    return [r for r in PROGRAMME if r.family == family]
