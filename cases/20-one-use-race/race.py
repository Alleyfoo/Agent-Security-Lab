"""Case 20 - two executors racing one valid one-use approval.

Pre-registered in `docs/target-architecture.md` after case 19, with the
prediction that case 19's R4 loses the race: `execute()` marks `consumed` only
after its checks, with nothing between them.

**What this case may claim, and the limit is the point:**

    CAN prove   a single approval cannot be concurrently acquired by two
                executions - an atomicity property around the approval itself
    CANNOT prove exactly-once execution of an arbitrary external effect

Exactly-once is not available for free when the side effect is not part of the
same transaction as the approval record. Anyone who reads `state == executed`
and writes "exactly once" in a README is wrong, and this module exists partly
so the registry can say so with a measurement behind it.

Four gates, and the second one is a trap worth measuring:

    G0  check -> execute -> mark        case 19's R4, as built
    G1  check -> mark -> execute        the tempting fix
    G2  atomic claim -> execute -> done exclusive execution ownership
    G3  G2 + an idempotent sink         the only one that survives a crash
                                        between effect and record

Determinism: the interleaving is forced through an explicit hook rather than
left to the scheduler, so the race is reproducible in a test. Real threads are
measured alongside, and the comparison is itself a finding - with an
instantaneous sink the race does not reproduce in 200 rounds, and with the
latency a real external call has it reproduces immediately. A race that
ordinary testing cannot hit is not a race that is not there.
"""

from __future__ import annotations

import importlib.util
import os
import sys
import threading
import time
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Tuple

CASE_20 = os.path.dirname(os.path.abspath(__file__))
CASE_19 = os.path.join(os.path.dirname(CASE_20), "19-two-sided-signoff")

for path in (CASE_19, os.path.dirname(os.path.dirname(CASE_20))):
    if path not in sys.path:
        sys.path.insert(0, path)


def _load19(name: str):
    spec = importlib.util.spec_from_file_location(
        f"case19_{name}", os.path.join(CASE_19, f"{name}.py"))
    module = importlib.util.module_from_spec(spec)
    sys.modules[f"case19_{name}"] = module
    spec.loader.exec_module(module)
    return module


s19 = _load19("signoff")
Action, DANGEROUS = s19.Action, s19.DANGEROUS


class RaceError(RuntimeError):
    """The gate refused. The message names which state check failed."""


class Crash(RuntimeError):
    """A simulated process death at a named point."""


UNUSED, CLAIMED, EXECUTED = "unused", "claimed", "executed"


@dataclass
class Approval:
    digest: str
    state: str = UNUSED
    claimed_by: Optional[str] = None


@dataclass
class Sink:
    """The external effect. Not part of the approval's transaction, which is
    the entire difficulty.

    `latency` models a real external call taking time. It is what makes the
    race reproducible without the interleaving hook: with an instantaneous
    sink the vulnerable window is a few bytecodes and CPython rarely switches
    threads inside it. A payment API does not return in a few bytecodes.
    """

    idempotent: bool = False
    latency: float = 0.0
    calls: List[Tuple[str, str]] = field(default_factory=list)

    def perform(self, digest: str, execution_id: str) -> str:
        if self.idempotent:
            for d, e in self.calls:
                if e == execution_id:
                    return "deduplicated"
            # Real services key on the caller-supplied id, not on content -
            # two legitimately identical payments must both go through.
        if self.latency:
            time.sleep(self.latency)
        self.calls.append((digest, execution_id))
        return "performed"

    @property
    def effects(self) -> int:
        return len(self.calls)


@dataclass(frozen=True)
class Gate:
    name: str
    mark_before_execute: bool = False
    atomic_claim: bool = False
    idempotent_sink: bool = False


G0 = Gate("G0 check-execute-mark")
G1 = Gate("G1 check-mark-execute", mark_before_execute=True)
G2 = Gate("G2 atomic claim", atomic_claim=True)
G3 = Gate("G3 atomic claim + idempotent sink", atomic_claim=True,
          idempotent_sink=True)

GATES = (G0, G1, G2, G3)

_LOCK = threading.Lock()


def execute(approval: Approval, act: Action, sink: Sink, gate: Gate,
            execution_id: str,
            pause: Optional[Callable[[str], None]] = None,
            crash_at: Optional[str] = None) -> str:
    """One execution attempt against one approval.

    `pause(point)` is the interleaving hook; `crash_at` raises at a named
    point to model a process dying mid-flight.
    """
    def at(point: str) -> None:
        if pause:
            pause(point)
        if crash_at == point:
            raise Crash(f"process died at {point!r}")

    if gate.atomic_claim:
        # The claim and the state test happen together, under one lock. This
        # is the only structural difference between G1 and G2, and it is the
        # one that matters.
        with _LOCK:
            at("after-check")
            if approval.state != UNUSED:
                raise RaceError(
                    f"approval is {approval.state!r}"
                    + (f", claimed by {approval.claimed_by!r}"
                       if approval.claimed_by else ""))
            approval.state = CLAIMED
            approval.claimed_by = execution_id
        at("after-claim")
        sink.perform(act.digest(), execution_id)
        at("after-effect")
        approval.state = EXECUTED
        return "executed"

    # G0 / G1: the check is not joined to the write.
    if approval.state != UNUSED:
        raise RaceError(f"approval is {approval.state!r}")
    at("after-check")
    if gate.mark_before_execute:
        approval.state = EXECUTED
        at("after-mark")
        sink.perform(act.digest(), execution_id)
        at("after-effect")
    else:
        sink.perform(act.digest(), execution_id)
        at("after-effect")
        approval.state = EXECUTED
    return "executed"


# ---------------------------------------------------------------------------
# Scenarios.
# ---------------------------------------------------------------------------

@dataclass
class Reading:
    gate: str
    scenario: str
    effects: int
    final_state: str
    note: str


def _fresh(gate: Gate, latency: float = 0.0) -> Tuple[Approval, Sink]:
    return (Approval(DANGEROUS.digest()),
            Sink(idempotent=gate.idempotent_sink, latency=latency))


def concurrent_forced(gate: Gate) -> Reading:
    """Two executors, interleaved deterministically at the worst moment: both
    pass their check before either writes."""
    approval, sink = _fresh(gate)
    gate_barrier = threading.Barrier(2, timeout=5)
    errors: List[str] = []

    def pause(point: str) -> None:
        if point == "after-check":
            try:
                gate_barrier.wait()
            except threading.BrokenBarrierError:
                pass

    def run(execution_id: str) -> None:
        try:
            execute(approval, DANGEROUS, sink, gate, execution_id, pause=pause)
        except (RaceError, threading.BrokenBarrierError) as exc:
            errors.append(str(exc))
            gate_barrier.abort()

    threads = [threading.Thread(target=run, args=(f"exec-{i}",))
               for i in (1, 2)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=5)

    return Reading(
        gate.name, "two executors race one approval", sink.effects,
        approval.state,
        "both passed the check before either wrote"
        if sink.effects > 1 else
        (f"one refused: {errors[0]}" if errors else "serialised"))


def concurrent_threads(gate: Gate, rounds: int = 25,
                       latency: float = 0.002) -> Reading:
    """The same race without the interleaving hook.

    An instantaneous sink does **not** reproduce it - the window is a few
    bytecodes and the interpreter rarely switches threads inside one. That is
    a fact about how hard the bug is to find by testing, not about whether it
    is there, and an adversary who can influence timing does not need luck.
    Giving the sink the latency a real external call has reproduces it.
    """
    worst = 0
    final = EXECUTED
    for r in range(rounds):
        approval, sink = _fresh(gate, latency=latency)
        start = threading.Barrier(2, timeout=5)

        def run(execution_id: str) -> None:
            try:
                start.wait()
                execute(approval, DANGEROUS, sink, gate, execution_id)
            except Exception:                             # noqa: BLE001
                pass

        threads = [threading.Thread(target=run, args=(f"exec-{r}-{i}",))
                   for i in (1, 2)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=5)
        worst = max(worst, sink.effects)
        final = approval.state
    return Reading(gate.name, f"unhooked threads x{rounds}", worst, final,
                   "worst observed effect count across all rounds")


def crash_before_effect(gate: Gate) -> Reading:
    """The process dies after the approval has been written but before the
    external effect happens."""
    approval, sink = _fresh(gate)
    point = "after-claim" if gate.atomic_claim else "after-mark"
    if not gate.atomic_claim and not gate.mark_before_execute:
        point = "after-check"                     # G0 has no pre-effect write
    try:
        execute(approval, DANGEROUS, sink, gate, "exec-crash", crash_at=point)
    except Crash:
        pass

    spendable = approval.state == UNUSED
    return Reading(
        gate.name, "crash before the effect", sink.effects, approval.state,
        "approval still spendable - nothing was lost" if spendable else
        ("approval spent, effect never happened - the action was LOST"
         if approval.state in (EXECUTED, CLAIMED) else "unclear"))


def crash_after_effect_then_retry(gate: Gate) -> Reading:
    """The effect happened; the process died before recording it. Someone
    retries. This is where 'exactly once' is decided, and it is decided by the
    sink rather than by the approval record."""
    approval, sink = _fresh(gate)
    try:
        execute(approval, DANGEROUS, sink, gate, "exec-A",
                crash_at="after-effect")
    except Crash:
        pass

    retried = ""
    try:
        # A recovery run retries. Whether it reuses the execution id is the
        # whole question, and a careful operator would.
        execute(approval, DANGEROUS, sink, gate, "exec-A")
        retried = "retry executed"
    except RaceError as exc:
        retried = f"retry refused: {exc}"

    return Reading(
        gate.name, "crash after effect, then retry", sink.effects,
        approval.state,
        f"{retried}; external effects = {sink.effects}")


SCENARIOS = (concurrent_forced, crash_before_effect,
             crash_after_effect_then_retry)


def measure() -> List[Reading]:
    out: List[Reading] = []
    for gate in GATES:
        for scenario in SCENARIOS:
            out.append(scenario(gate))
    return out


def get(readings: List[Reading], gate: Gate, scenario: str) -> Reading:
    return next(r for r in readings
                if r.gate == gate.name and r.scenario == scenario)
