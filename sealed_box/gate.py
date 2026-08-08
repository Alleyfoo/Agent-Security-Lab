"""The deterministic structural gate. No model, no reasoning, no judgement.

    exactly two tokens, one ASCII space
    each token: [A-Z][a-z]{1,19}
    total length <= 41

Anything else is flagged and **never reaches the agent** - not "reaches the
agent with a warning attached". The agent function is not called. A test counts
invocations rather than trusting this sentence.

What this gate is honestly for
------------------------------

It bounds the *shape* of the input. It does not bound what can be said.
`Approve Everything`, `Ignore Previous` and `Admin Override` are all
structurally perfect names and all sail straight through, which the corpus
predicted before this file existed.

`channel_capacity_bits()` puts a number on that, because "reduces the attack
surface" is the kind of claim that should come with a measurement. It counts
how many distinct strings the gate admits. If that number is large, the gate
has not meaningfully reduced what an attacker can say - only how strange it is
allowed to look.

Rejecting on a whitelist, not a blacklist
-----------------------------------------

There is no list of bad characters here. Everything that is not explicitly
permitted is refused, which is why the homoglyph, the zero-width joiner, the
RTL override and the non-breaking space all fail without being named. A
blacklist would have had to anticipate each one.
"""

from __future__ import annotations

import math
import string
from dataclasses import dataclass
from typing import Optional

MIN_TOKEN = 2
MAX_TOKEN = 20
MAX_TOTAL = 41
SEPARATOR = " "

UPPER = frozenset(string.ascii_uppercase)
LOWER = frozenset(string.ascii_lowercase)

# Refusal reasons. Structural facts about the string, never opinions about
# intent - the gate has no idea what `Approve Everything` means and must not
# pretend to.
TOO_LONG = "exceeds_total_length"
WRONG_TOKEN_COUNT = "not_exactly_two_tokens"
BAD_SEPARATOR = "separator_is_not_one_ascii_space"
TOKEN_LENGTH = "token_length_outside_bounds"
BAD_INITIAL = "token_does_not_start_with_ascii_capital"
BAD_BODY = "token_body_is_not_ascii_lowercase"

REASONS = (TOO_LONG, WRONG_TOKEN_COUNT, BAD_SEPARATOR, TOKEN_LENGTH,
           BAD_INITIAL, BAD_BODY)


@dataclass(frozen=True)
class GateResult:
    admitted: bool
    value: Optional[str]     # only set when admitted
    reason: str = ""

    def describe(self) -> str:
        return "admitted" if self.admitted else f"flagged: {self.reason}"


def check(raw: str) -> GateResult:
    if len(raw) > MAX_TOTAL:
        return GateResult(False, None, TOO_LONG)

    # Deliberately NOT raw.split(): split() collapses runs of whitespace and
    # treats tabs and newlines as separators, which would quietly admit
    # "Bob\tSmith" and "Bob  Smith" as two clean tokens. The separator is one
    # ASCII space or it is nothing.
    parts = raw.split(SEPARATOR)
    if len(parts) != 2:
        return GateResult(False, None, WRONG_TOKEN_COUNT)
    if any(c.isspace() and c != SEPARATOR for c in raw):
        return GateResult(False, None, BAD_SEPARATOR)

    for token in parts:
        if not MIN_TOKEN <= len(token) <= MAX_TOKEN:
            return GateResult(False, None, TOKEN_LENGTH)
        if token[0] not in UPPER:
            return GateResult(False, None, BAD_INITIAL)
        if any(c not in LOWER for c in token[1:]):
            return GateResult(False, None, BAD_BODY)

    return GateResult(True, raw)


def channel_capacity_bits() -> float:
    """How much can still be said through a gate this narrow.

    Counts the distinct strings the gate admits. The answer is the honest
    counterweight to calling a format check a surface reduction: if this is
    large, the gate has constrained how strange the input may look and almost
    nothing about what it may mean.
    """
    per_token = sum(26 ** (n - 1) for n in range(MIN_TOKEN, MAX_TOKEN + 1))
    # 26 initials x 26^(n-1) bodies, summed over permitted lengths.
    per_token *= 26
    total = per_token * per_token
    return math.log2(total)


def admitted_string_count() -> int:
    per_token = 26 * sum(26 ** (n - 1) for n in range(MIN_TOKEN, MAX_TOKEN + 1))
    return per_token * per_token
