"""Runner-owned receipt ledger and its read-only view.

A receipt is the trusted runner's record of what a stage *actually* did — the
keys it really read and wrote, and whether its contract held. It is the
evidence `ValidationAgent` audits.

The audited component must not be able to edit the evidence it is audited
against. Handing the validator the runner's own ``list`` gave it exactly that
power: a hostile validator could delete failing receipts through the object it
was legitimately given, with no reach-around and no privilege escalation.

So the ledger keeps two halves apart:

``ReceiptLedger``  append-only, held by the runner.
``ReceiptView``    read-only handle, given to agents. Yields deep copies and
                   raises :class:`ReceiptIntegrityError` on every mutation.

Scope, stated plainly: this constrains code that goes through the handle. It is
not a process-isolation boundary — same-process code can still reach the
underlying list through private attributes. What it changes is the *level of
adversary required*: editing the evidence now demands full in-process
compromise (ladder Level 2) rather than merely a hostile agent implementation
(Level 1). See cases/00-receipt-handle/README.md.
"""

from __future__ import annotations

from copy import deepcopy
from typing import Any, Dict, Iterator, List


class ReceiptIntegrityError(RuntimeError):
    """Raised when something tries to mutate the runner's receipt record."""


def _deny(operation: str) -> "ReceiptIntegrityError":
    return ReceiptIntegrityError(
        f"{operation} denied: the receipt record is runner-owned evidence and "
        "is read-only for agents. The audited component may not modify the "
        "evidence it is audited against."
    )


class ReceiptView:
    """Read-only, deep-copying handle on a :class:`ReceiptLedger`.

    Supports the operations an auditor legitimately needs — iteration, ``len``,
    truthiness, indexing — and denies every mutation with a specific reason.
    """

    __slots__ = ("_ledger",)

    def __init__(self, ledger: "ReceiptLedger") -> None:
        self._ledger = ledger

    # -- read -----------------------------------------------------------
    def __iter__(self) -> Iterator[Dict[str, Any]]:
        # Deep copy per item: without this an auditor could edit a receipt in
        # place while iterating.
        for receipt in self._ledger._receipts:
            yield deepcopy(receipt)

    def __len__(self) -> int:
        return len(self._ledger._receipts)

    def __bool__(self) -> bool:
        return bool(self._ledger._receipts)

    def __getitem__(self, index: Any) -> Any:
        return deepcopy(self._ledger._receipts[index])

    def snapshot(self) -> List[Dict[str, Any]]:
        return self._ledger.snapshot()

    def __repr__(self) -> str:  # pragma: no cover - diagnostic only
        return f"<ReceiptView {len(self)} receipts, read-only>"

    # -- denied ---------------------------------------------------------
    # Spelled out rather than trapped via __getattr__ so each failure names the
    # operation that was attempted. ``receipts[:] = [...]`` — the scrub used in
    # the case-00 attack — lands on __setitem__.
    def __setitem__(self, *_: Any) -> None:
        raise _deny("receipt assignment")

    def __delitem__(self, *_: Any) -> None:
        raise _deny("receipt deletion")

    def __iadd__(self, *_: Any) -> None:
        raise _deny("in-place extension of the receipt record")

    def append(self, *_: Any) -> None:
        raise _deny("append to the receipt record")

    def extend(self, *_: Any) -> None:
        raise _deny("extend of the receipt record")

    def insert(self, *_: Any) -> None:
        raise _deny("insert into the receipt record")

    def pop(self, *_: Any) -> None:
        raise _deny("pop from the receipt record")

    def remove(self, *_: Any) -> None:
        raise _deny("remove from the receipt record")

    def clear(self) -> None:
        raise _deny("clear of the receipt record")

    def sort(self, *_: Any, **__: Any) -> None:
        raise _deny("reordering of the receipt record")

    def reverse(self) -> None:
        raise _deny("reordering of the receipt record")


class ReceiptLedger:
    """Append-only record of trusted-runner receipts.

    Append-only *by API*, in the same sense as ``EventLog`` — there is no
    update or delete operation. It is not tamper-evident: no hash chain binds
    the entries. That arrives in Phase 7.
    """

    __slots__ = ("_receipts",)

    def __init__(self) -> None:
        self._receipts: List[Dict[str, Any]] = []

    def append(self, receipt: Dict[str, Any]) -> Dict[str, Any]:
        """Store a deep copy, so a later edit to the caller's dict cannot
        retroactively change the record."""
        if not isinstance(receipt, dict):
            raise TypeError("receipt must be a dict")
        stored = deepcopy(receipt)
        self._receipts.append(stored)
        return deepcopy(stored)

    def snapshot(self) -> List[Dict[str, Any]]:
        return deepcopy(self._receipts)

    def view(self) -> ReceiptView:
        return ReceiptView(self)

    def __len__(self) -> int:
        return len(self._receipts)

    def __iter__(self) -> Iterator[Dict[str, Any]]:
        for receipt in self._receipts:
            yield deepcopy(receipt)
