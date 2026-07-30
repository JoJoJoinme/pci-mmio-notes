"""Stable fail-closed diagnostics for portable DirectPath core callers."""

from __future__ import annotations

from dataclasses import dataclass
from typing import NoReturn


@dataclass(frozen=True, slots=True)
class VerificationFailure:
    code: str
    path: str
    message: str


class DirectPathVerificationError(ValueError):
    """One closed trust or capability precondition failed."""

    def __init__(self, failure: VerificationFailure):
        self.failure = failure
        super().__init__(f"{failure.code} at {failure.path}: {failure.message}")

    @property
    def code(self) -> str:
        return self.failure.code

    @property
    def path(self) -> str:
        return self.failure.path


def fail(code: str, path: str, message: str) -> NoReturn:
    raise DirectPathVerificationError(
        VerificationFailure(code=code, path=path, message=message)
    )


def require(condition: bool, code: str, path: str, message: str) -> None:
    if not condition:
        fail(code, path, message)
