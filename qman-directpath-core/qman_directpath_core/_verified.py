"""Internal construction support for verifier-produced value objects.

Python objects are not a process security boundary.  This marker only prevents
ordinary callers from accidentally constructing or ``dataclasses.replace``-ing
objects whose class name promises that a verifier has run.  Product authority
still comes from signed inputs, linearizable repository reads, leases, and CAS.
"""

from __future__ import annotations

from dataclasses import fields
from typing import Any, TypeVar

from .errors import fail


_FACTORY_MARKER = object()
_VerifiedT = TypeVar("_VerifiedT", bound="FactoryVerified")


class FactoryVerified:
    """Mixin for immutable values that only module verifiers may construct."""

    __slots__ = ("_factory_marker",)

    def __new__(cls, *_args: Any, **_kwargs: Any) -> "FactoryVerified":
        raise TypeError(f"{cls.__name__} has no public constructor; use its verifier")

    @classmethod
    def _construct(cls: type[_VerifiedT], **values: Any) -> _VerifiedT:
        expected = {field.name for field in fields(cls)}
        actual = set(values)
        if actual != expected:
            missing = sorted(expected - actual)
            extra = sorted(actual - expected)
            raise TypeError(
                f"{cls.__name__} verifier construction mismatch: "
                f"missing={missing!r}, extra={extra!r}"
            )
        instance = object.__new__(cls)
        for name, value in values.items():
            object.__setattr__(instance, name, value)
        object.__setattr__(instance, "_factory_marker", _FACTORY_MARKER)
        post_init = getattr(instance, "__post_init__", None)
        if post_init is not None:
            post_init()
        return instance

    def _factory_verified(self) -> bool:
        return getattr(self, "_factory_marker", None) is _FACTORY_MARKER


def require_factory_verified(
    value: object,
    expected_type: type[_VerifiedT],
    *,
    code: str,
    path: str,
    message: str,
) -> _VerifiedT:
    """Require both the expected type and its verifier construction marker."""

    if not isinstance(value, expected_type) or not value._factory_verified():
        fail(code, path, message)
    return value


__all__ = ["FactoryVerified", "require_factory_verified"]
