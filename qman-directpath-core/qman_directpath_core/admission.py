"""Typed binding of one verified static request to one verified policy.

This module is the only portable constructor for a static dependency
``ClosureRequest``.  Roots are derived from the closed request selector and
limits are derived from the closed capability policy; neither can be supplied
as an independent caller argument.

The resulting value still is not a repository-current authorization.  Product
code must prove the request row and policy pointer current with independent
linearizable reads and must keep those bindings current through every side
effect.
"""

from __future__ import annotations

from dataclasses import dataclass

from .canonical import canonical_json_bytes, sha256_digest
from .closure import ClosureRequest
from .errors import require
from .policy import VerifiedCapabilityPolicy
from .request import VerifiedStaticRequestContext
from ._verified import FactoryVerified, require_factory_verified


@dataclass(frozen=True, slots=True, init=False)
class VerifiedStaticAdmissionContext(FactoryVerified):
    """Exact verified request/policy pair and its derived closure request."""

    request: VerifiedStaticRequestContext
    policy: VerifiedCapabilityPolicy
    closure_request: ClosureRequest
    context_digest: str

    def to_subject(self) -> dict[str, object]:
        return {
            "subjectType": "VERIFIED_STATIC_ADMISSION_CONTEXT",
            "schemaVersion": 1,
            "requestEntityDigest": self.request.entity_digest,
            "requestHash": self.request.request_hash,
            "requestVersion": self.request.request_version,
            "requestResourceVersion": self.request.resource_version,
            "policyCanonicalDigest": self.policy.canonical_digest,
            "policyHash": self.policy.policy_hash,
            "policyVersion": self.policy.policy_version,
            "closureRequestDigest": (self.closure_request.request_digest),
            "contextDigest": self.context_digest,
        }


def bind_static_request_policy(
    request: VerifiedStaticRequestContext,
    policy: VerifiedCapabilityPolicy,
) -> VerifiedStaticAdmissionContext:
    """Derive closure roots and limits only after an exact policy binding."""

    require_factory_verified(
        request,
        VerifiedStaticRequestContext,
        code="STATIC_ADMISSION_INPUT_INVALID",
        path="request",
        message="request must come from verify_static_request",
    )
    require_factory_verified(
        policy,
        VerifiedCapabilityPolicy,
        code="STATIC_ADMISSION_INPUT_INVALID",
        path="policy",
        message="policy must come from verify_capability_policy",
    )
    expected_binding = policy.request_policy_binding()
    require(
        canonical_json_bytes(request.policy_binding)
        == canonical_json_bytes(expected_binding),
        "REQUEST_POLICY_BINDING_MISMATCH",
        "request.policyBinding",
        "request policyBinding does not exactly identify the verified policy",
    )

    closure_request = ClosureRequest(
        request_provenance_digest=request.request_hash,
        policy_provenance_digest=policy.policy_hash,
        payload_device_uids=request.payload_device_uids,
        limits=policy.closure_limits,
    )
    subject = {
        "subjectType": "VERIFIED_STATIC_ADMISSION_CONTEXT",
        "schemaVersion": 1,
        "requestEntityDigest": request.entity_digest,
        "requestHash": request.request_hash,
        "requestVersion": request.request_version,
        "requestResourceVersion": request.resource_version,
        "policyCanonicalDigest": policy.canonical_digest,
        "policyHash": policy.policy_hash,
        "policyVersion": policy.policy_version,
        "closureRequestDigest": closure_request.request_digest,
        "contextDigest": None,
    }
    context_digest = sha256_digest(canonical_json_bytes(subject))
    return VerifiedStaticAdmissionContext._construct(
        request=request,
        policy=policy,
        closure_request=closure_request,
        context_digest=context_digest,
    )


__all__ = [
    "VerifiedStaticAdmissionContext",
    "bind_static_request_policy",
]
