"""Side-effect-free verification for persisted static DirectPath requests.

This module verifies only the closed wire shape and the deterministic
derivations contained in one ``ENTITY-VM-DIRECTPATH-REQUEST`` document.  It
does not prove repository currentness, signature authenticity, idempotency
ownership, or that the mutation precondition won a compare-and-swap.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any

from .canonical import (
    CanonicalizationError,
    canonical_json_bytes,
    load_canonical_json,
    sha256_digest,
)
from .contracts import ContractSchemas
from .errors import fail, require
from ._verified import FactoryVerified


StaticRequestDocument = Mapping[str, Any] | bytes | bytearray | memoryview


def _freeze(value: Any) -> Any:
    if isinstance(value, Mapping):
        return MappingProxyType({key: _freeze(item) for key, item in value.items()})
    if isinstance(value, list):
        return tuple(_freeze(item) for item in value)
    return value


def _document(
    value: StaticRequestDocument,
) -> tuple[dict[str, Any], bytes]:
    path = "request"
    if isinstance(value, (bytes, bytearray, memoryview)):
        raw = bytes(value)
        try:
            loaded = load_canonical_json(raw)
        except CanonicalizationError as exc:
            fail("CANONICAL_JSON_INVALID", path, str(exc))
    elif isinstance(value, Mapping):
        try:
            raw = canonical_json_bytes(value)
            loaded = load_canonical_json(raw)
        except (
            CanonicalizationError,
            KeyError,
            RuntimeError,
            TypeError,
            ValueError,
        ) as exc:
            fail("CANONICAL_JSON_INVALID", path, str(exc))
    else:
        fail(
            "DOCUMENT_TYPE_INVALID",
            path,
            "expected canonical JSON bytes or a JSON object",
        )
    require(
        isinstance(loaded, dict),
        "DOCUMENT_TYPE_INVALID",
        path,
        "expected a JSON object",
    )
    return loaded, raw


def _require_exact_projection(
    outer: Any,
    canonical: Any,
    *,
    path: str,
    canonical_path: str,
) -> None:
    require(
        canonical_json_bytes(outer) == canonical_json_bytes(canonical),
        "REQUEST_PROJECTION_MISMATCH",
        path,
        f"must exactly equal {canonical_path}",
    )


def _verify_member_set(
    members: list[dict[str, Any]],
) -> tuple[str, ...]:
    order_keys = tuple(
        canonical_json_bytes(
            [
                member["requirementId"],
                member["guestSlot"],
                member["deviceUid"],
            ]
        )
        for member in members
    )
    require(
        order_keys == tuple(sorted(order_keys)),
        "REQUEST_STATIC_MEMBER_ORDER_INVALID",
        "request.canonicalRequest.selector.members",
        (
            "members must be ordered by ascending CANONICAL-JSON-V1 bytes "
            "of [requirementId,guestSlot,deviceUid]"
        ),
    )

    for field in ("requirementId", "guestSlot", "deviceUid"):
        encoded = tuple(canonical_json_bytes(member[field]) for member in members)
        require(
            len(encoded) == len(set(encoded)),
            "REQUEST_STATIC_MEMBER_DUPLICATE",
            "request.canonicalRequest.selector.members",
            f"duplicate {field} values are forbidden",
        )

    return tuple(
        sorted(
            (member["deviceUid"] for member in members),
            key=canonical_json_bytes,
        )
    )


def _verify_mutation_precondition(
    canonical_request: Mapping[str, Any],
) -> None:
    request_version = canonical_request["requestVersion"]
    precondition = canonical_request["mutationPrecondition"]
    expected_request_version = precondition["expectedExistingRequestVersionOrNull"]
    expected_resource_version = precondition["expectedExistingResourceVersionOrNull"]

    both_null = expected_request_version is None and expected_resource_version is None
    both_present = (
        expected_request_version is not None and expected_resource_version is not None
    )
    require(
        both_null or both_present,
        "REQUEST_MUTATION_PRECONDITION_INVALID",
        "request.canonicalRequest.mutationPrecondition",
        "the two expected-version fields must be null or present together",
    )
    if both_null:
        require(
            request_version == 1,
            "REQUEST_MUTATION_PRECONDITION_INVALID",
            "request.canonicalRequest.requestVersion",
            "a first creation with null preconditions must use requestVersion 1",
        )
        return

    require(
        expected_request_version + 1 == request_version,
        "REQUEST_MUTATION_PRECONDITION_INVALID",
        "request.canonicalRequest.requestVersion",
        (
            "an update requestVersion must equal "
            "expectedExistingRequestVersionOrNull + 1"
        ),
    )


@dataclass(frozen=True, slots=True, init=False)
class VerifiedStaticRequestContext(FactoryVerified):
    """Verifier-produced deterministic facts from one static request entity."""

    document: Mapping[str, Any]
    canonical_bytes: bytes
    entity_digest: str
    canonical_request: Mapping[str, Any]
    canonical_request_bytes: bytes
    request_hash: str
    policy_hash: str
    profile_hash: str
    payload_device_uids: tuple[str, ...]
    maximum_age_micros: int
    request_version: int
    resource_version: int
    host_id: str
    policy_binding: Mapping[str, Any]
    profile_binding: Mapping[str, Any]


def verify_static_request(
    schemas: ContractSchemas,
    document: StaticRequestDocument,
) -> VerifiedStaticRequestContext:
    """Validate and deterministically derive one static request context.

    Successful verification says nothing about repository currentness,
    signatures, authorization, or whether the declared CAS precondition was
    compared against a real current row.
    """

    request, raw = _document(document)
    schemas.validate("portable_entities", request, "request")

    require(
        request["requestType"] == "STATIC",
        "REQUEST_TYPE_UNSUPPORTED",
        "request.requestType",
        "only STATIC DirectPath requests are supported by this verifier",
    )
    canonical_request = request["canonicalRequest"]
    require(
        canonical_request["requestType"] == "STATIC",
        "REQUEST_TYPE_UNSUPPORTED",
        "request.canonicalRequest.requestType",
        "only STATIC DirectPath requests are supported by this verifier",
    )

    for field in (
        "vmId",
        "requestVersion",
        "requestType",
        "requiredGuestAbiClass",
        "lifecyclePolicy",
        "requestedBy",
    ):
        _require_exact_projection(
            request[field],
            canonical_request[field],
            path=f"request.{field}",
            canonical_path=f"request.canonicalRequest.{field}",
        )
    _require_exact_projection(
        request["createdAt"],
        canonical_request["issuedAt"],
        path="request.createdAt",
        canonical_path="request.canonicalRequest.issuedAt",
    )

    canonical_request_raw = canonical_json_bytes(canonical_request)
    request_hash = sha256_digest(canonical_request_raw)
    require(
        request["requestHash"] == request_hash,
        "REQUEST_HASH_MISMATCH",
        "request.requestHash",
        "does not equal SHA-256 of the exact canonicalRequest bytes",
    )

    members = canonical_request["selector"]["members"]
    payload_device_uids = _verify_member_set(members)
    host_id = canonical_request["hostAffinity"]["hostId"]
    for index, member in enumerate(members):
        require(
            member["enrolledHostId"] == host_id,
            "REQUEST_STATIC_HOST_AFFINITY_MISMATCH",
            (f"request.canonicalRequest.selector.members[{index}].enrolledHostId"),
            "must equal request.canonicalRequest.hostAffinity.hostId",
        )

    snapshot_constraint = canonical_request["snapshotConstraint"]
    if snapshot_constraint["mode"] == "PINNED_CURRENT_SNAPSHOT":
        require(
            snapshot_constraint["binding"]["hostId"] == host_id,
            "REQUEST_STATIC_HOST_AFFINITY_MISMATCH",
            "request.canonicalRequest.snapshotConstraint.binding.hostId",
            "must equal request.canonicalRequest.hostAffinity.hostId",
        )

    _verify_mutation_precondition(canonical_request)

    frozen = _freeze(request)
    frozen_canonical_request = frozen["canonicalRequest"]
    return VerifiedStaticRequestContext._construct(
        document=frozen,
        canonical_bytes=raw,
        entity_digest=sha256_digest(raw),
        canonical_request=frozen_canonical_request,
        canonical_request_bytes=canonical_request_raw,
        request_hash=request_hash,
        policy_hash=canonical_request["policyBinding"]["policyHash"],
        profile_hash=canonical_request["profileBinding"]["profileHash"],
        payload_device_uids=payload_device_uids,
        maximum_age_micros=snapshot_constraint["maximumAgeMicros"],
        request_version=request["requestVersion"],
        resource_version=request["resourceVersion"],
        host_id=host_id,
        policy_binding=frozen_canonical_request["policyBinding"],
        profile_binding=frozen_canonical_request["profileBinding"],
    )


__all__ = [
    "StaticRequestDocument",
    "VerifiedStaticRequestContext",
    "verify_static_request",
]
