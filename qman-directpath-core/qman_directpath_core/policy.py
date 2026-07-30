"""Closed capability-policy verification for deterministic admission inputs.

The verifier checks canonical bytes, the exact portable schema, the null-hash
projection and the declared validity interval.  It deliberately performs no
repository read and cannot prove that the supplied policy is current or
approved.  Product adapters must bind ``policy_hash`` to an independently read
current authority vector and must source ``verified_at`` from a trusted clock.
"""

from __future__ import annotations

import copy
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime, timezone
from types import MappingProxyType
from typing import Any

from .canonical import (
    CanonicalizationError,
    canonical_json_bytes,
    load_canonical_json,
    sha256_digest,
)
from .closure import ClosureLimits
from .contracts import ContractSchemas
from .errors import fail, require
from ._verified import FactoryVerified


JsonDocument = Mapping[str, Any] | bytes | bytearray | memoryview
CAPABILITY_POLICY_SCHEMA_REF = "contracts/directpath-capability-policy.schema.json"


def _deep_freeze(value: Any) -> Any:
    if isinstance(value, Mapping):
        return MappingProxyType(
            {key: _deep_freeze(item) for key, item in value.items()}
        )
    if isinstance(value, list):
        return tuple(_deep_freeze(item) for item in value)
    return value


def _document(value: JsonDocument) -> tuple[dict[str, Any], bytes]:
    if isinstance(value, (bytes, bytearray, memoryview)):
        raw = bytes(value)
        try:
            loaded = load_canonical_json(raw)
        except CanonicalizationError as exc:
            fail(
                "CANONICAL_JSON_INVALID",
                "policy",
                str(exc),
            )
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
            fail(
                "CANONICAL_JSON_INVALID",
                "policy",
                str(exc),
            )
    else:
        fail(
            "DOCUMENT_TYPE_INVALID",
            "policy",
            "expected canonical JSON bytes or a JSON object",
        )
    require(
        isinstance(loaded, dict),
        "DOCUMENT_TYPE_INVALID",
        "policy",
        "expected a JSON object",
    )
    return loaded, raw


def _timestamp(value: str, path: str) -> datetime:
    try:
        parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.%fZ")
    except (TypeError, ValueError) as exc:
        fail("TIME_INVALID", path, f"invalid contract timestamp: {exc}")
    return parsed.replace(tzinfo=timezone.utc)


def _utc(value: datetime, path: str) -> datetime:
    require(
        isinstance(value, datetime)
        and value.tzinfo is not None
        and value.utcoffset() is not None,
        "TIME_INVALID",
        path,
        "a timezone-aware datetime is required",
    )
    return value.astimezone(timezone.utc)


@dataclass(frozen=True, slots=True, init=False)
class VerifiedCapabilityPolicy(FactoryVerified):
    """Immutable, schema/hash/time-verified policy document."""

    document: Mapping[str, Any]
    canonical_bytes: bytes
    canonical_digest: str
    capability_policy_schema_digest: str
    policy_id: str
    policy_version: int
    policy_hash: str
    admission_mode: str
    supported_catalog_digest: str
    catalog_sequence: int
    trust_key_ring_sequence: int
    qualification_case_matrix_hash: str
    source_compatibility_profile_policy_digest: str
    closure_limits: ClosureLimits
    effective_at: datetime
    expires_at: datetime
    verified_at: datetime

    def request_policy_binding(self) -> dict[str, object]:
        """Return the exact projection required inside a VM request."""

        return {
            "policyId": self.policy_id,
            "policyVersion": self.policy_version,
            "policyHash": self.policy_hash,
            "admissionMode": self.admission_mode,
            "supportedCatalogDigest": self.supported_catalog_digest,
            "catalogSequence": self.catalog_sequence,
            "trustKeyRingSequence": self.trust_key_ring_sequence,
            "qualificationCaseMatrixHash": (self.qualification_case_matrix_hash),
        }


def verify_capability_policy(
    schemas: ContractSchemas,
    value: JsonDocument,
    *,
    verified_at: datetime,
) -> VerifiedCapabilityPolicy:
    """Verify one closed policy without claiming repository currentness."""

    require(
        isinstance(schemas, ContractSchemas),
        "CAPABILITY_POLICY_INPUT_INVALID",
        "schemas",
        "expected ContractSchemas",
    )
    checked_at = _utc(verified_at, "verified_at")
    document, raw = _document(value)
    schemas.validate("capability_policy", document, "policy")

    projection = copy.deepcopy(document)
    projection["policyHash"] = None
    expected_hash = sha256_digest(canonical_json_bytes(projection))
    require(
        document["policyHash"] == expected_hash,
        "CAPABILITY_POLICY_HASH_INVALID",
        "policy.policyHash",
        "policyHash does not match the null-hash canonical projection",
    )

    effective_at = _timestamp(document["effectiveAt"], "policy.effectiveAt")
    expires_at = _timestamp(document["expiresAt"], "policy.expiresAt")
    require(
        effective_at < expires_at,
        "CAPABILITY_POLICY_TIME_INVALID",
        "policy.expiresAt",
        "effectiveAt must be strictly before expiresAt",
    )
    require(
        effective_at <= checked_at,
        "CAPABILITY_POLICY_NOT_YET_EFFECTIVE",
        "policy.effectiveAt",
        "policy is not effective at verified_at",
    )
    require(
        checked_at < expires_at,
        "CAPABILITY_POLICY_EXPIRED",
        "policy.expiresAt",
        "policy is expired at verified_at",
    )

    closure = document["dependencyClosure"]
    limits = ClosureLimits(
        max_devices=closure["maxDevices"],
        max_edges=closure["maxEdges"],
    )
    return VerifiedCapabilityPolicy._construct(
        document=_deep_freeze(document),
        canonical_bytes=raw,
        canonical_digest=sha256_digest(raw),
        capability_policy_schema_digest=schemas.digest_for_ref(
            CAPABILITY_POLICY_SCHEMA_REF,
            path="policy.capabilityPolicySchemaDigest",
        ),
        policy_id=document["policyId"],
        policy_version=document["policyVersion"],
        policy_hash=document["policyHash"],
        admission_mode=document["admissionMode"],
        supported_catalog_digest=document["supportedCatalogDigest"],
        catalog_sequence=document["catalogSequence"],
        trust_key_ring_sequence=document["trustKeyRingSequence"],
        qualification_case_matrix_hash=(document["qualificationCaseMatrixHash"]),
        source_compatibility_profile_policy_digest=(
            document["sourceCompatibilityProfilePolicyDigest"]
        ),
        closure_limits=limits,
        effective_at=effective_at,
        expires_at=expires_at,
        verified_at=checked_at,
    )


__all__ = [
    "CAPABILITY_POLICY_SCHEMA_REF",
    "VerifiedCapabilityPolicy",
    "verify_capability_policy",
]
