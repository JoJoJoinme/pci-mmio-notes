"""Structural currentness binding for one verified HostSnapshot.

This module verifies canonical anchor and nonce-freshness bytes supplied by an
integration adapter.  It does not fetch those bytes, generate the nonce,
advance the external authority, prove a linearizable CAS, or publish the
inventory.  The result is therefore a component-only consumption gate and
never product authorization.
"""

from __future__ import annotations

import copy
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime
from types import MappingProxyType
from typing import Any, Final

from .canonical import canonical_json_bytes, sha256_digest
from .contracts import ContractSchemas
from .errors import require
from .inventory import VerifiedInventoryContext
from .trust import (
    JsonDocument,
    VerifiedTrustContext,
    _document,
    _projection_digest,
    _require_digest,
    _timestamp,
    _utc_now,
    _validate_freshness,
    _verify_root_quorum,
)
from ._verified import FactoryVerified, require_factory_verified


HOST_SNAPSHOT_ANCHOR_AUTHORITY_BOUNDARY: Final = (
    "COMPONENT_EXTERNAL_BYTES_VERIFICATION_ONLY"
)
HOST_SNAPSHOT_ANCHOR_PRODUCT_AUTHORIZED: Final = False
HOST_SNAPSHOT_ANCHOR_SCHEMA_REF: Final = (
    "contracts/directpath-host-snapshot-rollback-anchor.schema.json"
)
HOST_SNAPSHOT_ANCHOR_CANDIDATE_DOMAIN: Final = (
    b"QMAN-DIRECTPATH/HOST-SNAPSHOT-ANCHOR-CANDIDATE/V1\x00"
)
HOST_SNAPSHOT_ANCHOR_PREPARE_DOMAIN: Final = (
    b"QMAN-DIRECTPATH/HOST-SNAPSHOT-ANCHOR-PREPARE/V1\x00"
)
HOST_SNAPSHOT_ANCHOR_RECEIPT_DOMAIN: Final = (
    b"QMAN-DIRECTPATH/HOST-SNAPSHOT-ROLLBACK-ANCHOR-RECEIPT/V1\x00"
)
HOST_SNAPSHOT_ANCHOR_BINDING_DOMAIN: Final = (
    b"QMAN-DIRECTPATH/HOST-SNAPSHOT-ANCHOR-BINDING/V1\x00"
)

_CANDIDATE_FIELDS: Final = (
    "hostId",
    "kernelBootId",
    "hostEpoch",
    "agentIdentity",
    "agentGeneration",
    "acceptedSnapshotEpoch",
    "acceptedSnapshotContentHash",
    "acceptedHostAuthorityResourceVersion",
    "anchorVersion",
    "resourceVersion",
    "previousAnchorDigestOrNull",
    "authorityId",
    "casPrecondition",
)


def _deep_freeze(value: Any) -> Any:
    if isinstance(value, Mapping):
        return MappingProxyType(
            {key: _deep_freeze(item) for key, item in value.items()}
        )
    if isinstance(value, list):
        return tuple(_deep_freeze(item) for item in value)
    return value


@dataclass(frozen=True, slots=True, init=False)
class VerifiedHostSnapshotAnchorBinding(FactoryVerified):
    """Factory-only binding of a verified inventory to external anchor bytes."""

    trust: VerifiedTrustContext
    inventory: VerifiedInventoryContext
    authority_boundary: str
    product_authorized: bool
    external_anchor: Mapping[str, Any]
    external_anchor_canonical_bytes: bytes
    freshness_envelope: Mapping[str, Any]
    freshness_envelope_canonical_bytes: bytes
    expected_anchor_path: str
    verifier_nonce: str
    host_id: str
    kernel_boot_id: str
    host_epoch: int
    agent_identity: str
    agent_generation: int
    accepted_snapshot_epoch: int
    accepted_snapshot_content_hash: str
    accepted_host_authority_resource_version: int
    anchor_authority_id: str
    anchor_digest: str
    anchor_version: int
    anchor_resource_version: int
    anchor_receipt_digest: str
    anchor_schema_digest: str
    freshness_receipt_digest: str
    freshness_observed_at: datetime
    freshness_expires_at: datetime
    verified_at: datetime
    binding_digest: str
    _schemas: ContractSchemas = field(repr=False, compare=False)


def _validate_prepare_receipt(
    anchor: Mapping[str, Any],
    root_set: Mapping[str, Any],
    *,
    path: str,
) -> None:
    receipt = anchor["prepareReceipt"]
    bindings = {
        "hostId": anchor["hostId"],
        "candidateProjectionDigest": anchor["candidateProjectionDigest"],
        "predecessorAnchorDigestOrNull": anchor[
            "previousAnchorDigestOrNull"
        ],
        "authorityId": anchor["authorityId"],
        "trustRootDigest": root_set["rootSetDigest"],
    }
    for name, expected in bindings.items():
        require(
            receipt.get(name) == expected,
            "HOST_SNAPSHOT_ANCHOR_PREPARE_BINDING_MISMATCH",
            f"{path}.prepareReceipt.{name}",
            f"prepare receipt does not bind {expected!r}",
        )
    prepared_at = _timestamp(
        receipt["preparedAt"],
        f"{path}.prepareReceipt.preparedAt",
    )
    expires_at = _timestamp(
        receipt["expiresAt"],
        f"{path}.prepareReceipt.expiresAt",
    )
    require(
        prepared_at < expires_at,
        "HOST_SNAPSHOT_ANCHOR_PREPARE_TIME_INVALID",
        f"{path}.prepareReceipt",
        "preparedAt must precede expiresAt",
    )
    require(
        prepared_at
        <= _timestamp(anchor["updatedAt"], f"{path}.updatedAt"),
        "HOST_SNAPSHOT_ANCHOR_PREPARE_TIME_INVALID",
        f"{path}.updatedAt",
        "the committed anchor update cannot predate its reservation",
    )
    digest, _ = _projection_digest(
        receipt,
        null_fields=("receiptDigest",),
        empty_array_fields=("rootSignatures",),
        path=f"{path}.prepareReceipt.digestProjection",
    )
    _require_digest(
        receipt["receiptDigest"],
        digest,
        f"{path}.prepareReceipt.receiptDigest",
        "HOST_SNAPSHOT_ANCHOR_PREPARE_DIGEST_INVALID",
    )
    _verify_root_quorum(
        root_set,
        receipt["rootSignatures"],
        digest_field="receiptDigest",
        digest=digest,
        domain=HOST_SNAPSHOT_ANCHOR_PREPARE_DOMAIN,
        path=f"{path}.prepareReceipt.rootSignatures",
        require_algorithm=True,
        not_before=prepared_at,
        not_after=min(
            expires_at,
            _timestamp(anchor["updatedAt"], f"{path}.updatedAt"),
        ),
    )


def _validate_final_receipt(
    anchor: Mapping[str, Any],
    root_set: Mapping[str, Any],
    *,
    path: str,
) -> None:
    receipt = anchor["receipt"]
    require(
        isinstance(receipt, Mapping),
        "HOST_SNAPSHOT_ANCHOR_RECEIPT_INVALID",
        f"{path}.receipt",
        "a committed anchor requires its final receipt",
    )
    bindings = {
        "subjectAnchorDigest": anchor["anchorDigest"],
        "hostId": anchor["hostId"],
        "kernelBootId": anchor["kernelBootId"],
        "hostEpoch": anchor["hostEpoch"],
        "agentIdentity": anchor["agentIdentity"],
        "agentGeneration": anchor["agentGeneration"],
        "acceptedSnapshotEpoch": anchor["acceptedSnapshotEpoch"],
        "acceptedSnapshotContentHash": anchor[
            "acceptedSnapshotContentHash"
        ],
        "acceptedHostAuthorityResourceVersion": anchor[
            "acceptedHostAuthorityResourceVersion"
        ],
        "anchorVersion": anchor["anchorVersion"],
        "resourceVersion": anchor["resourceVersion"],
        "authorityId": anchor["authorityId"],
        "trustRootDigest": root_set["rootSetDigest"],
    }
    for name, expected in bindings.items():
        require(
            receipt.get(name) == expected,
            "HOST_SNAPSHOT_ANCHOR_RECEIPT_BINDING_MISMATCH",
            f"{path}.receipt.{name}",
            f"final receipt does not bind {expected!r}",
        )
    issued_at = _timestamp(receipt["issuedAt"], f"{path}.receipt.issuedAt")
    updated_at = _timestamp(anchor["updatedAt"], f"{path}.updatedAt")
    require(
        issued_at >= updated_at,
        "HOST_SNAPSHOT_ANCHOR_RECEIPT_TIME_INVALID",
        f"{path}.receipt.issuedAt",
        "final receipt predates the committed anchor update",
    )
    for index, signature in enumerate(
        anchor["prepareReceipt"]["rootSignatures"]
    ):
        require(
            _timestamp(
                signature["signedAt"],
                f"{path}.prepareReceipt.rootSignatures[{index}].signedAt",
            )
            <= issued_at,
            "HOST_SNAPSHOT_ANCHOR_RECEIPT_TIME_INVALID",
            f"{path}.receipt.issuedAt",
            "final receipt predates completion of the prepare quorum",
        )
    digest, _ = _projection_digest(
        receipt,
        null_fields=("receiptDigest",),
        empty_array_fields=("rootSignatures",),
        path=f"{path}.receipt.digestProjection",
    )
    _require_digest(
        receipt["receiptDigest"],
        digest,
        f"{path}.receipt.receiptDigest",
        "HOST_SNAPSHOT_ANCHOR_RECEIPT_DIGEST_INVALID",
    )
    _verify_root_quorum(
        root_set,
        receipt["rootSignatures"],
        digest_field="receiptDigest",
        digest=digest,
        domain=HOST_SNAPSHOT_ANCHOR_RECEIPT_DOMAIN,
        path=f"{path}.receipt.rootSignatures",
        require_algorithm=True,
        not_before=issued_at,
    )


def _validate_anchor_cas(
    anchor: Mapping[str, Any],
    *,
    inventory_previous_snapshot_hash: Any,
    path: str,
) -> None:
    require(
        anchor["anchorVersion"] == anchor["resourceVersion"],
        "HOST_SNAPSHOT_ANCHOR_CAS_INVALID",
        path,
        "anchorVersion and resourceVersion must advance in lockstep",
    )
    cas = anchor["casPrecondition"]
    if anchor["anchorVersion"] == 1:
        require(
            anchor["previousAnchorDigestOrNull"] is None
            and all(value is None for value in cas.values()),
            "HOST_SNAPSHOT_ANCHOR_CAS_INVALID",
            path,
            "genesis requires no predecessor and an all-null CAS state",
        )
        require(
            anchor["acceptedSnapshotEpoch"] == 1,
            "HOST_SNAPSHOT_ANCHOR_CAS_INVALID",
            f"{path}.acceptedSnapshotEpoch",
            "genesis must begin at snapshot epoch one",
        )
        require(
            inventory_previous_snapshot_hash is None,
            "HOST_SNAPSHOT_ANCHOR_CAS_INVALID",
            f"{path}.acceptedSnapshotContentHash",
            "genesis inventory must not claim a predecessor snapshot",
        )
        return

    require(
        anchor["anchorVersion"] == cas["expectedAnchorVersionOrNull"] + 1,
        "HOST_SNAPSHOT_ANCHOR_CAS_INVALID",
        f"{path}.anchorVersion",
        "successor must increment the predecessor anchor version by one",
    )
    require(
        anchor["resourceVersion"] == cas["expectedResourceVersionOrNull"] + 1,
        "HOST_SNAPSHOT_ANCHOR_CAS_INVALID",
        f"{path}.resourceVersion",
        "successor must increment the predecessor resource version by one",
    )
    require(
        anchor["previousAnchorDigestOrNull"]
        == cas["expectedAnchorDigestOrNull"],
        "HOST_SNAPSHOT_ANCHOR_CAS_INVALID",
        f"{path}.previousAnchorDigestOrNull",
        "successor does not bind the CAS predecessor digest",
    )
    require(
        anchor["acceptedSnapshotContentHash"]
        != cas["expectedSnapshotContentHashOrNull"],
        "HOST_SNAPSHOT_ANCHOR_CAS_INVALID",
        f"{path}.acceptedSnapshotContentHash",
        "a successor cannot re-publish the predecessor snapshot bytes",
    )
    require(
        anchor["acceptedHostAuthorityResourceVersion"]
        > cas["expectedHostAuthorityResourceVersionOrNull"],
        "HOST_SNAPSHOT_ANCHOR_CAS_INVALID",
        f"{path}.acceptedHostAuthorityResourceVersion",
        "a successor must advance the HostAuthority version",
    )
    same_incarnation = (
        anchor["kernelBootId"] == cas["expectedKernelBootIdOrNull"]
        and anchor["hostEpoch"] == cas["expectedHostEpochOrNull"]
        and anchor["agentIdentity"] == cas["expectedAgentIdentityOrNull"]
        and anchor["agentGeneration"]
        == cas["expectedAgentGenerationOrNull"]
    )
    if same_incarnation:
        require(
            inventory_previous_snapshot_hash
            == cas["expectedSnapshotContentHashOrNull"],
            "HOST_SNAPSHOT_ANCHOR_CAS_INVALID",
            f"{path}.casPrecondition.expectedSnapshotContentHashOrNull",
            "same-incarnation CAS must bind the signed snapshot predecessor",
        )
        require(
            anchor["acceptedSnapshotEpoch"]
            == cas["expectedSnapshotEpochOrNull"] + 1,
            "HOST_SNAPSHOT_ANCHOR_CAS_INVALID",
            f"{path}.acceptedSnapshotEpoch",
            "same-incarnation snapshot epoch must increment by one",
        )
    else:
        require(
            (
                anchor["hostEpoch"] >= cas["expectedHostEpochOrNull"]
                and anchor["agentGeneration"]
                >= cas["expectedAgentGenerationOrNull"]
                and (
                    anchor["hostEpoch"] > cas["expectedHostEpochOrNull"]
                    or anchor["agentGeneration"]
                    > cas["expectedAgentGenerationOrNull"]
                )
            )
            and anchor["acceptedSnapshotEpoch"] == 1,
            "HOST_SNAPSHOT_ANCHOR_CAS_INVALID",
            path,
            "a new incarnation must advance host/agent generation and start "
            "at snapshot epoch one",
        )
        require(
            inventory_previous_snapshot_hash is None,
            "HOST_SNAPSHOT_ANCHOR_CAS_INVALID",
            f"{path}.acceptedSnapshotContentHash",
            "a new inventory incarnation must begin a fresh snapshot chain",
        )


def _validate_anchor(
    schemas: ContractSchemas,
    value: JsonDocument,
    *,
    trust: VerifiedTrustContext,
    inventory: VerifiedInventoryContext,
) -> tuple[dict[str, Any], bytes]:
    path = "hostSnapshotAnchor.externalAnchor"
    anchor, raw = _document(value, path)
    schemas.validate("host_snapshot_anchor", anchor, path)
    require(
        anchor["recordState"] == "COMMITTED",
        "HOST_SNAPSHOT_ANCHOR_NOT_COMMITTED",
        f"{path}.recordState",
        "PREPARED is a reservation, not rollback authority",
    )

    candidate = {name: copy.deepcopy(anchor[name]) for name in _CANDIDATE_FIELDS}
    candidate_digest = sha256_digest(
        HOST_SNAPSHOT_ANCHOR_CANDIDATE_DOMAIN
        + canonical_json_bytes(candidate)
    )
    _require_digest(
        anchor["candidateProjectionDigest"],
        candidate_digest,
        f"{path}.candidateProjectionDigest",
        "HOST_SNAPSHOT_ANCHOR_CANDIDATE_DIGEST_INVALID",
    )
    anchor_digest, _ = _projection_digest(
        anchor,
        null_fields=("anchorDigest", "receipt"),
        path=f"{path}.digestProjection",
    )
    _require_digest(
        anchor["anchorDigest"],
        anchor_digest,
        f"{path}.anchorDigest",
        "HOST_SNAPSHOT_ANCHOR_DIGEST_INVALID",
    )
    inventory_previous_snapshot_hash = inventory.host_snapshot[
        "previousSnapshotContentHashOrNull"
    ]
    _validate_anchor_cas(
        anchor,
        inventory_previous_snapshot_hash=inventory_previous_snapshot_hash,
        path=path,
    )

    inventory_bindings = {
        "hostId": inventory.host_id,
        "kernelBootId": inventory.kernel_boot_id,
        "hostEpoch": inventory.host_epoch,
        "agentIdentity": inventory.agent_identity,
        "agentGeneration": inventory.agent_generation,
        "acceptedSnapshotEpoch": inventory.snapshot_epoch,
        "acceptedSnapshotContentHash": inventory.snapshot_content_hash,
        "acceptedHostAuthorityResourceVersion": (
            inventory.snapshot_authority_resource_version
        ),
    }
    for name, expected in inventory_bindings.items():
        require(
            anchor[name] == expected,
            "HOST_SNAPSHOT_ANCHOR_INVENTORY_MISMATCH",
            f"{path}.{name}",
            f"anchor value does not match verified inventory {expected!r}",
        )
    _validate_prepare_receipt(anchor, trust._root_set, path=path)
    require(
        inventory.captured_at
        <= _timestamp(
            anchor["prepareReceipt"]["preparedAt"],
            f"{path}.prepareReceipt.preparedAt",
        ),
        "HOST_SNAPSHOT_ANCHOR_PREPARE_TIME_INVALID",
        f"{path}.prepareReceipt.preparedAt",
        "anchor preparation predates the verified inventory capture",
    )
    _validate_final_receipt(anchor, trust._root_set, path=path)
    return anchor, raw


def verify_host_snapshot_anchor_binding(
    schemas: ContractSchemas,
    trust: VerifiedTrustContext,
    inventory: VerifiedInventoryContext,
    *,
    external_host_snapshot_anchor: JsonDocument,
    host_snapshot_anchor_freshness: JsonDocument,
    verifier_nonce: str,
    expected_anchor_path: str,
    now: datetime,
) -> VerifiedHostSnapshotAnchorBinding:
    """Bind one verified inventory to caller-supplied live-anchor evidence.

    Production must independently generate ``verifier_nonce`` and fetch both
    documents directly from the external authority.  This pure verifier cannot
    prove that transport or an authority-side CAS.
    """

    require_factory_verified(
        trust,
        VerifiedTrustContext,
        code="TRUST_CONTEXT_INVALID",
        path="hostSnapshotAnchor.trust",
        message="trust must come from verify_trust_context",
    )
    require_factory_verified(
        inventory,
        VerifiedInventoryContext,
        code="HOST_SNAPSHOT_INVENTORY_INVALID",
        path="hostSnapshotAnchor.inventory",
        message="inventory must come from verify_inventory_context",
    )
    require(
        inventory.trust.context_digest == trust.context_digest,
        "HOST_SNAPSHOT_ANCHOR_TRUST_MISMATCH",
        "hostSnapshotAnchor.trust",
        "inventory and anchor verification must use the same trust context",
    )
    require(
        isinstance(expected_anchor_path, str) and expected_anchor_path,
        "HOST_SNAPSHOT_ANCHOR_PATH_INVALID",
        "hostSnapshotAnchor.expectedAnchorPath",
        "an independently configured anchor path is required",
    )
    verified_now = _utc_now(now, "hostSnapshotAnchor.now")
    require(
        inventory.verified_at <= verified_now <= trust.freshness_expires_at,
        "HOST_SNAPSHOT_ANCHOR_TRUST_STALE",
        "hostSnapshotAnchor.now",
        "verification is outside the inventory/trust freshness window",
    )
    anchor, anchor_raw = _validate_anchor(
        schemas,
        external_host_snapshot_anchor,
        trust=trust,
        inventory=inventory,
    )
    freshness, freshness_raw, freshness_expires = _validate_freshness(
        schemas,
        host_snapshot_anchor_freshness,
        verifier_nonce=verifier_nonce,
        now=verified_now,
        anchor_kind="HOST_SNAPSHOT",
        anchor=anchor,
        anchor_raw=anchor_raw,
        anchor_schema_ref=HOST_SNAPSHOT_ANCHOR_SCHEMA_REF,
        subject_field="hostId",
        root_set=trust._root_set,
        path="hostSnapshotAnchor.freshness",
    )
    anchor_schema_digest = schemas.digest_for_ref(
        HOST_SNAPSHOT_ANCHOR_SCHEMA_REF,
        path="hostSnapshotAnchor.anchorSchemaDigest",
    )
    require(
        freshness["anchorPath"] == expected_anchor_path,
        "HOST_SNAPSHOT_ANCHOR_PATH_MISMATCH",
        "hostSnapshotAnchor.freshness.anchorPath",
        "freshness response does not use the independently configured path",
    )

    binding_subject = {
        "subjectType": "VERIFIED_HOST_SNAPSHOT_ANCHOR_BINDING",
        "schemaVersion": 1,
        "authorityBoundary": HOST_SNAPSHOT_ANCHOR_AUTHORITY_BOUNDARY,
        "productAuthorized": HOST_SNAPSHOT_ANCHOR_PRODUCT_AUTHORIZED,
        "trustContextDigest": trust.context_digest,
        "inventoryVerificationReceiptDigest": (
            inventory.inventory_verification_receipt_digest
        ),
        "hostId": inventory.host_id,
        "kernelBootId": inventory.kernel_boot_id,
        "hostEpoch": inventory.host_epoch,
        "agentIdentity": inventory.agent_identity,
        "agentGeneration": inventory.agent_generation,
        "acceptedSnapshotEpoch": inventory.snapshot_epoch,
        "acceptedSnapshotContentHash": inventory.snapshot_content_hash,
        "acceptedHostAuthorityResourceVersion": (
            inventory.snapshot_authority_resource_version
        ),
        "anchorAuthorityId": anchor["authorityId"],
        "anchorDigest": anchor["anchorDigest"],
        "anchorVersion": anchor["anchorVersion"],
        "anchorResourceVersion": anchor["resourceVersion"],
        "anchorReceiptDigest": anchor["receipt"]["receiptDigest"],
        "anchorSchemaDigest": anchor_schema_digest,
        "freshnessReceiptDigest": freshness["freshnessReceiptDigest"],
        "freshnessVerifierNonce": freshness["verifierNonce"],
        "expectedAnchorPath": expected_anchor_path,
        "verifiedAt": verified_now.strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
        "freshnessExpiresAt": freshness_expires.strftime(
            "%Y-%m-%dT%H:%M:%S.%fZ"
        ),
    }
    binding_digest = sha256_digest(
        HOST_SNAPSHOT_ANCHOR_BINDING_DOMAIN
        + canonical_json_bytes(binding_subject)
    )
    return VerifiedHostSnapshotAnchorBinding._construct(
        trust=trust,
        inventory=inventory,
        authority_boundary=HOST_SNAPSHOT_ANCHOR_AUTHORITY_BOUNDARY,
        product_authorized=HOST_SNAPSHOT_ANCHOR_PRODUCT_AUTHORIZED,
        external_anchor=_deep_freeze(anchor),
        external_anchor_canonical_bytes=anchor_raw,
        freshness_envelope=_deep_freeze(freshness),
        freshness_envelope_canonical_bytes=freshness_raw,
        expected_anchor_path=expected_anchor_path,
        verifier_nonce=verifier_nonce,
        host_id=inventory.host_id,
        kernel_boot_id=inventory.kernel_boot_id,
        host_epoch=inventory.host_epoch,
        agent_identity=inventory.agent_identity,
        agent_generation=inventory.agent_generation,
        accepted_snapshot_epoch=inventory.snapshot_epoch,
        accepted_snapshot_content_hash=inventory.snapshot_content_hash,
        accepted_host_authority_resource_version=(
            inventory.snapshot_authority_resource_version
        ),
        anchor_authority_id=anchor["authorityId"],
        anchor_digest=anchor["anchorDigest"],
        anchor_version=anchor["anchorVersion"],
        anchor_resource_version=anchor["resourceVersion"],
        anchor_receipt_digest=anchor["receipt"]["receiptDigest"],
        anchor_schema_digest=anchor_schema_digest,
        freshness_receipt_digest=freshness["freshnessReceiptDigest"],
        freshness_observed_at=_timestamp(
            freshness["observedAt"],
            "hostSnapshotAnchor.freshness.observedAt",
        ),
        freshness_expires_at=freshness_expires,
        verified_at=verified_now,
        binding_digest=binding_digest,
        _schemas=schemas,
    )


def replay_host_snapshot_anchor_binding(
    binding: VerifiedHostSnapshotAnchorBinding,
) -> VerifiedHostSnapshotAnchorBinding:
    """Re-verify the exact retained bytes behind a factory binding."""

    require_factory_verified(
        binding,
        VerifiedHostSnapshotAnchorBinding,
        code="HOST_SNAPSHOT_ANCHOR_BINDING_INVALID",
        path="hostSnapshotAnchor.binding",
        message=(
            "binding must come from verify_host_snapshot_anchor_binding"
        ),
    )
    require(
        binding.anchor_schema_digest
        == binding._schemas.digest_for_ref(
            HOST_SNAPSHOT_ANCHOR_SCHEMA_REF,
            path="hostSnapshotAnchor.binding.anchorSchemaDigest",
        ),
        "HOST_SNAPSHOT_ANCHOR_BINDING_INVALID",
        "hostSnapshotAnchor.binding.anchorSchemaDigest",
        "retained schema identity no longer matches the verified binding",
    )
    replayed = verify_host_snapshot_anchor_binding(
        binding._schemas,
        binding.trust,
        binding.inventory,
        external_host_snapshot_anchor=(
            binding.external_anchor_canonical_bytes
        ),
        host_snapshot_anchor_freshness=(
            binding.freshness_envelope_canonical_bytes
        ),
        verifier_nonce=binding.verifier_nonce,
        expected_anchor_path=binding.expected_anchor_path,
        now=binding.verified_at,
    )
    require(
        replayed == binding,
        "HOST_SNAPSHOT_ANCHOR_BINDING_INVALID",
        "hostSnapshotAnchor.binding",
        "retained binding fields do not replay from the exact verified bytes",
    )
    return replayed


__all__ = [
    "HOST_SNAPSHOT_ANCHOR_AUTHORITY_BOUNDARY",
    "HOST_SNAPSHOT_ANCHOR_BINDING_DOMAIN",
    "HOST_SNAPSHOT_ANCHOR_CANDIDATE_DOMAIN",
    "HOST_SNAPSHOT_ANCHOR_PREPARE_DOMAIN",
    "HOST_SNAPSHOT_ANCHOR_PRODUCT_AUTHORIZED",
    "HOST_SNAPSHOT_ANCHOR_RECEIPT_DOMAIN",
    "HOST_SNAPSHOT_ANCHOR_SCHEMA_REF",
    "VerifiedHostSnapshotAnchorBinding",
    "replay_host_snapshot_anchor_binding",
    "verify_host_snapshot_anchor_binding",
]
