"""Executable HostSnapshot semantic projections used by V3 inventory replay.

This module implements the machine-readable projection rules in
``directpath-host-snapshot-publication-trace.schema.json``.  It is deliberately
side-effect free: it neither captures provider output nor publishes a
snapshot.  Its purpose is to prevent a signed HostSnapshot from carrying
caller-chosen ``topologyDigest`` or ``providerFactsDigest`` values that are not
reproducible from its complete DeviceRecord set.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
import copy
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any

from ._verified import FactoryVerified
from .canonical import canonical_json_bytes, sha256_digest
from .errors import fail, require


DEVICE_TOPOLOGY_SEMANTIC_DOMAIN = (
    b"QMAN-DIRECTPATH/DEVICE-TOPOLOGY-SEMANTIC-PROJECTION/V2\x00"
)
HOST_TOPOLOGY_PROJECTION_DOMAIN = (
    b"QMAN-DIRECTPATH/HOST-TOPOLOGY-PROJECTION/V2\x00"
)
HOST_PROVIDER_PROJECTION_DOMAIN = (
    b"QMAN-DIRECTPATH/HOST-PROVIDER-PROJECTION/V1\x00"
)
HOST_SNAPSHOT_NO_CHANGE_DOMAIN = (
    b"QMAN-DIRECTPATH/HOST-SNAPSHOT-NO-CHANGE/V2\x00"
)

_DEVICE_EXACT_COPY_FIELDS = (
    "hostId",
    "deviceUid",
    "immutableIdentity",
    "identityFingerprint",
    "currentBdf",
    "physicalPathProvider",
    "physicalPath",
    "role",
    "iommuProvider",
    "physicalIsolationDomain",
    "dependencyDomains",
    "dependencyActions",
    "resetContract",
    "owner",
    "bars",
    "interrupts",
    "technicalTraits",
)
_DEVICE_DIGEST_NULL_PATHS = (
    "role.roleFactsDigest",
    "role.provenanceDigest",
    "role.pciStructureFact.providerFactId",
    "role.pciStructureFact.rawConfigSpaceHexOrNull",
    "role.pciStructureFact.rawConfigSpaceSha256OrNull",
    "role.pciStructureFact.failureReasonCodeOrNull",
    "role.pciStructureFact.captureEvidenceDigest",
    "role.pciStructureFact.rawHeaderTypeByteOrNull",
    "role.pciStructureFact.pcieCapabilityOffsetOrNull",
    "role.pciStructureFact.rawPcieCapabilitiesRegisterOrNull",
    "role.pciStructureFact.structureFactDigest",
    "role.pciStructureFact.authorityBoundary",
    "role.pciStructureFact.productAuthorized",
    "iommuProvider.evidenceHash",
    "physicalIsolationDomain.provenanceDigest",
    "dependencyDomains[].provenanceDigest",
    "dependencyDomains[].edges[].provenanceDigest",
    "dependencyActions[].provenanceDigest",
    "resetContract.contractDigest",
    "resetContract.provenanceDigest",
    "resetContract.resetProviderFactId",
    "resetContract.pciFlrCapabilityFact.structureFactDigest",
    "resetContract.pciFlrCapabilityFact.pcieCapabilityOffsetOrNull",
    "resetContract.pciFlrCapabilityFact.deviceCapabilitiesDwordOrNull",
    "resetContract.pciFlrCapabilityFact.flrFactDigest",
    "owner.provenanceDigest",
    "bars[].provenanceDigest",
    "interrupts.provenanceDigest",
    "health.healthEvidenceHash",
    "provenance.providerFacts[].factId",
    "provenance.providerFacts[].evidenceHash",
    "provenance.providerFactsDigest",
)


def _freeze(value: Any) -> Any:
    if isinstance(value, Mapping):
        return MappingProxyType(
            {key: _freeze(item) for key, item in value.items()}
        )
    if isinstance(value, list):
        return tuple(_freeze(item) for item in value)
    return value


def _clone_json(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {key: _clone_json(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_clone_json(item) for item in value]
    return value


def _set_null_path(value: Any, tokens: Sequence[str], *, path: str) -> None:
    token = tokens[0]
    is_array = token.endswith("[]")
    key = token[:-2] if is_array else token
    require(
        isinstance(value, dict) and key in value,
        "SNAPSHOT_SEMANTIC_PROJECTION_INVALID",
        path,
        f"digest-null path component {key!r} is absent",
    )
    selected = value[key]
    if is_array:
        require(
            isinstance(selected, list),
            "SNAPSHOT_SEMANTIC_PROJECTION_INVALID",
            path,
            f"digest-null wildcard {key!r} is not an array",
        )
        if len(tokens) == 1:
            for index in range(len(selected)):
                selected[index] = None
            return
        for index, item in enumerate(selected):
            _set_null_path(
                item,
                tokens[1:],
                path=f"{path}.{key}[{index}]",
            )
        return
    if len(tokens) == 1:
        value[key] = None
        return
    _set_null_path(selected, tokens[1:], path=f"{path}.{key}")


def derive_device_semantic_projection(
    record: Mapping[str, Any],
) -> dict[str, Any]:
    """Derive the stored V2 device semantic projection and its digest."""

    try:
        projection: dict[str, Any] = {
            "subjectType": "DEVICE_TOPOLOGY_SEMANTIC_PROJECTION",
            "schemaVersion": 2,
        }
        for field_name in _DEVICE_EXACT_COPY_FIELDS:
            projection[field_name] = _clone_json(record[field_name])
        health = record["health"]
        projection["health"] = {
            "state": health["state"],
            "lastResetResult": health["lastResetResult"],
            "quarantineReasonCodeOrNull": health[
                "quarantineReasonCodeOrNull"
            ],
            "healthEvidenceHash": health["healthEvidenceHash"],
        }
        provenance = record["provenance"]
        projection["provenance"] = {
            "providerFacts": [
                {
                    "factId": item["factId"],
                    "providerId": item["providerId"],
                    "providerVersion": item["providerVersion"],
                    "providerDefinitionDigest": item[
                        "providerDefinitionDigest"
                    ],
                    "evidenceHash": item["evidenceHash"],
                }
                for item in provenance["providerFacts"]
            ],
            "providerFactsDigest": provenance["providerFactsDigest"],
        }
        projection["deviceSemanticDigest"] = None
    except (KeyError, TypeError) as exc:
        fail(
            "SNAPSHOT_SEMANTIC_PROJECTION_INVALID",
            "deviceRecord",
            f"cannot construct the closed device projection: {exc}",
        )

    digest_projection = copy.deepcopy(projection)
    for null_path in _DEVICE_DIGEST_NULL_PATHS:
        _set_null_path(
            digest_projection,
            null_path.split("."),
            path="deviceSemanticProjection",
        )
    projection["deviceSemanticDigest"] = sha256_digest(
        DEVICE_TOPOLOGY_SEMANTIC_DOMAIN
        + canonical_json_bytes(digest_projection)
    )
    return projection


@dataclass(frozen=True, slots=True, init=False)
class VerifiedHostSnapshotSemantics(FactoryVerified):
    """Factory-only reconstruction of snapshot topology/provider semantics."""

    device_projections: tuple[Mapping[str, Any], ...]
    device_projections_by_uid: Mapping[str, Mapping[str, Any]]
    topology_projection: Mapping[str, Any]
    provider_semantic_projection: Mapping[str, Any]
    topology_digest: str
    provider_facts_digest: str


def derive_host_snapshot_semantics(
    snapshot: Mapping[str, Any],
    records: Sequence[Mapping[str, Any]],
) -> VerifiedHostSnapshotSemantics:
    """Reconstruct both semantic digests from the complete DeviceRecord set."""

    require(
        bool(records),
        "SNAPSHOT_SEMANTIC_PROJECTION_INVALID",
        "deviceRecords",
        "a HostSnapshot topology requires at least one DeviceRecord",
    )
    device_projections = [
        derive_device_semantic_projection(record) for record in records
    ]
    device_projections.sort(
        key=lambda item: canonical_json_bytes(item["deviceUid"])
    )
    uids = [item["deviceUid"] for item in device_projections]
    require(
        len(uids) == len(set(uids)),
        "SNAPSHOT_SEMANTIC_PROJECTION_INVALID",
        "deviceRecords",
        "device semantic projection contains duplicate device UIDs",
    )
    topology_projection: dict[str, Any] = {
        "subjectType": "HOST_TOPOLOGY_SEMANTIC_PROJECTION",
        "schemaVersion": 2,
        "hostId": snapshot["hostId"],
        "kernelBootId": snapshot["kernelBootId"],
        "hostEpoch": snapshot["hostEpoch"],
        "agentGeneration": snapshot["agentGeneration"],
        "members": device_projections,
        "topologyDigest": None,
    }
    topology_digest_subject = {
        "subjectType": topology_projection["subjectType"],
        "schemaVersion": topology_projection["schemaVersion"],
        "hostId": topology_projection["hostId"],
        "kernelBootId": topology_projection["kernelBootId"],
        "hostEpoch": topology_projection["hostEpoch"],
        "agentGeneration": topology_projection["agentGeneration"],
        "members": [
            {
                "deviceUid": member["deviceUid"],
                "deviceSemanticDigest": member["deviceSemanticDigest"],
            }
            for member in device_projections
        ],
        "topologyDigest": None,
    }
    topology_digest = sha256_digest(
        HOST_TOPOLOGY_PROJECTION_DOMAIN
        + canonical_json_bytes(topology_digest_subject)
    )
    topology_projection["topologyDigest"] = topology_digest

    providers: dict[bytes, dict[str, Any]] = {}
    for record in records:
        device_uid = record["deviceUid"]
        seen_for_device: set[bytes] = set()
        for provider_fact in record["provenance"]["providerFacts"]:
            identity = {
                "providerId": provider_fact["providerId"],
                "providerVersion": provider_fact["providerVersion"],
                "providerDefinitionDigest": provider_fact[
                    "providerDefinitionDigest"
                ],
            }
            key = canonical_json_bytes(
                [
                    identity["providerId"],
                    identity["providerVersion"],
                    identity["providerDefinitionDigest"],
                ]
            )
            if key in seen_for_device:
                continue
            seen_for_device.add(key)
            entry = providers.setdefault(
                key,
                {
                    **identity,
                    "coveredDeviceUids": set(),
                },
            )
            entry["coveredDeviceUids"].add(device_uid)
    provider_entries = [
        {
            "providerId": entry["providerId"],
            "providerVersion": entry["providerVersion"],
            "providerDefinitionDigest": entry["providerDefinitionDigest"],
            "coveredDeviceUids": sorted(
                entry["coveredDeviceUids"],
                key=canonical_json_bytes,
            ),
        }
        for _, entry in sorted(providers.items(), key=lambda item: item[0])
    ]
    require(
        bool(provider_entries),
        "SNAPSHOT_SEMANTIC_PROJECTION_INVALID",
        "deviceRecords.provenance.providerFacts",
        "provider semantic projection cannot be empty",
    )
    provider_projection: dict[str, Any] = {
        "subjectType": "HOST_PROVIDER_SEMANTIC_PROJECTION",
        "schemaVersion": 1,
        "providers": provider_entries,
        "providerFactsDigest": None,
    }
    provider_facts_digest = sha256_digest(
        HOST_PROVIDER_PROJECTION_DOMAIN
        + canonical_json_bytes(provider_projection)
    )
    provider_projection["providerFactsDigest"] = provider_facts_digest

    frozen_devices = tuple(_freeze(item) for item in device_projections)
    return VerifiedHostSnapshotSemantics._construct(
        device_projections=frozen_devices,
        device_projections_by_uid=MappingProxyType(
            {
                item["deviceUid"]: frozen
                for item, frozen in zip(
                    device_projections,
                    frozen_devices,
                    strict=True,
                )
            }
        ),
        topology_projection=_freeze(topology_projection),
        provider_semantic_projection=_freeze(provider_projection),
        topology_digest=topology_digest,
        provider_facts_digest=provider_facts_digest,
    )


def derive_no_change_projection(
    *,
    snapshot: Mapping[str, Any],
    agent_identity: str,
    topology_digest: str,
    provider_facts_digest: str,
) -> dict[str, Any]:
    """Construct the V2 publication comparator for one candidate capture."""

    projection = {
        "subjectType": "HOST_SNAPSHOT_NO_CHANGE_PROJECTION",
        "schemaVersion": 2,
        "hostId": snapshot["hostId"],
        "kernelBootId": snapshot["kernelBootId"],
        "hostEpoch": snapshot["hostEpoch"],
        "agentIdentity": agent_identity,
        "agentGeneration": snapshot["agentGeneration"],
        "topologyDigest": topology_digest,
        "providerFactsDigest": provider_facts_digest,
        "policyHash": snapshot["policyHash"],
        "snapshotFreshnessPolicyHash": snapshot[
            "snapshotFreshnessPolicyHash"
        ],
        "noChangeProjectionHash": None,
    }
    projection["noChangeProjectionHash"] = sha256_digest(
        HOST_SNAPSHOT_NO_CHANGE_DOMAIN
        + canonical_json_bytes(projection)
    )
    return projection


__all__ = [
    "DEVICE_TOPOLOGY_SEMANTIC_DOMAIN",
    "HOST_PROVIDER_PROJECTION_DOMAIN",
    "HOST_SNAPSHOT_NO_CHANGE_DOMAIN",
    "HOST_TOPOLOGY_PROJECTION_DOMAIN",
    "VerifiedHostSnapshotSemantics",
    "derive_device_semantic_projection",
    "derive_host_snapshot_semantics",
    "derive_no_change_projection",
]
