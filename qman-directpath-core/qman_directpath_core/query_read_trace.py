"""Pure verifier for one C15 DirectPath query read trace.

The verifier consumes retained bytes and performs no I/O.  It can prove that
one closed trace is internally complete, canonical, hash-bound, byte-stable,
and carries a zero-write witness.  It cannot prove that a repository
transaction, current-authority read, or host observation really occurred.
Consequently it deliberately rejects the product-E3 evidence boundary and
returns component-premise evidence only.

A ``GuardedCapabilityRead`` is not repository proof and is not an input to
this module.  Actual canonical instance and output bytes are mandatory; a
schema, decoder, SQL/API log, or digest-only label is never a substitute.
"""

from __future__ import annotations

import base64
import binascii
import copy
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any, Mapping

from ._verified import FactoryVerified
from .canonical import (
    CanonicalizationError,
    canonical_json_bytes,
    load_canonical_json,
    sha256_digest,
)
from .contracts import ContractSchemas
from .errors import fail, require


QUERY_READ_TRACE_SCHEMA_REF = "contracts/directpath-query-read-trace.schema.json"
QUERY_READ_TRACE_EVIDENCE_BOUNDARY = "COMPONENT_QUERY_TRACE_NOT_PRODUCT_CLOSURE"
REFERENCE_QUERY_READ_TRACE_EVIDENCE_BOUNDARY = (
    "REFERENCE_SQLITE_QUERY_TRANSACTION_COMPONENT_ONLY"
)

_COMPONENT_BOUNDARIES = frozenset(
    {
        QUERY_READ_TRACE_EVIDENCE_BOUNDARY,
        REFERENCE_QUERY_READ_TRACE_EVIDENCE_BOUNDARY,
    }
)
_OBSERVATION_DOMAIN = b"QMAN-DIRECTPATH/QUERY-OBSERVED-INSTANCE/V1\x00"
_PREDICATE_DOMAIN = b"QMAN-DIRECTPATH/QUERY-PREDICATE-OBSERVATION/V1\x00"
_STATE_DOMAIN = b"QMAN-DIRECTPATH/QUERY-READ-STATE/V1\x00"
_TRACE_DOMAIN = b"QMAN-DIRECTPATH/QUERY-READ-TRACE/V1\x00"
_REFERENCE_ROW_DOMAIN = b"QMAN-DIRECTPATH/REFERENCE-QUERY-OBSERVED-ROW/V1\x00"
_CAPABILITY_DECISION_DOMAIN = b"QMAN-DIRECTPATH/QUERY-CAPABILITY-DECISION/V1\x00"
_SEMANTIC_DEPENDENCIES_DOMAIN = b"QMAN-DIRECTPATH/QUERY-SEMANTIC-DEPENDENCIES/V1\x00"

_REFERENCE_ROW_SCHEMA_REF = QUERY_READ_TRACE_SCHEMA_REF + "#/$defs/referenceObservedRow"
_OUTPUT_SCHEMA_REF = (
    "contracts/directpath-operation-payload.schema.json"
    "#/$defs/output_OP_QUERY_DIRECTPATH"
)
_SCHEMA_REFS_BY_KIND = {
    "HOST_AUTHORITY": frozenset(
        {
            "contracts/directpath-authority-entities.schema.json"
            "#/$defs/ENTITY-HOST-AUTHORITY"
        }
    ),
    "CAPABILITY_POLICY_AUTHORITY": frozenset(
        {
            "contracts/directpath-authority-entities.schema.json"
            "#/$defs/ENTITY-CAPABILITY-POLICY-AUTHORITY"
        }
    ),
    "AVAILABILITY_AUTHORITY": frozenset(
        {
            "contracts/directpath-authority-entities.schema.json"
            "#/$defs/ENTITY-AVAILABILITY-AUTHORITY"
        }
    ),
    "VM_REQUEST_OR_ASSIGNMENT": frozenset(
        {
            "contracts/directpath-portable-entities.schema.json"
            "#/$defs/ENTITY-VM-DIRECTPATH-REQUEST"
        }
    ),
    "DEVICE_RECORD": frozenset(
        {
            "contracts/directpath-portable-entities.schema.json"
            "#/$defs/ENTITY-DEVICE-RECORD"
        }
    ),
    "DEPENDENCY_BUNDLE": frozenset(
        {
            "contracts/directpath-portable-entities.schema.json"
            "#/$defs/ENTITY-DEPENDENCY-BUNDLE"
        }
    ),
    "BUNDLE_LEASE": frozenset(
        {
            "contracts/directpath-authority-entities.schema.json"
            "#/$defs/ENTITY-BUNDLE-LEASE"
        }
    ),
    "OPERATION_LEASE": frozenset(
        {
            "contracts/directpath-authority-entities.schema.json"
            "#/$defs/ENTITY-OPERATION-LEASE"
        }
    ),
    "QUARANTINE_RECORD": frozenset(
        {
            "contracts/directpath-authority-entities.schema.json"
            "#/$defs/ENTITY-QUARANTINE-RECORD"
        }
    ),
    "HOST_JOURNAL_HEAD": frozenset(
        {QUERY_READ_TRACE_SCHEMA_REF + "#/$defs/hostJournalHead"}
    ),
    "HOST_SIDE_EFFECT_COUNTER": frozenset(
        {QUERY_READ_TRACE_SCHEMA_REF + "#/$defs/hostSideEffectCounter"}
    ),
    "RESET_OBSERVATION": frozenset(
        {QUERY_READ_TRACE_SCHEMA_REF + "#/$defs/resetObservation"}
    ),
}
_AVAILABILITY_PREDICATES = frozenset(
    {
        "DEVICE_RECORDS_BY_COMPLETE_BUNDLE",
        "ACTIVE_BUNDLE_LEASES_OVERLAPPING_BUNDLE_OR_MEMBER",
        "ACTIVE_OPERATION_LEASES_OVERLAPPING_SCOPE_BUNDLE_OR_MEMBER",
        "UNCLEARED_QUARANTINES_OVERLAPPING_BUNDLE_OR_MEMBER",
    }
)
_PREDICATE_INSTANCE_KINDS = {
    "CURRENT_AUTHORITY_BY_FIXED_KEYS": frozenset(
        {
            "HOST_AUTHORITY",
            "CAPABILITY_POLICY_AUTHORITY",
            "AVAILABILITY_AUTHORITY",
            "CURRENT_TRUST_POINTER",
            "CURRENT_TRUST_ANCHOR",
            "CURRENT_CATALOG_POINTER",
            "CURRENT_CATALOG_ANCHOR",
            "CURRENT_INVENTORY_POINTER",
            "HOST_SNAPSHOT_ANCHOR_BINDING",
            "VM_REQUEST_OR_ASSIGNMENT",
        }
    ),
    "CURRENT_HOST_SNAPSHOT_BY_POINTER": frozenset({"HOST_SNAPSHOT"}),
    "DEVICE_RECORDS_BY_COMPLETE_BUNDLE": frozenset({"DEVICE_RECORD"}),
    "ACTIVE_BUNDLE_LEASES_OVERLAPPING_BUNDLE_OR_MEMBER": frozenset({"BUNDLE_LEASE"}),
    "ACTIVE_OPERATION_LEASES_OVERLAPPING_SCOPE_BUNDLE_OR_MEMBER": frozenset(
        {"OPERATION_LEASE"}
    ),
    "UNCLEARED_QUARANTINES_OVERLAPPING_BUNDLE_OR_MEMBER": frozenset(
        {"QUARANTINE_RECORD"}
    ),
    "HOST_JOURNAL_HEAD_BY_HOST_EPOCH": frozenset({"HOST_JOURNAL_HEAD"}),
    "HOST_SIDE_EFFECT_COUNTERS_BY_AGENT_EPOCH": frozenset({"HOST_SIDE_EFFECT_COUNTER"}),
    "RESET_OBSERVATIONS_BY_MEMBER_SET": frozenset({"RESET_OBSERVATION"}),
}
_REQUIRED_ACTUAL_KINDS = frozenset(
    {
        "HOST_AUTHORITY",
        "CAPABILITY_POLICY_AUTHORITY",
        "AVAILABILITY_AUTHORITY",
        "CURRENT_TRUST_POINTER",
        "CURRENT_TRUST_ANCHOR",
        "CURRENT_CATALOG_POINTER",
        "CURRENT_CATALOG_ANCHOR",
        "CURRENT_INVENTORY_POINTER",
        "HOST_SNAPSHOT_ANCHOR_BINDING",
        "VM_REQUEST_OR_ASSIGNMENT",
        "HOST_SNAPSHOT",
        "DEVICE_RECORD",
        "DEPENDENCY_BUNDLE",
        "HOST_JOURNAL_HEAD",
        "HOST_SIDE_EFFECT_COUNTER",
        "RESET_OBSERVATION",
    }
)


def _freeze(value: Any) -> Any:
    if isinstance(value, Mapping):
        return MappingProxyType({key: _freeze(item) for key, item in value.items()})
    if isinstance(value, list):
        return tuple(_freeze(item) for item in value)
    return value


def _digest_subject(
    domain: bytes,
    value: Mapping[str, Any],
    digest_field: str,
) -> str:
    subject = copy.deepcopy(dict(value))
    subject[digest_field] = None
    return sha256_digest(domain + canonical_json_bytes(subject))


def _require_digest(
    value: Mapping[str, Any],
    *,
    digest_field: str,
    domain: bytes,
    path: str,
) -> None:
    require(
        value[digest_field] == _digest_subject(domain, value, digest_field),
        "QUERY_TRACE_HASH_MISMATCH",
        f"{path}.{digest_field}",
        f"{digest_field} does not bind the exact closed canonical subject",
    )


def _require_complete_canonical_set(values: list[Any], *, path: str) -> None:
    keys = [canonical_json_bytes(value) for value in values]
    require(
        len(set(keys)) == len(keys),
        "QUERY_TRACE_DUPLICATE_SET_MEMBER",
        path,
        "complete canonical set members must be unique",
    )
    require(
        keys == sorted(keys),
        "QUERY_TRACE_NONCANONICAL_SET",
        path,
        "members must be ordered by ascending complete CANONICAL-JSON-V1 bytes",
    )


def _require_name_value_set(values: list[Mapping[str, Any]], *, path: str) -> None:
    _require_complete_canonical_set(values, path=path)
    names = [item["name"] for item in values]
    require(
        len(set(names)) == len(names),
        "QUERY_TRACE_DUPLICATE_SET_MEMBER",
        path,
        "name/value set names must be unique",
    )


def _decode_canonical_object(
    encoded: str, *, path: str
) -> tuple[bytes, dict[str, Any]]:
    try:
        raw = base64.b64decode(encoded, validate=True)
    except (binascii.Error, ValueError) as exc:
        fail("QUERY_TRACE_BASE64_INVALID", path, f"invalid strict base64: {exc}")
    require(
        raw and base64.b64encode(raw).decode("ascii") == encoded,
        "QUERY_TRACE_BASE64_INVALID",
        path,
        "base64 must be the exact padded RFC 4648 representation",
    )
    try:
        decoded = load_canonical_json(raw)
    except CanonicalizationError as exc:
        fail("CANONICAL_JSON_INVALID", path, str(exc))
    require(
        isinstance(decoded, dict),
        "QUERY_TRACE_INSTANCE_INVALID",
        path,
        "retained actual bytes must encode one canonical JSON object",
    )
    return raw, decoded


def _nested_values(value: Any, key: str) -> list[Any]:
    result: list[Any] = []
    if isinstance(value, Mapping):
        for member, item in value.items():
            if member == key:
                result.append(item)
            result.extend(_nested_values(item, key))
    elif isinstance(value, list):
        for item in value:
            result.extend(_nested_values(item, key))
    return result


def _verify_wrapper_projection(
    wrapper: Mapping[str, Any],
    actual: Mapping[str, Any],
    *,
    path: str,
) -> None:
    primary_key = wrapper["sourcePrimaryKey"]
    _require_name_value_set(primary_key, path=f"{path}.sourcePrimaryKey")
    for index, item in enumerate(primary_key):
        require(
            item["name"] in actual and actual[item["name"]] == item["value"],
            "QUERY_TRACE_INSTANCE_PROJECTION_INVALID",
            f"{path}.sourcePrimaryKey[{index}]",
            "primary-key value is not projected from the actual instance",
        )

    resource_version = actual.get("resourceVersion")
    require(
        wrapper["resourceVersionOrNull"] == resource_version,
        "QUERY_TRACE_INSTANCE_PROJECTION_INVALID",
        f"{path}.resourceVersionOrNull",
        "resourceVersionOrNull must exactly project top-level resourceVersion",
    )

    generation_fields = {
        "HOST_AUTHORITY": "hostEpoch",
        "HOST_SNAPSHOT": "snapshotEpoch",
        "DEVICE_RECORD": "deviceGeneration",
        "BUNDLE_LEASE": "runGeneration",
        "OPERATION_LEASE": "runGenerationOrNull",
        "QUARANTINE_RECORD": "generation",
        "HOST_JOURNAL_HEAD": "hostEpoch",
        "HOST_SIDE_EFFECT_COUNTER": "agentGeneration",
        "RESET_OBSERVATION": "observerEpoch",
    }
    field = generation_fields.get(str(wrapper["instanceKind"]))
    projected_generation = None
    if field is not None:
        values = _nested_values(actual, field)
        require(
            len(values) <= 1,
            "QUERY_TRACE_INSTANCE_PROJECTION_INVALID",
            f"{path}.generationOrNull",
            f"actual instance has ambiguous {field} projections",
        )
        projected_generation = values[0] if values else None
    require(
        wrapper["generationOrNull"] == projected_generation,
        "QUERY_TRACE_INSTANCE_PROJECTION_INVALID",
        f"{path}.generationOrNull",
        ("generationOrNull must exactly project the instance-kind generation lineage"),
    )


def _verify_reference_row(
    wrapper: Mapping[str, Any],
    actual: Mapping[str, Any],
    *,
    evidence_boundary: str,
    path: str,
) -> None:
    require(
        evidence_boundary == REFERENCE_QUERY_READ_TRACE_EVIDENCE_BOUNDARY,
        "QUERY_TRACE_EVIDENCE_BOUNDARY_INVALID",
        f"{path}.schemaRef",
        "reference observed rows are forbidden outside the reference boundary",
    )
    require(
        actual["instanceKind"] == wrapper["instanceKind"]
        and actual["primaryKey"] == wrapper["sourcePrimaryKey"]
        and actual["resourceVersionOrNull"] == wrapper["resourceVersionOrNull"]
        and actual["generationOrNull"] == wrapper["generationOrNull"],
        "QUERY_TRACE_INSTANCE_PROJECTION_INVALID",
        path,
        "reference row does not byte-equal its observed-instance wrapper",
    )
    _require_name_value_set(actual["rowFields"], path=f"{path}.rowFields")
    _require_digest(
        actual,
        digest_field="rowDigest",
        domain=_REFERENCE_ROW_DOMAIN,
        path=f"{path}.canonicalInstanceBase64",
    )


def _verify_observed_instances(
    state: Mapping[str, Any],
    *,
    schemas: ContractSchemas,
    evidence_boundary: str,
    path: str,
) -> tuple[
    dict[str, Mapping[str, Any]],
    dict[str, Mapping[str, Any]],
]:
    observed = state["observedInstances"]
    _require_complete_canonical_set(observed, path=f"{path}.observedInstances")
    wrappers_by_digest: dict[str, Mapping[str, Any]] = {}
    actual_by_digest: dict[str, Mapping[str, Any]] = {}
    for index, wrapper in enumerate(observed):
        instance_path = f"{path}.observedInstances[{index}]"
        raw, actual = _decode_canonical_object(
            wrapper["canonicalInstanceBase64"],
            path=f"{instance_path}.canonicalInstanceBase64",
        )
        if wrapper["schemaRef"] != _REFERENCE_ROW_SCHEMA_REF:
            allowed_refs = _SCHEMA_REFS_BY_KIND.get(wrapper["instanceKind"])
            require(
                allowed_refs is not None and wrapper["schemaRef"] in allowed_refs,
                "QUERY_TRACE_INSTANCE_SCHEMA_MISMATCH",
                f"{instance_path}.schemaRef",
                "schemaRef is not the closed schema for this instanceKind",
            )
        schemas.validate_ref(wrapper["schemaRef"], actual, f"{instance_path}.actual")
        require(
            wrapper["instanceBytesSha256"] == sha256_digest(raw),
            "QUERY_TRACE_HASH_MISMATCH",
            f"{instance_path}.instanceBytesSha256",
            "hash does not bind the retained actual canonical instance bytes",
        )
        if wrapper["schemaRef"] == _REFERENCE_ROW_SCHEMA_REF:
            _verify_reference_row(
                wrapper,
                actual,
                evidence_boundary=evidence_boundary,
                path=instance_path,
            )
        else:
            _verify_wrapper_projection(wrapper, actual, path=instance_path)
            expected_subject_type = {
                "HOST_JOURNAL_HEAD": "HOST_JOURNAL_HEAD",
                "HOST_SIDE_EFFECT_COUNTER": "HOST_SIDE_EFFECT_COUNTER",
                "RESET_OBSERVATION": "RESET_OBSERVATION",
                "DEVICE_RECORD": "DEVICE_RECORD",
                "DEPENDENCY_BUNDLE": "DEPENDENCY_BUNDLE",
                "VM_REQUEST_OR_ASSIGNMENT": "VM_DIRECTPATH_REQUEST",
            }.get(wrapper["instanceKind"])
            if expected_subject_type is not None:
                require(
                    actual.get("subjectType") == expected_subject_type,
                    "QUERY_TRACE_INSTANCE_SCHEMA_MISMATCH",
                    f"{instance_path}.actual.subjectType",
                    "decoded subjectType does not match wrapper instanceKind",
                )
        if wrapper["instanceKind"] in {
            "HOST_JOURNAL_HEAD",
            "HOST_SIDE_EFFECT_COUNTER",
            "RESET_OBSERVATION",
        }:
            require(
                wrapper["observationPurpose"] == "NON_MUTATION_ORACLE"
                and wrapper["sourceStore"] == "HOST_OBSERVER",
                "QUERY_TRACE_NON_MUTATION_ORACLE_INVALID",
                instance_path,
                "host journal/counter/reset must be actual host-observer oracles",
            )
        _require_digest(
            wrapper,
            digest_field="observationDigest",
            domain=_OBSERVATION_DOMAIN,
            path=instance_path,
        )
        digest = wrapper["observationDigest"]
        require(
            digest not in wrappers_by_digest,
            "QUERY_TRACE_DUPLICATE_SET_MEMBER",
            f"{instance_path}.observationDigest",
            "observation digests must be unique",
        )
        wrappers_by_digest[digest] = wrapper
        actual_by_digest[digest] = actual

    kinds = {wrapper["instanceKind"] for wrapper in wrappers_by_digest.values()}
    missing = sorted(_REQUIRED_ACTUAL_KINDS - kinds)
    require(
        not missing,
        "QUERY_TRACE_INSTANCE_COVERAGE_INCOMPLETE",
        f"{path}.observedInstances",
        f"missing actual C15 observations: {missing!r}",
    )
    return wrappers_by_digest, actual_by_digest


def _expected_predicate_matches(
    predicate_id: str,
    wrappers_by_digest: Mapping[str, Mapping[str, Any]],
) -> list[str]:
    instance_kinds = _PREDICATE_INSTANCE_KINDS[predicate_id]
    return sorted(
        (
            digest
            for digest, wrapper in wrappers_by_digest.items()
            if wrapper["instanceKind"] in instance_kinds
        ),
        key=canonical_json_bytes,
    )


def _actual_projection(actual: Mapping[str, Any]) -> Mapping[str, Any]:
    if actual.get("subjectType") != "REFERENCE_QUERY_OBSERVED_ROW":
        return actual
    return {
        item["name"]: item["value"]
        for item in (*actual["primaryKey"], *actual["rowFields"])
    }


def _scope_set_digest(values: list[Any]) -> str:
    return sha256_digest(canonical_json_bytes(values))


def _expected_closed_parameters(
    predicate_id: str,
    wrappers_by_digest: Mapping[str, Mapping[str, Any]],
    actual_by_digest: Mapping[str, Mapping[str, Any]],
    *,
    path: str,
) -> list[dict[str, Any]]:
    by_kind: dict[str, list[tuple[Mapping[str, Any], Mapping[str, Any]]]] = {}
    for digest, wrapper in wrappers_by_digest.items():
        by_kind.setdefault(wrapper["instanceKind"], []).append(
            (wrapper, _actual_projection(actual_by_digest[digest]))
        )

    def one(kind: str) -> tuple[Mapping[str, Any], Mapping[str, Any]]:
        records = by_kind.get(kind, ())
        require(
            len(records) == 1,
            "QUERY_TRACE_PREDICATE_PARAMETERS_INVALID",
            path,
            f"parameter reconstruction requires exactly one {kind}",
        )
        return records[0]

    _, host = one("HOST_AUTHORITY")
    _, request = one("VM_REQUEST_OR_ASSIGNMENT")
    inventory_wrapper, inventory = one("CURRENT_INVENTORY_POINTER")
    host_id = host.get("hostId")
    vm_id = request.get("vmId")
    require(
        isinstance(host_id, str) and isinstance(vm_id, str),
        "QUERY_TRACE_PREDICATE_PARAMETERS_INVALID",
        path,
        "hostId and vmId must come from actual current rows",
    )
    if predicate_id == "CURRENT_AUTHORITY_BY_FIXED_KEYS":
        values = {"hostId": host_id, "vmId": vm_id}
    elif predicate_id == "CURRENT_HOST_SNAPSHOT_BY_POINTER":
        inventory_row = {
            field: inventory[field]
            for field in (
                "kind",
                "authorityId",
                "sequence",
                "artifactDigest",
                "validUntil",
                "blobSha256",
            )
        }
        inventory_row["resourceVersion"] = inventory_wrapper["resourceVersionOrNull"]
        values = {
            "hostId": host_id,
            "inventoryPointerDigest": sha256_digest(
                canonical_json_bytes(inventory_row)
            ),
        }
    else:
        availability_members: list[dict[str, Any]] = []
        for wrapper, device in by_kind.get("DEVICE_RECORD", ()):
            availability_members.append(
                {
                    "deviceId": device.get("deviceUid"),
                    "generation": wrapper["generationOrNull"],
                    "resourceVersion": wrapper["resourceVersionOrNull"],
                    "evidenceBlobHash": device.get("evidenceBlobHash"),
                }
            )
        availability_members.sort(key=canonical_json_bytes)
        bundle_members: list[dict[str, Any]] = []
        for _wrapper, bundle in by_kind.get("DEPENDENCY_BUNDLE", ()):
            bundle_members.append(
                {
                    "bundleId": bundle.get("bundleId"),
                    "deviceId": (
                        bundle.get("deviceUid")
                        if bundle.get("deviceUid") is not None
                        else bundle.get("deviceId")
                    ),
                }
            )
        bundle_members.sort(key=canonical_json_bytes)
        selected_projection = {
            "bundleMembers": bundle_members,
            "availabilityMembers": availability_members,
        }
        if predicate_id == "DEVICE_RECORDS_BY_COMPLETE_BUNDLE":
            values = {
                "bundleProjectionDigest": sha256_digest(
                    canonical_json_bytes(selected_projection)
                )
            }
        elif predicate_id in {
            "ACTIVE_BUNDLE_LEASES_OVERLAPPING_BUNDLE_OR_MEMBER",
            "ACTIVE_OPERATION_LEASES_OVERLAPPING_SCOPE_BUNDLE_OR_MEMBER",
            "UNCLEARED_QUARANTINES_OVERLAPPING_BUNDLE_OR_MEMBER",
        }:
            values = {
                "selectedScopeDigest": sha256_digest(
                    canonical_json_bytes(selected_projection)
                )
            }
        elif predicate_id == "HOST_JOURNAL_HEAD_BY_HOST_EPOCH":
            values = {"hostEpoch": host.get("hostEpoch"), "hostId": host_id}
        elif predicate_id == "HOST_SIDE_EFFECT_COUNTERS_BY_AGENT_EPOCH":
            counters = by_kind.get("HOST_SIDE_EFFECT_COUNTER", ())
            require(
                counters,
                "QUERY_TRACE_PREDICATE_PARAMETERS_INVALID",
                path,
                "counter parameter reconstruction requires actual counters",
            )
            counter_epochs = {
                counter.get("counterEpoch") for _wrapper, counter in counters
            }
            require(
                len(counter_epochs) == 1,
                "QUERY_TRACE_PREDICATE_PARAMETERS_INVALID",
                path,
                "counter observations have inconsistent epochs",
            )
            values = {
                "agentGeneration": host.get("agentGeneration"),
                "counterEpoch": next(iter(counter_epochs)),
                "hostId": host_id,
            }
        else:
            values = {
                "memberSetDigest": sha256_digest(
                    canonical_json_bytes(
                        [item["deviceId"] for item in availability_members]
                    )
                )
            }
    return sorted(
        ({"name": name, "value": value} for name, value in values.items()),
        key=canonical_json_bytes,
    )


def _flatten_field_values(actual: Mapping[str, Any], field: str) -> list[Any]:
    projected = _actual_projection(actual)
    values = _nested_values(projected, field)
    flattened: list[Any] = []
    for value in values:
        if isinstance(value, list):
            flattened.extend(value)
        else:
            flattened.append(value)
    return flattened


def _row_overlaps_selected_scope(
    actual: Mapping[str, Any],
    selected: Mapping[str, Any],
) -> bool:
    selected_scope_hash = selected["scopeHashOrNull"]
    if selected_scope_hash is not None and selected_scope_hash in _flatten_field_values(
        actual, "scopeHash"
    ):
        return True
    bundle_values = set(_flatten_field_values(actual, "bundleId"))
    bundle_values.update(_flatten_field_values(actual, "bundleIds"))
    if bundle_values.intersection(selected["bundleIds"]):
        return True
    member_values = set(_flatten_field_values(actual, "memberDeviceUid"))
    member_values.update(_flatten_field_values(actual, "memberDeviceUids"))
    member_values.update(_flatten_field_values(actual, "deviceUid"))
    member_values.update(_flatten_field_values(actual, "deviceId"))
    return bool(member_values.intersection(selected["memberDeviceUids"]))


def _verify_availability_fence(
    predicate: Mapping[str, Any],
    wrappers_by_digest: Mapping[str, Mapping[str, Any]],
    actual_by_digest: Mapping[str, Mapping[str, Any]],
    *,
    path: str,
) -> None:
    fence = predicate["fence"]
    predicate_id = predicate["predicateId"]
    if predicate_id not in _AVAILABILITY_PREDICATES:
        require(
            fence == {"fenceKind": "NOT_APPLICABLE"},
            "QUERY_TRACE_PREDICATE_FENCE_INVALID",
            f"{path}.fence",
            "non-availability predicate must carry the closed no-fence value",
        )
        return

    digest = fence["authorityObservationDigest"]
    require(
        digest in wrappers_by_digest,
        "QUERY_TRACE_PREDICATE_FENCE_INVALID",
        f"{path}.fence.authorityObservationDigest",
        "availability fence must resolve an actual observed authority row",
    )
    wrapper = wrappers_by_digest[digest]
    actual = _actual_projection(actual_by_digest[digest])
    require(
        wrapper["instanceKind"] == "AVAILABILITY_AUTHORITY"
        and actual.get("availabilityAuthorityId") == fence["availabilityAuthorityId"]
        and actual.get("resourceVersion")
        == fence["availabilityAuthorityResourceVersion"],
        "QUERY_TRACE_PREDICATE_FENCE_INVALID",
        f"{path}.fence",
        "availability fence does not bind the actual global authority instance",
    )


def _verify_predicates(
    state: Mapping[str, Any],
    wrappers_by_digest: Mapping[str, Mapping[str, Any]],
    actual_by_digest: Mapping[str, Mapping[str, Any]],
    *,
    path: str,
) -> None:
    predicates = state["predicateObservations"]
    _require_complete_canonical_set(
        predicates,
        path=f"{path}.predicateObservations",
    )
    actual_ids = [predicate["predicateId"] for predicate in predicates]
    require(
        set(actual_ids) == set(_PREDICATE_INSTANCE_KINDS)
        and len(actual_ids) == len(_PREDICATE_INSTANCE_KINDS),
        "QUERY_TRACE_PREDICATE_COVERAGE_INCOMPLETE",
        f"{path}.predicateObservations",
        "exactly one observation is required for each closed query predicate",
    )

    for index, predicate in enumerate(predicates):
        predicate_path = f"{path}.predicateObservations[{index}]"
        _require_name_value_set(
            predicate["closedParameters"],
            path=f"{predicate_path}.closedParameters",
        )
        expected_parameters = _expected_closed_parameters(
            predicate["predicateId"],
            wrappers_by_digest,
            actual_by_digest,
            path=predicate_path,
        )
        require(
            predicate["closedParameters"] == expected_parameters,
            "QUERY_TRACE_PREDICATE_PARAMETERS_INVALID",
            f"{predicate_path}.closedParameters",
            "closed parameters do not exactly bind the selected query scope",
        )
        matched = predicate["matchedInstanceDigests"]
        _require_complete_canonical_set(
            matched,
            path=f"{predicate_path}.matchedInstanceDigests",
        )
        for match_index, digest in enumerate(matched):
            require(
                digest in wrappers_by_digest,
                "QUERY_TRACE_PREDICATE_CLOSURE_INVALID",
                f"{predicate_path}.matchedInstanceDigests[{match_index}]",
                "predicate match does not resolve an actual observed instance",
            )
        expected = _expected_predicate_matches(
            predicate["predicateId"],
            wrappers_by_digest,
        )
        require(
            matched == expected,
            "QUERY_TRACE_PREDICATE_CLOSURE_INVALID",
            f"{predicate_path}.matchedInstanceDigests",
            "matched set is not the exact observed predicate closure",
        )
        _verify_availability_fence(
            predicate,
            wrappers_by_digest,
            actual_by_digest,
            path=predicate_path,
        )
        _require_digest(
            predicate,
            digest_field="predicateDigest",
            domain=_PREDICATE_DOMAIN,
            path=predicate_path,
        )


def _verify_current_authority_bindings(
    state: Mapping[str, Any],
    wrappers_by_digest: Mapping[str, Mapping[str, Any]],
    actual_by_digest: Mapping[str, Mapping[str, Any]],
    *,
    path: str,
) -> None:
    vector = state["currentAuthorityVector"]

    by_kind: dict[str, list[Mapping[str, Any]]] = {}
    for digest, wrapper in wrappers_by_digest.items():
        by_kind.setdefault(wrapper["instanceKind"], []).append(
            _actual_projection(actual_by_digest[digest])
        )

    exact_one_kinds = (
        "HOST_AUTHORITY",
        "CAPABILITY_POLICY_AUTHORITY",
        "AVAILABILITY_AUTHORITY",
        "CURRENT_TRUST_POINTER",
        "CURRENT_TRUST_ANCHOR",
        "CURRENT_CATALOG_POINTER",
        "CURRENT_CATALOG_ANCHOR",
        "CURRENT_INVENTORY_POINTER",
        "HOST_SNAPSHOT_ANCHOR_BINDING",
        "VM_REQUEST_OR_ASSIGNMENT",
        "HOST_SNAPSHOT",
    )
    for kind in exact_one_kinds:
        require(
            len(by_kind.get(kind, ())) == 1,
            "QUERY_TRACE_CURRENT_AUTHORITY_INVALID",
            f"{path}.observedInstances",
            f"exactly one current {kind} instance is required",
        )

    host = by_kind["HOST_AUTHORITY"][0]
    policy = by_kind["CAPABILITY_POLICY_AUTHORITY"][0]
    availability = by_kind["AVAILABILITY_AUTHORITY"][0]
    trust = by_kind["CURRENT_TRUST_POINTER"][0]
    trust_anchor = by_kind["CURRENT_TRUST_ANCHOR"][0]
    catalog = by_kind["CURRENT_CATALOG_POINTER"][0]
    catalog_anchor = by_kind["CURRENT_CATALOG_ANCHOR"][0]
    inventory = by_kind["CURRENT_INVENTORY_POINTER"][0]
    host_snapshot_anchor = by_kind["HOST_SNAPSHOT_ANCHOR_BINDING"][0]
    request = by_kind["VM_REQUEST_OR_ASSIGNMENT"][0]
    snapshot = by_kind["HOST_SNAPSHOT"][0]
    require(
        host_snapshot_anchor.get("productAuthorized") is False
        and host_snapshot_anchor.get("authorityBoundary")
        in {
            "COMPONENT_EXTERNAL_BYTES_VERIFICATION_ONLY",
            "REFERENCE_DERIVED_PLACEHOLDER_NO_EXTERNAL_AUTHORITY",
        },
        "QUERY_TRACE_CURRENT_AUTHORITY_INVALID",
        f"{path}.observedInstances.HOST_SNAPSHOT_ANCHOR_BINDING",
        (
            "component/reference HostSnapshot anchor observations cannot "
            "claim product authority"
        ),
    )
    expected_pairs = (
        (host.get("hostId"), vector["hostAuthorityId"], "hostAuthorityId"),
        (
            host.get("resourceVersion"),
            vector["hostAuthorityResourceVersion"],
            "hostAuthorityResourceVersion",
        ),
        (
            host.get("currentSnapshotContentHash"),
            vector["publisherSnapshotDigest"],
            "publisherSnapshotDigest",
        ),
        (
            snapshot.get("contentHash"),
            vector["publisherSnapshotDigest"],
            "publisherSnapshotDigest",
        ),
        (
            policy.get("policyAuthorityId"),
            vector["policyAuthorityId"],
            "policyAuthorityId",
        ),
        (policy.get("policyId"), vector["policyId"], "policyId"),
        (
            policy.get("policyVersion"),
            vector["policyVersion"],
            "policyVersion",
        ),
        (
            policy.get("policyDigest"),
            vector["policyDigest"],
            "policyDigest",
        ),
        (
            policy.get("resourceVersion"),
            vector["policyAuthorityResourceVersion"],
            "policyAuthorityResourceVersion",
        ),
        (
            availability.get("availabilityAuthorityId"),
            vector["availabilityAuthorityId"],
            "availabilityAuthorityId",
        ),
        (
            availability.get("resourceVersion"),
            vector["availabilityAuthorityResourceVersion"],
            "availabilityAuthorityResourceVersion",
        ),
        (
            trust.get("trustRootDigest"),
            vector["trustRootDigest"],
            "trustRootDigest",
        ),
        (
            trust.get("keyRingSequence"),
            vector["keyRingSequence"],
            "keyRingSequence",
        ),
        (
            trust.get("keyRingDigest"),
            vector["keyRingDigest"],
            "keyRingDigest",
        ),
        (
            trust_anchor.get("trustAnchorVersion"),
            vector["trustAnchorVersion"],
            "trustAnchorVersion",
        ),
        (
            trust_anchor.get("trustAnchorDigest"),
            vector["trustAnchorDigest"],
            "trustAnchorDigest",
        ),
        (catalog.get("catalogId"), vector["catalogId"], "catalogId"),
        (
            catalog.get("catalogSequence"),
            vector["catalogSequence"],
            "catalogSequence",
        ),
        (
            catalog.get("catalogDigest"),
            vector["catalogDigest"],
            "catalogDigest",
        ),
        (
            catalog_anchor.get("catalogAnchorVersion"),
            vector["catalogAnchorVersion"],
            "catalogAnchorVersion",
        ),
        (
            catalog_anchor.get("catalogAnchorDigest"),
            vector["catalogAnchorDigest"],
            "catalogAnchorDigest",
        ),
        (
            inventory.get("inventoryVerificationReceiptDigest"),
            vector["inventoryVerificationReceiptDigest"],
            "inventoryVerificationReceiptDigest",
        ),
        (
            inventory.get("inventoryVerifierIdentityDigest"),
            vector["inventoryVerifierIdentityDigest"],
            "inventoryVerifierIdentityDigest",
        ),
        (
            host_snapshot_anchor.get("anchorAuthorityId"),
            vector["hostSnapshotAnchorAuthorityId"],
            "hostSnapshotAnchorAuthorityId",
        ),
        (
            host_snapshot_anchor.get("anchorVersion"),
            vector["hostSnapshotAnchorVersion"],
            "hostSnapshotAnchorVersion",
        ),
        (
            host_snapshot_anchor.get("anchorResourceVersion"),
            vector["hostSnapshotAnchorResourceVersion"],
            "hostSnapshotAnchorResourceVersion",
        ),
        (
            host_snapshot_anchor.get("anchorDigest"),
            vector["hostSnapshotAnchorDigest"],
            "hostSnapshotAnchorDigest",
        ),
        (
            host_snapshot_anchor.get("freshnessReceiptDigest"),
            vector["hostSnapshotAnchorFreshnessReceiptDigest"],
            "hostSnapshotAnchorFreshnessReceiptDigest",
        ),
        (
            host_snapshot_anchor.get("bindingDigest"),
            vector["hostSnapshotAnchorBindingDigest"],
            "hostSnapshotAnchorBindingDigest",
        ),
        (
            request.get("requestAuthorityId"),
            vector["requestAuthorityId"],
            "requestAuthorityId",
        ),
        (
            request.get("requestReadSetDigest"),
            vector["requestReadSetDigest"],
            "requestReadSetDigest",
        ),
    )
    for actual, expected, field in expected_pairs:
        require(
            actual == expected,
            "QUERY_TRACE_CURRENT_AUTHORITY_INVALID",
            f"{path}.currentAuthorityVector.{field}",
            f"{field} does not bind the actual current authority instance",
        )


def _verify_selected_scope_bindings(
    state: Mapping[str, Any],
    wrappers_by_digest: Mapping[str, Mapping[str, Any]],
    actual_by_digest: Mapping[str, Mapping[str, Any]],
    *,
    path: str,
) -> None:
    selected = state["selectedScope"]
    actual_by_kind: dict[str, list[Mapping[str, Any]]] = {}
    for digest, wrapper in wrappers_by_digest.items():
        actual_by_kind.setdefault(wrapper["instanceKind"], []).append(
            actual_by_digest[digest]
        )

    device_uids: list[str] = []
    for actual in actual_by_kind.get("DEVICE_RECORD", ()):
        device_uids.extend(
            str(value) for value in _flatten_field_values(actual, "deviceUid")
        )
    require(
        sorted(set(device_uids), key=canonical_json_bytes)
        == selected["memberDeviceUids"]
        and len(device_uids) == len(set(device_uids)),
        "QUERY_TRACE_SELECTED_SCOPE_INVALID",
        f"{path}.observedInstances",
        "DEVICE_RECORD identities must exactly equal selected memberDeviceUids",
    )

    bundles = actual_by_kind.get("DEPENDENCY_BUNDLE", ())
    bundle_ids: list[str] = []
    members_by_bundle: dict[str, set[str]] = {}
    expected_member_digest = _scope_set_digest(selected["memberDeviceUids"])
    for index, actual in enumerate(bundles):
        values = _flatten_field_values(actual, "bundleId")
        require(
            len(values) == 1,
            "QUERY_TRACE_SELECTED_SCOPE_INVALID",
            f"{path}.dependencyBundles[{index}].bundleId",
            "dependency bundle must retain exactly one bundleId",
        )
        bundle_id = str(values[0])
        bundle_ids.append(bundle_id)
        member_sets = _nested_values(_actual_projection(actual), "memberDeviceUids")
        member_digests = _flatten_field_values(actual, "memberDeviceUidsDigest")
        member_values = set(
            str(value)
            for field in ("memberDeviceUid", "deviceUid", "deviceId")
            for value in _flatten_field_values(actual, field)
        )
        for value in member_sets:
            if isinstance(value, list):
                member_values.update(str(member) for member in value)
        members_by_bundle.setdefault(bundle_id, set()).update(member_values)
        exact_members = any(
            isinstance(value, list) and value == selected["memberDeviceUids"]
            for value in member_sets
        )
        require(
            exact_members
            or expected_member_digest in member_digests
            or bool(member_values),
            "QUERY_TRACE_SELECTED_SCOPE_INVALID",
            f"{path}.dependencyBundles[{index}]",
            "dependency bundle members must exactly bind the selected member set",
        )
    require(
        sorted(set(bundle_ids), key=canonical_json_bytes) == selected["bundleIds"],
        "QUERY_TRACE_SELECTED_SCOPE_INVALID",
        f"{path}.observedInstances",
        "DEPENDENCY_BUNDLE identities must exactly equal selected bundleIds",
    )
    for bundle_id in selected["bundleIds"]:
        require(
            sorted(members_by_bundle.get(bundle_id, ()), key=canonical_json_bytes)
            == selected["memberDeviceUids"],
            "QUERY_TRACE_SELECTED_SCOPE_INVALID",
            f"{path}.dependencyBundles",
            f"bundle {bundle_id!r} does not exactly cover selected members",
        )

    projected_by_kind = {
        kind: [_actual_projection(actual) for actual in records]
        for kind, records in actual_by_kind.items()
    }
    selected_hosts = selected["hostIds"]
    for kind in ("HOST_AUTHORITY", "HOST_SNAPSHOT", "HOST_JOURNAL_HEAD"):
        hosts = [record.get("hostId") for record in projected_by_kind.get(kind, ())]
        require(
            sorted(hosts, key=canonical_json_bytes) == selected_hosts
            and len(hosts) == len(set(hosts)),
            "QUERY_TRACE_NON_MUTATION_ORACLE_INVALID",
            f"{path}.{kind}",
            f"{kind} must exactly cover selected hostIds",
        )

    expected_counter_kinds = {
        "DRIVER_BIND",
        "DRIVER_UNBIND",
        "DEVICE_RESET",
        "VFIO_EXCLUSIVE_OPEN",
        "QEMU_SPAWN",
        "HOST_JOURNAL_APPEND",
    }
    counters = projected_by_kind.get("HOST_SIDE_EFFECT_COUNTER", ())
    require(
        len(counters) == len(selected_hosts) * len(expected_counter_kinds),
        "QUERY_TRACE_NON_MUTATION_ORACLE_INVALID",
        f"{path}.HOST_SIDE_EFFECT_COUNTER",
        "every selected host requires the complete six-kind counter vector",
    )
    host_authorities = {
        record["hostId"]: record for record in projected_by_kind["HOST_AUTHORITY"]
    }
    snapshots = {
        record["hostId"]: record for record in projected_by_kind["HOST_SNAPSHOT"]
    }
    journals = {
        record["hostId"]: record for record in projected_by_kind["HOST_JOURNAL_HEAD"]
    }
    counters_by_host: dict[str, list[Mapping[str, Any]]] = {}
    for counter in counters:
        counters_by_host.setdefault(str(counter.get("hostId")), []).append(counter)
    for host_id in selected_hosts:
        authority = host_authorities[host_id]
        snapshot = snapshots[host_id]
        journal = journals[host_id]
        host_counters = counters_by_host.get(host_id, ())
        require(
            {counter.get("counterKind") for counter in host_counters}
            == expected_counter_kinds
            and len(host_counters) == len(expected_counter_kinds),
            "QUERY_TRACE_NON_MUTATION_ORACLE_INVALID",
            f"{path}.HOST_SIDE_EFFECT_COUNTER",
            f"host {host_id!r} counter kinds are incomplete or duplicated",
        )
        kernel_boot_ids = {
            authority.get("kernelBootId"),
            snapshot.get("kernelBootId"),
            journal.get("kernelBootId"),
            *(counter.get("kernelBootId") for counter in host_counters),
        }
        agent_generations = {
            authority.get("agentGeneration"),
            snapshot.get("agentGeneration"),
            *(counter.get("agentGeneration") for counter in host_counters),
        }
        counter_epochs = {counter.get("counterEpoch") for counter in host_counters}
        require(
            len(kernel_boot_ids) == 1
            and None not in kernel_boot_ids
            and len(agent_generations) == 1
            and None not in agent_generations
            and len(counter_epochs) == 1
            and None not in counter_epochs
            and journal.get("hostEpoch") == authority.get("hostEpoch")
            and snapshot.get("hostEpoch") == authority.get("hostEpoch"),
            "QUERY_TRACE_NON_MUTATION_ORACLE_INVALID",
            f"{path}.hostLineage[{host_id}]",
            "host authority/snapshot/journal/counter lineage is inconsistent",
        )

    resets = projected_by_kind.get("RESET_OBSERVATION", ())
    reset_members = [record.get("memberDeviceUid") for record in resets]
    require(
        sorted(reset_members, key=canonical_json_bytes) == selected["memberDeviceUids"]
        and len(reset_members) == len(set(reset_members)),
        "QUERY_TRACE_NON_MUTATION_ORACLE_INVALID",
        f"{path}.RESET_OBSERVATION",
        "reset observations must exactly cover selected memberDeviceUids",
    )
    reset_lineages = {
        (
            reset.get("hostId"),
            reset.get("kernelBootId"),
            reset.get("agentGeneration"),
            reset.get("observerId"),
            reset.get("observerEpoch"),
        )
        for reset in resets
    }
    require(
        len(reset_lineages) == 1
        and next(iter(reset_lineages))[0] in selected_hosts
        and None not in next(iter(reset_lineages)),
        "QUERY_TRACE_NON_MUTATION_ORACLE_INVALID",
        f"{path}.RESET_OBSERVATION",
        "reset observations must share one selected-host observer lineage",
    )
    reset_host, reset_boot, reset_agent, _observer, _epoch = next(iter(reset_lineages))
    require(
        reset_boot == host_authorities[reset_host].get("kernelBootId")
        and reset_agent == host_authorities[reset_host].get("agentGeneration"),
        "QUERY_TRACE_NON_MUTATION_ORACLE_INVALID",
        f"{path}.RESET_OBSERVATION",
        "reset observer lineage does not match the selected host authority",
    )

    for kind in ("BUNDLE_LEASE", "OPERATION_LEASE", "QUARANTINE_RECORD"):
        for index, actual in enumerate(actual_by_kind.get(kind, ())):
            projection = _actual_projection(actual)
            require(
                _row_overlaps_selected_scope(actual, selected),
                "QUERY_TRACE_PREDICATE_CLOSURE_INVALID",
                f"{path}.{kind}[{index}]",
                "observed availability row does not overlap the selected scope",
            )
            if kind == "BUNDLE_LEASE":
                require(
                    projection.get("state")
                    in {
                        "RESERVED",
                        "PREPARING",
                        "ATTACHED",
                        "RELEASING",
                        "QUARANTINED",
                    },
                    "QUERY_TRACE_PREDICATE_CLOSURE_INVALID",
                    f"{path}.{kind}[{index}].state",
                    "bundle lease is not an active/blocking availability row",
                )
            elif kind == "OPERATION_LEASE":
                require(
                    projection.get("state") == "ACTIVE",
                    "QUERY_TRACE_PREDICATE_CLOSURE_INVALID",
                    f"{path}.{kind}[{index}].state",
                    "operation lease is not ACTIVE",
                )
            elif actual.get("subjectType") != "REFERENCE_QUERY_OBSERVED_ROW":
                require(
                    projection.get("clearedAt") is None,
                    "QUERY_TRACE_PREDICATE_CLOSURE_INVALID",
                    f"{path}.{kind}[{index}].clearedAt",
                    "quarantine observation is already cleared",
                )


def _verify_state(
    state: Mapping[str, Any],
    *,
    schemas: ContractSchemas,
    evidence_boundary: str,
    path: str,
) -> tuple[
    dict[str, Mapping[str, Any]],
    dict[str, Mapping[str, Any]],
]:
    for field in ("bundleIds", "memberDeviceUids", "hostIds"):
        _require_complete_canonical_set(
            state["selectedScope"][field],
            path=f"{path}.selectedScope.{field}",
        )
    require(
        state["currentAuthorityVectorBytesSha256"]
        == sha256_digest(canonical_json_bytes(state["currentAuthorityVector"])),
        "QUERY_TRACE_HASH_MISMATCH",
        f"{path}.currentAuthorityVectorBytesSha256",
        "authority-vector hash does not bind its complete canonical bytes",
    )
    wrappers, actual = _verify_observed_instances(
        state,
        schemas=schemas,
        evidence_boundary=evidence_boundary,
        path=path,
    )
    _verify_current_authority_bindings(
        state,
        wrappers,
        actual,
        path=path,
    )
    _verify_selected_scope_bindings(
        state,
        wrappers,
        actual,
        path=path,
    )
    _verify_predicates(state, wrappers, actual, path=path)
    _require_digest(
        state,
        digest_field="stateDigest",
        domain=_STATE_DOMAIN,
        path=path,
    )
    return wrappers, actual


def _observation_set_digest(
    wrappers_by_digest: Mapping[str, Mapping[str, Any]],
    instance_kinds: frozenset[str],
) -> str:
    digests = sorted(
        (
            digest
            for digest, wrapper in wrappers_by_digest.items()
            if wrapper["instanceKind"] in instance_kinds
        ),
        key=canonical_json_bytes,
    )
    return sha256_digest(canonical_json_bytes(digests))


def _verify_zero_write_witness(
    document: Mapping[str, Any],
    wrappers_by_digest: Mapping[str, Mapping[str, Any]],
) -> None:
    witness = document["zeroWriteWitness"]
    transaction = document["repositoryTransaction"]
    before_state = document["before"]["state"]
    after_state = document["after"]["state"]

    require(
        witness["queryTransactionId"] == transaction["transactionId"],
        "QUERY_TRACE_ZERO_WRITE_INVALID",
        "query_read_trace.zeroWriteWitness.queryTransactionId",
        "zero-write witness is not bound to the query transaction",
    )
    require(
        transaction["databaseEnforcedReadOnly"] is True
        and witness["databaseEnforcedReadOnly"] is True,
        "QUERY_TRACE_ZERO_WRITE_INVALID",
        "query_read_trace.repositoryTransaction.databaseEnforcedReadOnly",
        "both repository transaction and witness must be database-enforced read-only",
    )
    for field in ("writeStatementCount", "affectedRowCount"):
        require(
            witness[field] == 0,
            "QUERY_TRACE_ZERO_WRITE_INVALID",
            f"query_read_trace.zeroWriteWitness.{field}",
            f"{field} must be zero",
        )
    for field in ("repositoryMutationInstances", "hostSideEffectInvocations"):
        require(
            witness[field] == [],
            "QUERY_TRACE_ZERO_WRITE_INVALID",
            f"query_read_trace.zeroWriteWitness.{field}",
            f"{field} must be the empty closed set",
        )
    require(
        witness["commitClockBefore"] == before_state["repositoryCommitClock"]
        and witness["commitClockAfter"] == after_state["repositoryCommitClock"]
        and witness["commitClockBefore"] == witness["commitClockAfter"],
        "QUERY_TRACE_ZERO_WRITE_INVALID",
        "query_read_trace.zeroWriteWitness.commitClockAfter",
        "repository commit clock changed during the read-only query",
    )

    journal_digest = _observation_set_digest(
        wrappers_by_digest,
        frozenset({"HOST_JOURNAL_HEAD"}),
    )
    side_effect_digest = _observation_set_digest(
        wrappers_by_digest,
        frozenset({"HOST_SIDE_EFFECT_COUNTER", "RESET_OBSERVATION"}),
    )
    expected = (
        ("journalHeadBeforeDigest", journal_digest),
        ("journalHeadAfterDigest", journal_digest),
        ("sideEffectCounterVectorBeforeDigest", side_effect_digest),
        ("sideEffectCounterVectorAfterDigest", side_effect_digest),
    )
    for field, digest in expected:
        require(
            witness[field] == digest,
            "QUERY_TRACE_ZERO_WRITE_INVALID",
            f"query_read_trace.zeroWriteWitness.{field}",
            f"{field} is not derived from the complete observed-instance set",
        )


def _verify_output_instance(
    output: Mapping[str, Any],
    *,
    state_digest: str,
    schemas: ContractSchemas,
) -> tuple[bytes, Mapping[str, Any]]:
    raw, actual = _decode_canonical_object(
        output["canonicalOutputBase64"],
        path="query_read_trace.outputInstance.canonicalOutputBase64",
    )
    require(
        output["schemaRef"] == _OUTPUT_SCHEMA_REF,
        "QUERY_TRACE_OUTPUT_INVALID",
        "query_read_trace.outputInstance.schemaRef",
        "output must use the fixed OP-QUERY-DIRECTPATH output schema",
    )
    schemas.validate_ref(
        output["schemaRef"],
        actual,
        "query_read_trace.outputInstance.actual",
    )
    require(
        output["canonicalBytesSha256"] == sha256_digest(raw),
        "QUERY_TRACE_HASH_MISMATCH",
        "query_read_trace.outputInstance.canonicalBytesSha256",
        "output hash does not bind the exact retained canonical output bytes",
    )
    for field in (
        "capabilityDecisionHash",
        "semanticDependencyHash",
        "queryStateHash",
    ):
        require(
            output[field] == actual[field],
            "QUERY_TRACE_OUTPUT_BINDING_INVALID",
            f"query_read_trace.outputInstance.{field}",
            f"{field} does not byte-equal the actual output",
        )
    expected_decision_hash = sha256_digest(
        _CAPABILITY_DECISION_DOMAIN
        + canonical_json_bytes(
            {
                "capabilityStatus": actual["capabilityStatus"],
                "reasons": actual["reasons"],
            }
        )
    )
    require(
        actual["capabilityDecisionHash"] == expected_decision_hash,
        "QUERY_TRACE_OUTPUT_BINDING_INVALID",
        "query_read_trace.outputInstance.capabilityDecisionHash",
        "capability decision hash is not derived from status and reasons",
    )
    expected_semantic_hash = sha256_digest(
        _SEMANTIC_DEPENDENCIES_DOMAIN
        + canonical_json_bytes(
            {
                "bundleSummaries": actual["bundleSummaries"],
                "leaseSummaries": actual["leaseSummaries"],
                "evidenceRefs": actual["evidenceRefs"],
            }
        )
    )
    require(
        actual["semanticDependencyHash"] == expected_semantic_hash,
        "QUERY_TRACE_OUTPUT_BINDING_INVALID",
        "query_read_trace.outputInstance.semanticDependencyHash",
        "semantic dependency hash is not derived from bundle/lease/evidence sets",
    )
    require(
        output["queryStateHash"] == state_digest,
        "QUERY_TRACE_OUTPUT_BINDING_INVALID",
        "query_read_trace.outputInstance.queryStateHash",
        "output does not bind the verified before/after state",
    )

    _require_unique_canonical_key_order(
        actual["bundleSummaries"],
        key_fields=("bundleId",),
        path="query_read_trace.outputInstance.actual.bundleSummaries",
    )
    _require_unique_canonical_key_order(
        actual["leaseSummaries"],
        key_fields=("bundleId", "leaseId"),
        path="query_read_trace.outputInstance.actual.leaseSummaries",
        unique_fields=("leaseId",),
    )
    _require_unique_canonical_key_order(
        actual["reasons"],
        key_fields=("code", "stableMessageId", "detailBindings"),
        path="query_read_trace.outputInstance.actual.reasons",
    )
    _require_unique_canonical_key_order(
        actual["evidenceRefs"],
        key_fields=("documentKind", "documentId", "documentVersion", "contentHash"),
        path="query_read_trace.outputInstance.actual.evidenceRefs",
        unique_fields=("documentKind", "documentId", "documentVersion"),
    )
    return raw, actual


def _require_unique_canonical_key_order(
    values: list[Mapping[str, Any]],
    *,
    key_fields: tuple[str, ...],
    path: str,
    unique_fields: tuple[str, ...] | None = None,
) -> None:
    keys = [
        canonical_json_bytes([value[field] for field in key_fields]) for value in values
    ]
    require(
        keys == sorted(keys),
        "QUERY_TRACE_NONCANONICAL_SET",
        path,
        f"members must use canonical {list(key_fields)!r} order",
    )
    uniqueness_fields = unique_fields or key_fields
    uniqueness = [
        canonical_json_bytes([value[field] for field in uniqueness_fields])
        for value in values
    ]
    require(
        len(set(uniqueness)) == len(uniqueness),
        "QUERY_TRACE_DUPLICATE_SET_MEMBER",
        path,
        f"members must have unique {list(uniqueness_fields)!r} keys",
    )


def _verify_retained_envelope(
    raw: bytes | bytearray | memoryview,
    *,
    expected_digest: str,
    path: str,
) -> tuple[bytes, Mapping[str, Any]]:
    if not isinstance(raw, (bytes, bytearray, memoryview)):
        fail(
            "QUERY_TRACE_ENVELOPE_INVALID",
            path,
            "expected retained raw envelope bytes, not a hash label or log",
        )
    retained = bytes(raw)
    require(
        retained,
        "QUERY_TRACE_ENVELOPE_INVALID",
        path,
        "retained envelope bytes must be non-empty",
    )
    require(
        sha256_digest(retained) == expected_digest,
        "QUERY_TRACE_HASH_MISMATCH",
        path,
        "retained raw envelope bytes do not match the trace hash",
    )
    try:
        document = load_canonical_json(retained)
    except CanonicalizationError as exc:
        fail("CANONICAL_JSON_INVALID", path, str(exc))
    require(
        isinstance(document, dict),
        "QUERY_TRACE_ENVELOPE_INVALID",
        path,
        "retained envelope must be one canonical JSON object",
    )
    return retained, document


def _verify_reference_envelope_bindings(
    trace: Mapping[str, Any],
    request: Mapping[str, Any],
    result: Mapping[str, Any],
    *,
    output_bytes: bytes,
    actual_by_digest: Mapping[str, Mapping[str, Any]],
    wrappers_by_digest: Mapping[str, Mapping[str, Any]],
) -> None:
    expected_request_fields = {
        "subjectType",
        "schemaVersion",
        "evidenceBoundary",
        "queryCommandId",
        "selector",
        "vmId",
    }
    expected_result_fields = {
        "subjectType",
        "schemaVersion",
        "evidenceBoundary",
        "queryCommandId",
        "canonicalOutputBase64",
        "canonicalOutputSha256",
    }
    require(
        set(request) == expected_request_fields
        and set(result) == expected_result_fields,
        "QUERY_TRACE_ENVELOPE_INVALID",
        "query_read_trace.envelopes",
        "reference request/result envelopes must have exact closed fields",
    )
    boundary = REFERENCE_QUERY_READ_TRACE_EVIDENCE_BOUNDARY
    require(
        request["subjectType"] == "REFERENCE_QUERY_REQUEST_ENVELOPE"
        and result["subjectType"] == "REFERENCE_QUERY_RESULT_ENVELOPE"
        and request["schemaVersion"] == result["schemaVersion"] == 1
        and request["evidenceBoundary"] == result["evidenceBoundary"] == boundary,
        "QUERY_TRACE_ENVELOPE_INVALID",
        "query_read_trace.envelopes",
        "reference request/result envelope constants are invalid",
    )
    require(
        request["queryCommandId"] == result["queryCommandId"] == trace["queryCommandId"]
        and request["selector"] == trace["selector"],
        "QUERY_TRACE_ENVELOPE_CORRELATION_INVALID",
        "query_read_trace.envelopes",
        "request/result command or selector does not match the trace",
    )
    request_rows = [
        _actual_projection(actual_by_digest[digest])
        for digest, wrapper in wrappers_by_digest.items()
        if wrapper["instanceKind"] == "VM_REQUEST_OR_ASSIGNMENT"
    ]
    require(
        len(request_rows) == 1 and request_rows[0].get("vmId") == request["vmId"],
        "QUERY_TRACE_ENVELOPE_CORRELATION_INVALID",
        "query_read_trace.requestEnvelope.vmId",
        "request vmId does not match the actual current request observation",
    )
    decoded_output, _ = _decode_canonical_object(
        result["canonicalOutputBase64"],
        path="query_read_trace.resultEnvelope.canonicalOutputBase64",
    )
    require(
        decoded_output == output_bytes
        and result["canonicalOutputSha256"] == sha256_digest(output_bytes),
        "QUERY_TRACE_ENVELOPE_CORRELATION_INVALID",
        "query_read_trace.resultEnvelope",
        "result envelope does not retain the exact trace output bytes and hash",
    )


@dataclass(frozen=True, slots=True, init=False)
class VerifiedQueryReadTrace(FactoryVerified):
    """Factory-only, immutable C15 component trace."""

    document: Mapping[str, Any]
    canonical_bytes: bytes
    output_document: Mapping[str, Any]
    output_canonical_bytes: bytes
    request_envelope_bytes: bytes
    result_envelope_bytes: bytes
    schema_sha256: str
    trace_digest: str
    state_digest: str
    deterministic_output_hash: str

    def to_subject(self) -> dict[str, Any]:
        """Return a detached mutable representation of the verified bytes."""

        loaded = load_canonical_json(self.canonical_bytes)
        if not isinstance(loaded, dict):  # pragma: no cover - factory invariant
            raise RuntimeError("verified query trace ceased to be an object")
        return loaded


def verify_query_read_trace(
    trace_bytes: bytes | bytearray | memoryview,
    *,
    request_envelope_bytes: bytes | bytearray | memoryview,
    result_envelope_bytes: bytes | bytearray | memoryview,
    schemas: ContractSchemas,
) -> VerifiedQueryReadTrace:
    """Verify exact retained C15 bytes without reading any authority or store."""

    if not isinstance(trace_bytes, (bytes, bytearray, memoryview)):
        fail(
            "QUERY_TRACE_INPUT_INVALID",
            "query_read_trace",
            "expected exact CANONICAL-JSON-V1 bytes, not a decoded substitute",
        )
    canonical_bytes = bytes(trace_bytes)
    try:
        document = load_canonical_json(canonical_bytes)
    except CanonicalizationError as exc:
        fail("CANONICAL_JSON_INVALID", "query_read_trace", str(exc))
    require(
        isinstance(document, dict),
        "QUERY_TRACE_INPUT_INVALID",
        "query_read_trace",
        "expected one closed query trace object",
    )
    require(
        isinstance(schemas, ContractSchemas),
        "QUERY_TRACE_SCHEMA_INVALID",
        "query_read_trace.schema",
        "expected ContractSchemas loaded from the selected contract closure",
    )
    schemas.validate("query_read_trace", document, "query_read_trace")
    schema_sha256 = schemas.digest_for_ref(
        QUERY_READ_TRACE_SCHEMA_REF,
        path="query_read_trace.schema",
    )
    require(
        document["subjectType"] == "DIRECTPATH_QUERY_READ_TRACE"
        and document["schemaVersion"] == 1
        and document["operationId"] == "OP-QUERY-DIRECTPATH",
        "QUERY_TRACE_SCHEMA_IDENTITY_INVALID",
        "query_read_trace",
        "trace does not carry the fixed query schema identity",
    )
    require(
        document["evidenceBoundary"] in _COMPONENT_BOUNDARIES,
        "QUERY_TRACE_EVIDENCE_BOUNDARY_INVALID",
        "query_read_trace.evidenceBoundary",
        "the pure verifier cannot attest or emit product-E3 evidence",
    )

    request_bytes, request_envelope = _verify_retained_envelope(
        request_envelope_bytes,
        expected_digest=document["requestEnvelopeSha256"],
        path="query_read_trace.requestEnvelopeSha256",
    )
    result_bytes, result_envelope = _verify_retained_envelope(
        result_envelope_bytes,
        expected_digest=document["resultEnvelopeSha256"],
        path="query_read_trace.resultEnvelopeSha256",
    )
    require(
        document["evidenceBoundary"] == REFERENCE_QUERY_READ_TRACE_EVIDENCE_BOUNDARY,
        "QUERY_TRACE_ENVELOPE_INVALID",
        "query_read_trace.evidenceBoundary",
        (
            "the portable component envelope verifier is not implemented; "
            "non-reference traces fail closed"
        ),
    )
    before_wrappers, before_actual = _verify_state(
        document["before"]["state"],
        schemas=schemas,
        evidence_boundary=document["evidenceBoundary"],
        path="query_read_trace.before.state",
    )
    _verify_state(
        document["after"]["state"],
        schemas=schemas,
        evidence_boundary=document["evidenceBoundary"],
        path="query_read_trace.after.state",
    )
    require(
        canonical_json_bytes(document["before"]["state"])
        == canonical_json_bytes(document["after"]["state"]),
        "QUERY_TRACE_STATE_DRIFT",
        "query_read_trace.after.state",
        "complete before/after repository state is not byte-equal",
    )

    output_raw, output_document = _verify_output_instance(
        document["outputInstance"],
        state_digest=document["before"]["state"]["stateDigest"],
        schemas=schemas,
    )
    _verify_reference_envelope_bindings(
        document,
        request_envelope,
        result_envelope,
        output_bytes=output_raw,
        actual_by_digest=before_actual,
        wrappers_by_digest=before_wrappers,
    )
    _verify_zero_write_witness(document, before_wrappers)
    _require_digest(
        document,
        digest_field="traceDigest",
        domain=_TRACE_DOMAIN,
        path="query_read_trace",
    )
    return VerifiedQueryReadTrace._construct(
        document=_freeze(document),
        canonical_bytes=canonical_bytes,
        output_document=_freeze(output_document),
        output_canonical_bytes=output_raw,
        request_envelope_bytes=request_bytes,
        result_envelope_bytes=result_bytes,
        schema_sha256=schema_sha256,
        trace_digest=document["traceDigest"],
        state_digest=document["before"]["state"]["stateDigest"],
        deterministic_output_hash=document["outputInstance"]["canonicalBytesSha256"],
    )


__all__ = [
    "QUERY_READ_TRACE_EVIDENCE_BOUNDARY",
    "QUERY_READ_TRACE_SCHEMA_REF",
    "REFERENCE_QUERY_READ_TRACE_EVIDENCE_BOUNDARY",
    "VerifiedQueryReadTrace",
    "verify_query_read_trace",
]
