"""Schema-aligned C15 read trace for the SQLite reference query lane.

Every repository row is retained as canonical bytes. Product rows that do not
exist in this package are represented only by the shared contract's closed
``referenceObservedRow`` projection and the explicit REFERENCE evidence
boundary. Host journal/counter/reset rows come from the separately bootstrapped
reference observer and never claim Qman product E3 coverage.
"""

from __future__ import annotations

import base64
from collections import defaultdict
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime
import hmac
import re
from typing import Any

from .query_snapshot import (
    REFERENCE_QUERY_EVIDENCE_BOUNDARY,
    ReferenceDeterministicQueryOutput,
    ReferenceRawQueryRead,
    ReferenceSqliteSnapshotReader,
)
from .static_admission_contracts import (
    ContractViolation,
    canonical_json_bytes,
    load_canonical_json,
    sha256_digest,
)


REFERENCE_QUERY_READ_TRACE = "DIRECTPATH_QUERY_READ_TRACE"

_QUERY_SCHEMA = "contracts/directpath-query-read-trace.schema.json"
_REFERENCE_ROW_SCHEMA = f"{_QUERY_SCHEMA}#/$defs/referenceObservedRow"
_HOST_JOURNAL_SCHEMA = f"{_QUERY_SCHEMA}#/$defs/hostJournalHead"
_HOST_COUNTER_SCHEMA = f"{_QUERY_SCHEMA}#/$defs/hostSideEffectCounter"
_RESET_OBSERVATION_SCHEMA = f"{_QUERY_SCHEMA}#/$defs/resetObservation"

_OBSERVATION_DOMAIN = b"QMAN-DIRECTPATH/QUERY-OBSERVED-INSTANCE/V1"
_REFERENCE_ROW_DOMAIN = b"QMAN-DIRECTPATH/REFERENCE-QUERY-OBSERVED-ROW/V1"
_PREDICATE_DOMAIN = b"QMAN-DIRECTPATH/QUERY-PREDICATE-OBSERVATION/V1"
_STATE_DOMAIN = b"QMAN-DIRECTPATH/QUERY-READ-STATE/V1"
_TRACE_DOMAIN = b"QMAN-DIRECTPATH/QUERY-READ-TRACE/V1"

_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:@/-]{0,255}$")
_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_TIMESTAMP_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z$")

_PREDICATE_KINDS = {
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
_AVAILABILITY_PREDICATES = frozenset(
    {
        "DEVICE_RECORDS_BY_COMPLETE_BUNDLE",
        "ACTIVE_BUNDLE_LEASES_OVERLAPPING_BUNDLE_OR_MEMBER",
        "ACTIVE_OPERATION_LEASES_OVERLAPPING_SCOPE_BUNDLE_OR_MEMBER",
        "UNCLEARED_QUARANTINES_OVERLAPPING_BUNDLE_OR_MEMBER",
    }
)


def _closed(
    value: object,
    fields: frozenset[str],
    path: str,
) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise ContractViolation(f"{path}: expected an object")
    actual = set(value)
    if actual != fields:
        raise ContractViolation(
            f"{path}: closed fields mismatch; "
            f"missing={sorted(fields - actual)}, extra={sorted(actual - fields)}"
        )
    return value


def _id(value: object, path: str) -> str:
    if not isinstance(value, str) or _ID_RE.fullmatch(value) is None:
        raise ContractViolation(f"{path}: invalid closed identifier")
    return value


def _digest(value: object, path: str) -> str:
    if not isinstance(value, str) or _DIGEST_RE.fullmatch(value) is None:
        raise ContractViolation(f"{path}: invalid sha256 digest")
    return value


def _nonnegative(value: object, path: str) -> int:
    if (
        not isinstance(value, int)
        or isinstance(value, bool)
        or value < 0
        or value > 9_007_199_254_740_991
    ):
        raise ContractViolation(f"{path}: expected a safe non-negative integer")
    return value


def _positive(value: object, path: str) -> int:
    result = _nonnegative(value, path)
    if result == 0:
        raise ContractViolation(f"{path}: expected a positive integer")
    return result


def _timestamp(value: object, path: str) -> str:
    if not isinstance(value, str) or _TIMESTAMP_RE.fullmatch(value) is None:
        raise ContractViolation(f"{path}: expected exact UTC timestamp")
    try:
        datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.%fZ")
    except ValueError as error:
        raise ContractViolation(f"{path}: invalid UTC timestamp") from error
    return value


def _canonical_set(values: Sequence[Any], path: str) -> list[Any]:
    result = list(values)
    expected = sorted(result, key=canonical_json_bytes)
    if result != expected:
        raise ContractViolation(f"{path}: array is not in canonical order")
    encoded = [canonical_json_bytes(item) for item in result]
    if len(encoded) != len(set(encoded)):
        raise ContractViolation(f"{path}: duplicate item")
    return result


def _domain_hash(domain: bytes, subject: object) -> str:
    return sha256_digest(domain + b"\x00" + canonical_json_bytes(subject))


def _null_domain_hash(
    domain: bytes,
    subject: Mapping[str, object],
    field: str,
) -> str:
    projected = dict(subject)
    projected[field] = None
    return _domain_hash(domain, projected)


def _name_values(values: Mapping[str, object]) -> list[dict[str, object]]:
    result = [{"name": name, "value": value} for name, value in values.items()]
    result.sort(key=canonical_json_bytes)
    _canonical_set(result, "nameValueSet")
    return result


def _base64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _strict_base64_canonical_json(value: object, path: str) -> bytes:
    if not isinstance(value, str):
        raise ContractViolation(f"{path}: expected base64 string")
    try:
        decoded = base64.b64decode(value, validate=True)
    except (ValueError, base64.binascii.Error) as error:
        raise ContractViolation(f"{path}: invalid strict base64") from error
    if not decoded:
        raise ContractViolation(f"{path}: decoded bytes are empty")
    load_canonical_json(decoded)
    return decoded


@dataclass(frozen=True, slots=True)
class ReferenceQueryContext:
    """Frozen correlation context for byte-identical repeated reference reads."""

    trace_id: str
    query_command_id: str
    transaction_id: str
    assignment_id: str
    vm_id: str
    captured_at: str
    portable_contract_sha256: str

    def __post_init__(self) -> None:
        for field in (
            "trace_id",
            "query_command_id",
            "transaction_id",
            "assignment_id",
            "vm_id",
        ):
            _id(getattr(self, field), field)
        _timestamp(self.captured_at, "captured_at")
        _digest(self.portable_contract_sha256, "portable_contract_sha256")

    @property
    def selector(self) -> dict[str, object]:
        return {
            "selectorKind": "ASSIGNMENT",
            "assignmentId": self.assignment_id,
        }

    def request_envelope_bytes(self) -> bytes:
        return canonical_json_bytes(
            {
                "subjectType": "REFERENCE_QUERY_REQUEST_ENVELOPE",
                "schemaVersion": 1,
                "evidenceBoundary": REFERENCE_QUERY_EVIDENCE_BOUNDARY,
                "queryCommandId": self.query_command_id,
                "selector": self.selector,
                "vmId": self.vm_id,
            }
        )


@dataclass(frozen=True, slots=True)
class ReferenceQueryReadTrace:
    """Strict canonical shared ``DIRECTPATH_QUERY_READ_TRACE`` value."""

    _canonical_bytes: bytes

    @classmethod
    def from_wire(cls, value: object) -> "ReferenceQueryReadTrace":
        wire = _validate_trace(value)
        return cls(canonical_json_bytes(wire))

    @classmethod
    def from_canonical_bytes(
        cls,
        data: bytes | bytearray | memoryview,
    ) -> "ReferenceQueryReadTrace":
        return cls.from_wire(load_canonical_json(data))

    def to_wire(self) -> dict[str, object]:
        value = load_canonical_json(self._canonical_bytes)
        assert isinstance(value, dict)
        return value

    def to_canonical_bytes(self) -> bytes:
        return self._canonical_bytes

    @property
    def trace_digest(self) -> str:
        return str(self.to_wire()["traceDigest"])


@dataclass(frozen=True, slots=True)
class ReferenceDirectPathQueryResult:
    """Raw request/result/output bytes and the trace that binds all three."""

    request_envelope_bytes: bytes
    result_envelope_bytes: bytes
    output: ReferenceDeterministicQueryOutput
    trace: ReferenceQueryReadTrace

    def __post_init__(self) -> None:
        request = load_canonical_json(self.request_envelope_bytes)
        result = load_canonical_json(self.result_envelope_bytes)
        request = _closed(
            request,
            frozenset(
                {
                    "subjectType",
                    "schemaVersion",
                    "evidenceBoundary",
                    "queryCommandId",
                    "selector",
                    "vmId",
                }
            ),
            "requestEnvelope",
        )
        result = _closed(
            result,
            frozenset(
                {
                    "subjectType",
                    "schemaVersion",
                    "evidenceBoundary",
                    "queryCommandId",
                    "canonicalOutputBase64",
                    "canonicalOutputSha256",
                }
            ),
            "resultEnvelope",
        )
        if (
            request["subjectType"] != "REFERENCE_QUERY_REQUEST_ENVELOPE"
            or result["subjectType"] != "REFERENCE_QUERY_RESULT_ENVELOPE"
            or request["schemaVersion"] != 1
            or result["schemaVersion"] != 1
            or request["evidenceBoundary"] != REFERENCE_QUERY_EVIDENCE_BOUNDARY
            or result["evidenceBoundary"] != REFERENCE_QUERY_EVIDENCE_BOUNDARY
        ):
            raise ContractViolation("reference request/result envelope constants")
        decoded_output = _strict_base64_canonical_json(
            result["canonicalOutputBase64"],
            "resultEnvelope.canonicalOutputBase64",
        )
        if decoded_output != self.output.to_canonical_bytes():
            raise ContractViolation("resultEnvelope: output bytes mismatch")
        if result["canonicalOutputSha256"] != self.output.canonical_bytes_sha256:
            raise ContractViolation("resultEnvelope: output hash mismatch")
        trace = self.trace.to_wire()
        if trace["queryCommandId"] != request["queryCommandId"]:
            raise ContractViolation("trace/request queryCommandId mismatch")
        if trace["queryCommandId"] != result["queryCommandId"]:
            raise ContractViolation("trace/result queryCommandId mismatch")
        if trace["selector"] != request["selector"]:
            raise ContractViolation("trace/request selector mismatch")
        if trace["requestEnvelopeSha256"] != sha256_digest(self.request_envelope_bytes):
            raise ContractViolation("trace/request raw bytes hash mismatch")
        if trace["resultEnvelopeSha256"] != sha256_digest(self.result_envelope_bytes):
            raise ContractViolation("trace/result raw bytes hash mismatch")

    @property
    def canonical_output_bytes(self) -> bytes:
        return self.output.to_canonical_bytes()


class SqliteReferenceDirectPathQuery:
    """High-level schema-aligned query over a fresh mode=ro snapshot."""

    def __init__(self, database_path, **reader_options: object) -> None:
        self._reader = ReferenceSqliteSnapshotReader(
            database_path,
            **reader_options,
        )

    def query_directpath(
        self,
        context: ReferenceQueryContext,
    ) -> ReferenceDirectPathQueryResult:
        if not isinstance(context, ReferenceQueryContext):
            raise TypeError("context must be ReferenceQueryContext")
        raw = self._reader.read(context.vm_id)
        before_state = _build_read_state(raw.before, context.vm_id)
        after_state = _build_read_state(raw.after, context.vm_id)
        if canonical_json_bytes(before_state) != canonical_json_bytes(after_state):
            raise ContractViolation("reference query observed a mixed snapshot")
        output = _build_output(raw.before, str(before_state["stateDigest"]))
        request_bytes = context.request_envelope_bytes()
        result_bytes = canonical_json_bytes(
            {
                "subjectType": "REFERENCE_QUERY_RESULT_ENVELOPE",
                "schemaVersion": 1,
                "evidenceBoundary": REFERENCE_QUERY_EVIDENCE_BOUNDARY,
                "queryCommandId": context.query_command_id,
                "canonicalOutputBase64": _base64(output.to_canonical_bytes()),
                "canonicalOutputSha256": output.canonical_bytes_sha256,
            }
        )
        wire = _build_trace_wire(
            context,
            raw,
            before_state,
            after_state,
            output,
            request_bytes,
            result_bytes,
        )
        return ReferenceDirectPathQueryResult(
            request_envelope_bytes=request_bytes,
            result_envelope_bytes=result_bytes,
            output=output,
            trace=ReferenceQueryReadTrace.from_wire(wire),
        )


def parse_reference_query_read_trace(
    data: bytes | bytearray | memoryview,
) -> ReferenceQueryReadTrace:
    return ReferenceQueryReadTrace.from_canonical_bytes(data)


def _reference_row_instance(
    *,
    instance_kind: str,
    primary_key: Mapping[str, object],
    row_fields: Mapping[str, object],
    resource_version: int | None,
    generation: int | None,
) -> dict[str, object]:
    wire: dict[str, object] = {
        "subjectType": "REFERENCE_QUERY_OBSERVED_ROW",
        "schemaVersion": 1,
        "evidenceBoundary": REFERENCE_QUERY_EVIDENCE_BOUNDARY,
        "instanceKind": instance_kind,
        "primaryKey": _name_values(primary_key),
        "resourceVersionOrNull": resource_version,
        "generationOrNull": generation,
        "rowFields": _name_values(row_fields),
        "rowDigest": None,
    }
    wire["rowDigest"] = _null_domain_hash(
        _REFERENCE_ROW_DOMAIN,
        wire,
        "rowDigest",
    )
    return wire


def _observed_wrapper(
    *,
    instance_kind: str,
    observation_purpose: str,
    source_store: str,
    source_primary_key: Mapping[str, object],
    schema_ref: str,
    resource_version: int | None,
    generation: int | None,
    instance: Mapping[str, object],
) -> dict[str, object]:
    instance_bytes = canonical_json_bytes(instance)
    wire: dict[str, object] = {
        "instanceKind": instance_kind,
        "observationPurpose": observation_purpose,
        "sourceStore": source_store,
        "sourcePrimaryKey": _name_values(source_primary_key),
        "schemaRef": schema_ref,
        "resourceVersionOrNull": resource_version,
        "generationOrNull": generation,
        "canonicalInstanceBase64": _base64(instance_bytes),
        "instanceBytesSha256": sha256_digest(instance_bytes),
        "observationDigest": None,
    }
    wire["observationDigest"] = _null_domain_hash(
        _OBSERVATION_DOMAIN,
        wire,
        "observationDigest",
    )
    return wire


def _add_reference_observation(
    target: list[dict[str, object]],
    *,
    instance_kind: str,
    primary_key: Mapping[str, object],
    row_fields: Mapping[str, object],
    resource_version: int | None = None,
    generation: int | None = None,
    purpose: str = "DECISION_INPUT",
    source_store: str = "GLOBAL_REPOSITORY",
) -> None:
    instance = _reference_row_instance(
        instance_kind=instance_kind,
        primary_key=primary_key,
        row_fields=row_fields,
        resource_version=resource_version,
        generation=generation,
    )
    target.append(
        _observed_wrapper(
            instance_kind=instance_kind,
            observation_purpose=purpose,
            source_store=source_store,
            source_primary_key=primary_key,
            schema_ref=_REFERENCE_ROW_SCHEMA,
            resource_version=resource_version,
            generation=generation,
            instance=instance,
        )
    )


def _reference_host_snapshot_anchor_placeholder(
    raw: Mapping[str, object],
) -> dict[str, object]:
    """Derive a visibly non-authoritative reference-only anchor placeholder."""

    artifacts = {
        str(item["kind"]): item
        for item in raw["currentArtifacts"]
        if isinstance(item, Mapping)
    }
    observer = raw["observer"]
    inventory = artifacts["INVENTORY"]
    assert isinstance(observer, Mapping)
    anchor_subject = {
        "authorityBoundary": (
            "REFERENCE_DERIVED_PLACEHOLDER_NO_EXTERNAL_AUTHORITY"
        ),
        "productAuthorized": False,
        "hostId": observer["hostId"],
        "snapshotDigest": inventory["artifactDigest"],
        "inventoryBlobSha256": inventory["blobSha256"],
        "anchorVersion": inventory["sequence"],
        "anchorResourceVersion": inventory["resourceVersion"],
    }
    anchor_digest = sha256_digest(
        b"QMAN-DIRECTPATH/REFERENCE-HOST-SNAPSHOT-ANCHOR-PLACEHOLDER/V1\x00"
        + canonical_json_bytes(anchor_subject)
    )
    freshness_receipt_digest = sha256_digest(
        b"QMAN-DIRECTPATH/REFERENCE-HOST-SNAPSHOT-FRESHNESS-PLACEHOLDER/V1\x00"
        + canonical_json_bytes(
            {
                "anchorDigest": anchor_digest,
                "validUntil": inventory["validUntil"],
                "verifierNoncePresent": False,
                "productAuthorized": False,
            }
        )
    )
    binding_subject = {
        **anchor_subject,
        "anchorAuthorityId": (
            f"reference-no-external-anchor:{observer['hostId']}"
        ),
        "anchorDigest": anchor_digest,
        "freshnessReceiptDigest": freshness_receipt_digest,
    }
    return {
        **binding_subject,
        "bindingDigest": sha256_digest(
            b"QMAN-DIRECTPATH/REFERENCE-HOST-SNAPSHOT-BINDING-PLACEHOLDER/V1\x00"
            + canonical_json_bytes(binding_subject)
        ),
    }


def _build_observed_instances(raw: Mapping[str, object]) -> list[dict[str, object]]:
    observed: list[dict[str, object]] = []
    artifacts = {
        str(item["kind"]): item
        for item in raw["currentArtifacts"]
        if isinstance(item, Mapping)
    }
    observer = raw["observer"]
    controller = raw["controllerCurrent"]
    request = raw["requestCurrent"]
    availability = raw["availabilityAuthority"]
    assert isinstance(observer, Mapping)
    assert isinstance(controller, Mapping)
    assert isinstance(request, Mapping)
    assert isinstance(availability, Mapping)

    _add_reference_observation(
        observed,
        instance_kind="HOST_AUTHORITY",
        primary_key={"hostId": observer["hostId"]},
        row_fields={
            "hostId": observer["hostId"],
            "hostEpoch": observer["hostEpoch"],
            "kernelBootId": observer["kernelBootId"],
            "agentGeneration": observer["agentGeneration"],
            "resourceVersion": observer["resourceVersion"],
            "controllerGeneration": controller["controllerGeneration"],
            "authorityLeaseId": controller["authorityLeaseId"],
            "expiresAt": controller["expiresAt"],
            "currentSnapshotContentHash": artifacts["INVENTORY"]["artifactDigest"],
        },
        resource_version=int(observer["resourceVersion"]),
        generation=int(observer["hostEpoch"]),
    )
    policy = artifacts["POLICY"]
    _add_reference_observation(
        observed,
        instance_kind="CAPABILITY_POLICY_AUTHORITY",
        primary_key={"policyAuthorityId": policy["authorityId"]},
        row_fields={
            "policyAuthorityId": policy["authorityId"],
            "policyId": "reference-policy",
            "policyVersion": policy["sequence"],
            "policyDigest": policy["artifactDigest"],
            "resourceVersion": policy["resourceVersion"],
            "validUntil": policy["validUntil"],
        },
        resource_version=int(policy["resourceVersion"]),
    )
    _add_reference_observation(
        observed,
        instance_kind="AVAILABILITY_AUTHORITY",
        primary_key={"availabilityAuthorityId": availability["authorityId"]},
        row_fields={
            "authorityId": availability["authorityId"],
            "resourceVersion": availability["resourceVersion"],
        },
        resource_version=int(availability["resourceVersion"]),
    )
    for kind, instance_kind in (
        ("TRUST", "CURRENT_TRUST_POINTER"),
        ("CATALOG", "CURRENT_CATALOG_POINTER"),
        ("INVENTORY", "CURRENT_INVENTORY_POINTER"),
    ):
        artifact = artifacts[kind]
        aligned_fields: dict[str, object]
        if kind == "TRUST":
            aligned_fields = {
                "trustRootDigest": artifact["artifactDigest"],
                "keyRingSequence": artifact["sequence"],
                "keyRingDigest": artifact["artifactDigest"],
            }
        elif kind == "CATALOG":
            aligned_fields = {
                "catalogId": artifact["authorityId"],
                "catalogSequence": artifact["sequence"],
                "catalogDigest": artifact["artifactDigest"],
            }
        else:
            aligned_fields = {
                "inventoryVerificationReceiptDigest": artifact["artifactDigest"],
                "inventoryVerifierIdentityDigest": sha256_digest(
                    b"REFERENCE_SQLITE_INVENTORY_VERIFIER_V1"
                ),
            }
        _add_reference_observation(
            observed,
            instance_kind=instance_kind,
            primary_key={"authorityId": artifact["authorityId"]},
            row_fields={
                "kind": artifact["kind"],
                "sequence": artifact["sequence"],
                "artifactDigest": artifact["artifactDigest"],
                "validUntil": artifact["validUntil"],
                "blobSha256": artifact["blobSha256"],
                **aligned_fields,
            },
            resource_version=int(artifact["resourceVersion"]),
        )
    for kind, instance_kind, version_name, digest_name in (
        (
            "TRUST",
            "CURRENT_TRUST_ANCHOR",
            "trustAnchorVersion",
            "trustAnchorDigest",
        ),
        (
            "CATALOG",
            "CURRENT_CATALOG_ANCHOR",
            "catalogAnchorVersion",
            "catalogAnchorDigest",
        ),
    ):
        artifact = artifacts[kind]
        _add_reference_observation(
            observed,
            instance_kind=instance_kind,
            primary_key={version_name: artifact["sequence"]},
            row_fields={
                version_name: artifact["sequence"],
                digest_name: artifact["blobSha256"],
                "pointerArtifactDigest": artifact["artifactDigest"],
                "validUntil": artifact["validUntil"],
            },
            resource_version=int(artifact["resourceVersion"]),
        )
    anchor_placeholder = _reference_host_snapshot_anchor_placeholder(raw)
    _add_reference_observation(
        observed,
        instance_kind="HOST_SNAPSHOT_ANCHOR_BINDING",
        primary_key={
            "bindingDigest": anchor_placeholder["bindingDigest"],
        },
        row_fields=anchor_placeholder,
        source_store="VERIFIER_OUTPUT",
    )
    _add_reference_observation(
        observed,
        instance_kind="VM_REQUEST_OR_ASSIGNMENT",
        primary_key={"vmId": request["vmId"]},
        row_fields={
            "requestVersion": request["requestVersion"],
            "requestHash": request["requestHash"],
            "blobSha256": request["blobSha256"],
            "requestAuthorityId": (f"reference-request-authority:{request['vmId']}"),
            "requestReadSetDigest": sha256_digest(canonical_json_bytes(request)),
        },
        resource_version=int(request["resourceVersion"]),
    )
    _add_reference_observation(
        observed,
        instance_kind="HOST_SNAPSHOT",
        primary_key={
            "hostId": observer["hostId"],
            "snapshotSequence": artifacts["INVENTORY"]["sequence"],
        },
        row_fields={
            "hostId": observer["hostId"],
            "hostEpoch": observer["hostEpoch"],
            "kernelBootId": observer["kernelBootId"],
            "agentGeneration": observer["agentGeneration"],
            "contentHash": artifacts["INVENTORY"]["artifactDigest"],
            "validUntil": artifacts["INVENTORY"]["validUntil"],
        },
        resource_version=int(artifacts["INVENTORY"]["resourceVersion"]),
        generation=int(artifacts["INVENTORY"]["sequence"]),
    )
    for member in raw["availabilityMembers"]:
        assert isinstance(member, Mapping)
        _add_reference_observation(
            observed,
            instance_kind="DEVICE_RECORD",
            primary_key={"deviceUid": member["deviceId"]},
            row_fields={
                "deviceUid": member["deviceId"],
                "evidenceBlobHash": member["evidenceBlobHash"],
                "driverOrNull": None,
                "ownerState": "REFERENCE_UNKNOWN",
                "lastResetResult": "UNKNOWN",
                "resetContractDigest": sha256_digest(
                    canonical_json_bytes(
                        {
                            "referenceResetContract": "UNKNOWN",
                            "deviceUid": member["deviceId"],
                        }
                    )
                ),
            },
            resource_version=int(member["resourceVersion"]),
            generation=int(member["generation"]),
        )
    for membership in raw["bundleMembers"]:
        assert isinstance(membership, Mapping)
        _add_reference_observation(
            observed,
            instance_kind="DEPENDENCY_BUNDLE",
            primary_key={
                "bundleId": membership["bundleId"],
                "deviceUid": membership["deviceId"],
            },
            row_fields={
                "bundleId": membership["bundleId"],
                "deviceUid": membership["deviceId"],
            },
        )
    for claim in raw["bundleClaims"]:
        assert isinstance(claim, Mapping)
        _add_reference_observation(
            observed,
            instance_kind="BUNDLE_LEASE",
            primary_key={"leaseId": claim["leaseId"]},
            row_fields=dict(claim),
            resource_version=int(claim["resourceVersion"]),
        )
    for lease in raw["operationLeases"]:
        assert isinstance(lease, Mapping)
        _add_reference_observation(
            observed,
            instance_kind="OPERATION_LEASE",
            primary_key={"operationLeaseId": lease["operationLeaseId"]},
            row_fields=dict(lease),
            resource_version=int(lease["resourceVersion"]),
            generation=int(lease["runGeneration"]),
        )
    for quarantine in raw["quarantines"]:
        assert isinstance(quarantine, Mapping)
        _add_reference_observation(
            observed,
            instance_kind="QUARANTINE_RECORD",
            primary_key={"conflictKey": quarantine["conflictKey"]},
            row_fields=dict(quarantine),
            resource_version=int(quarantine["resourceVersion"]),
        )

    journal = {
        "subjectType": "HOST_JOURNAL_HEAD",
        "schemaVersion": 1,
        "hostId": observer["hostId"],
        "kernelBootId": observer["kernelBootId"],
        "hostEpoch": observer["hostEpoch"],
        "journalEpoch": observer["journalEpoch"],
        "sequence": observer["hostJournalSequence"],
        "entryHash": observer["observationDigest"],
    }
    observed.append(
        _observed_wrapper(
            instance_kind="HOST_JOURNAL_HEAD",
            observation_purpose="NON_MUTATION_ORACLE",
            source_store="HOST_OBSERVER",
            source_primary_key={
                "hostId": observer["hostId"],
                "hostEpoch": observer["hostEpoch"],
                "journalEpoch": observer["journalEpoch"],
            },
            schema_ref=_HOST_JOURNAL_SCHEMA,
            resource_version=None,
            generation=int(observer["hostEpoch"]),
            instance=journal,
        )
    )
    counter_values = {
        "DRIVER_BIND": observer["driverBindCount"],
        "DRIVER_UNBIND": observer["driverUnbindCount"],
        "DEVICE_RESET": observer["deviceResetCount"],
        "VFIO_EXCLUSIVE_OPEN": observer["vfioExclusiveOpenCount"],
        "QEMU_SPAWN": observer["qemuSpawnCount"],
        "HOST_JOURNAL_APPEND": observer["hostJournalSequence"],
    }
    for counter_kind, value in counter_values.items():
        counter = {
            "subjectType": "HOST_SIDE_EFFECT_COUNTER",
            "schemaVersion": 1,
            "hostId": observer["hostId"],
            "kernelBootId": observer["kernelBootId"],
            "agentGeneration": observer["agentGeneration"],
            "counterEpoch": observer["counterEpoch"],
            "counterKind": counter_kind,
            "value": value,
        }
        observed.append(
            _observed_wrapper(
                instance_kind="HOST_SIDE_EFFECT_COUNTER",
                observation_purpose="NON_MUTATION_ORACLE",
                source_store="HOST_OBSERVER",
                source_primary_key={
                    "hostId": observer["hostId"],
                    "counterEpoch": observer["counterEpoch"],
                    "counterKind": counter_kind,
                },
                schema_ref=_HOST_COUNTER_SCHEMA,
                resource_version=None,
                generation=int(observer["agentGeneration"]),
                instance=counter,
            )
        )
    for member in raw["availabilityMembers"]:
        assert isinstance(member, Mapping)
        reset = {
            "subjectType": "RESET_OBSERVATION",
            "schemaVersion": 1,
            "hostId": observer["hostId"],
            "kernelBootId": observer["kernelBootId"],
            "agentGeneration": observer["agentGeneration"],
            "observerId": observer["resetObserverId"],
            "observerEpoch": observer["restartGeneration"],
            "memberDeviceUid": member["deviceId"],
            "resetOccurrenceCount": observer["deviceResetCount"],
            "lastResetAtOrNull": None,
            "lastResetResultOrNull": (
                None if observer["deviceResetCount"] == 0 else "UNKNOWN"
            ),
        }
        observed.append(
            _observed_wrapper(
                instance_kind="RESET_OBSERVATION",
                observation_purpose="NON_MUTATION_ORACLE",
                source_store="HOST_OBSERVER",
                source_primary_key={
                    "observerId": observer["resetObserverId"],
                    "memberDeviceUid": member["deviceId"],
                },
                schema_ref=_RESET_OBSERVATION_SCHEMA,
                resource_version=None,
                generation=int(observer["restartGeneration"]),
                instance=reset,
            )
        )
    observed.sort(key=canonical_json_bytes)
    _canonical_set(observed, "observedInstances")
    digests = [item["observationDigest"] for item in observed]
    if len(digests) != len(set(digests)):
        raise ContractViolation("observedInstances: duplicate observationDigest")
    return observed


def _build_current_authority_vector(raw: Mapping[str, object]) -> dict[str, object]:
    artifacts = {
        str(item["kind"]): item
        for item in raw["currentArtifacts"]
        if isinstance(item, Mapping)
    }
    observer = raw["observer"]
    request = raw["requestCurrent"]
    availability = raw["availabilityAuthority"]
    assert isinstance(observer, Mapping)
    assert isinstance(request, Mapping)
    assert isinstance(availability, Mapping)
    policy = artifacts["POLICY"]
    trust = artifacts["TRUST"]
    catalog = artifacts["CATALOG"]
    inventory = artifacts["INVENTORY"]
    host_snapshot_anchor = _reference_host_snapshot_anchor_placeholder(raw)
    availability_read_set = {
        "availabilityAuthority": availability,
        "availabilityMembers": raw["availabilityMembers"],
        "bundleMembers": raw["bundleMembers"],
        "bundleClaims": raw["bundleClaims"],
        "operationLeases": raw["operationLeases"],
        "quarantines": raw["quarantines"],
    }
    return {
        "subjectType": "CURRENT_AUTHORITY_VECTOR",
        "schemaVersion": 1,
        "hostAuthorityId": observer["hostId"],
        "hostAuthorityResourceVersion": observer["resourceVersion"],
        "publisherSnapshotDigest": inventory["artifactDigest"],
        "hostSnapshotAnchorAuthorityId": host_snapshot_anchor[
            "anchorAuthorityId"
        ],
        "hostSnapshotAnchorVersion": host_snapshot_anchor["anchorVersion"],
        "hostSnapshotAnchorResourceVersion": host_snapshot_anchor[
            "anchorResourceVersion"
        ],
        "hostSnapshotAnchorDigest": host_snapshot_anchor["anchorDigest"],
        "hostSnapshotAnchorFreshnessReceiptDigest": host_snapshot_anchor[
            "freshnessReceiptDigest"
        ],
        "hostSnapshotAnchorBindingDigest": host_snapshot_anchor[
            "bindingDigest"
        ],
        "policyAuthorityId": policy["authorityId"],
        "policyId": "reference-policy",
        "policyVersion": policy["sequence"],
        "policyDigest": policy["artifactDigest"],
        "policyAuthorityResourceVersion": policy["resourceVersion"],
        "trustRootDigest": trust["artifactDigest"],
        "keyRingSequence": trust["sequence"],
        "keyRingDigest": trust["artifactDigest"],
        "trustAnchorVersion": trust["sequence"],
        "trustAnchorDigest": trust["blobSha256"],
        "catalogId": catalog["authorityId"],
        "catalogSequence": catalog["sequence"],
        "catalogDigest": catalog["artifactDigest"],
        "catalogAnchorVersion": catalog["sequence"],
        "catalogAnchorDigest": catalog["blobSha256"],
        "availabilityAuthorityId": availability["authorityId"],
        "availabilityAuthorityResourceVersion": availability["resourceVersion"],
        "availabilityReadSetDigest": sha256_digest(
            canonical_json_bytes(availability_read_set)
        ),
        "requestAuthorityId": f"reference-request-authority:{request['vmId']}",
        "requestReadSetDigest": sha256_digest(canonical_json_bytes(request)),
        "inventoryVerificationReceiptDigest": inventory["artifactDigest"],
        "inventoryVerifierIdentityDigest": sha256_digest(
            b"REFERENCE_SQLITE_INVENTORY_VERIFIER_V1"
        ),
        "evidenceValidUntil": min(
            str(item["validUntil"]) for item in artifacts.values()
        ),
    }


def _predicate_parameters(
    predicate_id: str,
    raw: Mapping[str, object],
    vm_id: str,
) -> dict[str, object]:
    observer = raw["observer"]
    assert isinstance(observer, Mapping)
    if predicate_id == "CURRENT_AUTHORITY_BY_FIXED_KEYS":
        return {"hostId": observer["hostId"], "vmId": vm_id}
    if predicate_id == "CURRENT_HOST_SNAPSHOT_BY_POINTER":
        return {
            "hostId": observer["hostId"],
            "inventoryPointerDigest": sha256_digest(
                canonical_json_bytes(raw["inventoryCurrent"])
            ),
        }
    availability_members = [
        {
            "deviceId": item["deviceId"],
            "generation": item["generation"],
            "resourceVersion": item["resourceVersion"],
            "evidenceBlobHash": item["evidenceBlobHash"],
        }
        for item in raw["availabilityMembers"]
        if isinstance(item, Mapping)
    ]
    availability_members.sort(key=canonical_json_bytes)
    bundle_members = [
        {
            "bundleId": item["bundleId"],
            "deviceId": item["deviceId"],
        }
        for item in raw["bundleMembers"]
        if isinstance(item, Mapping)
    ]
    bundle_members.sort(key=canonical_json_bytes)
    selected_projection = {
        "bundleMembers": bundle_members,
        "availabilityMembers": availability_members,
    }
    if predicate_id == "DEVICE_RECORDS_BY_COMPLETE_BUNDLE":
        return {
            "bundleProjectionDigest": sha256_digest(
                canonical_json_bytes(selected_projection)
            )
        }
    if predicate_id in {
        "ACTIVE_BUNDLE_LEASES_OVERLAPPING_BUNDLE_OR_MEMBER",
        "ACTIVE_OPERATION_LEASES_OVERLAPPING_SCOPE_BUNDLE_OR_MEMBER",
        "UNCLEARED_QUARANTINES_OVERLAPPING_BUNDLE_OR_MEMBER",
    }:
        return {
            "selectedScopeDigest": sha256_digest(
                canonical_json_bytes(selected_projection)
            )
        }
    if predicate_id == "HOST_JOURNAL_HEAD_BY_HOST_EPOCH":
        return {
            "hostEpoch": observer["hostEpoch"],
            "hostId": observer["hostId"],
        }
    if predicate_id == "HOST_SIDE_EFFECT_COUNTERS_BY_AGENT_EPOCH":
        return {
            "agentGeneration": observer["agentGeneration"],
            "counterEpoch": observer["counterEpoch"],
            "hostId": observer["hostId"],
        }
    return {
        "memberSetDigest": sha256_digest(
            canonical_json_bytes([item["deviceId"] for item in availability_members])
        )
    }


def _build_predicates(
    raw: Mapping[str, object],
    vm_id: str,
    observed: Sequence[Mapping[str, object]],
) -> list[dict[str, object]]:
    by_kind: defaultdict[str, list[str]] = defaultdict(list)
    availability_observations = []
    for item in observed:
        kind = str(item["instanceKind"])
        digest = str(item["observationDigest"])
        by_kind[kind].append(digest)
        if kind == "AVAILABILITY_AUTHORITY":
            availability_observations.append(digest)
    if len(availability_observations) != 1:
        raise ContractViolation(
            "exactly one AVAILABILITY_AUTHORITY observation is required"
        )
    availability = raw["availabilityAuthority"]
    assert isinstance(availability, Mapping)
    result: list[dict[str, object]] = []
    for predicate_id, kinds in _PREDICATE_KINDS.items():
        matched = sorted(
            {digest for kind in kinds for digest in by_kind.get(kind, ())},
            key=canonical_json_bytes,
        )
        fence: dict[str, object]
        if predicate_id in _AVAILABILITY_PREDICATES:
            fence = {
                "fenceKind": "GLOBAL_AVAILABILITY_AUTHORITY",
                "availabilityAuthorityId": availability["authorityId"],
                "availabilityAuthorityResourceVersion": availability["resourceVersion"],
                "authorityObservationDigest": availability_observations[0],
            }
        else:
            fence = {"fenceKind": "NOT_APPLICABLE"}
        predicate: dict[str, object] = {
            "predicateId": predicate_id,
            "closedParameters": _name_values(
                _predicate_parameters(predicate_id, raw, vm_id)
            ),
            "matchedInstanceDigests": matched,
            "fence": fence,
            "predicateDigest": None,
        }
        predicate["predicateDigest"] = _null_domain_hash(
            _PREDICATE_DOMAIN,
            predicate,
            "predicateDigest",
        )
        result.append(predicate)
    result.sort(key=canonical_json_bytes)
    return result


def _build_read_state(
    raw: Mapping[str, object],
    vm_id: str,
) -> dict[str, object]:
    observed = _build_observed_instances(raw)
    authority = _build_current_authority_vector(raw)
    observer = raw["observer"]
    assert isinstance(observer, Mapping)
    active_scope_hashes = sorted(
        {
            str(item["scopeHash"])
            for item in raw["operationLeases"]
            if isinstance(item, Mapping)
        },
        key=canonical_json_bytes,
    )
    if len(active_scope_hashes) > 1:
        raise ContractViolation(
            "reference assignment selector resolves multiple active scope hashes"
        )
    selected_scope = {
        "scopeHashOrNull": (active_scope_hashes[0] if active_scope_hashes else None),
        "bundleIds": sorted(
            {
                str(item["bundleId"])
                for item in raw["bundleMembers"]
                if isinstance(item, Mapping)
            },
            key=canonical_json_bytes,
        ),
        "memberDeviceUids": sorted(
            {
                str(item["deviceId"])
                for item in raw["availabilityMembers"]
                if isinstance(item, Mapping)
            },
            key=canonical_json_bytes,
        ),
        "hostIds": [observer["hostId"]],
    }
    state: dict[str, object] = {
        "repositoryCommitClock": raw["repositoryCommitClock"],
        "currentAuthorityVector": authority,
        "currentAuthorityVectorBytesSha256": sha256_digest(
            canonical_json_bytes(authority)
        ),
        "selectedScope": selected_scope,
        "observedInstances": observed,
        "predicateObservations": _build_predicates(
            raw,
            vm_id,
            observed,
        ),
        "stateDigest": None,
    }
    state["stateDigest"] = _null_domain_hash(
        _STATE_DOMAIN,
        state,
        "stateDigest",
    )
    return state


def _build_output(
    raw: Mapping[str, object],
    query_state_hash: str,
) -> ReferenceDeterministicQueryOutput:
    members_by_bundle: defaultdict[str, list[str]] = defaultdict(list)
    for item in raw["bundleMembers"]:
        assert isinstance(item, Mapping)
        members_by_bundle[str(item["bundleId"])].append(str(item["deviceId"]))
    claims = {
        str(item["bundleId"]): item
        for item in raw["bundleClaims"]
        if isinstance(item, Mapping)
    }
    quarantine_keys = {
        str(item["conflictKey"])
        for item in raw["quarantines"]
        if isinstance(item, Mapping)
    }
    active_scopes = {
        str(item["scopeHash"])
        for item in raw["operationLeases"]
        if isinstance(item, Mapping)
    }
    summaries = []
    for bundle_id, member_ids in members_by_bundle.items():
        member_ids = sorted(set(member_ids), key=canonical_json_bytes)
        overlap = {bundle_id, *member_ids, *active_scopes}
        if quarantine_keys & overlap:
            state = "QUARANTINED"
        elif bundle_id in claims:
            state = "RESERVED"
        else:
            state = "FREE"
        summaries.append(
            {
                "bundleId": bundle_id,
                "memberDeviceUids": member_ids,
                "state": state,
            }
        )
    summaries.sort(key=canonical_json_bytes)
    lease_summaries = [
        {
            "leaseId": item["leaseId"],
            "bundleId": item["bundleId"],
            "runId": item["runId"],
            "resourceVersion": item["resourceVersion"],
            "state": "ACTIVE",
        }
        for item in raw["bundleClaims"]
        if isinstance(item, Mapping)
    ]
    lease_summaries.sort(key=canonical_json_bytes)
    if any(item["state"] == "QUARANTINED" for item in summaries):
        assignment_state = "QUARANTINED"
    elif raw["assignmentRuns"]:
        assignment_state = "PREPARING"
    elif summaries:
        assignment_state = "FREE"
    else:
        assignment_state = "ABSENT"
    if not summaries:
        available = "UNKNOWN"
    elif all(item["state"] == "FREE" for item in summaries):
        available = "YES"
    else:
        available = "NO"
    capability_status = {
        "hardwareCapable": "UNKNOWN",
        "technicallyAttachable": "UNKNOWN",
        "eligible": "UNKNOWN",
        "available": available,
        "qualified": "UNKNOWN",
        "supported": "UNKNOWN",
        "assignmentState": assignment_state,
    }
    reasons = [
        {
            "code": "REFERENCE_COMPONENT_ONLY",
            "stableMessageId": "REFERENCE.QUERY.COMPONENT_ONLY",
            "detailBindings": [
                {
                    "name": "evidenceBoundary",
                    "valueHash": sha256_digest(
                        REFERENCE_QUERY_EVIDENCE_BOUNDARY.encode("ascii")
                    ),
                }
            ],
        }
    ]
    return ReferenceDeterministicQueryOutput.create(
        capability_status=capability_status,
        bundle_summaries=summaries,
        lease_summaries=lease_summaries,
        reasons=reasons,
        evidence_refs=[],
        query_state_hash=query_state_hash,
    )


def _observation_set_digest(
    state: Mapping[str, object],
    kinds: frozenset[str],
) -> str:
    values = sorted(
        {
            str(item["observationDigest"])
            for item in state["observedInstances"]
            if isinstance(item, Mapping) and item["instanceKind"] in kinds
        },
        key=canonical_json_bytes,
    )
    return sha256_digest(canonical_json_bytes(values))


def _build_trace_wire(
    context: ReferenceQueryContext,
    raw: ReferenceRawQueryRead,
    before_state: dict[str, object],
    after_state: dict[str, object],
    output: ReferenceDeterministicQueryOutput,
    request_bytes: bytes,
    result_bytes: bytes,
) -> dict[str, object]:
    output_bytes = output.to_canonical_bytes()
    target_projection = {
        "repositoryInstanceId": raw.store_instance_id,
        "repositoryCommitClock": before_state["repositoryCommitClock"],
        "repositoryCommitHead": raw.before["repositoryCommitHead"],
    }
    wire: dict[str, object] = {
        "subjectType": REFERENCE_QUERY_READ_TRACE,
        "schemaVersion": 1,
        "evidenceBoundary": REFERENCE_QUERY_EVIDENCE_BOUNDARY,
        "operationId": "OP-QUERY-DIRECTPATH",
        "traceId": context.trace_id,
        "queryCommandId": context.query_command_id,
        "targetRepositoryCommit": sha256_digest(
            canonical_json_bytes(target_projection)
        ),
        "portableContractSha256": context.portable_contract_sha256,
        "requestEnvelopeSha256": sha256_digest(request_bytes),
        "resultEnvelopeSha256": sha256_digest(result_bytes),
        "selector": context.selector,
        "repositoryTransaction": {
            "repositoryInstanceId": raw.store_instance_id,
            "transactionId": context.transaction_id,
            "isolationMode": "SQLITE_WAL_READ_TRANSACTION",
            "databaseEnforcedReadOnly": True,
            "snapshotToken": sha256_digest(raw.before_bytes),
        },
        "before": {
            "capturedAt": context.captured_at,
            "state": before_state,
        },
        "after": {
            "capturedAt": context.captured_at,
            "state": after_state,
        },
        "outputInstance": {
            "schemaRef": (
                "contracts/directpath-operation-payload.schema.json"
                "#/$defs/output_OP_QUERY_DIRECTPATH"
            ),
            "canonicalOutputBase64": _base64(output_bytes),
            "canonicalBytesSha256": output.canonical_bytes_sha256,
            "capabilityDecisionHash": output.capability_decision_hash,
            "semanticDependencyHash": output.semantic_dependency_hash,
            "queryStateHash": output.query_state_hash,
        },
        "zeroWriteWitness": {
            "queryTransactionId": context.transaction_id,
            "databaseEnforcedReadOnly": True,
            "writeStatementCount": 0,
            "affectedRowCount": 0,
            "repositoryMutationInstances": [],
            "hostSideEffectInvocations": [],
            "commitClockBefore": before_state["repositoryCommitClock"],
            "commitClockAfter": after_state["repositoryCommitClock"],
            "journalHeadBeforeDigest": _observation_set_digest(
                before_state,
                frozenset({"HOST_JOURNAL_HEAD"}),
            ),
            "journalHeadAfterDigest": _observation_set_digest(
                after_state,
                frozenset({"HOST_JOURNAL_HEAD"}),
            ),
            "sideEffectCounterVectorBeforeDigest": _observation_set_digest(
                before_state,
                frozenset({"HOST_SIDE_EFFECT_COUNTER", "RESET_OBSERVATION"}),
            ),
            "sideEffectCounterVectorAfterDigest": _observation_set_digest(
                after_state,
                frozenset({"HOST_SIDE_EFFECT_COUNTER", "RESET_OBSERVATION"}),
            ),
        },
        "traceDigest": None,
    }
    wire["traceDigest"] = _null_domain_hash(
        _TRACE_DOMAIN,
        wire,
        "traceDigest",
    )
    return wire


def _validate_observed_instance(
    value: object,
    path: str,
) -> Mapping[str, object]:
    fields = frozenset(
        {
            "instanceKind",
            "observationPurpose",
            "sourceStore",
            "sourcePrimaryKey",
            "schemaRef",
            "resourceVersionOrNull",
            "generationOrNull",
            "canonicalInstanceBase64",
            "instanceBytesSha256",
            "observationDigest",
        }
    )
    raw = _closed(value, fields, path)
    instance_bytes = _strict_base64_canonical_json(
        raw["canonicalInstanceBase64"],
        f"{path}.canonicalInstanceBase64",
    )
    if raw["instanceBytesSha256"] != sha256_digest(instance_bytes):
        raise ContractViolation(f"{path}.instanceBytesSha256: mismatch")
    expected_observation = _null_domain_hash(
        _OBSERVATION_DOMAIN,
        raw,
        "observationDigest",
    )
    if raw["observationDigest"] != expected_observation:
        raise ContractViolation(f"{path}.observationDigest: mismatch")
    instance = load_canonical_json(instance_bytes)
    if raw["schemaRef"] == _REFERENCE_ROW_SCHEMA:
        reference = _closed(
            instance,
            frozenset(
                {
                    "subjectType",
                    "schemaVersion",
                    "evidenceBoundary",
                    "instanceKind",
                    "primaryKey",
                    "resourceVersionOrNull",
                    "generationOrNull",
                    "rowFields",
                    "rowDigest",
                }
            ),
            f"{path}.referenceObservedRow",
        )
        if (
            reference["subjectType"] != "REFERENCE_QUERY_OBSERVED_ROW"
            or reference["schemaVersion"] != 1
            or reference["evidenceBoundary"]
            != "REFERENCE_SQLITE_QUERY_TRANSACTION_COMPONENT_ONLY"
            or reference["instanceKind"] != raw["instanceKind"]
            or reference["primaryKey"] != raw["sourcePrimaryKey"]
            or reference["resourceVersionOrNull"] != raw["resourceVersionOrNull"]
            or reference["generationOrNull"] != raw["generationOrNull"]
        ):
            raise ContractViolation(f"{path}: reference row wrapper mismatch")
        expected_row = _null_domain_hash(
            _REFERENCE_ROW_DOMAIN,
            reference,
            "rowDigest",
        )
        if reference["rowDigest"] != expected_row:
            raise ContractViolation(f"{path}: reference rowDigest mismatch")
    return raw


def _validate_state(value: object, path: str) -> Mapping[str, object]:
    fields = frozenset(
        {
            "repositoryCommitClock",
            "currentAuthorityVector",
            "currentAuthorityVectorBytesSha256",
            "selectedScope",
            "observedInstances",
            "predicateObservations",
            "stateDigest",
        }
    )
    raw = _closed(value, fields, path)
    _nonnegative(raw["repositoryCommitClock"], f"{path}.repositoryCommitClock")
    authority = raw["currentAuthorityVector"]
    if not isinstance(authority, Mapping):
        raise ContractViolation(f"{path}.currentAuthorityVector: expected object")
    if raw["currentAuthorityVectorBytesSha256"] != sha256_digest(
        canonical_json_bytes(authority)
    ):
        raise ContractViolation(f"{path}.currentAuthorityVector hash mismatch")
    observed = raw["observedInstances"]
    if not isinstance(observed, list) or not observed:
        raise ContractViolation(f"{path}.observedInstances: non-empty array required")
    _canonical_set(observed, f"{path}.observedInstances")
    wrappers = [
        _validate_observed_instance(item, f"{path}.observedInstances[{index}]")
        for index, item in enumerate(observed)
    ]
    observation_digests = [str(item["observationDigest"]) for item in wrappers]
    if len(observation_digests) != len(set(observation_digests)):
        raise ContractViolation(f"{path}.observedInstances: digest collision")
    predicates = raw["predicateObservations"]
    if not isinstance(predicates, list) or len(predicates) != 9:
        raise ContractViolation(f"{path}.predicateObservations: exactly nine required")
    _canonical_set(predicates, f"{path}.predicateObservations")
    by_kind: defaultdict[str, set[str]] = defaultdict(set)
    for wrapper in wrappers:
        by_kind[str(wrapper["instanceKind"])].add(str(wrapper["observationDigest"]))
    seen_predicates = set()
    availability_digests = by_kind["AVAILABILITY_AUTHORITY"]
    if len(availability_digests) != 1:
        raise ContractViolation(f"{path}: availability authority observation")
    for index, item in enumerate(predicates):
        predicate = _closed(
            item,
            frozenset(
                {
                    "predicateId",
                    "closedParameters",
                    "matchedInstanceDigests",
                    "fence",
                    "predicateDigest",
                }
            ),
            f"{path}.predicateObservations[{index}]",
        )
        predicate_id = str(predicate["predicateId"])
        if predicate_id not in _PREDICATE_KINDS or predicate_id in seen_predicates:
            raise ContractViolation(f"{path}: invalid/duplicate predicateId")
        seen_predicates.add(predicate_id)
        expected_matches = sorted(
            {
                digest
                for kind in _PREDICATE_KINDS[predicate_id]
                for digest in by_kind[kind]
            },
            key=canonical_json_bytes,
        )
        if predicate["matchedInstanceDigests"] != expected_matches:
            raise ContractViolation(f"{path}.{predicate_id}: match set mismatch")
        expected_digest = _null_domain_hash(
            _PREDICATE_DOMAIN,
            predicate,
            "predicateDigest",
        )
        if predicate["predicateDigest"] != expected_digest:
            raise ContractViolation(f"{path}.{predicate_id}: digest mismatch")
        fence = predicate["fence"]
        if predicate_id in _AVAILABILITY_PREDICATES:
            if (
                not isinstance(fence, Mapping)
                or fence.get("fenceKind") != "GLOBAL_AVAILABILITY_AUTHORITY"
                or fence.get("authorityObservationDigest")
                != next(iter(availability_digests))
            ):
                raise ContractViolation(f"{path}.{predicate_id}: fence mismatch")
        elif fence != {"fenceKind": "NOT_APPLICABLE"}:
            raise ContractViolation(f"{path}.{predicate_id}: unexpected fence")
    if seen_predicates != set(_PREDICATE_KINDS):
        raise ContractViolation(f"{path}: incomplete predicate set")
    expected_state = _null_domain_hash(_STATE_DOMAIN, raw, "stateDigest")
    if raw["stateDigest"] != expected_state:
        raise ContractViolation(f"{path}.stateDigest: mismatch")
    return raw


def _validate_trace(value: object) -> dict[str, object]:
    fields = frozenset(
        {
            "subjectType",
            "schemaVersion",
            "evidenceBoundary",
            "operationId",
            "traceId",
            "queryCommandId",
            "targetRepositoryCommit",
            "portableContractSha256",
            "requestEnvelopeSha256",
            "resultEnvelopeSha256",
            "selector",
            "repositoryTransaction",
            "before",
            "after",
            "outputInstance",
            "zeroWriteWitness",
            "traceDigest",
        }
    )
    raw = _closed(value, fields, "trace")
    if (
        raw["subjectType"] != "DIRECTPATH_QUERY_READ_TRACE"
        or raw["schemaVersion"] != 1
        or raw["evidenceBoundary"]
        != "REFERENCE_SQLITE_QUERY_TRANSACTION_COMPONENT_ONLY"
        or raw["operationId"] != "OP-QUERY-DIRECTPATH"
    ):
        raise ContractViolation("trace: constant field mismatch")
    for field in ("traceId", "queryCommandId"):
        _id(raw[field], f"trace.{field}")
    for field in (
        "targetRepositoryCommit",
        "portableContractSha256",
        "requestEnvelopeSha256",
        "resultEnvelopeSha256",
        "traceDigest",
    ):
        _digest(raw[field], f"trace.{field}")
    selector = _closed(
        raw["selector"],
        frozenset({"selectorKind", "assignmentId"}),
        "trace.selector",
    )
    if selector["selectorKind"] != "ASSIGNMENT":
        raise ContractViolation("trace.selector.selectorKind")
    _id(selector["assignmentId"], "trace.selector.assignmentId")
    transaction = _closed(
        raw["repositoryTransaction"],
        frozenset(
            {
                "repositoryInstanceId",
                "transactionId",
                "isolationMode",
                "databaseEnforcedReadOnly",
                "snapshotToken",
            }
        ),
        "trace.repositoryTransaction",
    )
    if (
        transaction["isolationMode"] != "SQLITE_WAL_READ_TRANSACTION"
        or transaction["databaseEnforcedReadOnly"] is not True
    ):
        raise ContractViolation("trace.repositoryTransaction: profile mismatch")
    _id(
        transaction["repositoryInstanceId"],
        "trace.repositoryTransaction.repositoryInstanceId",
    )
    _id(transaction["transactionId"], "trace.repositoryTransaction.transactionId")
    _digest(transaction["snapshotToken"], "trace.repositoryTransaction.snapshotToken")
    observations = []
    for field in ("before", "after"):
        capture = _closed(
            raw[field],
            frozenset({"capturedAt", "state"}),
            f"trace.{field}",
        )
        _timestamp(capture["capturedAt"], f"trace.{field}.capturedAt")
        observations.append(_validate_state(capture["state"], f"trace.{field}.state"))
    if canonical_json_bytes(observations[0]) != canonical_json_bytes(observations[1]):
        raise ContractViolation("trace.before/after state mismatch")
    state = observations[0]
    output_instance = _closed(
        raw["outputInstance"],
        frozenset(
            {
                "schemaRef",
                "canonicalOutputBase64",
                "canonicalBytesSha256",
                "capabilityDecisionHash",
                "semanticDependencyHash",
                "queryStateHash",
            }
        ),
        "trace.outputInstance",
    )
    if output_instance["schemaRef"] != (
        "contracts/directpath-operation-payload.schema.json"
        "#/$defs/output_OP_QUERY_DIRECTPATH"
    ):
        raise ContractViolation("trace.outputInstance.schemaRef")
    output_bytes = _strict_base64_canonical_json(
        output_instance["canonicalOutputBase64"],
        "trace.outputInstance.canonicalOutputBase64",
    )
    output = ReferenceDeterministicQueryOutput.from_canonical_bytes(output_bytes)
    if (
        output_instance["canonicalBytesSha256"] != output.canonical_bytes_sha256
        or output_instance["capabilityDecisionHash"] != output.capability_decision_hash
        or output_instance["semanticDependencyHash"] != output.semantic_dependency_hash
        or output_instance["queryStateHash"] != output.query_state_hash
        or output.query_state_hash != state["stateDigest"]
    ):
        raise ContractViolation("trace.outputInstance: binding mismatch")
    zero = _closed(
        raw["zeroWriteWitness"],
        frozenset(
            {
                "queryTransactionId",
                "databaseEnforcedReadOnly",
                "writeStatementCount",
                "affectedRowCount",
                "repositoryMutationInstances",
                "hostSideEffectInvocations",
                "commitClockBefore",
                "commitClockAfter",
                "journalHeadBeforeDigest",
                "journalHeadAfterDigest",
                "sideEffectCounterVectorBeforeDigest",
                "sideEffectCounterVectorAfterDigest",
            }
        ),
        "trace.zeroWriteWitness",
    )
    if (
        zero["queryTransactionId"] != transaction["transactionId"]
        or zero["databaseEnforcedReadOnly"] is not True
        or zero["writeStatementCount"] != 0
        or zero["affectedRowCount"] != 0
        or zero["repositoryMutationInstances"] != []
        or zero["hostSideEffectInvocations"] != []
        or zero["commitClockBefore"] != state["repositoryCommitClock"]
        or zero["commitClockAfter"] != state["repositoryCommitClock"]
        or zero["journalHeadBeforeDigest"] != zero["journalHeadAfterDigest"]
        or zero["sideEffectCounterVectorBeforeDigest"]
        != zero["sideEffectCounterVectorAfterDigest"]
    ):
        raise ContractViolation("trace.zeroWriteWitness: mismatch")
    expected_journal = _observation_set_digest(
        state,
        frozenset({"HOST_JOURNAL_HEAD"}),
    )
    expected_counters = _observation_set_digest(
        state,
        frozenset({"HOST_SIDE_EFFECT_COUNTER", "RESET_OBSERVATION"}),
    )
    if (
        zero["journalHeadBeforeDigest"] != expected_journal
        or zero["sideEffectCounterVectorBeforeDigest"] != expected_counters
    ):
        raise ContractViolation("trace.zeroWriteWitness: oracle digest mismatch")
    expected_trace = _null_domain_hash(_TRACE_DOMAIN, raw, "traceDigest")
    if not hmac.compare_digest(str(raw["traceDigest"]), expected_trace):
        raise ContractViolation("trace.traceDigest: mismatch")
    return dict(raw)


__all__ = [
    "REFERENCE_QUERY_READ_TRACE",
    "ReferenceDirectPathQueryResult",
    "ReferenceQueryContext",
    "ReferenceQueryReadTrace",
    "SqliteReferenceDirectPathQuery",
    "parse_reference_query_read_trace",
]
