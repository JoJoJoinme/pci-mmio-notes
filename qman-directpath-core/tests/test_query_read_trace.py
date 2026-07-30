from __future__ import annotations

import base64
import copy
from dataclasses import replace
import hashlib
from pathlib import Path
import unittest

from qman_directpath_core.canonical import canonical_json_bytes, sha256_digest
from qman_directpath_core.contracts import ContractSchemas
from qman_directpath_core.errors import DirectPathVerificationError
from qman_directpath_core.query_read_trace import (
    REFERENCE_QUERY_READ_TRACE_EVIDENCE_BOUNDARY,
    VerifiedQueryReadTrace,
    verify_query_read_trace,
)


ROOT = Path(__file__).resolve().parents[2]
CONTRACTS = ContractSchemas(ROOT / "contracts", include_query_read_trace=True)

OBSERVATION_DOMAIN = b"QMAN-DIRECTPATH/QUERY-OBSERVED-INSTANCE/V1\x00"
PREDICATE_DOMAIN = b"QMAN-DIRECTPATH/QUERY-PREDICATE-OBSERVATION/V1\x00"
STATE_DOMAIN = b"QMAN-DIRECTPATH/QUERY-READ-STATE/V1\x00"
TRACE_DOMAIN = b"QMAN-DIRECTPATH/QUERY-READ-TRACE/V1\x00"
REFERENCE_ROW_DOMAIN = b"QMAN-DIRECTPATH/REFERENCE-QUERY-OBSERVED-ROW/V1\x00"
CAPABILITY_DECISION_DOMAIN = b"QMAN-DIRECTPATH/QUERY-CAPABILITY-DECISION/V1\x00"
SEMANTIC_DEPENDENCIES_DOMAIN = b"QMAN-DIRECTPATH/QUERY-SEMANTIC-DEPENDENCIES/V1\x00"
REFERENCE_ROW_SCHEMA_REF = (
    "contracts/directpath-query-read-trace.schema.json#/$defs/referenceObservedRow"
)
OUTPUT_SCHEMA_REF = (
    "contracts/directpath-operation-payload.schema.json"
    "#/$defs/output_OP_QUERY_DIRECTPATH"
)

PREDICATE_KINDS = {
    "CURRENT_AUTHORITY_BY_FIXED_KEYS": {
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
    },
    "CURRENT_HOST_SNAPSHOT_BY_POINTER": {"HOST_SNAPSHOT"},
    "DEVICE_RECORDS_BY_COMPLETE_BUNDLE": {"DEVICE_RECORD"},
    "ACTIVE_BUNDLE_LEASES_OVERLAPPING_BUNDLE_OR_MEMBER": {"BUNDLE_LEASE"},
    "ACTIVE_OPERATION_LEASES_OVERLAPPING_SCOPE_BUNDLE_OR_MEMBER": {"OPERATION_LEASE"},
    "UNCLEARED_QUARANTINES_OVERLAPPING_BUNDLE_OR_MEMBER": {"QUARANTINE_RECORD"},
    "HOST_JOURNAL_HEAD_BY_HOST_EPOCH": {"HOST_JOURNAL_HEAD"},
    "HOST_SIDE_EFFECT_COUNTERS_BY_AGENT_EPOCH": {"HOST_SIDE_EFFECT_COUNTER"},
    "RESET_OBSERVATIONS_BY_MEMBER_SET": {"RESET_OBSERVATION"},
}
AVAILABILITY_PREDICATES = {
    "DEVICE_RECORDS_BY_COMPLETE_BUNDLE",
    "ACTIVE_BUNDLE_LEASES_OVERLAPPING_BUNDLE_OR_MEMBER",
    "ACTIVE_OPERATION_LEASES_OVERLAPPING_SCOPE_BUNDLE_OR_MEMBER",
    "UNCLEARED_QUARANTINES_OVERLAPPING_BUNDLE_OR_MEMBER",
}


def digest(label: str) -> str:
    return "sha256:" + hashlib.sha256(label.encode()).hexdigest()


def null_field_digest(domain: bytes, value: dict[str, object], field: str) -> str:
    subject = copy.deepcopy(value)
    subject[field] = None
    return sha256_digest(domain + canonical_json_bytes(subject))


def name_values(values: dict[str, object]) -> list[dict[str, object]]:
    result = [{"name": name, "value": value} for name, value in values.items()]
    return sorted(result, key=canonical_json_bytes)


def authority_vector() -> dict[str, object]:
    return {
        "subjectType": "CURRENT_AUTHORITY_VECTOR",
        "schemaVersion": 1,
        "hostAuthorityId": "host-a",
        "hostAuthorityResourceVersion": 11,
        "publisherSnapshotDigest": digest("snapshot"),
        "hostSnapshotAnchorAuthorityId": (
            "external-host-snapshot-authority-a"
        ),
        "hostSnapshotAnchorVersion": 6,
        "hostSnapshotAnchorResourceVersion": 6,
        "hostSnapshotAnchorDigest": digest("host-snapshot-anchor"),
        "hostSnapshotAnchorFreshnessReceiptDigest": digest(
            "host-snapshot-anchor-freshness"
        ),
        "hostSnapshotAnchorBindingDigest": digest(
            "host-snapshot-anchor-binding"
        ),
        "policyAuthorityId": "policy-authority-a",
        "policyId": "policy-a",
        "policyVersion": 3,
        "policyDigest": digest("policy"),
        "policyAuthorityResourceVersion": 12,
        "trustRootDigest": digest("root"),
        "keyRingSequence": 7,
        "keyRingDigest": digest("ring"),
        "trustAnchorVersion": 4,
        "trustAnchorDigest": digest("trust-anchor"),
        "catalogId": "catalog-a",
        "catalogSequence": 8,
        "catalogDigest": digest("catalog"),
        "catalogAnchorVersion": 5,
        "catalogAnchorDigest": digest("catalog-anchor"),
        "availabilityAuthorityId": "availability-global-a",
        "availabilityAuthorityResourceVersion": 19,
        "availabilityReadSetDigest": digest("availability-read-set"),
        "requestAuthorityId": "request-authority-a",
        "requestReadSetDigest": digest("request-read-set"),
        "inventoryVerificationReceiptDigest": digest("inventory-receipt"),
        "inventoryVerifierIdentityDigest": digest("inventory-verifier"),
        "evidenceValidUntil": "2030-01-01T00:00:00.000000Z",
    }


def reference_observation(
    instance_kind: str,
    *,
    primary_key: dict[str, object],
    row_fields: dict[str, object],
    resource_version: int | None = None,
    generation: int | None = None,
    purpose: str = "DECISION_INPUT",
    source_store: str = "GLOBAL_REPOSITORY",
) -> dict[str, object]:
    primary = name_values(primary_key)
    fields = name_values(row_fields)
    actual: dict[str, object] = {
        "subjectType": "REFERENCE_QUERY_OBSERVED_ROW",
        "schemaVersion": 1,
        "evidenceBoundary": REFERENCE_QUERY_READ_TRACE_EVIDENCE_BOUNDARY,
        "instanceKind": instance_kind,
        "primaryKey": primary,
        "resourceVersionOrNull": resource_version,
        "generationOrNull": generation,
        "rowFields": fields,
        "rowDigest": None,
    }
    actual["rowDigest"] = null_field_digest(
        REFERENCE_ROW_DOMAIN,
        actual,
        "rowDigest",
    )
    actual_bytes = canonical_json_bytes(actual)
    wrapper: dict[str, object] = {
        "instanceKind": instance_kind,
        "observationPurpose": purpose,
        "sourceStore": source_store,
        "sourcePrimaryKey": primary,
        "schemaRef": REFERENCE_ROW_SCHEMA_REF,
        "resourceVersionOrNull": resource_version,
        "generationOrNull": generation,
        "canonicalInstanceBase64": base64.b64encode(actual_bytes).decode("ascii"),
        "instanceBytesSha256": sha256_digest(actual_bytes),
        "observationDigest": None,
    }
    wrapper["observationDigest"] = null_field_digest(
        OBSERVATION_DOMAIN,
        wrapper,
        "observationDigest",
    )
    return wrapper


def observations() -> list[dict[str, object]]:
    vector = authority_vector()
    values = [
        reference_observation(
            "HOST_AUTHORITY",
            primary_key={"hostId": "host-a"},
            row_fields={
                "agentGeneration": 7,
                "currentSnapshotContentHash": vector["publisherSnapshotDigest"],
                "hostEpoch": 3,
                "hostId": "host-a",
                "kernelBootId": "boot-a",
                "resourceVersion": vector["hostAuthorityResourceVersion"],
            },
            resource_version=11,
            generation=3,
        ),
        reference_observation(
            "CAPABILITY_POLICY_AUTHORITY",
            primary_key={"policyAuthorityId": vector["policyAuthorityId"]},
            row_fields={
                "policyDigest": vector["policyDigest"],
                "policyId": vector["policyId"],
                "policyVersion": vector["policyVersion"],
                "resourceVersion": vector["policyAuthorityResourceVersion"],
            },
            resource_version=12,
        ),
        reference_observation(
            "AVAILABILITY_AUTHORITY",
            primary_key={"availabilityAuthorityId": vector["availabilityAuthorityId"]},
            row_fields={
                "resourceVersion": vector["availabilityAuthorityResourceVersion"]
            },
            resource_version=19,
        ),
        reference_observation(
            "CURRENT_TRUST_POINTER",
            primary_key={"trustPointerId": "trust-current-a"},
            row_fields={
                "keyRingDigest": vector["keyRingDigest"],
                "keyRingSequence": vector["keyRingSequence"],
                "trustRootDigest": vector["trustRootDigest"],
            },
        ),
        reference_observation(
            "CURRENT_TRUST_ANCHOR",
            primary_key={"trustAnchorId": "trust-anchor-a"},
            row_fields={
                "trustAnchorDigest": vector["trustAnchorDigest"],
                "trustAnchorVersion": vector["trustAnchorVersion"],
            },
        ),
        reference_observation(
            "CURRENT_CATALOG_POINTER",
            primary_key={"catalogPointerId": "catalog-current-a"},
            row_fields={
                "catalogDigest": vector["catalogDigest"],
                "catalogId": vector["catalogId"],
                "catalogSequence": vector["catalogSequence"],
            },
        ),
        reference_observation(
            "CURRENT_CATALOG_ANCHOR",
            primary_key={"catalogAnchorId": "catalog-anchor-a"},
            row_fields={
                "catalogAnchorDigest": vector["catalogAnchorDigest"],
                "catalogAnchorVersion": vector["catalogAnchorVersion"],
            },
        ),
        reference_observation(
            "CURRENT_INVENTORY_POINTER",
            primary_key={"authorityId": "inventory-authority-a"},
            row_fields={
                "artifactDigest": vector["publisherSnapshotDigest"],
                "authorityId": "inventory-authority-a",
                "blobSha256": digest("inventory-blob"),
                "inventoryVerificationReceiptDigest": vector[
                    "inventoryVerificationReceiptDigest"
                ],
                "inventoryVerifierIdentityDigest": vector[
                    "inventoryVerifierIdentityDigest"
                ],
                "kind": "INVENTORY",
                "sequence": 9,
                "validUntil": "2030-01-01T00:00:00.000000Z",
            },
            resource_version=14,
        ),
        reference_observation(
            "HOST_SNAPSHOT_ANCHOR_BINDING",
            primary_key={
                "bindingDigest": vector[
                    "hostSnapshotAnchorBindingDigest"
                ]
            },
            row_fields={
                "anchorAuthorityId": vector[
                    "hostSnapshotAnchorAuthorityId"
                ],
                "anchorDigest": vector["hostSnapshotAnchorDigest"],
                "anchorResourceVersion": vector[
                    "hostSnapshotAnchorResourceVersion"
                ],
                "anchorVersion": vector["hostSnapshotAnchorVersion"],
                "bindingDigest": vector[
                    "hostSnapshotAnchorBindingDigest"
                ],
                "freshnessReceiptDigest": vector[
                    "hostSnapshotAnchorFreshnessReceiptDigest"
                ],
                "authorityBoundary": (
                    "COMPONENT_EXTERNAL_BYTES_VERIFICATION_ONLY"
                ),
                "productAuthorized": False,
            },
            source_store="VERIFIER_OUTPUT",
        ),
        reference_observation(
            "VM_REQUEST_OR_ASSIGNMENT",
            primary_key={"vmId": "vm-a"},
            row_fields={
                "requestAuthorityId": vector["requestAuthorityId"],
                "requestReadSetDigest": vector["requestReadSetDigest"],
            },
        ),
        reference_observation(
            "HOST_SNAPSHOT",
            primary_key={"hostId": "host-a", "snapshotEpoch": 9},
            row_fields={
                "agentGeneration": 7,
                "contentHash": vector["publisherSnapshotDigest"],
                "hostEpoch": 3,
                "hostId": "host-a",
                "kernelBootId": "boot-a",
            },
            generation=9,
        ),
        reference_observation(
            "DEVICE_RECORD",
            primary_key={"deviceUid": "device-a"},
            row_fields={
                "deviceUid": "device-a",
                "evidenceBlobHash": digest("device-evidence"),
                "ownerDriver": "vfio-pci",
            },
            resource_version=15,
            generation=2,
        ),
        reference_observation(
            "DEPENDENCY_BUNDLE",
            primary_key={
                "bundleId": digest("bundle"),
                "deviceUid": "device-a",
            },
            row_fields={
                "bundleId": digest("bundle"),
                "deviceUid": "device-a",
            },
        ),
        reference_observation(
            "HOST_JOURNAL_HEAD",
            primary_key={"hostId": "host-a"},
            row_fields={
                "entryHash": digest("journal-head"),
                "hostEpoch": 3,
                "hostId": "host-a",
                "journalEpoch": 4,
                "kernelBootId": "boot-a",
                "sequence": 3,
            },
            generation=3,
            purpose="NON_MUTATION_ORACLE",
            source_store="HOST_OBSERVER",
        ),
        reference_observation(
            "RESET_OBSERVATION",
            primary_key={"deviceUid": "device-a", "hostId": "host-a"},
            row_fields={
                "agentGeneration": 7,
                "hostId": "host-a",
                "kernelBootId": "boot-a",
                "memberDeviceUid": "device-a",
                "observerEpoch": 8,
                "observerId": "reset-observer-a",
                "resetOccurrenceCount": 6,
            },
            generation=8,
            purpose="NON_MUTATION_ORACLE",
            source_store="HOST_OBSERVER",
        ),
    ]
    for counter_kind in (
        "DRIVER_BIND",
        "DRIVER_UNBIND",
        "DEVICE_RESET",
        "VFIO_EXCLUSIVE_OPEN",
        "QEMU_SPAWN",
        "HOST_JOURNAL_APPEND",
    ):
        values.append(
            reference_observation(
                "HOST_SIDE_EFFECT_COUNTER",
                primary_key={
                    "counterEpoch": 5,
                    "counterKind": counter_kind,
                    "hostId": "host-a",
                },
                row_fields={
                    "agentGeneration": 7,
                    "counterEpoch": 5,
                    "counterKind": counter_kind,
                    "hostId": "host-a",
                    "kernelBootId": "boot-a",
                    "value": 17,
                },
                generation=7,
                purpose="NON_MUTATION_ORACLE",
                source_store="HOST_OBSERVER",
            )
        )
    return sorted(values, key=canonical_json_bytes)


def predicate_observations(
    observed: list[dict[str, object]],
) -> list[dict[str, object]]:
    availability = next(
        item for item in observed if item["instanceKind"] == "AVAILABILITY_AUTHORITY"
    )
    inventory_current = {
        "kind": "INVENTORY",
        "authorityId": "inventory-authority-a",
        "sequence": 9,
        "artifactDigest": digest("snapshot"),
        "resourceVersion": 14,
        "validUntil": "2030-01-01T00:00:00.000000Z",
        "blobSha256": digest("inventory-blob"),
    }
    selected_projection = {
        "bundleMembers": [{"bundleId": digest("bundle"), "deviceId": "device-a"}],
        "availabilityMembers": [
            {
                "deviceId": "device-a",
                "generation": 2,
                "resourceVersion": 15,
                "evidenceBlobHash": digest("device-evidence"),
            }
        ],
    }

    def parameters(predicate_id: str) -> dict[str, object]:
        if predicate_id == "CURRENT_AUTHORITY_BY_FIXED_KEYS":
            return {"hostId": "host-a", "vmId": "vm-a"}
        if predicate_id == "CURRENT_HOST_SNAPSHOT_BY_POINTER":
            return {
                "hostId": "host-a",
                "inventoryPointerDigest": sha256_digest(
                    canonical_json_bytes(inventory_current)
                ),
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
            return {"hostEpoch": 3, "hostId": "host-a"}
        if predicate_id == "HOST_SIDE_EFFECT_COUNTERS_BY_AGENT_EPOCH":
            return {
                "agentGeneration": 7,
                "counterEpoch": 5,
                "hostId": "host-a",
            }
        return {"memberSetDigest": sha256_digest(canonical_json_bytes(["device-a"]))}

    predicates: list[dict[str, object]] = []
    for predicate_id, kinds in PREDICATE_KINDS.items():
        matched = sorted(
            [
                item["observationDigest"]
                for item in observed
                if item["instanceKind"] in kinds
            ],
            key=canonical_json_bytes,
        )
        if predicate_id in AVAILABILITY_PREDICATES:
            fence: dict[str, object] = {
                "fenceKind": "GLOBAL_AVAILABILITY_AUTHORITY",
                "availabilityAuthorityId": "availability-global-a",
                "availabilityAuthorityResourceVersion": 19,
                "authorityObservationDigest": availability["observationDigest"],
            }
        else:
            fence = {"fenceKind": "NOT_APPLICABLE"}
        predicate: dict[str, object] = {
            "predicateId": predicate_id,
            "closedParameters": name_values(parameters(predicate_id)),
            "matchedInstanceDigests": matched,
            "fence": fence,
            "predicateDigest": None,
        }
        predicate["predicateDigest"] = null_field_digest(
            PREDICATE_DOMAIN,
            predicate,
            "predicateDigest",
        )
        predicates.append(predicate)
    return sorted(predicates, key=canonical_json_bytes)


def output_document(state_digest: str) -> dict[str, object]:
    output: dict[str, object] = {
        "capabilityStatus": {
            "hardwareCapable": "YES",
            "technicallyAttachable": "YES",
            "eligible": "YES",
            "available": "YES",
            "qualified": "YES",
            "supported": "YES",
            "assignmentState": "FREE",
        },
        "bundleSummaries": [],
        "leaseSummaries": [],
        "reasons": [],
        "evidenceRefs": [],
        "capabilityDecisionHash": None,
        "semanticDependencyHash": None,
        "queryStateHash": state_digest,
    }
    output["capabilityDecisionHash"] = sha256_digest(
        CAPABILITY_DECISION_DOMAIN
        + canonical_json_bytes(
            {
                "capabilityStatus": output["capabilityStatus"],
                "reasons": output["reasons"],
            }
        )
    )
    output["semanticDependencyHash"] = sha256_digest(
        SEMANTIC_DEPENDENCIES_DOMAIN
        + canonical_json_bytes(
            {
                "bundleSummaries": output["bundleSummaries"],
                "leaseSummaries": output["leaseSummaries"],
                "evidenceRefs": output["evidenceRefs"],
            }
        )
    )
    return output


def trace_fixture() -> tuple[dict[str, object], bytes, bytes]:
    observed = observations()
    state: dict[str, object] = {
        "repositoryCommitClock": 23,
        "currentAuthorityVector": authority_vector(),
        "currentAuthorityVectorBytesSha256": sha256_digest(
            canonical_json_bytes(authority_vector())
        ),
        "selectedScope": {
            "scopeHashOrNull": digest("scope"),
            "bundleIds": [digest("bundle")],
            "memberDeviceUids": ["device-a"],
            "hostIds": ["host-a"],
        },
        "observedInstances": observed,
        "predicateObservations": predicate_observations(observed),
        "stateDigest": None,
    }
    state["stateDigest"] = null_field_digest(STATE_DOMAIN, state, "stateDigest")
    output = output_document(str(state["stateDigest"]))
    output_bytes = canonical_json_bytes(output)
    journal_digest = sha256_digest(
        canonical_json_bytes(
            [
                item["observationDigest"]
                for item in observed
                if item["instanceKind"] == "HOST_JOURNAL_HEAD"
            ]
        )
    )
    side_effect_digest = sha256_digest(
        canonical_json_bytes(
            sorted(
                [
                    item["observationDigest"]
                    for item in observed
                    if item["instanceKind"]
                    in {"HOST_SIDE_EFFECT_COUNTER", "RESET_OBSERVATION"}
                ],
                key=canonical_json_bytes,
            )
        )
    )
    request_bytes = canonical_json_bytes(
        {
            "subjectType": "REFERENCE_QUERY_REQUEST_ENVELOPE",
            "schemaVersion": 1,
            "evidenceBoundary": REFERENCE_QUERY_READ_TRACE_EVIDENCE_BOUNDARY,
            "queryCommandId": "query-a",
            "selector": {"selectorKind": "HOST", "hostId": "host-a"},
            "vmId": "vm-a",
        }
    )
    result_bytes = canonical_json_bytes(
        {
            "subjectType": "REFERENCE_QUERY_RESULT_ENVELOPE",
            "schemaVersion": 1,
            "evidenceBoundary": REFERENCE_QUERY_READ_TRACE_EVIDENCE_BOUNDARY,
            "queryCommandId": "query-a",
            "canonicalOutputBase64": base64.b64encode(output_bytes).decode("ascii"),
            "canonicalOutputSha256": sha256_digest(output_bytes),
        }
    )
    trace: dict[str, object] = {
        "subjectType": "DIRECTPATH_QUERY_READ_TRACE",
        "schemaVersion": 1,
        "evidenceBoundary": REFERENCE_QUERY_READ_TRACE_EVIDENCE_BOUNDARY,
        "operationId": "OP-QUERY-DIRECTPATH",
        "traceId": "trace-a",
        "queryCommandId": "query-a",
        "targetRepositoryCommit": digest("target-commit"),
        "portableContractSha256": digest("portable-contract"),
        "requestEnvelopeSha256": sha256_digest(request_bytes),
        "resultEnvelopeSha256": sha256_digest(result_bytes),
        "selector": {"selectorKind": "HOST", "hostId": "host-a"},
        "repositoryTransaction": {
            "repositoryInstanceId": "reference-repository-a",
            "transactionId": "transaction-a",
            "isolationMode": "SQLITE_WAL_READ_TRANSACTION",
            "databaseEnforcedReadOnly": True,
            "snapshotToken": digest("snapshot-token"),
        },
        "before": {
            "capturedAt": "2026-07-24T01:00:00.000000Z",
            "state": copy.deepcopy(state),
        },
        "after": {
            "capturedAt": "2026-07-24T01:00:01.000000Z",
            "state": copy.deepcopy(state),
        },
        "outputInstance": {
            "schemaRef": OUTPUT_SCHEMA_REF,
            "canonicalOutputBase64": base64.b64encode(output_bytes).decode("ascii"),
            "canonicalBytesSha256": sha256_digest(output_bytes),
            "capabilityDecisionHash": output["capabilityDecisionHash"],
            "semanticDependencyHash": output["semanticDependencyHash"],
            "queryStateHash": output["queryStateHash"],
        },
        "zeroWriteWitness": {
            "queryTransactionId": "transaction-a",
            "databaseEnforcedReadOnly": True,
            "writeStatementCount": 0,
            "affectedRowCount": 0,
            "repositoryMutationInstances": [],
            "hostSideEffectInvocations": [],
            "commitClockBefore": 23,
            "commitClockAfter": 23,
            "journalHeadBeforeDigest": journal_digest,
            "journalHeadAfterDigest": journal_digest,
            "sideEffectCounterVectorBeforeDigest": side_effect_digest,
            "sideEffectCounterVectorAfterDigest": side_effect_digest,
        },
        "traceDigest": None,
    }
    trace["traceDigest"] = null_field_digest(TRACE_DOMAIN, trace, "traceDigest")
    return trace, request_bytes, result_bytes


def verify_fixture(
    trace: dict[str, object],
    request_bytes: bytes,
    result_bytes: bytes,
) -> VerifiedQueryReadTrace:
    return verify_query_read_trace(
        canonical_json_bytes(trace),
        request_envelope_bytes=request_bytes,
        result_envelope_bytes=result_bytes,
        schemas=CONTRACTS,
    )


class QueryReadTraceTests(unittest.TestCase):
    def test_complete_trace_is_deterministic_and_factory_only(self) -> None:
        trace, request_bytes, result_bytes = trace_fixture()
        first = verify_fixture(trace, request_bytes, result_bytes)
        second = verify_fixture(trace, request_bytes, result_bytes)

        self.assertEqual(first, second)
        self.assertEqual(first.to_subject(), trace)
        self.assertEqual(
            first.deterministic_output_hash,
            trace["outputInstance"]["canonicalBytesSha256"],
        )
        with self.assertRaises(TypeError):
            VerifiedQueryReadTrace()
        with self.assertRaises(TypeError):
            replace(first)

    def test_missing_actual_instance_fails_closed(self) -> None:
        trace, request_bytes, result_bytes = trace_fixture()
        for capture in ("before", "after"):
            state = trace[capture]["state"]
            state["observedInstances"] = [
                item
                for item in state["observedInstances"]
                if item["instanceKind"] != "DEVICE_RECORD"
            ]
        with self.assertRaises(DirectPathVerificationError) as raised:
            verify_fixture(trace, request_bytes, result_bytes)
        self.assertEqual(
            raised.exception.code,
            "QUERY_TRACE_INSTANCE_COVERAGE_INCOMPLETE",
        )

    def test_missing_current_pointer_fails_closed(self) -> None:
        trace, request_bytes, result_bytes = trace_fixture()
        for capture in ("before", "after"):
            state = trace[capture]["state"]
            state["observedInstances"] = [
                item
                for item in state["observedInstances"]
                if item["instanceKind"] != "CURRENT_TRUST_POINTER"
            ]
        with self.assertRaises(DirectPathVerificationError) as raised:
            verify_fixture(trace, request_bytes, result_bytes)
        self.assertEqual(
            raised.exception.code,
            "QUERY_TRACE_INSTANCE_COVERAGE_INCOMPLETE",
        )

    def test_host_snapshot_anchor_vector_requires_observed_binding(self) -> None:
        mutations = {
            "hostSnapshotAnchorAuthorityId": "other-anchor-authority",
            "hostSnapshotAnchorVersion": 7,
            "hostSnapshotAnchorResourceVersion": 7,
            "hostSnapshotAnchorDigest": digest("other-anchor"),
            "hostSnapshotAnchorFreshnessReceiptDigest": digest(
                "other-freshness"
            ),
            "hostSnapshotAnchorBindingDigest": digest("other-binding"),
        }
        for field, value in mutations.items():
            with self.subTest(field=field):
                trace, request_bytes, result_bytes = trace_fixture()
                state = trace["before"]["state"]
                state["currentAuthorityVector"][field] = value
                state["currentAuthorityVectorBytesSha256"] = sha256_digest(
                    canonical_json_bytes(state["currentAuthorityVector"])
                )

                with self.assertRaises(
                    DirectPathVerificationError
                ) as raised:
                    verify_fixture(trace, request_bytes, result_bytes)

                self.assertEqual(
                    "QUERY_TRACE_CURRENT_AUTHORITY_INVALID",
                    raised.exception.code,
                )
                self.assertEqual(
                    "query_read_trace.before.state."
                    f"currentAuthorityVector.{field}",
                    raised.exception.path,
                )

    def test_empty_availability_predicate_without_fence_is_rejected(self) -> None:
        trace, request_bytes, result_bytes = trace_fixture()
        predicate = next(
            item
            for item in trace["before"]["state"]["predicateObservations"]
            if item["predicateId"]
            == "ACTIVE_BUNDLE_LEASES_OVERLAPPING_BUNDLE_OR_MEMBER"
        )
        predicate["fence"] = {"fenceKind": "NOT_APPLICABLE"}
        with self.assertRaises(DirectPathVerificationError) as raised:
            verify_fixture(trace, request_bytes, result_bytes)
        self.assertEqual(raised.exception.code, "CONTRACT_SCHEMA_VIOLATION")

    def test_complete_wrapper_reordering_is_rejected(self) -> None:
        trace, request_bytes, result_bytes = trace_fixture()
        observed = trace["before"]["state"]["observedInstances"]
        observed[0], observed[1] = observed[1], observed[0]
        with self.assertRaises(DirectPathVerificationError) as raised:
            verify_fixture(trace, request_bytes, result_bytes)
        self.assertEqual(raised.exception.code, "QUERY_TRACE_NONCANONICAL_SET")

    def test_decoder_or_log_substitute_is_rejected(self) -> None:
        trace, request_bytes, result_bytes = trace_fixture()
        observed = trace["before"]["state"]["observedInstances"][0]
        substitute = canonical_json_bytes(
            {
                "decoder": "query-row-decoder",
                "log": "SELECT returned one row",
            }
        )
        observed["canonicalInstanceBase64"] = base64.b64encode(substitute).decode(
            "ascii"
        )
        with self.assertRaises(DirectPathVerificationError) as raised:
            verify_fixture(trace, request_bytes, result_bytes)
        self.assertEqual(raised.exception.code, "CONTRACT_SCHEMA_VIOLATION")

    def test_instance_kind_schema_relabel_is_rejected(self) -> None:
        trace, request_bytes, result_bytes = trace_fixture()
        observed = next(
            item
            for item in trace["before"]["state"]["observedInstances"]
            if item["instanceKind"] == "DEVICE_RECORD"
        )
        observed["schemaRef"] = (
            "contracts/directpath-query-read-trace.schema.json#/$defs/hostJournalHead"
        )
        with self.assertRaises(DirectPathVerificationError) as raised:
            verify_fixture(trace, request_bytes, result_bytes)
        self.assertEqual(
            raised.exception.code,
            "QUERY_TRACE_INSTANCE_SCHEMA_MISMATCH",
        )

    def test_unrelated_availability_row_is_rejected(self) -> None:
        trace, request_bytes, result_bytes = trace_fixture()
        unrelated = reference_observation(
            "BUNDLE_LEASE",
            primary_key={"leaseId": "lease-unrelated"},
            row_fields={
                "bundleId": digest("other-bundle"),
                "memberDeviceUid": "other-device",
                "scopeHash": digest("other-scope"),
                "state": "ACTIVE",
            },
            resource_version=30,
        )
        for capture in ("before", "after"):
            state = trace[capture]["state"]
            state["observedInstances"].append(copy.deepcopy(unrelated))
            state["observedInstances"].sort(key=canonical_json_bytes)
        with self.assertRaises(DirectPathVerificationError) as raised:
            verify_fixture(trace, request_bytes, result_bytes)
        self.assertEqual(
            raised.exception.code,
            "QUERY_TRACE_PREDICATE_CLOSURE_INVALID",
        )

    def test_journal_and_counter_witness_drift_is_rejected(self) -> None:
        for field in (
            "journalHeadAfterDigest",
            "sideEffectCounterVectorAfterDigest",
        ):
            with self.subTest(field=field):
                trace, request_bytes, result_bytes = trace_fixture()
                trace["zeroWriteWitness"][field] = digest("drift-" + field)
                with self.assertRaises(DirectPathVerificationError) as raised:
                    verify_fixture(trace, request_bytes, result_bytes)
                self.assertEqual(
                    raised.exception.code,
                    "QUERY_TRACE_ZERO_WRITE_INVALID",
                )

    def test_incomplete_counter_vector_is_rejected(self) -> None:
        trace, request_bytes, result_bytes = trace_fixture()
        for capture in ("before", "after"):
            state = trace[capture]["state"]
            removed = False
            retained = []
            for item in state["observedInstances"]:
                if not removed and item["instanceKind"] == "HOST_SIDE_EFFECT_COUNTER":
                    removed = True
                    continue
                retained.append(item)
            state["observedInstances"] = retained
        with self.assertRaises(DirectPathVerificationError) as raised:
            verify_fixture(trace, request_bytes, result_bytes)
        self.assertEqual(
            raised.exception.code,
            "QUERY_TRACE_NON_MUTATION_ORACLE_INVALID",
        )

    def test_unrelated_reset_observer_lineage_is_rejected(self) -> None:
        trace, request_bytes, result_bytes = trace_fixture()
        unrelated = reference_observation(
            "RESET_OBSERVATION",
            primary_key={"deviceUid": "device-a", "hostId": "host-other"},
            row_fields={
                "agentGeneration": 7,
                "hostId": "host-other",
                "kernelBootId": "boot-other",
                "memberDeviceUid": "device-a",
                "observerEpoch": 8,
                "observerId": "reset-observer-other",
                "resetOccurrenceCount": 6,
            },
            generation=8,
            purpose="NON_MUTATION_ORACLE",
            source_store="HOST_OBSERVER",
        )
        for capture in ("before", "after"):
            state = trace[capture]["state"]
            state["observedInstances"] = [
                copy.deepcopy(unrelated)
                if item["instanceKind"] == "RESET_OBSERVATION"
                else item
                for item in state["observedInstances"]
            ]
            state["observedInstances"].sort(key=canonical_json_bytes)
        with self.assertRaises(DirectPathVerificationError) as raised:
            verify_fixture(trace, request_bytes, result_bytes)
        self.assertEqual(
            raised.exception.code,
            "QUERY_TRACE_NON_MUTATION_ORACLE_INVALID",
        )

    def test_nonempty_write_set_is_rejected(self) -> None:
        trace, request_bytes, result_bytes = trace_fixture()
        trace["zeroWriteWitness"]["repositoryMutationInstances"] = [{"table": "audit"}]
        with self.assertRaises(DirectPathVerificationError) as raised:
            verify_fixture(trace, request_bytes, result_bytes)
        self.assertEqual(raised.exception.code, "CONTRACT_SCHEMA_VIOLATION")

    def test_output_byte_mutation_breaks_hash_binding(self) -> None:
        trace, request_bytes, result_bytes = trace_fixture()
        encoded = trace["outputInstance"]["canonicalOutputBase64"]
        output = copy.deepcopy(__import__("json").loads(base64.b64decode(encoded)))
        output["capabilityStatus"]["available"] = "NO"
        trace["outputInstance"]["canonicalOutputBase64"] = base64.b64encode(
            canonical_json_bytes(output)
        ).decode("ascii")
        with self.assertRaises(DirectPathVerificationError) as raised:
            verify_fixture(trace, request_bytes, result_bytes)
        self.assertEqual(raised.exception.code, "QUERY_TRACE_HASH_MISMATCH")

    def test_self_consistent_forged_output_hash_is_rejected(self) -> None:
        trace, request_bytes, result_bytes = trace_fixture()
        encoded = trace["outputInstance"]["canonicalOutputBase64"]
        output = copy.deepcopy(__import__("json").loads(base64.b64decode(encoded)))
        forged = digest("caller-selected-decision")
        output["capabilityDecisionHash"] = forged
        output_bytes = canonical_json_bytes(output)
        trace["outputInstance"].update(
            {
                "canonicalOutputBase64": base64.b64encode(output_bytes).decode("ascii"),
                "canonicalBytesSha256": sha256_digest(output_bytes),
                "capabilityDecisionHash": forged,
            }
        )
        with self.assertRaises(DirectPathVerificationError) as raised:
            verify_fixture(trace, request_bytes, result_bytes)
        self.assertEqual(
            raised.exception.code,
            "QUERY_TRACE_OUTPUT_BINDING_INVALID",
        )

    def test_retained_envelope_hash_mutation_is_rejected(self) -> None:
        trace, request_bytes, result_bytes = trace_fixture()
        with self.assertRaises(DirectPathVerificationError) as raised:
            verify_fixture(trace, request_bytes + b"x", result_bytes)
        self.assertEqual(raised.exception.code, "QUERY_TRACE_HASH_MISMATCH")

    def test_request_selector_and_command_correlation_are_required(self) -> None:
        for field, value in (
            ("queryCommandId", "query-other"),
            ("selector", {"selectorKind": "HOST", "hostId": "host-other"}),
        ):
            with self.subTest(field=field):
                trace, request_bytes, result_bytes = trace_fixture()
                request = __import__("json").loads(request_bytes)
                request[field] = value
                request_bytes = canonical_json_bytes(request)
                trace["requestEnvelopeSha256"] = sha256_digest(request_bytes)
                with self.assertRaises(DirectPathVerificationError) as raised:
                    verify_fixture(trace, request_bytes, result_bytes)
                self.assertEqual(
                    raised.exception.code,
                    "QUERY_TRACE_ENVELOPE_CORRELATION_INVALID",
                )

    def test_result_must_retain_the_exact_output(self) -> None:
        trace, request_bytes, result_bytes = trace_fixture()
        result = __import__("json").loads(result_bytes)
        wrong_output = canonical_json_bytes({"substitute": "log-or-decoder"})
        result["canonicalOutputBase64"] = base64.b64encode(wrong_output).decode("ascii")
        result["canonicalOutputSha256"] = sha256_digest(wrong_output)
        result_bytes = canonical_json_bytes(result)
        trace["resultEnvelopeSha256"] = sha256_digest(result_bytes)
        with self.assertRaises(DirectPathVerificationError) as raised:
            verify_fixture(trace, request_bytes, result_bytes)
        self.assertEqual(
            raised.exception.code,
            "QUERY_TRACE_ENVELOPE_CORRELATION_INVALID",
        )

    def test_arbitrary_hash_matching_envelope_object_is_rejected(self) -> None:
        trace, _request_bytes, result_bytes = trace_fixture()
        request_bytes = canonical_json_bytes({"queryCommandId": "query-a"})
        trace["requestEnvelopeSha256"] = sha256_digest(request_bytes)
        with self.assertRaises(DirectPathVerificationError) as raised:
            verify_fixture(trace, request_bytes, result_bytes)
        self.assertEqual(
            raised.exception.code,
            "QUERY_TRACE_ENVELOPE_INVALID",
        )

    def test_product_e3_label_cannot_be_created_by_component_verifier(self) -> None:
        trace, request_bytes, result_bytes = trace_fixture()
        trace["evidenceBoundary"] = "QMAN_PRODUCT_E3_QUERY_READ_TRACE"
        with self.assertRaises(DirectPathVerificationError) as raised:
            verify_fixture(trace, request_bytes, result_bytes)
        self.assertEqual(
            raised.exception.code,
            "QUERY_TRACE_EVIDENCE_BOUNDARY_INVALID",
        )


if __name__ == "__main__":
    unittest.main()
