from __future__ import annotations

import copy
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

import pytest

from qman_directpath_core.canonical import (
    canonical_json_bytes,
    sha256_digest,
)
from qman_directpath_core.contracts import ContractSchemas
from qman_directpath_core.errors import DirectPathVerificationError
from qman_directpath_core.publication_mutation import (
    AUDIT_EVENT_ID_DOMAIN,
    HOST_SNAPSHOT_PUBLICATION_MUTATION_AUTHORITY_BOUNDARY,
    HOST_SNAPSHOT_PUBLICATION_MUTATION_PRODUCT_EVIDENCE_BLOCKERS,
    MAX_PUBLICATION_MUTATION_DEVICE_RECORDS,
    MAX_PUBLICATION_MUTATIONS,
    PublicationMutationVerifierLimits,
    OUTBOX_EVENT_ID_DOMAIN,
    VerifiedHostSnapshotPublicationMutationContext,
    replay_host_snapshot_publication_mutation_closure,
    verify_host_snapshot_publication_mutation_closure,
)
from qman_directpath_core.publication_operation import (
    OPERATION_PAYLOAD_SCHEMA_DOCUMENT_REF,
    verify_host_snapshot_publication_operation_request,
)
from tests.test_publication_capture import thaw
from tests.test_publication_decision import artifact
from tests.test_publication_rollback import RollbackFixture


TRACE_SCHEMA_REF = (
    "contracts/directpath-host-snapshot-publication-trace.schema.json"
)
MUTATION_SET_DOMAIN = (
    b"QMAN-DIRECTPATH/HOST-SNAPSHOT-MUTATION-SET/V1\x00"
)
OUTBOX_PAYLOAD_DOMAIN = (
    b"QMAN-DIRECTPATH/HOST-SNAPSHOT-PUBLISHED-PAYLOAD/V1\x00"
)
AUDIT_DOMAIN = (
    b"QMAN-DIRECTPATH/HOST-SNAPSHOT-PUBLICATION-AUDIT/V1\x00"
)
OUTBOX_DOMAIN = (
    b"QMAN-DIRECTPATH/HOST-SNAPSHOT-PUBLICATION-OUTBOX/V1\x00"
)
COMMIT_DOMAIN = (
    b"QMAN-DIRECTPATH/HOST-SNAPSHOT-REPOSITORY-COMMIT/V1\x00"
)
DEVICE_SET_DOMAIN = (
    b"QMAN-DIRECTPATH/HOST-SNAPSHOT-DEVICE-RECORD-SET/V1\x00"
)
RESOLVED_VECTOR_DOMAIN = (
    b"QMAN-DIRECTPATH/HOST-SNAPSHOT-PUBLICATION-AUTHORITY-STATE/V1\x00"
)
MUTATION_CONTEXT_DOMAIN = (
    b"QMAN-DIRECTPATH/HOST-SNAPSHOT-PUBLICATION-MUTATION-CONTEXT/V1\x00"
)
COMMIT_PROJECTION_NULL_FIELDS = (
    "mutationSetHash",
    "availabilityAuthorityAfterInstanceSha256",
    "auditRecordInstanceSha256",
    "outboxRecordInstanceSha256",
    "commitRecordDigest",
)
COMMITTED_AT = "2026-07-24T02:00:02.000000Z"
TARGET_COMMIT = "a" * 40
PORTABLE_REVISION = "2026-07-30.1"
PORTABLE_SHA256 = sha256_digest(b"portable-contract")
ROOT = Path(__file__).resolve().parents[2]


def digest(label: str) -> str:
    return sha256_digest(label.encode())


def projected(
    document: dict,
    *null_fields: str,
) -> dict:
    value = copy.deepcopy(document)
    for name in null_fields:
        value[name] = None
    return value


def plain_projection_digest(
    document: dict,
    *null_fields: str,
) -> str:
    return sha256_digest(
        canonical_json_bytes(projected(document, *null_fields))
    )


def domain_projection_digest(
    domain: bytes,
    document: dict,
    *null_fields: str,
) -> str:
    return sha256_digest(
        domain + canonical_json_bytes(projected(document, *null_fields))
    )


def deterministic_event_id(
    domain: bytes,
    subject: dict,
    prefix: str,
) -> str:
    return (
        prefix
        + ":"
        + sha256_digest(
            domain + canonical_json_bytes(subject)
        ).removeprefix("sha256:")
    )


def mutation(
    kind: str,
    entity: str,
    record_id: str,
    projection: str,
    before: str | None,
    after: str,
) -> dict:
    return {
        "mutationKind": kind,
        "entityType": entity,
        "recordId": record_id,
        "digestProjection": projection,
        "beforeDigestOrNull": before,
        "afterDigestOrNull": after,
    }


class MutationFixture:
    def __init__(self, branch: str) -> None:
        self.schemas = ContractSchemas(
            ROOT / "contracts",
            include_operation_exchange=True,
        )
        self.rollback_fixture = RollbackFixture(
            branch,
            schemas=self.schemas,
        )
        self.rollback = self.rollback_fixture.verify()
        self.decision = self.rollback.decision
        self.command_id = f"capture-{branch.lower()}"
        self.target_format = "SHA1"
        self.target_commit = TARGET_COMMIT
        self.commit_id = f"commit-{branch.lower()}"
        self.operation_request_payload: dict
        self.operation_request_envelope: dict
        self.operation_request = self._build_operation_request()
        self.availability_artifact: dict | None = None
        self.audit_artifact: dict | None = None
        self.outbox_artifact: dict | None = None
        self.commit_artifact: dict | None = None
        if self.decision.write_required:
            self._build_committed_rows()
        self.transaction = self._transaction()
        self.context = self.verify()

    @staticmethod
    def _entity_ref(
        artifact_value: dict,
        *,
        entity_type: str,
        entity_id: str,
        resource_version: int,
        generation_or_null: int | None,
    ) -> dict:
        return {
            "entityType": entity_type,
            "entityId": entity_id,
            "resourceVersion": resource_version,
            "generationOrNull": generation_or_null,
            "contentHash": artifact_value["instanceBytesSha256"],
        }

    @staticmethod
    def _document_ref(
        artifact_value: dict,
        *,
        document_kind: str,
        document_id: str,
        document_version: int,
        schema_ref: str,
    ) -> dict:
        return {
            "documentKind": document_kind,
            "documentId": document_id,
            "documentVersion": document_version,
            "canonicalProfile": "CANONICAL-JSON-V1",
            "schemaRef": schema_ref,
            "contentHash": artifact_value["instanceBytesSha256"],
        }

    @staticmethod
    def _trust_ref(
        *,
        document_kind: str,
        document_id: str,
        document_version: int,
        schema_ref: str,
        canonical_sha256: str,
    ) -> dict:
        return {
            "documentKind": document_kind,
            "documentId": document_id,
            "documentVersion": document_version,
            "canonicalProfile": "CANONICAL-JSON-V1",
            "schemaRef": schema_ref,
            "contentHash": canonical_sha256,
        }

    def _build_operation_request(self):
        read_set = self.decision.read_set
        batch = self.decision.capture.capture_batch
        host_artifact = thaw(read_set.host_authority_before_artifact)
        host = host_artifact["state"]
        availability_artifact = thaw(
            read_set.availability_authority_before_artifact
        )
        availability = availability_artifact["state"]
        capability_artifact = thaw(read_set.capability_policy_artifact)
        capability = capability_artifact["state"]
        capability_authority_artifact = thaw(
            read_set.capability_policy_authority_artifact
        )
        capability_authority = capability_authority_artifact["state"]
        freshness_artifact = thaw(read_set.freshness_policy_artifact)
        freshness = freshness_artifact["state"]
        freshness_authority_artifact = thaw(
            read_set.freshness_policy_authority_artifact
        )
        freshness_authority = freshness_authority_artifact["state"]
        trust = self.rollback.trust
        body = {
            "hostId": batch["hostId"],
            "hostBootIdentity": {
                "hostId": batch["hostId"],
                "kernelBootId": batch["kernelBootId"],
                "hostEpoch": batch["hostEpoch"],
            },
            "currentHostAuthority": self._entity_ref(
                host_artifact,
                entity_type="ENTITY-HOST-AUTHORITY",
                entity_id=host["hostId"],
                resource_version=host["resourceVersion"],
                generation_or_null=host["agentGeneration"],
            ),
            "currentAvailabilityAuthority": self._entity_ref(
                availability_artifact,
                entity_type="ENTITY-AVAILABILITY-AUTHORITY",
                entity_id=availability["availabilityAuthorityId"],
                resource_version=availability["resourceVersion"],
                generation_or_null=None,
            ),
            "capabilityPolicy": self._document_ref(
                capability_artifact,
                document_kind="CAPABILITY_POLICY",
                document_id=capability["policyId"],
                document_version=capability["policyVersion"],
                schema_ref=(
                    "contracts/directpath-capability-policy.schema.json"
                ),
            ),
            "capabilityPolicyAuthority": self._entity_ref(
                capability_authority_artifact,
                entity_type="ENTITY-CAPABILITY-POLICY-AUTHORITY",
                entity_id=capability_authority["policyAuthorityId"],
                resource_version=capability_authority[
                    "resourceVersion"
                ],
                generation_or_null=None,
            ),
            "trustedKeyRing": self._trust_ref(
                document_kind="TRUST_KEY_RING",
                document_id=trust.key_ring_id,
                document_version=trust.key_ring_sequence,
                schema_ref=(
                    "contracts/directpath-trust-key-ring.schema.json"
                ),
                canonical_sha256=trust.current_key_ring_canonical_sha256,
            ),
            "trustRootSet": self._trust_ref(
                document_kind="TRUST_ROOT_SET",
                document_id=trust.root_set_id,
                document_version=1,
                schema_ref=(
                    "contracts/directpath-trust-root-set.schema.json"
                ),
                canonical_sha256=trust.root_set_canonical_sha256,
            ),
            "rollbackAnchor": self._trust_ref(
                document_kind="TRUST_ROLLBACK_ANCHOR",
                document_id=trust.trust_anchor_digest,
                document_version=trust.trust_anchor_version,
                schema_ref=(
                    "contracts/"
                    "directpath-trust-rollback-anchor.schema.json"
                ),
                canonical_sha256=trust.trust_anchor_canonical_sha256,
            ),
            "hostSnapshotRollbackAnchorOrNull": None,
            "hostSnapshotAnchorFreshnessOrNull": None,
            "snapshotFreshnessPolicy": self._document_ref(
                freshness_artifact,
                document_kind="HOST_SNAPSHOT_FRESHNESS_POLICY",
                document_id=freshness["policyId"],
                document_version=freshness["policyVersion"],
                schema_ref=(
                    "contracts/"
                    "directpath-host-snapshot-publication-trace.schema.json"
                    "#/$defs/freshnessPolicy"
                ),
            ),
            "snapshotFreshnessPolicyAuthority": self._entity_ref(
                freshness_authority_artifact,
                entity_type=(
                    "ENTITY-HOST-SNAPSHOT-FRESHNESS-POLICY-AUTHORITY"
                ),
                entity_id=freshness_authority[
                    "freshnessPolicyAuthorityId"
                ],
                resource_version=freshness_authority[
                    "resourceVersion"
                ],
                generation_or_null=None,
            ),
        }
        if read_set.predecessor_rollback_anchor_artifact_or_null is not None:
            predecessor_anchor_artifact = thaw(
                read_set.predecessor_rollback_anchor_artifact_or_null
            )
            predecessor_anchor = predecessor_anchor_artifact["state"]
            predecessor_freshness_artifact = thaw(
                read_set.predecessor_rollback_freshness_artifact_or_null
            )
            predecessor_freshness = predecessor_freshness_artifact["state"]
            body["hostSnapshotRollbackAnchorOrNull"] = self._document_ref(
                predecessor_anchor_artifact,
                document_kind="HOST_SNAPSHOT_ROLLBACK_ANCHOR",
                document_id=predecessor_anchor["anchorDigest"],
                document_version=predecessor_anchor["anchorVersion"],
                schema_ref=(
                    "contracts/"
                    "directpath-host-snapshot-rollback-anchor.schema.json"
                ),
            )
            body["hostSnapshotAnchorFreshnessOrNull"] = self._document_ref(
                predecessor_freshness_artifact,
                document_kind="ANCHOR_FRESHNESS_ENVELOPE",
                document_id=predecessor_freshness["envelopeId"],
                document_version=predecessor_freshness[
                    "resourceVersion"
                ],
                schema_ref=(
                    "contracts/"
                    "directpath-anchor-freshness-envelope.schema.json"
                ),
            )
        payload = {
            "schemaVersion": 1,
            "profileId": (
                "QMAN-DIRECTPATH-OP-PAYLOAD-V1:"
                "OP-CAPTURE-HOST-SNAPSHOT:REQUEST"
            ),
            "operationId": "OP-CAPTURE-HOST-SNAPSHOT",
            "direction": "REQUEST",
            "canonicalProfile": "CANONICAL-JSON-V1",
            "body": body,
        }
        resource_versions = [
            {
                "entityType": body[name]["entityType"],
                "resourceId": body[name]["entityId"],
                "expectedResourceVersion": body[name]["resourceVersion"],
            }
            for name in (
                "currentHostAuthority",
                "currentAvailabilityAuthority",
                "capabilityPolicyAuthority",
                "snapshotFreshnessPolicyAuthority",
            )
        ]
        resource_versions.sort(key=canonical_json_bytes)
        current_inventory = read_set.current_inventory_or_null
        envelope = {
            "schemaVersion": 1,
            "envelopeKind": "REQUEST",
            "operationId": "OP-CAPTURE-HOST-SNAPSHOT",
            "commandId": self.command_id,
            "idempotencyMode": (
                "NEW_EPOCH_WHEN_SEMANTICS_CHANGE_OR_"
                "FRESHNESS_THRESHOLD_IS_REACHED"
            ),
            "idempotencyKey": f"{self.command_id}-key",
            "idempotencyScopeHash": digest(
                f"scope:{self.command_id}"
            ),
            "actorPortId": "PORT-INVENTORY-SNAPSHOT",
            "issuedAt": "2026-07-24T02:00:00.000000Z",
            "deadlineAt": "2026-07-24T02:01:00.000000Z",
            "portableContractId": (
                "QMAN-DIRECTPATH-PORTABLE-CONTROL"
            ),
            "portableContractRevision": PORTABLE_REVISION,
            "portableContractSha256": PORTABLE_SHA256,
            "targetRepositoryObjectFormat": self.target_format,
            "targetRepositoryCommit": self.target_commit,
            "authority": {
                "controllerGeneration": 13,
                "snapshotEpoch": (
                    None
                    if current_inventory is None
                    else current_inventory.snapshot_epoch
                ),
                "hostEpochs": [
                    {
                        "id": batch["hostId"],
                        "generation": batch["hostEpoch"],
                    }
                ],
                "runGenerations": [],
                "memberGenerations": [],
                "resourceVersions": resource_versions,
            },
            "operationLeaseCapabilityOrNull": None,
            "releaseOwnershipGuardCapabilityOrNull": None,
            "payloadSchemaAuthority": "PORTABLE_CONTRACT",
            "payloadSchemaRef": (
                "contracts/directpath-operation-payload.schema.json"
                "#/$defs/profile_OP_CAPTURE_HOST_SNAPSHOT_REQUEST"
            ),
            "payloadSchemaSha256": self.schemas.digest_for_ref(
                OPERATION_PAYLOAD_SCHEMA_DOCUMENT_REF,
                path="test.payloadSchemaSha256",
            ),
            "payloadCanonicalProfile": "CANONICAL-JSON-V1",
            "payloadHash": sha256_digest(canonical_json_bytes(payload)),
            "correlation": {
                "traceId": "1" * 32,
                "spanId": "2" * 16,
                "parentCommandIdOrNull": None,
                "assignmentIdOrNull": None,
                "runIdOrNull": None,
                "relocationIdOrNull": None,
                "hostIds": [batch["hostId"]],
                "deviceUids": [],
            },
            "requestHash": digest("pending-request"),
        }
        projected = copy.deepcopy(envelope)
        projected["requestHash"] = None
        envelope["requestHash"] = sha256_digest(
            canonical_json_bytes(projected)
        )
        self.operation_request_payload = payload
        self.operation_request_envelope = envelope
        return verify_host_snapshot_publication_operation_request(
            self.schemas,
            request_envelope=canonical_json_bytes(envelope),
            request_payload=canonical_json_bytes(payload),
            expected_portable_contract_revision=PORTABLE_REVISION,
            expected_portable_contract_sha256=PORTABLE_SHA256,
            expected_target_repository_object_format=self.target_format,
            expected_target_repository_commit=self.target_commit,
            expected_controller_generation=13,
        )

    def _device_record_set_digest(self) -> str:
        snapshot = self.rollback.host_snapshot_after_artifact["state"]
        subject = {
            "hostSnapshotContentHashOrNull": snapshot["contentHash"],
            "deviceRecordDigests": thaw(snapshot["deviceRecordDigests"]),
        }
        return sha256_digest(
            DEVICE_SET_DOMAIN + canonical_json_bytes(subject)
        )

    def _event_subject(
        self,
        *,
        aggregate_id: str,
        created_at: str,
        commit_clock_before: int,
        commit_clock_after: int,
    ) -> dict:
        return {
            "operationId": "OP-CAPTURE-HOST-SNAPSHOT",
            "commandId": self.operation_request.command_id,
            "requestHash": self.operation_request.request_hash,
            "operationRequestContextDigest": (
                self.operation_request.context_digest
            ),
            "decisionContextDigest": self.decision.context_digest,
            "expectationHash": self.decision.expectation_hash,
            "repositoryId": self.decision.read_set.repository_id,
            "transactionId": self.decision.read_set.transaction_id,
            "commitId": self.commit_id,
            "aggregateId": aggregate_id,
            "createdAt": created_at,
            "commitClockBefore": commit_clock_before,
            "commitClockAfter": commit_clock_after,
            "anchorReservationId": self.rollback.reservation_id_or_null,
            "anchorPrepareReceiptDigest": (
                self.rollback.prepare_receipt_digest_or_null
            ),
            "anchorCandidateProjectionDigest": (
                self.rollback.candidate_projection_digest
            ),
        }

    def _base_mutations(
        self,
        availability: dict,
        audit: dict,
        outbox: dict,
        commit: dict,
    ) -> list[dict]:
        values = [
            mutation(
                "INSERT",
                "ENTITY-DEVICE-RECORD",
                record.device_record_hash,
                "FULL_CANONICAL_INSTANCE",
                None,
                sha256_digest(record.canonical_bytes),
            )
            for record in self.decision.persisted_device_records
        ]
        snapshot = thaw(
            self.rollback.host_snapshot_after_artifact["state"]
        )
        host_before = thaw(self.decision.read_set.host_authority_before)
        host_after = thaw(
            self.rollback.host_authority_after_artifact["state"]
        )
        availability_before = thaw(
            self.decision.read_set.availability_authority_before
        )
        values.extend(
            (
                mutation(
                    "INSERT",
                    "ENTITY-HOST-SNAPSHOT",
                    snapshot["contentHash"],
                    "FULL_CANONICAL_INSTANCE",
                    None,
                    plain_projection_digest(snapshot),
                ),
                mutation(
                    "UPDATE",
                    "ENTITY-HOST-AUTHORITY",
                    host_after["hostId"],
                    "FULL_CANONICAL_INSTANCE",
                    plain_projection_digest(host_before),
                    plain_projection_digest(host_after),
                ),
                mutation(
                    "UPDATE",
                    "ENTITY-AVAILABILITY-AUTHORITY",
                    availability["availabilityAuthorityId"],
                    (
                        "AVAILABILITY_AUTHORITY_"
                        "LAST_MUTATION_DIGEST_NULL"
                    ),
                    plain_projection_digest(
                        availability_before,
                        "lastMutationDigest",
                    ),
                    plain_projection_digest(
                        availability,
                        "lastMutationDigest",
                    ),
                ),
                mutation(
                    "INSERT",
                    "ENTITY-HOST-SNAPSHOT-PUBLICATION-AUDIT",
                    audit["auditEventId"],
                    (
                        "PUBLICATION_AUDIT_MUTATION_SET_"
                        "AND_AUDIT_DIGEST_NULL"
                    ),
                    None,
                    plain_projection_digest(
                        audit,
                        "mutationSetHash",
                        "auditDigest",
                    ),
                ),
                mutation(
                    "INSERT",
                    "ENTITY-HOST-SNAPSHOT-PUBLICATION-OUTBOX",
                    outbox["outboxEventId"],
                    (
                        "PUBLICATION_OUTBOX_MUTATION_SET_"
                        "AND_OUTBOX_DIGEST_NULL"
                    ),
                    None,
                    plain_projection_digest(
                        outbox,
                        "mutationSetHash",
                        "outboxDigest",
                    ),
                ),
                mutation(
                    "INSERT",
                    "ENTITY-HOST-SNAPSHOT-PUBLICATION-COMMIT",
                    commit["commitId"],
                    "PUBLICATION_COMMIT_DERIVED_FIELDS_NULL",
                    None,
                    plain_projection_digest(
                        commit,
                        *COMMIT_PROJECTION_NULL_FIELDS,
                    ),
                ),
            )
        )
        values.sort(
            key=lambda item: canonical_json_bytes(
                [
                    item["entityType"],
                    item["recordId"],
                    item["mutationKind"],
                ]
            )
        )
        return values

    def _build_committed_rows(self) -> None:
        snapshot_artifact = thaw(
            self.rollback.host_snapshot_after_artifact
        )
        host_artifact = thaw(
            self.rollback.host_authority_after_artifact
        )
        snapshot = snapshot_artifact["state"]
        host = host_artifact["state"]
        availability = thaw(
            self.decision.read_set.availability_authority_before
        )
        availability.update(
            {
                "lastMutationDigest": digest("pending-mutation"),
                "lastMutatedAt": COMMITTED_AT,
                "resourceVersion": availability["resourceVersion"] + 1,
            }
        )
        event_subject = self._event_subject(
            aggregate_id=snapshot["hostId"],
            created_at=COMMITTED_AT,
            commit_clock_before=41,
            commit_clock_after=42,
        )
        audit = {
            "schemaVersion": 1,
            "auditEventId": deterministic_event_id(
                AUDIT_EVENT_ID_DOMAIN,
                event_subject,
                "audit",
            ),
            "operationId": "OP-CAPTURE-HOST-SNAPSHOT",
            "commandId": self.command_id,
            "transactionId": self.decision.read_set.transaction_id,
            "commitId": self.commit_id,
            "targetRepositoryObjectFormat": self.target_format,
            "targetRepositoryCommit": self.target_commit,
            "hostId": snapshot["hostId"],
            "anchorReservationId": self.rollback.reservation_id_or_null,
            "anchorPrepareReceiptDigest": (
                self.rollback.prepare_receipt_digest_or_null
            ),
            "anchorCandidateProjectionDigest": (
                self.rollback.candidate_projection_digest
            ),
            "requiredAnchorVersion": self.rollback.required_anchor_version,
            "snapshotContentHash": snapshot["contentHash"],
            "hostAuthorityResourceVersion": host["resourceVersion"],
            "availabilityAuthorityResourceVersion": (
                availability["resourceVersion"]
            ),
            "mutationSetHash": digest("pending-mutation"),
            "priorAuditDigestOrNull": None,
            "createdAt": COMMITTED_AT,
            "auditDigest": digest("pending-audit"),
        }
        outbox = {
            "schemaVersion": 1,
            "outboxEventId": deterministic_event_id(
                OUTBOX_EVENT_ID_DOMAIN,
                event_subject,
                "outbox",
            ),
            "eventType": (
                "HOST_SNAPSHOT_PUBLICATION_COMMITTED_PENDING_ANCHOR"
            ),
            "aggregateId": snapshot["hostId"],
            "transactionId": self.decision.read_set.transaction_id,
            "commitId": self.commit_id,
            "anchorReservationId": self.rollback.reservation_id_or_null,
            "anchorPrepareReceiptDigest": (
                self.rollback.prepare_receipt_digest_or_null
            ),
            "anchorCandidateProjectionDigest": (
                self.rollback.candidate_projection_digest
            ),
            "requiredAnchorVersion": self.rollback.required_anchor_version,
            "deliveryGate": (
                "REQUIRE_LIVE_COMMITTED_ANCHOR_AND_FRESH_NONCE"
            ),
            "deliveryAttemptCountBeforeAnchor": 0,
            "deliverySuccessCountBeforeAnchor": 0,
            "snapshotContentHash": snapshot["contentHash"],
            "hostAuthorityResourceVersion": host["resourceVersion"],
            "availabilityAuthorityResourceVersion": (
                availability["resourceVersion"]
            ),
            "mutationSetHash": digest("pending-mutation"),
            "payloadHash": digest("pending-payload"),
            "createdAt": COMMITTED_AT,
            "resourceVersion": 1,
            "outboxDigest": digest("pending-outbox"),
        }
        payload_subject = {
            "eventType": outbox["eventType"],
            "aggregateId": outbox["aggregateId"],
            "anchorReservationId": outbox["anchorReservationId"],
            "anchorPrepareReceiptDigest": outbox[
                "anchorPrepareReceiptDigest"
            ],
            "anchorCandidateProjectionDigest": outbox[
                "anchorCandidateProjectionDigest"
            ],
            "requiredAnchorVersion": outbox["requiredAnchorVersion"],
            "deliveryGate": outbox["deliveryGate"],
            "snapshotContentHash": outbox["snapshotContentHash"],
            "hostAuthorityResourceVersion": outbox[
                "hostAuthorityResourceVersion"
            ],
            "availabilityAuthorityResourceVersion": outbox[
                "availabilityAuthorityResourceVersion"
            ],
        }
        outbox["payloadHash"] = sha256_digest(
            OUTBOX_PAYLOAD_DOMAIN + canonical_json_bytes(payload_subject)
        )
        commit = {
            "schemaVersion": 1,
            "operationId": "OP-CAPTURE-HOST-SNAPSHOT",
            "commandId": self.operation_request.command_id,
            "requestHash": self.operation_request.request_hash,
            "operationRequestContextDigest": (
                self.operation_request.context_digest
            ),
            "decisionContextDigest": self.decision.context_digest,
            "expectationHash": self.decision.expectation_hash,
            "commitId": self.commit_id,
            "transactionId": self.decision.read_set.transaction_id,
            "repositoryId": self.decision.read_set.repository_id,
            "commitClockBefore": 41,
            "commitClockAfter": 42,
            "committedAt": COMMITTED_AT,
            "anchorReservationId": self.rollback.reservation_id_or_null,
            "anchorPrepareReceiptDigest": (
                self.rollback.prepare_receipt_digest_or_null
            ),
            "anchorCandidateProjectionDigest": (
                self.rollback.candidate_projection_digest
            ),
            "mutationSetHash": digest("pending-mutation"),
            "hostSnapshotInstanceSha256": snapshot_artifact[
                "instanceBytesSha256"
            ],
            "deviceRecordSetDigest": self._device_record_set_digest(),
            "hostAuthorityAfterInstanceSha256": host_artifact[
                "instanceBytesSha256"
            ],
            "availabilityAuthorityAfterInstanceSha256": digest(
                "pending-availability"
            ),
            "auditRecordInstanceSha256": digest("pending-audit-instance"),
            "outboxRecordInstanceSha256": digest(
                "pending-outbox-instance"
            ),
            "commitRecordDigest": digest("pending-commit"),
        }
        mutations = self._base_mutations(
            availability,
            audit,
            outbox,
            commit,
        )
        mutation_hash = sha256_digest(
            MUTATION_SET_DOMAIN + canonical_json_bytes(mutations)
        )
        availability["lastMutationDigest"] = mutation_hash
        audit["mutationSetHash"] = mutation_hash
        outbox["mutationSetHash"] = mutation_hash
        commit["mutationSetHash"] = mutation_hash
        audit["auditDigest"] = domain_projection_digest(
            AUDIT_DOMAIN,
            audit,
            "auditDigest",
        )
        outbox["outboxDigest"] = domain_projection_digest(
            OUTBOX_DOMAIN,
            outbox,
            "outboxDigest",
        )
        self.availability_artifact = artifact(
            (
                "contracts/directpath-authority-entities.schema.json"
                "#/$defs/ENTITY-AVAILABILITY-AUTHORITY"
            ),
            availability,
        )
        self.audit_artifact = artifact(
            TRACE_SCHEMA_REF + "#/$defs/publicationAuditRecord",
            audit,
        )
        self.outbox_artifact = artifact(
            TRACE_SCHEMA_REF + "#/$defs/publicationOutboxRecord",
            outbox,
        )
        commit.update(
            {
                "availabilityAuthorityAfterInstanceSha256": (
                    self.availability_artifact["instanceBytesSha256"]
                ),
                "auditRecordInstanceSha256": self.audit_artifact[
                    "instanceBytesSha256"
                ],
                "outboxRecordInstanceSha256": self.outbox_artifact[
                    "instanceBytesSha256"
                ],
            }
        )
        commit["commitRecordDigest"] = domain_projection_digest(
            COMMIT_DOMAIN,
            commit,
            "commitRecordDigest",
        )
        self.commit_artifact = artifact(
            TRACE_SCHEMA_REF + "#/$defs/repositoryCommitRecord",
            commit,
        )

    def reseal_committed_rows(
        self,
        *,
        transaction: dict | None = None,
        availability: dict | None = None,
        audit: dict | None = None,
        outbox: dict | None = None,
        commit: dict | None = None,
    ) -> dict:
        if (
            self.availability_artifact is None
            or self.audit_artifact is None
            or self.outbox_artifact is None
            or self.commit_artifact is None
        ):
            raise AssertionError("committed rows are unavailable")
        selected_transaction = copy.deepcopy(
            self.transaction if transaction is None else transaction
        )
        availability_state = copy.deepcopy(
            self.availability_artifact["state"]
            if availability is None
            else availability
        )
        audit_state = copy.deepcopy(
            self.audit_artifact["state"] if audit is None else audit
        )
        outbox_state = copy.deepcopy(
            self.outbox_artifact["state"] if outbox is None else outbox
        )
        commit_state = copy.deepcopy(
            self.commit_artifact["state"] if commit is None else commit
        )

        payload_subject = {
            "eventType": outbox_state["eventType"],
            "aggregateId": outbox_state["aggregateId"],
            "anchorReservationId": outbox_state["anchorReservationId"],
            "anchorPrepareReceiptDigest": outbox_state[
                "anchorPrepareReceiptDigest"
            ],
            "anchorCandidateProjectionDigest": outbox_state[
                "anchorCandidateProjectionDigest"
            ],
            "requiredAnchorVersion": outbox_state[
                "requiredAnchorVersion"
            ],
            "deliveryGate": outbox_state["deliveryGate"],
            "snapshotContentHash": outbox_state["snapshotContentHash"],
            "hostAuthorityResourceVersion": outbox_state[
                "hostAuthorityResourceVersion"
            ],
            "availabilityAuthorityResourceVersion": outbox_state[
                "availabilityAuthorityResourceVersion"
            ],
        }
        outbox_state["payloadHash"] = sha256_digest(
            OUTBOX_PAYLOAD_DOMAIN + canonical_json_bytes(payload_subject)
        )
        pending = digest("reseal-pending")
        availability_state["lastMutationDigest"] = pending
        audit_state["mutationSetHash"] = pending
        audit_state["auditDigest"] = pending
        outbox_state["mutationSetHash"] = pending
        outbox_state["outboxDigest"] = pending
        commit_state["mutationSetHash"] = pending
        commit_state["availabilityAuthorityAfterInstanceSha256"] = pending
        commit_state["auditRecordInstanceSha256"] = pending
        commit_state["outboxRecordInstanceSha256"] = pending
        commit_state["commitRecordDigest"] = pending
        mutations = self._base_mutations(
            availability_state,
            audit_state,
            outbox_state,
            commit_state,
        )
        mutation_hash = sha256_digest(
            MUTATION_SET_DOMAIN + canonical_json_bytes(mutations)
        )
        availability_state["lastMutationDigest"] = mutation_hash
        audit_state["mutationSetHash"] = mutation_hash
        outbox_state["mutationSetHash"] = mutation_hash
        commit_state["mutationSetHash"] = mutation_hash
        audit_state["auditDigest"] = domain_projection_digest(
            AUDIT_DOMAIN,
            audit_state,
            "auditDigest",
        )
        outbox_state["outboxDigest"] = domain_projection_digest(
            OUTBOX_DOMAIN,
            outbox_state,
            "outboxDigest",
        )
        availability_artifact = artifact(
            (
                "contracts/directpath-authority-entities.schema.json"
                "#/$defs/ENTITY-AVAILABILITY-AUTHORITY"
            ),
            availability_state,
        )
        audit_artifact = artifact(
            TRACE_SCHEMA_REF + "#/$defs/publicationAuditRecord",
            audit_state,
        )
        outbox_artifact = artifact(
            TRACE_SCHEMA_REF + "#/$defs/publicationOutboxRecord",
            outbox_state,
        )
        commit_state["availabilityAuthorityAfterInstanceSha256"] = (
            availability_artifact["instanceBytesSha256"]
        )
        commit_state["auditRecordInstanceSha256"] = audit_artifact[
            "instanceBytesSha256"
        ]
        commit_state["outboxRecordInstanceSha256"] = outbox_artifact[
            "instanceBytesSha256"
        ]
        commit_state["commitRecordDigest"] = domain_projection_digest(
            COMMIT_DOMAIN,
            commit_state,
            "commitRecordDigest",
        )
        commit_artifact = artifact(
            TRACE_SCHEMA_REF + "#/$defs/repositoryCommitRecord",
            commit_state,
        )
        selected_transaction["resolvedAuthorityVectorHash"] = (
            self.resolved_hash(availability_artifact)
        )
        return {
            "repository_transaction": canonical_json_bytes(
                selected_transaction
            ),
            "availability_authority_after_artifact_or_none": (
                canonical_json_bytes(availability_artifact)
            ),
            "audit_record_artifact_or_none": canonical_json_bytes(
                audit_artifact
            ),
            "outbox_record_artifact_or_none": canonical_json_bytes(
                outbox_artifact
            ),
            "commit_record_artifact_or_none": canonical_json_bytes(
                commit_artifact
            ),
        }

    def resolved_hash(
        self,
        availability_artifact: dict | None = None,
    ) -> str:
        if self.decision.write_required:
            actual_availability = (
                availability_artifact or self.availability_artifact
            )
            if actual_availability is None:
                raise AssertionError("availability artifact is required")
            host_sha = self.rollback.host_authority_after_artifact[
                "instanceBytesSha256"
            ]
            availability_sha = actual_availability[
                "instanceBytesSha256"
            ]
            outcome = "COMMITTED"
            commit_id = self.commit_id
        else:
            host_sha = (
                self.decision.read_set.host_authority_before_artifact[
                    "instanceBytesSha256"
                ]
            )
            availability_sha = (
                self.decision.read_set.availability_authority_before_artifact[
                    "instanceBytesSha256"
                ]
            )
            outcome = "NO_CHANGE"
            commit_id = None
        subject = {
            "subjectType": (
                "HOST_SNAPSHOT_PUBLICATION_RESOLVED_AUTHORITY_VECTOR"
            ),
            "schemaVersion": 1,
            "repositoryId": self.decision.read_set.repository_id,
            "transactionId": self.decision.read_set.transaction_id,
            "outcome": outcome,
            "commitIdOrNull": commit_id,
            "hostAuthorityInstanceSha256": host_sha,
            "availabilityAuthorityInstanceSha256": availability_sha,
            "capabilityPolicyAuthorityInstanceSha256": (
                self.decision.read_set.capability_policy_authority_artifact[
                    "instanceBytesSha256"
                ]
            ),
            "freshnessPolicyAuthorityInstanceSha256": (
                self.decision.read_set.freshness_policy_authority_artifact[
                    "instanceBytesSha256"
                ]
            ),
            "resolvedAuthorityVectorHash": None,
        }
        return sha256_digest(
            RESOLVED_VECTOR_DOMAIN + canonical_json_bytes(subject)
        )

    def _transaction(self) -> dict:
        cas = self.decision.cas_operands
        return {
            "operationId": "OP-CAPTURE-HOST-SNAPSHOT",
            "commandId": self.operation_request.command_id,
            "requestHash": self.operation_request.request_hash,
            "operationRequestContextDigest": (
                self.operation_request.context_digest
            ),
            "decisionContextDigest": self.decision.context_digest,
            "transactionId": self.decision.read_set.transaction_id,
            "repositoryId": self.decision.read_set.repository_id,
            "isolation": "SERIALIZABLE",
            "expectedHostAuthorityResourceVersion": cas[
                "hostAuthority"
            ]["resourceVersion"],
            "expectedAvailabilityAuthorityResourceVersion": cas[
                "availabilityAuthority"
            ]["resourceVersion"],
            "expectedCapabilityPolicyAuthorityResourceVersion": cas[
                "capabilityPolicyAuthority"
            ]["resourceVersion"],
            "expectedCapabilityPolicyHash": cas[
                "capabilityPolicyAuthority"
            ]["policyHash"],
            "expectedFreshnessPolicyAuthorityResourceVersion": cas[
                "freshnessPolicyAuthority"
            ]["resourceVersion"],
            "expectedFreshnessPolicyHash": cas[
                "freshnessPolicyAuthority"
            ]["policyHash"],
            "expectationHash": self.decision.expectation_hash,
            "beganAt": self.decision.read_set.began_at_text,
            "commitClockBefore": 41,
            "commitClockAfter": (
                42 if self.decision.write_required else 41
            ),
            "outcome": (
                "COMMITTED"
                if self.decision.write_required
                else "NO_CHANGE"
            ),
            "commitIdOrNull": (
                self.commit_id if self.decision.write_required else None
            ),
            "committedAtOrNull": (
                COMMITTED_AT if self.decision.write_required else None
            ),
            "resolvedAuthorityVectorHash": self.resolved_hash(),
        }

    def verify(self, **changes):
        operation_request = changes.pop(
            "operation_request",
            self.operation_request,
        )
        arguments = {
            "repository_transaction": canonical_json_bytes(
                self.transaction
            ),
            "availability_authority_after_artifact_or_none": (
                None
                if self.availability_artifact is None
                else canonical_json_bytes(self.availability_artifact)
            ),
            "audit_record_artifact_or_none": (
                None
                if self.audit_artifact is None
                else canonical_json_bytes(self.audit_artifact)
            ),
            "outbox_record_artifact_or_none": (
                None
                if self.outbox_artifact is None
                else canonical_json_bytes(self.outbox_artifact)
            ),
            "commit_record_artifact_or_none": (
                None
                if self.commit_artifact is None
                else canonical_json_bytes(self.commit_artifact)
            ),
        }
        arguments.update(changes)
        return verify_host_snapshot_publication_mutation_closure(
            self.schemas,
            operation_request,
            self.decision,
            self.rollback,
            **arguments,
        )


@pytest.fixture(scope="module")
def successor() -> MutationFixture:
    return MutationFixture("SUCCESSOR")


@pytest.fixture(scope="module")
def no_change() -> MutationFixture:
    return MutationFixture("NO_CHANGE")


def test_successor_committed_closes_all_seven_mutation_types(
    successor: MutationFixture,
) -> None:
    context = successor.context
    by_entity: dict[str, list] = {}
    for item in context.mutations:
        by_entity.setdefault(item["entityType"], []).append(item)

    assert context.publication_mutation_count == (
        len(successor.decision.persisted_device_records) + 6
    )
    assert set(by_entity) == {
        "ENTITY-DEVICE-RECORD",
        "ENTITY-HOST-SNAPSHOT",
        "ENTITY-HOST-AUTHORITY",
        "ENTITY-AVAILABILITY-AUTHORITY",
        "ENTITY-HOST-SNAPSHOT-PUBLICATION-AUDIT",
        "ENTITY-HOST-SNAPSHOT-PUBLICATION-OUTBOX",
        "ENTITY-HOST-SNAPSHOT-PUBLICATION-COMMIT",
    }
    assert {
        item["recordId"]
        for item in by_entity["ENTITY-DEVICE-RECORD"]
    } == {
        record.device_record_hash
        for record in successor.decision.persisted_device_records
    }
    assert by_entity["ENTITY-HOST-SNAPSHOT"][0]["recordId"] == (
        successor.rollback.host_snapshot_after_artifact["state"][
            "contentHash"
        ]
    )
    assert by_entity["ENTITY-HOST-AUTHORITY"][0]["recordId"] == (
        successor.rollback.host_authority_after_artifact["state"]["hostId"]
    )
    assert by_entity["ENTITY-AVAILABILITY-AUTHORITY"][0][
        "recordId"
    ] == successor.availability_artifact["state"]["availabilityAuthorityId"]
    assert by_entity[
        "ENTITY-HOST-SNAPSHOT-PUBLICATION-AUDIT"
    ][0]["recordId"] == successor.audit_artifact["state"]["auditEventId"]
    assert by_entity[
        "ENTITY-HOST-SNAPSHOT-PUBLICATION-OUTBOX"
    ][0]["recordId"] == successor.outbox_artifact["state"]["outboxEventId"]
    assert by_entity[
        "ENTITY-HOST-SNAPSHOT-PUBLICATION-COMMIT"
    ][0]["recordId"] == successor.commit_artifact["state"]["commitId"]
    assert context.authority_boundary == (
        HOST_SNAPSHOT_PUBLICATION_MUTATION_AUTHORITY_BOUNDARY
    )
    assert not context.product_authorized
    assert context.product_evidence_blockers == (
        HOST_SNAPSHOT_PUBLICATION_MUTATION_PRODUCT_EVIDENCE_BLOCKERS
    )


def test_all_digest_projections_match_independent_reconstruction(
    successor: MutationFixture,
) -> None:
    expected = successor._base_mutations(
        successor.availability_artifact["state"],
        successor.audit_artifact["state"],
        successor.outbox_artifact["state"],
        successor.commit_artifact["state"],
    )
    assert canonical_json_bytes([thaw(item) for item in successor.context.mutations]) == (
        canonical_json_bytes(expected)
    )
    assert successor.context.mutation_set_hash_or_null == sha256_digest(
        MUTATION_SET_DOMAIN + canonical_json_bytes(expected)
    )


@pytest.mark.parametrize(
    "artifact_name",
    ("audit", "outbox", "commit"),
)
def test_projection_tampering_breaks_the_fixed_point(
    successor: MutationFixture,
    artifact_name: str,
) -> None:
    if artifact_name == "audit":
        state = copy.deepcopy(successor.audit_artifact["state"])
        state["createdAt"] = "2026-07-24T02:00:02.000001Z"
        state["auditDigest"] = domain_projection_digest(
            AUDIT_DOMAIN,
            state,
            "auditDigest",
        )
        changed = artifact(
            TRACE_SCHEMA_REF + "#/$defs/publicationAuditRecord",
            state,
        )
        changes = {
            "audit_record_artifact_or_none": canonical_json_bytes(changed)
        }
    elif artifact_name == "outbox":
        state = copy.deepcopy(successor.outbox_artifact["state"])
        state["createdAt"] = "2026-07-24T02:00:02.000001Z"
        state["outboxDigest"] = domain_projection_digest(
            OUTBOX_DOMAIN,
            state,
            "outboxDigest",
        )
        changed = artifact(
            TRACE_SCHEMA_REF + "#/$defs/publicationOutboxRecord",
            state,
        )
        changes = {
            "outbox_record_artifact_or_none": canonical_json_bytes(changed)
        }
    else:
        state = copy.deepcopy(successor.commit_artifact["state"])
        state["commitClockBefore"] += 1
        state["commitRecordDigest"] = domain_projection_digest(
            COMMIT_DOMAIN,
            state,
            "commitRecordDigest",
        )
        changed = artifact(
            TRACE_SCHEMA_REF + "#/$defs/repositoryCommitRecord",
            state,
        )
        changes = {
            "commit_record_artifact_or_none": canonical_json_bytes(changed)
        }

    with pytest.raises(
        DirectPathVerificationError,
        match="PUBLICATION_MUTATION_BINDING_MISMATCH",
    ):
        successor.verify(**changes)


def test_availability_mutation_hash_is_a_true_fixed_point(
    successor: MutationFixture,
) -> None:
    state = copy.deepcopy(successor.availability_artifact["state"])
    state["lastMutationDigest"] = digest("wrong-fixed-point")
    changed = artifact(
        (
            "contracts/directpath-authority-entities.schema.json"
            "#/$defs/ENTITY-AVAILABILITY-AUTHORITY"
        ),
        state,
    )
    transaction = copy.deepcopy(successor.transaction)
    transaction["resolvedAuthorityVectorHash"] = successor.resolved_hash(
        changed
    )

    with pytest.raises(
        DirectPathVerificationError,
        match="PUBLICATION_MUTATION_FIXED_POINT_MISMATCH",
    ):
        successor.verify(
            repository_transaction=canonical_json_bytes(transaction),
            availability_authority_after_artifact_or_none=(
                canonical_json_bytes(changed)
            ),
        )


def test_commit_time_must_be_inside_prepared_window(
    successor: MutationFixture,
) -> None:
    transaction = copy.deepcopy(successor.transaction)
    transaction["committedAtOrNull"] = "2026-07-24T02:01:31.000001Z"

    with pytest.raises(
        DirectPathVerificationError,
        match="PUBLICATION_MUTATION_COMMIT_WINDOW_INVALID",
    ):
        successor.verify(
            repository_transaction=canonical_json_bytes(transaction)
        )


def test_resolved_authority_vector_is_substitution_sensitive(
    successor: MutationFixture,
) -> None:
    transaction = copy.deepcopy(successor.transaction)
    transaction["resolvedAuthorityVectorHash"] = digest(
        "wrong-authority-vector"
    )

    with pytest.raises(
        DirectPathVerificationError,
        match="PUBLICATION_MUTATION_BINDING_MISMATCH",
    ):
        successor.verify(
            repository_transaction=canonical_json_bytes(transaction)
        )


def test_no_change_is_exact_zero_write(
    no_change: MutationFixture,
) -> None:
    context = no_change.context

    assert context.publication_mutation_count == 0
    assert context.mutations == ()
    assert context.mutations_canonical_bytes == b"[]"
    assert context.mutation_set_hash_or_null is None
    assert context.commit_record_digest_or_null is None
    assert (
        context.availability_authority_after_artifact_or_null is None
    )
    assert context.audit_record_artifact_or_null is None
    assert context.outbox_record_artifact_or_null is None
    assert context.commit_record_artifact_or_null is None
    assert context.resolved_authority_vector["outcome"] == "NO_CHANGE"
    assert context.resolved_authority_vector["commitIdOrNull"] is None
    assert context.snapshot_publication_cas_result[
        "publicationMutationCount"
    ] == 0
    assert not context.product_authorized


def test_no_change_rejects_any_extra_row_artifact(
    no_change: MutationFixture,
) -> None:
    extra = canonical_json_bytes(
        no_change.decision.read_set.availability_authority_before_artifact
    )
    with pytest.raises(
        DirectPathVerificationError,
        match="PUBLICATION_MUTATION_NO_CHANGE_WRITE",
    ):
        no_change.verify(
            availability_authority_after_artifact_or_none=extra
        )


def test_factory_replay_and_closed_limits(
    successor: MutationFixture,
) -> None:
    context = successor.context
    replayed = replay_host_snapshot_publication_mutation_closure(context)

    assert replayed.context_digest == context.context_digest
    with pytest.raises(TypeError):
        VerifiedHostSnapshotPublicationMutationContext()
    with pytest.raises(TypeError):
        replace(context, publication_mutation_count=0)

    record_count = len(successor.decision.persisted_device_records)
    with (
        patch(
            (
                "qman_directpath_core.publication_mutation."
                "replay_host_snapshot_publication_operation_request"
            )
        ) as operation_replay,
        patch(
            (
                "qman_directpath_core.publication_mutation."
                "replay_host_snapshot_publication_decision"
            )
        ) as decision_replay,
        patch(
            (
                "qman_directpath_core.publication_mutation."
                "replay_host_snapshot_publication_rollback_closure"
            )
        ) as rollback_replay,
        pytest.raises(
            DirectPathVerificationError,
            match="PUBLICATION_MUTATION_TOO_LARGE",
        ),
    ):
        successor.verify(
            limits=PublicationMutationVerifierLimits(
                max_mutations=record_count + 5
            )
        )
    operation_replay.assert_not_called()
    decision_replay.assert_not_called()
    rollback_replay.assert_not_called()

    with pytest.raises(
        DirectPathVerificationError,
        match="PUBLICATION_MUTATION_LIMIT_INVALID",
    ):
        successor.verify(
            limits=PublicationMutationVerifierLimits(
                max_device_records=MAX_PUBLICATION_MUTATION_DEVICE_RECORDS + 1
            )
        )
    assert MAX_PUBLICATION_MUTATION_DEVICE_RECORDS == 4096
    assert MAX_PUBLICATION_MUTATIONS == 4102


def test_cas_result_is_inside_receipt_and_replay_identity(
    successor: MutationFixture,
) -> None:
    context = successor.context
    receipt = thaw(context.context_receipt)
    cas_result = thaw(context.snapshot_publication_cas_result)

    assert receipt["snapshotPublicationCasResult"] == cas_result
    original_projection = copy.deepcopy(receipt)
    original_projection["contextDigest"] = None
    assert context.context_digest == sha256_digest(
        MUTATION_CONTEXT_DOMAIN
        + canonical_json_bytes(original_projection)
    )

    changed_cas = copy.deepcopy(cas_result)
    changed_cas["committedHostAuthorityResourceVersionOrNull"] += 1
    changed_receipt = copy.deepcopy(receipt)
    changed_receipt["snapshotPublicationCasResult"] = changed_cas
    changed_receipt["contextDigest"] = None
    assert sha256_digest(
        MUTATION_CONTEXT_DOMAIN + canonical_json_bytes(changed_receipt)
    ) != context.context_digest

    original_cas = context.snapshot_publication_cas_result
    object.__setattr__(
        context,
        "snapshot_publication_cas_result",
        changed_cas,
    )
    try:
        with pytest.raises(
            DirectPathVerificationError,
            match="PUBLICATION_MUTATION_CONTEXT_REPLAY_MISMATCH",
        ):
            replay_host_snapshot_publication_mutation_closure(context)
    finally:
        object.__setattr__(
            context,
            "snapshot_publication_cas_result",
            original_cas,
        )


def test_verified_request_exactly_binds_read_set_and_durable_context(
    successor: MutationFixture,
) -> None:
    context = successor.context
    transaction = successor.transaction
    commit = successor.commit_artifact["state"]
    receipt = thaw(context.context_receipt)

    assert context.operation_request.request_hash == transaction["requestHash"]
    assert transaction["operationRequestContextDigest"] == (
        context.operation_request.context_digest
    )
    assert transaction["decisionContextDigest"] == (
        successor.decision.context_digest
    )
    for field in (
        "operationId",
        "commandId",
        "requestHash",
        "operationRequestContextDigest",
        "decisionContextDigest",
        "expectationHash",
        "commitClockBefore",
        "commitClockAfter",
    ):
        assert commit[field] == transaction[field]
    assert receipt["operationRequestContextDigest"] == (
        context.operation_request.context_digest
    )
    assert receipt["requestHash"] == context.operation_request.request_hash
    assert receipt["expectationHash"] == successor.decision.expectation_hash


def test_same_command_with_resealed_different_request_cannot_mix_read_sets(
    successor: MutationFixture,
) -> None:
    payload = copy.deepcopy(successor.operation_request_payload)
    envelope = copy.deepcopy(successor.operation_request_envelope)
    payload["body"]["currentHostAuthority"]["contentHash"] = digest(
        "substitute-host-authority"
    )
    envelope["payloadHash"] = sha256_digest(canonical_json_bytes(payload))
    projected = copy.deepcopy(envelope)
    projected["requestHash"] = None
    envelope["requestHash"] = sha256_digest(
        canonical_json_bytes(projected)
    )
    substitute = verify_host_snapshot_publication_operation_request(
        successor.schemas,
        request_envelope=canonical_json_bytes(envelope),
        request_payload=canonical_json_bytes(payload),
        expected_portable_contract_revision=PORTABLE_REVISION,
        expected_portable_contract_sha256=PORTABLE_SHA256,
        expected_target_repository_object_format=successor.target_format,
        expected_target_repository_commit=successor.target_commit,
        expected_controller_generation=13,
    )
    assert substitute.command_id == successor.operation_request.command_id
    assert substitute.request_hash != successor.operation_request.request_hash

    with pytest.raises(
        DirectPathVerificationError,
        match="PUBLICATION_MUTATION_BINDING_MISMATCH",
    ):
        successor.verify(operation_request=substitute)


def test_event_ids_aggregate_and_created_at_are_independently_reconstructable(
    successor: MutationFixture,
) -> None:
    snapshot = successor.rollback.host_snapshot_after_artifact["state"]
    subject = successor._event_subject(
        aggregate_id=snapshot["hostId"],
        created_at=COMMITTED_AT,
        commit_clock_before=41,
        commit_clock_after=42,
    )
    assert successor.audit_artifact["state"]["auditEventId"] == (
        deterministic_event_id(AUDIT_EVENT_ID_DOMAIN, subject, "audit")
    )
    assert successor.outbox_artifact["state"]["outboxEventId"] == (
        deterministic_event_id(OUTBOX_EVENT_ID_DOMAIN, subject, "outbox")
    )
    assert successor.outbox_artifact["state"]["aggregateId"] == (
        snapshot["hostId"]
    )
    assert (
        successor.audit_artifact["state"]["createdAt"]
        == successor.outbox_artifact["state"]["createdAt"]
        == successor.commit_artifact["state"]["committedAt"]
        == successor.transaction["committedAtOrNull"]
    )


def test_fully_resealed_event_id_substitution_still_fails_semantics(
    successor: MutationFixture,
) -> None:
    audit = copy.deepcopy(successor.audit_artifact["state"])
    audit["auditEventId"] = "audit:" + "f" * 64
    changes = successor.reseal_committed_rows(audit=audit)

    with pytest.raises(
        DirectPathVerificationError,
        match="PUBLICATION_MUTATION_BINDING_MISMATCH",
    ):
        successor.verify(**changes)


def test_fully_resealed_aggregate_and_created_at_substitutions_fail(
    successor: MutationFixture,
) -> None:
    outbox = copy.deepcopy(successor.outbox_artifact["state"])
    outbox["aggregateId"] = "host-substitute"
    subject = successor._event_subject(
        aggregate_id=outbox["aggregateId"],
        created_at=outbox["createdAt"],
        commit_clock_before=41,
        commit_clock_after=42,
    )
    outbox["outboxEventId"] = deterministic_event_id(
        OUTBOX_EVENT_ID_DOMAIN,
        subject,
        "outbox",
    )
    changes = successor.reseal_committed_rows(outbox=outbox)
    with pytest.raises(
        DirectPathVerificationError,
        match="PUBLICATION_MUTATION_BINDING_MISMATCH",
    ):
        successor.verify(**changes)

    changed_at = "2026-07-24T02:00:02.000001Z"
    audit = copy.deepcopy(successor.audit_artifact["state"])
    outbox = copy.deepcopy(successor.outbox_artifact["state"])
    audit["createdAt"] = changed_at
    outbox["createdAt"] = changed_at
    subject = successor._event_subject(
        aggregate_id=outbox["aggregateId"],
        created_at=changed_at,
        commit_clock_before=41,
        commit_clock_after=42,
    )
    audit["auditEventId"] = deterministic_event_id(
        AUDIT_EVENT_ID_DOMAIN,
        subject,
        "audit",
    )
    outbox["outboxEventId"] = deterministic_event_id(
        OUTBOX_EVENT_ID_DOMAIN,
        subject,
        "outbox",
    )
    changes = successor.reseal_committed_rows(
        audit=audit,
        outbox=outbox,
    )
    with pytest.raises(
        DirectPathVerificationError,
        match="PUBLICATION_MUTATION_BINDING_MISMATCH",
    ):
        successor.verify(**changes)


def test_fully_resealed_commit_context_and_clock_attacks_fail(
    successor: MutationFixture,
) -> None:
    commit = copy.deepcopy(successor.commit_artifact["state"])
    commit["requestHash"] = digest("substitute-request")
    changes = successor.reseal_committed_rows(commit=commit)
    with pytest.raises(
        DirectPathVerificationError,
        match="PUBLICATION_MUTATION_BINDING_MISMATCH",
    ):
        successor.verify(**changes)

    transaction = copy.deepcopy(successor.transaction)
    commit = copy.deepcopy(successor.commit_artifact["state"])
    audit = copy.deepcopy(successor.audit_artifact["state"])
    outbox = copy.deepcopy(successor.outbox_artifact["state"])
    transaction["commitClockAfter"] = 43
    commit["commitClockAfter"] = 43
    subject = successor._event_subject(
        aggregate_id=outbox["aggregateId"],
        created_at=outbox["createdAt"],
        commit_clock_before=41,
        commit_clock_after=43,
    )
    audit["auditEventId"] = deterministic_event_id(
        AUDIT_EVENT_ID_DOMAIN,
        subject,
        "audit",
    )
    outbox["outboxEventId"] = deterministic_event_id(
        OUTBOX_EVENT_ID_DOMAIN,
        subject,
        "outbox",
    )
    changes = successor.reseal_committed_rows(
        transaction=transaction,
        audit=audit,
        outbox=outbox,
        commit=commit,
    )
    with pytest.raises(
        DirectPathVerificationError,
        match="PUBLICATION_MUTATION_COMMIT_CLOCK_INVALID",
    ):
        successor.verify(**changes)


def test_no_change_cannot_advance_commit_clock(
    no_change: MutationFixture,
) -> None:
    transaction = copy.deepcopy(no_change.transaction)
    transaction["commitClockAfter"] += 1
    with pytest.raises(
        DirectPathVerificationError,
        match="PUBLICATION_MUTATION_COMMIT_CLOCK_INVALID",
    ):
        no_change.verify(
            repository_transaction=canonical_json_bytes(transaction)
        )


def test_verified_operation_binding_keeps_only_product_receipt_blockers(
    successor: MutationFixture,
) -> None:
    context = successor.context
    assert (
        (
            "TARGET_ACCEPTED_OPERATION_REQUEST_IDEMPOTENCY_AND_"
            "DEADLINE_RECEIPT_REQUIRED"
        )
        in context.product_evidence_blockers
    )
    assert (
        "TARGET_PRODUCT_REPOSITORY_TRANSACTION_PORT_REQUIRED"
        in context.product_evidence_blockers
    )
    assert (
        "TARGET_REPOSITORY_FOUR_AUTHORITY_CAS_RECEIPT_REQUIRED"
        in context.product_evidence_blockers
    )
    assert (
        "TARGET_ATOMIC_PUBLICATION_VISIBILITY_RECEIPT_REQUIRED"
        in context.product_evidence_blockers
    )
    assert (
        "TARGET_OUTBOX_POST_ANCHOR_DELIVERY_RECEIPT_REQUIRED"
        in context.product_evidence_blockers
    )
    assert (
        "TARGET_OPERATION_RESULT_SCHEMA_AND_ENVELOPE_BINDING_REQUIRED"
        in context.product_evidence_blockers
    )
    assert (
        (
            "TARGET_DURABLE_COMMIT_CONTEXT_AND_COMMIT_CLOCK_"
            "RECEIPT_REQUIRED"
        )
        in context.product_evidence_blockers
    )
    assert (
        "TARGET_OPERATION_BINDING_AUTHORITY_REQUIRED"
        not in context.product_evidence_blockers
    )
    assert (
        "TARGET_AGGREGATE_EVENT_ID_AND_CREATED_AT_BINDING_REQUIRED"
        not in context.product_evidence_blockers
    )


def test_default_commit_time_is_before_external_finalization(
    successor: MutationFixture,
) -> None:
    committed_at = datetime.strptime(
        successor.transaction["committedAtOrNull"],
        "%Y-%m-%dT%H:%M:%S.%fZ",
    ).replace(tzinfo=timezone.utc)
    assert committed_at <= successor.rollback.finalized_at
