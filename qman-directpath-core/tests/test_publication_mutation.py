from __future__ import annotations

import copy
from dataclasses import replace
from datetime import datetime, timezone
from unittest.mock import patch

import pytest

from qman_directpath_core.canonical import (
    canonical_json_bytes,
    sha256_digest,
)
from qman_directpath_core.errors import DirectPathVerificationError
from qman_directpath_core.publication_mutation import (
    HOST_SNAPSHOT_PUBLICATION_MUTATION_AUTHORITY_BOUNDARY,
    HOST_SNAPSHOT_PUBLICATION_MUTATION_PRODUCT_EVIDENCE_BLOCKERS,
    MAX_PUBLICATION_MUTATION_DEVICE_RECORDS,
    MAX_PUBLICATION_MUTATIONS,
    PublicationMutationVerifierLimits,
    VerifiedHostSnapshotPublicationMutationContext,
    replay_host_snapshot_publication_mutation_closure,
    verify_host_snapshot_publication_mutation_closure,
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
        self.rollback_fixture = RollbackFixture(branch)
        self.schemas = self.rollback_fixture.schemas
        self.rollback = self.rollback_fixture.verify()
        self.decision = self.rollback.decision
        self.command_id = f"capture-{branch.lower()}"
        self.target_format = "SHA1"
        self.target_commit = TARGET_COMMIT
        self.commit_id = f"commit-{branch.lower()}"
        self.availability_artifact: dict | None = None
        self.audit_artifact: dict | None = None
        self.outbox_artifact: dict | None = None
        self.commit_artifact: dict | None = None
        if self.decision.write_required:
            self._build_committed_rows()
        self.transaction = self._transaction()
        self.context = self.verify()

    def _device_record_set_digest(self) -> str:
        snapshot = self.rollback.host_snapshot_after_artifact["state"]
        subject = {
            "hostSnapshotContentHashOrNull": snapshot["contentHash"],
            "deviceRecordDigests": thaw(snapshot["deviceRecordDigests"]),
        }
        return sha256_digest(
            DEVICE_SET_DOMAIN + canonical_json_bytes(subject)
        )

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
        audit = {
            "schemaVersion": 1,
            "auditEventId": "audit-successor",
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
            "outboxEventId": "outbox-successor",
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
        arguments = {
            "repository_transaction": canonical_json_bytes(
                self.transaction
            ),
            "command_id": self.command_id,
            "target_repository_object_format": self.target_format,
            "target_repository_commit": self.target_commit,
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
        match="PUBLICATION_MUTATION_FIXED_POINT_MISMATCH",
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


def test_structural_operation_binding_remains_a_product_blocker(
    successor: MutationFixture,
) -> None:
    context = successor.context
    assert (
        "TARGET_OPERATION_BINDING_AUTHORITY_REQUIRED"
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
        "TARGET_AGGREGATE_EVENT_ID_AND_CREATED_AT_BINDING_REQUIRED"
        in context.product_evidence_blockers
    )
    assert (
        (
            "TARGET_DURABLE_COMMIT_CONTEXT_AND_COMMIT_CLOCK_"
            "SEMANTICS_REQUIRED"
        )
        in context.product_evidence_blockers
    )


def test_default_commit_time_is_before_external_finalization(
    successor: MutationFixture,
) -> None:
    committed_at = datetime.strptime(
        successor.transaction["committedAtOrNull"],
        "%Y-%m-%dT%H:%M:%S.%fZ",
    ).replace(tzinfo=timezone.utc)
    assert committed_at <= successor.rollback.finalized_at
