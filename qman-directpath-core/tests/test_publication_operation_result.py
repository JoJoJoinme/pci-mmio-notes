from __future__ import annotations

import copy
from pathlib import Path
from unittest.mock import patch

import pytest

from qman_directpath_core.canonical import (
    canonical_json_bytes,
    sha256_digest,
)
from qman_directpath_core.errors import DirectPathVerificationError
from qman_directpath_core.publication_operation import (
    HOST_SNAPSHOT_PUBLICATION_OPERATION_RESULT_AUTHORITY_BOUNDARY,
    HOST_SNAPSHOT_PUBLICATION_OPERATION_RESULT_PRODUCT_EVIDENCE_BLOCKERS,
    OPERATION_PAYLOAD_SCHEMA_DOCUMENT_REF,
    PublicationOperationVerifierLimits,
    VerifiedHostSnapshotPublicationOperationResultContext,
    replay_host_snapshot_publication_operation_result,
    verify_host_snapshot_publication_operation_result,
)
from tests.test_publication_capture import thaw
from tests.test_publication_mutation import MutationFixture


ROOT = Path(__file__).resolve().parents[2]
COMPLETED_AT = "2026-07-24T02:00:07.000000Z"
ANCHOR_SCHEMA = (
    "contracts/directpath-host-snapshot-rollback-anchor.schema.json"
)
FRESHNESS_SCHEMA = (
    "contracts/directpath-anchor-freshness-envelope.schema.json"
)
TRACE_SCHEMA = (
    "contracts/directpath-host-snapshot-publication-trace.schema.json"
)


def digest(label: str) -> str:
    return sha256_digest(label.encode())


def sort_rows(rows: list[dict], fields: tuple[str, ...]) -> list[dict]:
    return sorted(
        rows,
        key=lambda row: canonical_json_bytes(
            [row[field_name] for field_name in fields]
        ),
    )


class OperationResultFixture:
    def __init__(self, branch: str) -> None:
        self.mutation_fixture = MutationFixture(branch)
        self.mutation = self.mutation_fixture.context
        self.schemas = self.mutation_fixture.schemas
        self.payload = self._payload()
        self.envelope = self._envelope()

    def _authority(self) -> dict:
        request = thaw(self.mutation.operation_request.request_envelope)
        read_set = self.mutation.decision.read_set
        snapshot = thaw(
            self.mutation.rollback.host_snapshot_after_artifact["state"]
        )
        host = thaw(
            self.mutation.rollback.host_authority_after_artifact["state"]
        )
        if self.mutation.decision.write_required:
            availability_artifact = (
                self.mutation.availability_authority_after_artifact_or_null
            )
            assert availability_artifact is not None
            availability = thaw(availability_artifact["state"])
        else:
            availability = thaw(
                read_set.availability_authority_before
            )
        rows = [
            {
                "entityType": "ENTITY-HOST-AUTHORITY",
                "resourceId": host["hostId"],
                "expectedResourceVersion": host["resourceVersion"],
            },
            {
                "entityType": "ENTITY-AVAILABILITY-AUTHORITY",
                "resourceId": availability["availabilityAuthorityId"],
                "expectedResourceVersion": availability["resourceVersion"],
            },
            {
                "entityType": "ENTITY-CAPABILITY-POLICY-AUTHORITY",
                "resourceId": read_set.capability_policy_authority[
                    "policyAuthorityId"
                ],
                "expectedResourceVersion": (
                    read_set.capability_policy_authority["resourceVersion"]
                ),
            },
            {
                "entityType": (
                    "ENTITY-HOST-SNAPSHOT-FRESHNESS-POLICY-AUTHORITY"
                ),
                "resourceId": read_set.freshness_policy_authority[
                    "freshnessPolicyAuthorityId"
                ],
                "expectedResourceVersion": (
                    read_set.freshness_policy_authority["resourceVersion"]
                ),
            },
        ]
        return {
            "controllerGeneration": request["authority"][
                "controllerGeneration"
            ],
            "snapshotEpoch": snapshot["snapshotEpoch"],
            "hostEpochs": request["authority"]["hostEpochs"],
            "runGenerations": [],
            "memberGenerations": [],
            "resourceVersions": sort_rows(
                rows,
                (
                    "entityType",
                    "resourceId",
                    "expectedResourceVersion",
                ),
            ),
        }

    def _committed_versions(self) -> list[dict]:
        if not self.mutation.decision.write_required:
            return []
        read_set = self.mutation.decision.read_set
        host = thaw(
            self.mutation.rollback.host_authority_after_artifact["state"]
        )
        availability_artifact = (
            self.mutation.availability_authority_after_artifact_or_null
        )
        assert availability_artifact is not None
        availability = thaw(availability_artifact["state"])
        rows = [
            {
                "entityType": "ENTITY-HOST-AUTHORITY",
                "resourceId": host["hostId"],
                "previousResourceVersionOrNull": (
                    read_set.host_authority_before["resourceVersion"]
                ),
                "committedResourceVersion": host["resourceVersion"],
            },
            {
                "entityType": "ENTITY-AVAILABILITY-AUTHORITY",
                "resourceId": availability["availabilityAuthorityId"],
                "previousResourceVersionOrNull": (
                    read_set.availability_authority_before["resourceVersion"]
                ),
                "committedResourceVersion": availability["resourceVersion"],
            },
        ]
        return sort_rows(
            rows,
            (
                "entityType",
                "resourceId",
                "committedResourceVersion",
            ),
        )

    def _receipt(
        self,
        receipt_type: str,
        receipt_id: str,
        schema_ref: str,
        receipt: dict,
    ) -> dict:
        schema_document, _, _ = schema_ref.partition("#")
        return {
            "receiptType": receipt_type,
            "receiptId": receipt_id,
            "schemaRef": schema_ref,
            "schemaSha256": self.schemas.digest_for_ref(
                schema_document,
                path=f"test.{receipt_type}.schemaSha256",
            ),
            "receiptSha256": sha256_digest(
                canonical_json_bytes(receipt)
            ),
        }

    def _receipt_hashes(self) -> list[dict]:
        read_set = self.mutation.decision.read_set
        rollback = self.mutation.rollback
        preflight = thaw(read_set.rollback_authority_preflight)
        anchor = thaw(rollback.after_anchor_artifact["state"])
        freshness = thaw(rollback.after_freshness_artifact["state"])
        rows = [
            self._receipt(
                "RECEIPT-HOST-SNAPSHOT-ROLLBACK-PREFLIGHT",
                preflight["receiptId"],
                ANCHOR_SCHEMA + "#/$defs/rollbackAuthorityPreflightReceipt",
                preflight,
            ),
            self._receipt(
                "RECEIPT-HOST-SNAPSHOT-ANCHOR-COMMIT",
                anchor["receipt"]["receiptId"],
                ANCHOR_SCHEMA + "#/$defs/receipt",
                anchor["receipt"],
            ),
            self._receipt(
                "RECEIPT-HOST-SNAPSHOT-ANCHOR-FRESHNESS",
                freshness["envelopeId"],
                FRESHNESS_SCHEMA,
                freshness,
            ),
        ]
        if self.mutation.decision.write_required:
            prepared_artifact = (
                rollback.prepared_anchor_artifact_or_null
            )
            commit_artifact = self.mutation.commit_record_artifact_or_null
            assert prepared_artifact is not None
            assert commit_artifact is not None
            prepare = thaw(
                prepared_artifact["state"]["prepareReceipt"]
            )
            commit = thaw(commit_artifact["state"])
            rows.extend(
                (
                    self._receipt(
                        "RECEIPT-HOST-SNAPSHOT-ANCHOR-PREPARE",
                        prepare["reservationId"],
                        ANCHOR_SCHEMA + "#/$defs/prepareReceipt",
                        prepare,
                    ),
                    self._receipt(
                        "RECEIPT-HOST-SNAPSHOT-REPOSITORY-COMMIT",
                        commit["commitId"],
                        TRACE_SCHEMA + "#/$defs/repositoryCommitRecord",
                        commit,
                    ),
                )
            )
        return sort_rows(
            rows,
            (
                "receiptType",
                "receiptId",
                "schemaRef",
                "receiptSha256",
            ),
        )

    def _output(self) -> dict:
        rollback = self.mutation.rollback
        snapshot_artifact = thaw(
            rollback.host_snapshot_after_artifact
        )
        host_artifact = thaw(
            rollback.host_authority_after_artifact
        )
        anchor_artifact = thaw(rollback.after_anchor_artifact)
        freshness_artifact = thaw(rollback.after_freshness_artifact)
        snapshot = snapshot_artifact["state"]
        host = host_artifact["state"]
        anchor = anchor_artifact["state"]
        freshness = freshness_artifact["state"]
        snapshot_schema = (
            "contracts/directpath-portable-hash-subjects.schema.json"
            "#/$defs/hostSnapshot"
        )
        return {
            "hostSnapshot": {
                "documentKind": "HOST_SNAPSHOT",
                "documentId": snapshot["contentHash"],
                "documentVersion": snapshot["snapshotEpoch"],
                "canonicalProfile": "CANONICAL-JSON-V1",
                "schemaRef": snapshot_schema,
                "contentHash": snapshot_artifact["instanceBytesSha256"],
            },
            "snapshotContentHash": snapshot["contentHash"],
            "inventorySignature": {
                "documentKind": "HOST_INVENTORY_SIGNATURE",
                "documentId": snapshot["contentHash"],
                "documentVersion": snapshot["keyRingVersion"],
                "canonicalProfile": "CANONICAL-JSON-V1",
                "schemaRef": snapshot_schema,
                "contentHash": snapshot_artifact["instanceBytesSha256"],
            },
            "advancedHostAuthority": {
                "entityType": "ENTITY-HOST-AUTHORITY",
                "entityId": host["hostId"],
                "resourceVersion": host["resourceVersion"],
                "generationOrNull": host["agentGeneration"],
                "contentHash": host_artifact["instanceBytesSha256"],
            },
            "factProvenanceSetHash": (
                self.mutation.decision.capture.snapshot_semantics
                .provider_facts_digest
            ),
            "freshnessDecision": thaw(
                self.mutation.decision.freshness_decision
            ),
            "snapshotRollbackAnchor": {
                "documentKind": "HOST_SNAPSHOT_ROLLBACK_ANCHOR",
                "documentId": anchor["anchorDigest"],
                "documentVersion": anchor["anchorVersion"],
                "canonicalProfile": "CANONICAL-JSON-V1",
                "schemaRef": ANCHOR_SCHEMA,
                "contentHash": anchor_artifact["instanceBytesSha256"],
            },
            "snapshotAnchorFreshness": {
                "documentKind": "ANCHOR_FRESHNESS_ENVELOPE",
                "documentId": freshness["envelopeId"],
                "documentVersion": freshness["resourceVersion"],
                "canonicalProfile": "CANONICAL-JSON-V1",
                "schemaRef": FRESHNESS_SCHEMA,
                "contentHash": freshness_artifact["instanceBytesSha256"],
            },
        }

    def _payload(self) -> dict:
        return {
            "schemaVersion": 1,
            "profileId": (
                "QMAN-DIRECTPATH-OP-PAYLOAD-V1:"
                "OP-CAPTURE-HOST-SNAPSHOT:RESULT"
            ),
            "operationId": "OP-CAPTURE-HOST-SNAPSHOT",
            "direction": "RESULT",
            "canonicalProfile": "CANONICAL-JSON-V1",
            "body": {
                "outcome": "SUCCEEDED",
                "outputOrNull": self._output(),
                "errorOrNull": None,
                "progressOrNull": None,
                "casResult": thaw(
                    self.mutation.snapshot_publication_cas_result
                ),
            },
        }

    def _envelope(self) -> dict:
        request = thaw(self.mutation.operation_request.request_envelope)
        envelope = {
            "schemaVersion": 1,
            "envelopeKind": "RESULT",
            "operationId": request["operationId"],
            "commandId": request["commandId"],
            "idempotencyMode": request["idempotencyMode"],
            "idempotencyKey": request["idempotencyKey"],
            "idempotencyScopeHash": request["idempotencyScopeHash"],
            "actorPortId": request["actorPortId"],
            "status": "SUCCEEDED",
            "retryable": False,
            "reason": None,
            "portableContractId": request["portableContractId"],
            "portableContractRevision": request["portableContractRevision"],
            "portableContractSha256": request["portableContractSha256"],
            "targetRepositoryObjectFormat": (
                request["targetRepositoryObjectFormat"]
            ),
            "targetRepositoryCommit": request["targetRepositoryCommit"],
            "authority": self._authority(),
            "policyHash": (
                self.mutation.decision.read_set.capability_policy.policy_hash
            ),
            "profileHash": None,
            "authoritativeStates": [],
            "committedResourceVersions": self._committed_versions(),
            "receiptHashes": self._receipt_hashes(),
            "payloadSchemaAuthority": "PORTABLE_CONTRACT",
            "payloadSchemaRef": (
                "contracts/directpath-operation-payload.schema.json"
                "#/$defs/profile_OP_CAPTURE_HOST_SNAPSHOT_RESULT"
            ),
            "payloadSchemaSha256": self.schemas.digest_for_ref(
                OPERATION_PAYLOAD_SCHEMA_DOCUMENT_REF,
                path="test.result.payloadSchemaSha256",
            ),
            "payloadCanonicalProfile": "CANONICAL-JSON-V1",
            "payloadHash": sha256_digest(
                canonical_json_bytes(self.payload)
            ),
            "correlation": request["correlation"],
            "completedAt": COMPLETED_AT,
            "resultHash": digest("pending-result"),
        }
        projection = copy.deepcopy(envelope)
        projection["resultHash"] = None
        envelope["resultHash"] = sha256_digest(
            canonical_json_bytes(projection)
        )
        return envelope

    @staticmethod
    def reseal(envelope: dict, payload: dict) -> None:
        envelope["payloadHash"] = sha256_digest(
            canonical_json_bytes(payload)
        )
        projection = copy.deepcopy(envelope)
        projection["resultHash"] = None
        envelope["resultHash"] = sha256_digest(
            canonical_json_bytes(projection)
        )

    def verify(
        self,
        *,
        envelope: dict | bytes | None = None,
        payload: dict | bytes | None = None,
        limits: PublicationOperationVerifierLimits | None = None,
    ) -> VerifiedHostSnapshotPublicationOperationResultContext:
        selected_envelope = self.envelope if envelope is None else envelope
        selected_payload = self.payload if payload is None else payload
        return verify_host_snapshot_publication_operation_result(
            self.schemas,
            self.mutation,
            result_envelope=(
                selected_envelope
                if isinstance(selected_envelope, bytes)
                else canonical_json_bytes(selected_envelope)
            ),
            result_payload=(
                selected_payload
                if isinstance(selected_payload, bytes)
                else canonical_json_bytes(selected_payload)
            ),
            limits=limits,
        )


@pytest.fixture(scope="module")
def committed() -> OperationResultFixture:
    return OperationResultFixture("SUCCESSOR")


@pytest.fixture(scope="module")
def no_change() -> OperationResultFixture:
    return OperationResultFixture("NO_CHANGE")


@pytest.fixture(scope="module")
def committed_context(
    committed: OperationResultFixture,
) -> VerifiedHostSnapshotPublicationOperationResultContext:
    return committed.verify()


def test_committed_success_closes_post_state_and_five_receipts(
    committed: OperationResultFixture,
    committed_context: VerifiedHostSnapshotPublicationOperationResultContext,
) -> None:
    context = committed_context
    assert context.product_authorized is False
    assert context.authority_boundary == (
        HOST_SNAPSHOT_PUBLICATION_OPERATION_RESULT_AUTHORITY_BOUNDARY
    )
    assert context.product_evidence_blockers == (
        HOST_SNAPSHOT_PUBLICATION_OPERATION_RESULT_PRODUCT_EVIDENCE_BLOCKERS
    )
    assert (
        "TARGET_OPERATION_RESULT_SCHEMA_AND_ENVELOPE_BINDING_REQUIRED"
        not in context.product_evidence_blockers
    )
    assert len(context.committed_resource_versions) == 2
    assert len(context.receipt_hashes) == 5
    assert context.result_envelope["authority"] != (
        context.request.request_envelope["authority"]
    )
    assert context.result_envelope["authority"]["snapshotEpoch"] == (
        context.mutation.rollback.host_snapshot_after_artifact["state"][
            "snapshotEpoch"
        ]
    )
    assert all(
        context.result_hash
        not in canonical_json_bytes(artifact).decode()
        for artifact in (
            context.mutation.repository_transaction,
            context.mutation.commit_record_artifact_or_null,
        )
        if artifact is not None
    )


def test_no_change_success_has_zero_versions_and_three_receipts(
    no_change: OperationResultFixture,
) -> None:
    context = no_change.verify()
    assert context.mutation.decision.write_required is False
    assert context.committed_resource_versions == ()
    assert len(context.receipt_hashes) == 3
    assert context.result_payload["body"]["casResult"][
        "committedHostAuthorityResourceVersionOrNull"
    ] is not None
    assert context.result_envelope["authority"] == (
        context.request.request_envelope["authority"]
    )


def test_result_context_replays_and_cannot_be_forged(
    committed_context: VerifiedHostSnapshotPublicationOperationResultContext,
) -> None:
    replayed = replay_host_snapshot_publication_operation_result(
        committed_context
    )
    assert replayed.context_receipt_canonical_bytes == (
        committed_context.context_receipt_canonical_bytes
    )
    with pytest.raises(TypeError):
        VerifiedHostSnapshotPublicationOperationResultContext()
    with pytest.raises(DirectPathVerificationError) as caught:
        replay_host_snapshot_publication_operation_result(object())
    assert caught.value.failure.code == "PUBLICATION_OPERATION_CONTEXT_INVALID"


def test_replay_rejects_tampered_redundant_public_claims(
    committed: OperationResultFixture,
    no_change: OperationResultFixture,
) -> None:
    context = committed.verify()
    original_request = context.request
    object.__setattr__(
        context,
        "request",
        no_change.mutation.operation_request,
    )
    with pytest.raises(DirectPathVerificationError) as caught:
        replay_host_snapshot_publication_operation_result(context)
    assert caught.value.failure.code == (
        "PUBLICATION_OPERATION_CONTEXT_REPLAY_MISMATCH"
    )
    assert caught.value.failure.path.endswith(".request")

    object.__setattr__(context, "request", original_request)
    object.__setattr__(context, "result_hash", digest("tampered-result-claim"))
    with pytest.raises(DirectPathVerificationError) as caught:
        replay_host_snapshot_publication_operation_result(context)
    assert caught.value.failure.code == (
        "PUBLICATION_OPERATION_CONTEXT_REPLAY_MISMATCH"
    )


def test_fully_resealed_request_authority_echo_is_rejected(
    committed: OperationResultFixture,
) -> None:
    envelope = copy.deepcopy(committed.envelope)
    payload = copy.deepcopy(committed.payload)
    envelope["authority"] = thaw(
        committed.mutation.operation_request.request_envelope["authority"]
    )
    committed.reseal(envelope, payload)
    with pytest.raises(DirectPathVerificationError) as caught:
        committed.verify(envelope=envelope, payload=payload)
    assert caught.value.failure.code == (
        "PUBLICATION_OPERATION_BINDING_MISMATCH"
    )
    assert caught.value.failure.path.endswith(".authority")


def test_result_rejects_tampered_redundant_request_echo_before_use(
    committed: OperationResultFixture,
) -> None:
    request = committed.mutation.operation_request
    original_envelope = request.request_envelope
    tampered_request_envelope = thaw(original_envelope)
    tampered_request_envelope["targetRepositoryCommit"] = "b" * 40
    envelope = copy.deepcopy(committed.envelope)
    payload = copy.deepcopy(committed.payload)
    envelope["targetRepositoryCommit"] = "b" * 40
    committed.reseal(envelope, payload)

    object.__setattr__(
        request,
        "request_envelope",
        tampered_request_envelope,
    )
    try:
        with pytest.raises(DirectPathVerificationError) as caught:
            committed.verify(envelope=envelope, payload=payload)
    finally:
        object.__setattr__(request, "request_envelope", original_envelope)

    assert caught.value.failure.code == (
        "PUBLICATION_OPERATION_CONTEXT_REPLAY_MISMATCH"
    )
    assert caught.value.failure.path.endswith(".requestContext")


@pytest.mark.parametrize(
    ("mutate", "expected_path"),
    (
        (
            lambda envelope, payload: payload["body"]["outputOrNull"].__setitem__(
                "factProvenanceSetHash",
                digest("substitute-provider-provenance"),
            ),
            ".body.outputOrNull",
        ),
        (
            lambda envelope, payload: payload["body"]["casResult"].__setitem__(
                "committedAuthorityHashOrNull",
                digest("substitute-authority-vector"),
            ),
            ".body.casResult",
        ),
        (
            lambda envelope, payload: envelope[
                "committedResourceVersions"
            ][0].__setitem__(
                "committedResourceVersion",
                envelope["committedResourceVersions"][0][
                    "committedResourceVersion"
                ]
                + 1,
            ),
            ".committedResourceVersions",
        ),
        (
            lambda envelope, payload: envelope["receiptHashes"][0].__setitem__(
                "receiptSha256",
                digest("substitute-receipt"),
            ),
            ".receiptHashes",
        ),
    ),
)
def test_fully_resealed_semantic_substitutions_are_rejected(
    committed: OperationResultFixture,
    mutate,
    expected_path: str,
) -> None:
    envelope = copy.deepcopy(committed.envelope)
    payload = copy.deepcopy(committed.payload)
    mutate(envelope, payload)
    committed.reseal(envelope, payload)
    with pytest.raises(DirectPathVerificationError) as caught:
        committed.verify(envelope=envelope, payload=payload)
    assert caught.value.failure.code == (
        "PUBLICATION_OPERATION_BINDING_MISMATCH"
    )
    assert caught.value.failure.path.endswith(expected_path)


def test_result_hash_and_payload_hash_are_independently_verified(
    committed: OperationResultFixture,
) -> None:
    envelope = copy.deepcopy(committed.envelope)
    envelope["payloadHash"] = digest("wrong-payload")
    projection = copy.deepcopy(envelope)
    projection["resultHash"] = None
    envelope["resultHash"] = sha256_digest(canonical_json_bytes(projection))
    with pytest.raises(DirectPathVerificationError) as caught:
        committed.verify(envelope=envelope)
    assert caught.value.failure.path.endswith(".payloadHash")

    envelope = copy.deepcopy(committed.envelope)
    envelope["resultHash"] = digest("wrong-result")
    with pytest.raises(DirectPathVerificationError) as caught:
        committed.verify(envelope=envelope)
    assert caught.value.failure.path.endswith(".resultHash")


def test_completed_at_must_follow_freshness_and_precede_deadline(
    committed: OperationResultFixture,
) -> None:
    for completed_at in (
        "2026-07-24T02:00:04.999999Z",
        "2026-07-24T02:01:00.000001Z",
    ):
        envelope = copy.deepcopy(committed.envelope)
        payload = copy.deepcopy(committed.payload)
        envelope["completedAt"] = completed_at
        committed.reseal(envelope, payload)
        with pytest.raises(DirectPathVerificationError) as caught:
            committed.verify(envelope=envelope, payload=payload)
        assert caught.value.failure.code == "PUBLICATION_OPERATION_TIME_INVALID"


def test_size_gate_runs_before_expensive_upstream_replay(
    committed: OperationResultFixture,
) -> None:
    limits = PublicationOperationVerifierLimits(max_envelope_bytes=64)
    with (
        patch(
            "qman_directpath_core.publication_operation."
            "replay_host_snapshot_publication_operation_request"
        ) as request_replay,
        patch(
            "qman_directpath_core.publication_mutation."
            "replay_host_snapshot_publication_mutation_closure"
        ) as mutation_replay,
        pytest.raises(DirectPathVerificationError) as caught,
    ):
        committed.verify(limits=limits)
    assert caught.value.failure.code == "PUBLICATION_OPERATION_TOO_LARGE"
    request_replay.assert_not_called()
    mutation_replay.assert_not_called()
