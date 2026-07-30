from __future__ import annotations

import copy
from dataclasses import FrozenInstanceError, replace
from datetime import datetime, timezone
import inspect
from typing import get_type_hints
from unittest.mock import patch

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
)
import pytest

from qman_directpath_core.canonical import (
    canonical_json_bytes,
    sha256_digest,
)
from qman_directpath_core.errors import DirectPathVerificationError
from qman_directpath_core.publication_repository import (
    HOST_SNAPSHOT_PUBLICATION_REPOSITORY_AUTHORITY_BOUNDARY,
    HOST_SNAPSHOT_PUBLICATION_REPOSITORY_AUTHORITY_DISPOSITION,
    HOST_SNAPSHOT_PUBLICATION_REPOSITORY_PRODUCT_EVIDENCE_BLOCKERS,
    HOST_SNAPSHOT_PUBLICATION_REPOSITORY_RECEIPT_DOMAIN,
    HOST_SNAPSHOT_PUBLICATION_REPOSITORY_RECEIPT_SCHEMA_REF,
    HostSnapshotPublicationRepositoryReceiptLimits,
    HostSnapshotPublicationRepositoryReceiptPort,
    HostSnapshotPublicationRepositoryReceiptQuery,
    VerifiedHostSnapshotPublicationRepositoryContext,
    prepare_host_snapshot_publication_repository_receipt_query,
    replay_host_snapshot_publication_repository_receipt_query,
    replay_verified_host_snapshot_publication_repository_context,
    verify_host_snapshot_publication_repository_receipt,
)
from tests.test_publication_capture import thaw
from tests.test_publication_mutation import MutationFixture
from tests.test_publication_operation_result import OperationResultFixture
from tests.test_trust import (
    NOW_TEXT,
    TrustFixture,
    VALID_FROM,
    VALID_TO,
    projected_digest,
    public_text,
    signature_text,
)


REPOSITORY_KEY_ID = "repository-evidence-key-v1"
QUERY_NONCE = "cmVwb3NpdG9yeS1ub25jZS0wMQ"
REQUESTED_AT = datetime(
    2026,
    7,
    24,
    2,
    0,
    7,
    tzinfo=timezone.utc,
)
OBSERVED_AT = "2026-07-24T02:00:08.000000Z"
SIGNED_AT = "2026-07-24T02:00:09.000000Z"
VERIFIED_AT = datetime(
    2026,
    7,
    24,
    2,
    0,
    10,
    tzinfo=timezone.utc,
)


def digest(label: str) -> str:
    return sha256_digest(label.encode())


def timestamp(value: datetime) -> str:
    return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


class RepositoryTrustFixture(TrustFixture):
    """Trust fixture with a separately held repository-evidence signer."""

    def __init__(self, *, include_inventory_key: bool = False) -> None:
        self.repository_private = Ed25519PrivateKey.generate()
        super().__init__(include_inventory_key=include_inventory_key)

    def _ring(self) -> dict:
        ring = super()._ring()
        ring["keys"].append(
            {
                "keyId": REPOSITORY_KEY_ID,
                "principalId": "urn:qman:principal:repository-evidence",
                "algorithm": "Ed25519",
                "publicKeyBase64Url": public_text(self.repository_private),
                "roles": ["CONTROL_REPOSITORY_EVIDENCE"],
                "notBefore": VALID_FROM,
                "notAfter": VALID_TO,
                "revokedAtOrNull": None,
            }
        )
        ring["keys"].sort(key=canonical_json_bytes)
        ring["rootSignatures"] = []
        ring["keyRingDigest"] = None
        ring["keyRingDigest"], _ = projected_digest(
            ring,
            null_fields=("keyRingDigest",),
            empty_fields=("rootSignatures",),
        )
        subject = {
            "rootKeyId": "root-a",
            "signedAt": NOW_TEXT,
            "keyRingDigest": ring["keyRingDigest"],
        }
        ring["rootSignatures"] = [
            {
                "rootKeyId": "root-a",
                "signature": signature_text(
                    self.root_private,
                    b"QMAN-DIRECTPATH/TRUST-KEY-RING/V1\x00"
                    + canonical_json_bytes(subject),
                ),
                "signedAt": NOW_TEXT,
            }
        ]
        return ring


def _trust_binding(trust) -> dict:
    return {
        "rootSetId": trust.root_set_id,
        "rootSetDigest": trust.root_set_digest,
        "rootSetCanonicalSha256": trust.root_set_canonical_sha256,
        "keyRingId": trust.key_ring_id,
        "keyRingSequence": trust.key_ring_sequence,
        "keyRingDigest": trust.key_ring_digest,
        "currentKeyRingCanonicalSha256": (trust.current_key_ring_canonical_sha256),
        "trustAnchorAuthorityId": trust.trust_anchor_authority_id,
        "trustAnchorVersion": trust.trust_anchor_version,
        "trustAnchorResourceVersion": (trust.trust_anchor_resource_version),
        "trustAnchorDigest": trust.trust_anchor_digest,
        "trustAnchorCanonicalSha256": (trust.trust_anchor_canonical_sha256),
        "trustFreshnessReceiptDigest": trust.freshness_receipt_digest,
        "trustFreshnessExpiresAt": timestamp(trust.freshness_expires_at),
    }


def _artifact_hashes(mutation) -> dict:
    return {
        "hostSnapshotAfter": sha256_digest(
            mutation.rollback.host_snapshot_after_artifact_canonical_bytes
        ),
        "hostAuthorityAfter": sha256_digest(
            mutation.rollback.host_authority_after_artifact_canonical_bytes
        ),
        "availabilityAuthorityAfterOrNull": (
            None
            if (
                mutation.availability_authority_after_artifact_canonical_bytes_or_null
                is None
            )
            else sha256_digest(
                mutation.availability_authority_after_artifact_canonical_bytes_or_null
            )
        ),
        "auditRecordOrNull": (
            None
            if mutation.audit_record_artifact_canonical_bytes_or_null is None
            else sha256_digest(mutation.audit_record_artifact_canonical_bytes_or_null)
        ),
        "outboxRecordOrNull": (
            None
            if mutation.outbox_record_artifact_canonical_bytes_or_null is None
            else sha256_digest(mutation.outbox_record_artifact_canonical_bytes_or_null)
        ),
        "commitRecordOrNull": (
            None
            if mutation.commit_record_artifact_canonical_bytes_or_null is None
            else sha256_digest(mutation.commit_record_artifact_canonical_bytes_or_null)
        ),
    }


def _write_counts(mutation) -> dict:
    if mutation.repository_transaction["outcome"] == "NO_CHANGE":
        return {
            "hostSnapshot": 0,
            "deviceRecord": 0,
            "hostAuthority": 0,
            "availabilityAuthority": 0,
            "publicationAuditRecord": 0,
            "publicationOutboxRecord": 0,
            "repositoryCommitRecord": 0,
        }
    return {
        "hostSnapshot": 1,
        "deviceRecord": len(mutation.decision.persisted_device_records),
        "hostAuthority": 1,
        "availabilityAuthority": 1,
        "publicationAuditRecord": 1,
        "publicationOutboxRecord": 1,
        "repositoryCommitRecord": 1,
    }


class RepositoryFixture:
    def __init__(self, branch: str) -> None:
        with patch(
            "tests.test_publication_rollback.TrustFixture",
            RepositoryTrustFixture,
        ):
            self.mutation_fixture = MutationFixture(branch)
        self.schemas = self.mutation_fixture.schemas
        self.mutation = self.mutation_fixture.context
        self.trust = self.mutation.rollback.trust
        trust_fixture = self.mutation_fixture.rollback_fixture.trust_fixture
        if not isinstance(trust_fixture, RepositoryTrustFixture):
            raise AssertionError("repository trust patch did not take effect")
        self.trust_fixture = trust_fixture
        self.private = trust_fixture.repository_private
        self.query = prepare_host_snapshot_publication_repository_receipt_query(
            self.mutation,
            verification_nonce=QUERY_NONCE,
            requested_at=REQUESTED_AT,
        )
        self.receipt = self.make_receipt()
        self.context = self.verify()

    def make_receipt(self) -> dict:
        mutation = self.mutation
        transaction = thaw(mutation.repository_transaction)
        receipt = {
            "subjectType": ("HOST_SNAPSHOT_PUBLICATION_REPOSITORY_RECEIPT"),
            "schemaVersion": 1,
            "receiptKind": ("HOST_SNAPSHOT_PUBLICATION_REPOSITORY_TRANSACTION"),
            "receiptId": (
                "repository-receipt-" + transaction["outcome"].lower().replace("_", "-")
            ),
            "canonicalProfileId": "CANONICAL-JSON-V1",
            "schemaRef": (HOST_SNAPSHOT_PUBLICATION_REPOSITORY_RECEIPT_SCHEMA_REF),
            "schemaSha256": self.schemas.digest_for_ref(
                HOST_SNAPSHOT_PUBLICATION_REPOSITORY_RECEIPT_SCHEMA_REF,
                path="test.publicationRepository.schemaSha256",
            ),
            "queryDigest": self.query.query_digest,
            "repositoryId": transaction["repositoryId"],
            "transactionId": transaction["transactionId"],
            "operationId": transaction["operationId"],
            "commandId": transaction["commandId"],
            "requestHash": transaction["requestHash"],
            "operationRequestContextDigest": transaction[
                "operationRequestContextDigest"
            ],
            "decisionContextDigest": transaction["decisionContextDigest"],
            "mutationContextDigest": mutation.context_digest,
            "verificationNonce": self.query.verification_nonce,
            "targetRepositoryObjectFormat": (
                self.query.target_repository_object_format
            ),
            "targetRepositoryCommit": (self.query.target_repository_commit),
            "trustContextDigest": self.trust.context_digest,
            "trustBinding": _trust_binding(self.trust),
            "repositoryTransactionCanonicalSha256": sha256_digest(
                mutation.repository_transaction_canonical_bytes
            ),
            "repositoryTransaction": transaction,
            "outcome": transaction["outcome"],
            "commitIdOrNull": transaction["commitIdOrNull"],
            "committedAtOrNull": transaction["committedAtOrNull"],
            "commitClockBefore": transaction["commitClockBefore"],
            "commitClockAfter": transaction["commitClockAfter"],
            "mutationSetHashOrNull": mutation.mutation_set_hash_or_null,
            "mutationsCanonicalSha256": sha256_digest(
                mutation.mutations_canonical_bytes
            ),
            "publicationMutationCount": (mutation.publication_mutation_count),
            "deviceRecordSetDigest": mutation.device_record_set_digest,
            "resolvedAuthorityVectorHash": (mutation.resolved_authority_vector_hash),
            "commitRecordDigestOrNull": (mutation.commit_record_digest_or_null),
            "snapshotPublicationCasResult": thaw(
                mutation.snapshot_publication_cas_result
            ),
            "artifactCanonicalSha256": _artifact_hashes(mutation),
            "writeCounts": _write_counts(mutation),
            "requestedAt": timestamp(self.query.requested_at),
            "observedAt": OBSERVED_AT,
            "signedAt": SIGNED_AT,
            "signerKeyId": REPOSITORY_KEY_ID,
            "keyRingSequence": self.trust.key_ring_sequence,
            "algorithm": "Ed25519",
            "receiptDigest": None,
            "signature": None,
        }
        return self.reseal(receipt)

    def reseal(
        self,
        receipt: dict,
        *,
        private: Ed25519PrivateKey | None = None,
    ) -> dict:
        selected = copy.deepcopy(receipt)
        selected["receiptDigest"] = None
        selected["signature"] = None
        projection = canonical_json_bytes(selected)
        selected["receiptDigest"] = sha256_digest(projection)
        selected["signature"] = signature_text(
            private or self.private,
            HOST_SNAPSHOT_PUBLICATION_REPOSITORY_RECEIPT_DOMAIN + projection,
        )
        return selected

    def verify(
        self,
        *,
        receipt: dict | bytes | None = None,
        query=None,
        trust=None,
        verified_at: datetime = VERIFIED_AT,
        limits: (HostSnapshotPublicationRepositoryReceiptLimits | None) = None,
    ):
        selected_receipt = self.receipt if receipt is None else receipt
        if isinstance(selected_receipt, dict):
            selected_receipt = canonical_json_bytes(selected_receipt)
        return verify_host_snapshot_publication_repository_receipt(
            self.schemas,
            self.trust if trust is None else trust,
            self.mutation,
            query=self.query if query is None else query,
            receipt=selected_receipt,
            verified_at=verified_at,
            limits=limits,
        )


@pytest.fixture(scope="module")
def committed() -> RepositoryFixture:
    return RepositoryFixture("SUCCESSOR")


@pytest.fixture(scope="module")
def no_change() -> RepositoryFixture:
    return RepositoryFixture("NO_CHANGE")


def test_committed_receipt_closes_transaction_cas_and_signature(
    committed: RepositoryFixture,
) -> None:
    context = committed.context
    receipt = committed.receipt
    projection = copy.deepcopy(receipt)
    projection["receiptDigest"] = None
    projection["signature"] = None
    projection_raw = canonical_json_bytes(projection)

    assert context.outcome == "COMMITTED"
    assert context.commit_id_or_null == committed.mutation_fixture.commit_id
    assert context.repository_transaction_canonical_sha256 == sha256_digest(
        committed.mutation.repository_transaction_canonical_bytes
    )
    assert receipt["receiptDigest"] == sha256_digest(projection_raw)
    assert receipt["writeCounts"]["deviceRecord"] == len(
        committed.mutation.decision.persisted_device_records
    )
    assert sum(receipt["writeCounts"].values()) == (
        committed.mutation.publication_mutation_count
    )
    assert receipt["commitClockAfter"] == (receipt["commitClockBefore"] + 1)
    assert receipt["snapshotPublicationCasResult"] == thaw(
        committed.mutation.snapshot_publication_cas_result
    )
    assert context.signer_key_id == REPOSITORY_KEY_ID
    assert context.signer_principal_id == ("urn:qman:principal:repository-evidence")


def test_no_change_receipt_proves_zero_writes_and_stable_clock(
    no_change: RepositoryFixture,
) -> None:
    receipt = no_change.receipt
    context = no_change.context

    assert context.outcome == "NO_CHANGE"
    assert context.commit_id_or_null is None
    assert receipt["committedAtOrNull"] is None
    assert receipt["mutationSetHashOrNull"] is None
    assert receipt["commitRecordDigestOrNull"] is None
    assert receipt["publicationMutationCount"] == 0
    assert set(receipt["writeCounts"].values()) == {0}
    assert receipt["commitClockAfter"] == receipt["commitClockBefore"]
    assert receipt["snapshotPublicationCasResult"]["decision"] == ("NO_CHANGE")
    assert {
        receipt["artifactCanonicalSha256"][name]
        for name in (
            "availabilityAuthorityAfterOrNull",
            "auditRecordOrNull",
            "outboxRecordOrNull",
            "commitRecordOrNull",
        )
    } == {None}


def test_query_factory_replay_and_protocol_keep_exact_bytes(
    committed: RepositoryFixture,
) -> None:
    query = committed.query
    replayed = replay_host_snapshot_publication_repository_receipt_query(query)

    assert replayed == query
    assert replayed.canonical_bytes == canonical_json_bytes(thaw(query.document))
    assert (
        get_type_hints(
            HostSnapshotPublicationRepositoryReceiptPort.read_host_snapshot_publication_repository_receipt
        )["return"]
        is bytes
    )
    parameters = inspect.signature(
        HostSnapshotPublicationRepositoryReceiptPort.read_host_snapshot_publication_repository_receipt
    ).parameters
    assert set(parameters) == {"self", "query"}

    class BytesPort:
        def read_host_snapshot_publication_repository_receipt(
            self,
            *,
            query: HostSnapshotPublicationRepositoryReceiptQuery,
        ) -> bytes:
            assert query is committed.query
            return canonical_json_bytes(committed.receipt)

    port: HostSnapshotPublicationRepositoryReceiptPort = BytesPort()
    raw = port.read_host_snapshot_publication_repository_receipt(query=query)
    assert type(raw) is bytes
    assert committed.verify(receipt=raw) == committed.context


def test_query_replay_rejects_redundant_claim_tamper(
    committed: RepositoryFixture,
) -> None:
    query = prepare_host_snapshot_publication_repository_receipt_query(
        committed.mutation,
        verification_nonce=("cmVwb3NpdG9yeS1ub25jZS0wMg"),
        requested_at=REQUESTED_AT,
    )
    original = query.command_id
    object.__setattr__(query, "command_id", "tampered-command")
    try:
        with pytest.raises(DirectPathVerificationError) as error:
            replay_host_snapshot_publication_repository_receipt_query(query)
        assert error.value.code == ("PUBLICATION_REPOSITORY_QUERY_REPLAY_MISMATCH")
    finally:
        object.__setattr__(query, "command_id", original)


@pytest.mark.parametrize(
    "nonce",
    [
        pytest.param("A" * 25, id="impossible-length-modulo-four"),
        pytest.param("AAAAAAAAAAAAAAAAAAAAAB", id="noncanonical-tail-bits"),
        pytest.param("AAAAAAAAAAAAAAAAAAAA", id="less-than-128-bits"),
    ],
)
def test_query_factory_rejects_noncanonical_or_short_nonce(
    committed: RepositoryFixture,
    nonce: str,
) -> None:
    with pytest.raises(DirectPathVerificationError) as error:
        prepare_host_snapshot_publication_repository_receipt_query(
            committed.mutation,
            verification_nonce=nonce,
            requested_at=REQUESTED_AT,
        )
    assert error.value.code == ("PUBLICATION_REPOSITORY_QUERY_NONCE_INVALID")


def test_factory_context_replays_but_cannot_authorize_product(
    committed: RepositoryFixture,
) -> None:
    context = committed.verify()
    replayed = replay_verified_host_snapshot_publication_repository_context(context)

    assert replayed == context
    assert not context.product_authorized
    assert context.authority_boundary == (
        HOST_SNAPSHOT_PUBLICATION_REPOSITORY_AUTHORITY_BOUNDARY
    )
    assert context.authority_disposition == (
        HOST_SNAPSHOT_PUBLICATION_REPOSITORY_AUTHORITY_DISPOSITION
    )
    assert context.product_evidence_blockers == (
        HOST_SNAPSHOT_PUBLICATION_REPOSITORY_PRODUCT_EVIDENCE_BLOCKERS
    )
    assert context.context_receipt["productAuthorized"] is False
    with pytest.raises(TypeError):
        replace(context, product_authorized=True)
    with pytest.raises(FrozenInstanceError):
        context.product_authorized = True  # type: ignore[misc]
    with pytest.raises(TypeError):
        HostSnapshotPublicationRepositoryReceiptQuery()
    with pytest.raises(TypeError):
        VerifiedHostSnapshotPublicationRepositoryContext()


def test_noncanonical_receipt_fails_before_upstream_replay(
    committed: RepositoryFixture,
) -> None:
    raw = canonical_json_bytes(committed.receipt) + b"\n"
    with patch(
        "qman_directpath_core.publication_repository."
        "replay_host_snapshot_publication_mutation_closure"
    ) as replay:
        with pytest.raises(DirectPathVerificationError) as error:
            committed.verify(receipt=raw)
    assert error.value.code == ("PUBLICATION_REPOSITORY_CANONICAL_BYTES_INVALID")
    replay.assert_not_called()


@pytest.mark.parametrize(
    "receipt",
    [
        pytest.param({}, id="mapping"),
        pytest.param(bytearray(b"{}"), id="bytearray"),
        pytest.param(memoryview(b"{}"), id="memoryview"),
    ],
)
def test_repository_port_rejects_non_bytes_before_upstream_replay(
    committed: RepositoryFixture,
    receipt: object,
) -> None:
    with patch(
        "qman_directpath_core.publication_repository."
        "replay_host_snapshot_publication_mutation_closure"
    ) as replay:
        with pytest.raises(DirectPathVerificationError) as error:
            verify_host_snapshot_publication_repository_receipt(
                committed.schemas,
                committed.trust,
                committed.mutation,
                query=committed.query,
                receipt=receipt,  # type: ignore[arg-type]
                verified_at=VERIFIED_AT,
            )
    assert error.value.code == ("PUBLICATION_REPOSITORY_DOCUMENT_TYPE_INVALID")
    replay.assert_not_called()


def test_byte_ceiling_fails_before_upstream_replay(
    committed: RepositoryFixture,
) -> None:
    limits = HostSnapshotPublicationRepositoryReceiptLimits(max_receipt_bytes=128)
    with patch(
        "qman_directpath_core.publication_repository."
        "replay_host_snapshot_publication_mutation_closure"
    ) as replay:
        with pytest.raises(DirectPathVerificationError) as error:
            committed.verify(limits=limits)
    assert error.value.code == "PUBLICATION_REPOSITORY_TOO_LARGE"
    replay.assert_not_called()


def test_raw_deep_nesting_fails_before_upstream_replay(
    committed: RepositoryFixture,
) -> None:
    raw = b'{"x":' + (b"[" * 20) + b"0" + (b"]" * 20) + b"}"
    limits = HostSnapshotPublicationRepositoryReceiptLimits(max_json_depth=8)
    with patch(
        "qman_directpath_core.publication_repository."
        "replay_host_snapshot_publication_mutation_closure"
    ) as replay:
        with pytest.raises(DirectPathVerificationError) as error:
            committed.verify(receipt=raw, limits=limits)
    assert error.value.code == "PUBLICATION_REPOSITORY_TOO_LARGE"
    replay.assert_not_called()


def test_extra_receipt_field_is_rejected_before_replay(
    committed: RepositoryFixture,
) -> None:
    receipt = copy.deepcopy(committed.receipt)
    receipt["unexpected"] = None
    with patch(
        "qman_directpath_core.publication_repository."
        "replay_host_snapshot_publication_mutation_closure"
    ) as replay:
        with pytest.raises(DirectPathVerificationError) as error:
            committed.verify(receipt=receipt)
    assert error.value.code == ("PUBLICATION_REPOSITORY_RECEIPT_SHAPE_INVALID")
    replay.assert_not_called()


@pytest.mark.parametrize(
    ("field_name", "replacement", "expected_code"),
    (
        (
            "verificationNonce",
            "YWx0ZXJuYXRlLXJlcG8tbm9uY2U",
            "PUBLICATION_REPOSITORY_RECEIPT_BINDING_MISMATCH",
        ),
        (
            "targetRepositoryCommit",
            "b" * 40,
            "PUBLICATION_REPOSITORY_RECEIPT_BINDING_MISMATCH",
        ),
        (
            "commandId",
            "replacement-command",
            "PUBLICATION_REPOSITORY_RECEIPT_BINDING_MISMATCH",
        ),
        (
            "requestHash",
            digest("replacement-request"),
            "PUBLICATION_REPOSITORY_RECEIPT_BINDING_MISMATCH",
        ),
        (
            "operationRequestContextDigest",
            digest("replacement-operation-context"),
            "PUBLICATION_REPOSITORY_RECEIPT_BINDING_MISMATCH",
        ),
        (
            "decisionContextDigest",
            digest("replacement-decision-context"),
            "PUBLICATION_REPOSITORY_RECEIPT_BINDING_MISMATCH",
        ),
        (
            "mutationContextDigest",
            digest("replacement-mutation-context"),
            "PUBLICATION_REPOSITORY_RECEIPT_BINDING_MISMATCH",
        ),
    ),
)
def test_resealed_query_target_command_request_and_context_substitution(
    committed: RepositoryFixture,
    field_name: str,
    replacement,
    expected_code: str,
) -> None:
    receipt = copy.deepcopy(committed.receipt)
    receipt[field_name] = replacement
    receipt = committed.reseal(receipt)

    with pytest.raises(DirectPathVerificationError) as error:
        committed.verify(receipt=receipt)

    assert error.value.code == expected_code


def test_resealed_embedded_transaction_substitution_is_rejected(
    committed: RepositoryFixture,
) -> None:
    receipt = copy.deepcopy(committed.receipt)
    receipt["repositoryTransaction"]["repositoryId"] = "alternate-repository"
    transaction_raw = canonical_json_bytes(receipt["repositoryTransaction"])
    receipt["repositoryTransactionCanonicalSha256"] = sha256_digest(transaction_raw)
    receipt["repositoryId"] = "alternate-repository"
    receipt = committed.reseal(receipt)

    with pytest.raises(DirectPathVerificationError) as error:
        committed.verify(receipt=receipt)

    assert error.value.code == ("PUBLICATION_REPOSITORY_TRANSACTION_BYTES_MISMATCH")


@pytest.mark.parametrize(
    "field_name",
    (
        "expectedHostAuthorityResourceVersionOrNull",
        "expectedAvailabilityAuthorityResourceVersionOrNull",
        "expectedCapabilityPolicyAuthorityResourceVersionOrNull",
        "expectedFreshnessPolicyAuthorityResourceVersionOrNull",
        "committedHostAuthorityResourceVersionOrNull",
        "committedAvailabilityAuthorityResourceVersionOrNull",
    ),
)
def test_resealed_four_authority_version_or_cas_substitution_is_rejected(
    committed: RepositoryFixture,
    field_name: str,
) -> None:
    receipt = copy.deepcopy(committed.receipt)
    cas = receipt["snapshotPublicationCasResult"]
    assert isinstance(cas[field_name], int)
    cas[field_name] += 1
    receipt = committed.reseal(receipt)

    with pytest.raises(DirectPathVerificationError) as error:
        committed.verify(receipt=receipt)

    assert error.value.code == ("PUBLICATION_REPOSITORY_RECEIPT_BINDING_MISMATCH")


@pytest.mark.parametrize(
    "field_name",
    (
        "expectedCapabilityPolicyHashOrNull",
        "expectedFreshnessPolicyHashOrNull",
        "expectationHashOrNull",
        "committedAuthorityHashOrNull",
    ),
)
def test_resealed_policy_or_cas_hash_substitution_is_rejected(
    committed: RepositoryFixture,
    field_name: str,
) -> None:
    receipt = copy.deepcopy(committed.receipt)
    receipt["snapshotPublicationCasResult"][field_name] = digest(
        "replacement-" + field_name
    )
    receipt = committed.reseal(receipt)

    with pytest.raises(DirectPathVerificationError) as error:
        committed.verify(receipt=receipt)

    assert error.value.code == ("PUBLICATION_REPOSITORY_RECEIPT_BINDING_MISMATCH")


@pytest.mark.parametrize(
    "field_name",
    ("commitClockBefore", "commitClockAfter"),
)
def test_resealed_commit_clock_substitution_is_rejected(
    committed: RepositoryFixture,
    field_name: str,
) -> None:
    receipt = copy.deepcopy(committed.receipt)
    receipt[field_name] += 1
    receipt = committed.reseal(receipt)

    with pytest.raises(DirectPathVerificationError) as error:
        committed.verify(receipt=receipt)

    assert error.value.code == ("PUBLICATION_REPOSITORY_RECEIPT_BINDING_MISMATCH")


def test_resealed_write_count_substitution_is_rejected(
    committed: RepositoryFixture,
) -> None:
    receipt = copy.deepcopy(committed.receipt)
    receipt["writeCounts"]["deviceRecord"] += 1
    receipt = committed.reseal(receipt)

    with pytest.raises(DirectPathVerificationError) as error:
        committed.verify(receipt=receipt)

    assert error.value.code == ("PUBLICATION_REPOSITORY_WRITE_COUNT_MISMATCH")


@pytest.mark.parametrize(
    "field_name",
    (
        "mutationSetHashOrNull",
        "mutationsCanonicalSha256",
        "deviceRecordSetDigest",
        "resolvedAuthorityVectorHash",
        "commitRecordDigestOrNull",
    ),
)
def test_resealed_mutation_or_commit_hash_substitution_is_rejected(
    committed: RepositoryFixture,
    field_name: str,
) -> None:
    receipt = copy.deepcopy(committed.receipt)
    receipt[field_name] = digest("replacement-" + field_name)
    receipt = committed.reseal(receipt)

    with pytest.raises(DirectPathVerificationError) as error:
        committed.verify(receipt=receipt)

    assert error.value.code == ("PUBLICATION_REPOSITORY_RECEIPT_BINDING_MISMATCH")


def test_resealed_publication_mutation_count_substitution_is_rejected(
    committed: RepositoryFixture,
) -> None:
    receipt = copy.deepcopy(committed.receipt)
    receipt["publicationMutationCount"] += 1
    receipt = committed.reseal(receipt)

    with pytest.raises(DirectPathVerificationError) as error:
        committed.verify(receipt=receipt)

    assert error.value.code == ("PUBLICATION_REPOSITORY_RECEIPT_BINDING_MISMATCH")


@pytest.mark.parametrize(
    "field_name",
    (
        "hostSnapshotAfter",
        "hostAuthorityAfter",
        "availabilityAuthorityAfterOrNull",
        "auditRecordOrNull",
        "outboxRecordOrNull",
        "commitRecordOrNull",
    ),
)
def test_resealed_artifact_hash_substitution_is_rejected(
    committed: RepositoryFixture,
    field_name: str,
) -> None:
    receipt = copy.deepcopy(committed.receipt)
    receipt["artifactCanonicalSha256"][field_name] = digest("replacement-" + field_name)
    receipt = committed.reseal(receipt)

    with pytest.raises(DirectPathVerificationError) as error:
        committed.verify(receipt=receipt)

    assert error.value.code == ("PUBLICATION_REPOSITORY_ARTIFACT_HASH_MISMATCH")


def test_receipt_digest_and_signature_are_independently_verified(
    committed: RepositoryFixture,
) -> None:
    wrong_digest = copy.deepcopy(committed.receipt)
    wrong_digest["receiptDigest"] = digest("wrong-receipt")
    with pytest.raises(DirectPathVerificationError) as digest_error:
        committed.verify(receipt=wrong_digest)
    assert digest_error.value.code == ("PUBLICATION_REPOSITORY_RECEIPT_DIGEST_INVALID")

    wrong_signature = copy.deepcopy(committed.receipt)
    wrong_signature["signature"] = "ed25519:" + ("A" * 86)
    with pytest.raises(DirectPathVerificationError) as signature_error:
        committed.verify(receipt=wrong_signature)
    assert signature_error.value.code == "SIGNATURE_INVALID"


def test_signer_must_have_repository_evidence_role(
    committed: RepositoryFixture,
) -> None:
    inventory_private = committed.trust_fixture.inventory_private
    if inventory_private is None:
        raise AssertionError("inventory signer is required")
    receipt = copy.deepcopy(committed.receipt)
    receipt["signerKeyId"] = "inventory-key-v1"
    receipt = committed.reseal(receipt, private=inventory_private)

    with pytest.raises(DirectPathVerificationError) as error:
        committed.verify(receipt=receipt)

    assert error.value.code == "SIGNER_ROLE_INVALID"


def test_repository_signer_revocation_is_checked_at_signed_time(
    committed: RepositoryFixture,
) -> None:
    key = committed.trust.keys[REPOSITORY_KEY_ID]
    original = key.revoked_at
    object.__setattr__(
        key,
        "revoked_at",
        datetime(2026, 7, 24, 2, 0, 8, tzinfo=timezone.utc),
    )
    try:
        with pytest.raises(DirectPathVerificationError) as error:
            committed.verify()
        assert error.value.code == "SIGNER_REVOKED"
    finally:
        object.__setattr__(key, "revoked_at", original)


def test_repository_signer_expiry_is_checked_at_signed_time(
    committed: RepositoryFixture,
) -> None:
    key = committed.trust.keys[REPOSITORY_KEY_ID]
    original = key.not_after
    object.__setattr__(
        key,
        "not_after",
        datetime(2026, 7, 24, 2, 0, 9, tzinfo=timezone.utc),
    )
    try:
        with pytest.raises(DirectPathVerificationError) as error:
            committed.verify()
        assert error.value.code == "SIGNER_INACTIVE"
    finally:
        object.__setattr__(key, "not_after", original)


def test_alternate_self_consistent_trust_is_not_substitutable(
    committed: RepositoryFixture,
    no_change: RepositoryFixture,
) -> None:
    with pytest.raises(DirectPathVerificationError) as error:
        committed.verify(trust=no_change.trust)

    assert error.value.code == ("PUBLICATION_REPOSITORY_TRUST_CONTEXT_MISMATCH")


def test_resealed_trust_binding_substitution_is_rejected(
    committed: RepositoryFixture,
) -> None:
    receipt = copy.deepcopy(committed.receipt)
    receipt["trustBinding"]["keyRingDigest"] = digest("alternate-key-ring")
    receipt = committed.reseal(receipt)

    with pytest.raises(DirectPathVerificationError) as error:
        committed.verify(receipt=receipt)

    assert error.value.code == ("PUBLICATION_REPOSITORY_TRUST_BINDING_MISMATCH")


def test_operation_request_and_signature_use_the_same_exact_trust(
    committed: RepositoryFixture,
) -> None:
    body = thaw(committed.mutation.operation_request.request_payload["body"])
    trust = committed.trust

    assert body["trustRootSet"]["contentHash"] == (trust.root_set_canonical_sha256)
    assert body["trustedKeyRing"]["contentHash"] == (
        trust.current_key_ring_canonical_sha256
    )
    assert body["rollbackAnchor"]["contentHash"] == (
        trust.trust_anchor_canonical_sha256
    )
    assert committed.receipt["trustContextDigest"] == (trust.context_digest)
    assert REPOSITORY_KEY_ID in trust.keys


def test_later_receipt_material_is_absent_from_commit_mutation_and_result(
    committed: RepositoryFixture,
) -> None:
    receipt = committed.receipt
    result = OperationResultFixture.__new__(OperationResultFixture)
    result.mutation_fixture = committed.mutation_fixture
    result.mutation = committed.mutation
    result.schemas = committed.schemas
    result.payload = result._payload()
    result.envelope = result._envelope()
    preimages = [
        committed.mutation.repository_transaction_canonical_bytes,
        committed.mutation.mutations_canonical_bytes,
        canonical_json_bytes(result.payload),
        canonical_json_bytes(result.envelope),
    ]
    commit_bytes = committed.mutation.commit_record_artifact_canonical_bytes_or_null
    assert commit_bytes is not None
    preimages.append(commit_bytes)

    for value in (
        receipt["queryDigest"],
        receipt["receiptDigest"],
        receipt["signature"],
    ):
        encoded = value.encode()
        assert all(encoded not in preimage for preimage in preimages)


def test_back_reference_gate_rejects_later_query_digest_in_retained_row(
    committed: RepositoryFixture,
) -> None:
    rollback = committed.mutation.rollback
    field_name = "host_snapshot_after_artifact_canonical_bytes"
    original = getattr(rollback, field_name)
    injected = original + committed.query.query_digest.encode()
    object.__setattr__(rollback, field_name, injected)
    try:
        receipt = copy.deepcopy(committed.receipt)
        receipt["artifactCanonicalSha256"]["hostSnapshotAfter"] = sha256_digest(
            injected
        )
        receipt = committed.reseal(receipt)
        with patch(
            "qman_directpath_core.publication_repository."
            "replay_host_snapshot_publication_mutation_closure",
            side_effect=lambda value: value,
        ):
            with pytest.raises(DirectPathVerificationError) as error:
                committed.verify(receipt=receipt)
        assert error.value.code == ("PUBLICATION_REPOSITORY_DIGEST_BACK_REFERENCE")
    finally:
        object.__setattr__(rollback, field_name, original)
