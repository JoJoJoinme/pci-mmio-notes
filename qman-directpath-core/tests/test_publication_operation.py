from __future__ import annotations

import copy
from dataclasses import replace
from pathlib import Path

import pytest

from qman_directpath_core.canonical import canonical_json_bytes, sha256_digest
from qman_directpath_core.contracts import ContractSchemas
from qman_directpath_core.errors import DirectPathVerificationError
from qman_directpath_core.publication_operation import (
    HOST_SNAPSHOT_PUBLICATION_OPERATION_REQUEST_AUTHORITY_BOUNDARY,
    HOST_SNAPSHOT_PUBLICATION_OPERATION_REQUEST_PRODUCT_EVIDENCE_BLOCKERS,
    OPERATION_PAYLOAD_SCHEMA_DOCUMENT_REF,
    PublicationOperationVerifierLimits,
    VerifiedHostSnapshotPublicationOperationRequestContext,
    replay_host_snapshot_publication_operation_request,
    verify_host_snapshot_publication_operation_request,
)


ROOT = Path(__file__).resolve().parents[2]
CONTRACTS = ROOT / "contracts"
SCHEMAS = ContractSchemas(CONTRACTS, include_operation_exchange=True)
PORTABLE_REVISION = "2026-07-30.1"
PORTABLE_SHA256 = sha256_digest(b"portable-contract")
TARGET_COMMIT = "a" * 40


def digest(label: str) -> str:
    return sha256_digest(label.encode("utf-8"))


def document_ref(
    kind: str,
    identifier: str,
    version: int,
    schema_ref: str,
) -> dict:
    return {
        "documentKind": kind,
        "documentId": identifier,
        "documentVersion": version,
        "canonicalProfile": "CANONICAL-JSON-V1",
        "schemaRef": schema_ref,
        "contentHash": digest(f"{kind}:{identifier}:{version}"),
    }


def entity_ref(
    kind: str,
    identifier: str,
    version: int,
    generation: int | None,
) -> dict:
    return {
        "entityType": kind,
        "entityId": identifier,
        "resourceVersion": version,
        "generationOrNull": generation,
        "contentHash": digest(f"{kind}:{identifier}:{version}"),
    }


class OperationRequestFixture:
    def __init__(self) -> None:
        self.schemas = SCHEMAS
        self.payload = {
            "schemaVersion": 1,
            "profileId": (
                "QMAN-DIRECTPATH-OP-PAYLOAD-V1:"
                "OP-CAPTURE-HOST-SNAPSHOT:REQUEST"
            ),
            "operationId": "OP-CAPTURE-HOST-SNAPSHOT",
            "direction": "REQUEST",
            "canonicalProfile": "CANONICAL-JSON-V1",
            "body": {
                "hostId": "host-a",
                "hostBootIdentity": {
                    "hostId": "host-a",
                    "kernelBootId": "boot-a",
                    "hostEpoch": 3,
                },
                "currentHostAuthority": entity_ref(
                    "ENTITY-HOST-AUTHORITY",
                    "host-a",
                    11,
                    5,
                ),
                "currentAvailabilityAuthority": entity_ref(
                    "ENTITY-AVAILABILITY-AUTHORITY",
                    "availability-global",
                    17,
                    None,
                ),
                "capabilityPolicy": document_ref(
                    "CAPABILITY_POLICY",
                    "capability-policy",
                    4,
                    "contracts/directpath-capability-policy.schema.json",
                ),
                "capabilityPolicyAuthority": entity_ref(
                    "ENTITY-CAPABILITY-POLICY-AUTHORITY",
                    "capability-policy-authority",
                    7,
                    None,
                ),
                "trustedKeyRing": document_ref(
                    "TRUST_KEY_RING",
                    "directpath-ring",
                    2,
                    "contracts/directpath-trust-key-ring.schema.json",
                ),
                "trustRootSet": document_ref(
                    "TRUST_ROOT_SET",
                    "directpath-root",
                    1,
                    "contracts/directpath-trust-root-set.schema.json",
                ),
                "rollbackAnchor": document_ref(
                    "TRUST_ROLLBACK_ANCHOR",
                    digest("trust-anchor"),
                    2,
                    "contracts/directpath-trust-rollback-anchor.schema.json",
                ),
                "hostSnapshotRollbackAnchorOrNull": document_ref(
                    "HOST_SNAPSHOT_ROLLBACK_ANCHOR",
                    digest("snapshot-anchor"),
                    7,
                    (
                        "contracts/"
                        "directpath-host-snapshot-rollback-anchor.schema.json"
                    ),
                ),
                "hostSnapshotAnchorFreshnessOrNull": document_ref(
                    "ANCHOR_FRESHNESS_ENVELOPE",
                    "snapshot-anchor-freshness",
                    9,
                    "contracts/directpath-anchor-freshness-envelope.schema.json",
                ),
                "snapshotFreshnessPolicy": document_ref(
                    "HOST_SNAPSHOT_FRESHNESS_POLICY",
                    "snapshot-freshness-policy",
                    3,
                    (
                        "contracts/"
                        "directpath-host-snapshot-publication-trace.schema.json"
                        "#/$defs/freshnessPolicy"
                    ),
                ),
                "snapshotFreshnessPolicyAuthority": entity_ref(
                    "ENTITY-HOST-SNAPSHOT-FRESHNESS-POLICY-AUTHORITY",
                    "snapshot-freshness-authority",
                    6,
                    None,
                ),
            },
        }
        body = self.payload["body"]
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
        payload_hash = sha256_digest(canonical_json_bytes(self.payload))
        self.envelope = {
            "schemaVersion": 1,
            "envelopeKind": "REQUEST",
            "operationId": "OP-CAPTURE-HOST-SNAPSHOT",
            "commandId": "capture-command-1",
            "idempotencyMode": (
                "NEW_EPOCH_WHEN_SEMANTICS_CHANGE_OR_"
                "FRESHNESS_THRESHOLD_IS_REACHED"
            ),
            "idempotencyKey": "capture-scope-0001",
            "idempotencyScopeHash": digest("capture-scope"),
            "actorPortId": "PORT-INVENTORY-SNAPSHOT",
            "issuedAt": "2026-07-24T01:59:59.000000Z",
            "deadlineAt": "2026-07-24T02:05:00.000000Z",
            "portableContractId": "QMAN-DIRECTPATH-PORTABLE-CONTROL",
            "portableContractRevision": PORTABLE_REVISION,
            "portableContractSha256": PORTABLE_SHA256,
            "targetRepositoryObjectFormat": "SHA1",
            "targetRepositoryCommit": TARGET_COMMIT,
            "authority": {
                "controllerGeneration": 13,
                "snapshotEpoch": 7,
                "hostEpochs": [{"id": "host-a", "generation": 3}],
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
            "payloadHash": payload_hash,
            "correlation": {
                "traceId": "1" * 32,
                "spanId": "2" * 16,
                "parentCommandIdOrNull": None,
                "assignmentIdOrNull": None,
                "runIdOrNull": None,
                "relocationIdOrNull": None,
                "hostIds": ["host-a"],
                "deviceUids": [],
            },
            "requestHash": digest("placeholder"),
        }
        self.reseal()

    def reseal(self) -> None:
        self.envelope["payloadHash"] = sha256_digest(
            canonical_json_bytes(self.payload)
        )
        projected = copy.deepcopy(self.envelope)
        projected["requestHash"] = None
        self.envelope["requestHash"] = sha256_digest(
            canonical_json_bytes(projected)
        )

    def verify(
        self,
        *,
        envelope: dict | bytes | None = None,
        payload: dict | bytes | None = None,
        limits: PublicationOperationVerifierLimits | None = None,
        portable_revision: str = PORTABLE_REVISION,
        portable_sha256: str = PORTABLE_SHA256,
        target_format: str = "SHA1",
        target_commit: str = TARGET_COMMIT,
        controller_generation: int = 13,
    ):
        return verify_host_snapshot_publication_operation_request(
            self.schemas,
            request_envelope=self.envelope if envelope is None else envelope,
            request_payload=self.payload if payload is None else payload,
            expected_portable_contract_revision=portable_revision,
            expected_portable_contract_sha256=portable_sha256,
            expected_target_repository_object_format=target_format,
            expected_target_repository_commit=target_commit,
            expected_controller_generation=controller_generation,
            limits=limits,
        )


def test_request_exact_bytes_hashes_and_replay_are_closed() -> None:
    fixture = OperationRequestFixture()
    context = fixture.verify(
        envelope=canonical_json_bytes(fixture.envelope),
        payload=canonical_json_bytes(fixture.payload),
    )

    assert context.command_id == "capture-command-1"
    assert context.payload_hash == fixture.envelope["payloadHash"]
    assert context.request_hash == fixture.envelope["requestHash"]
    assert context.authority_boundary == (
        HOST_SNAPSHOT_PUBLICATION_OPERATION_REQUEST_AUTHORITY_BOUNDARY
    )
    assert not context.product_authorized
    assert context.product_evidence_blockers == (
        HOST_SNAPSHOT_PUBLICATION_OPERATION_REQUEST_PRODUCT_EVIDENCE_BLOCKERS
    )
    assert context.context_receipt["productAuthorized"] is False

    replayed = replay_host_snapshot_publication_operation_request(context)
    assert replayed.context_digest == context.context_digest
    assert (
        replayed.context_receipt_canonical_bytes
        == context.context_receipt_canonical_bytes
    )
    with pytest.raises(TypeError):
        context.request_envelope["commandId"] = "changed"
    with pytest.raises(TypeError):
        replace(context, command_id="changed")


@pytest.mark.parametrize(
    ("target", "mutate", "expected_code"),
    [
        (
            "payload",
            lambda item: item["body"].__setitem__("hostId", "host-b"),
            "PUBLICATION_OPERATION_BINDING_MISMATCH",
        ),
        (
            "envelope",
            lambda item: item.__setitem__(
                "payloadHash",
                digest("wrong-payload"),
            ),
            "PUBLICATION_OPERATION_BINDING_MISMATCH",
        ),
        (
            "envelope",
            lambda item: item.__setitem__(
                "requestHash",
                digest("wrong-request"),
            ),
            "PUBLICATION_OPERATION_BINDING_MISMATCH",
        ),
    ],
)
def test_detached_payload_and_envelope_hash_substitution_fail_closed(
    target: str,
    mutate,
    expected_code: str,
) -> None:
    fixture = OperationRequestFixture()
    document = copy.deepcopy(
        fixture.payload if target == "payload" else fixture.envelope
    )
    mutate(document)
    with pytest.raises(DirectPathVerificationError) as caught:
        fixture.verify(
            payload=document if target == "payload" else None,
            envelope=document if target == "envelope" else None,
        )
    assert caught.value.failure.code == expected_code


@pytest.mark.parametrize(
    "mutation",
    [
        lambda item: item.__setitem__("operationId", "OP-PLAN-STATIC"),
        lambda item: item.__setitem__("actorPortId", "PORT-CONTROL-API"),
        lambda item: item.__setitem__(
            "operationLeaseCapabilityOrNull",
            {
                "operationLeaseId": "lease",
            },
        ),
        lambda item: item["correlation"].__setitem__(
            "deviceUids",
            ["device-a"],
        ),
        lambda item: item["authority"].__setitem__(
            "hostEpochs",
            [{"id": "host-a", "generation": 4}],
        ),
    ],
)
def test_operation_identity_capability_correlation_and_authority_fail_closed(
    mutation,
) -> None:
    fixture = OperationRequestFixture()
    mutation(fixture.envelope)
    fixture.reseal()
    with pytest.raises(DirectPathVerificationError):
        fixture.verify()


def test_time_and_independent_deployment_expectations_fail_closed() -> None:
    fixture = OperationRequestFixture()
    fixture.envelope["deadlineAt"] = fixture.envelope["issuedAt"]
    fixture.reseal()
    with pytest.raises(DirectPathVerificationError) as caught:
        fixture.verify()
    assert caught.value.failure.code == "PUBLICATION_OPERATION_TIME_INVALID"

    fixture = OperationRequestFixture()
    for kwargs in (
        {"portable_revision": "2026-07-30.2"},
        {"portable_sha256": digest("other-portable")},
        {"target_commit": "b" * 40},
        {"controller_generation": 14},
    ):
        with pytest.raises(DirectPathVerificationError) as caught:
            fixture.verify(**kwargs)
        assert caught.value.failure.code == (
            "PUBLICATION_OPERATION_BINDING_MISMATCH"
        )


def test_noncanonical_duplicate_and_resource_limits_fail_closed() -> None:
    fixture = OperationRequestFixture()
    noncanonical = canonical_json_bytes(fixture.envelope) + b"\n"
    with pytest.raises(DirectPathVerificationError) as caught:
        fixture.verify(envelope=noncanonical)
    assert caught.value.failure.code == (
        "PUBLICATION_OPERATION_CANONICAL_BYTES_INVALID"
    )

    duplicate = b'{"schemaVersion":1,"schemaVersion":1}'
    with pytest.raises(DirectPathVerificationError) as caught:
        fixture.verify(envelope=duplicate)
    assert caught.value.failure.code == (
        "PUBLICATION_OPERATION_CANONICAL_BYTES_INVALID"
    )

    limits = PublicationOperationVerifierLimits(max_envelope_bytes=64)
    with pytest.raises(DirectPathVerificationError) as caught:
        fixture.verify(limits=limits)
    assert caught.value.failure.code == "PUBLICATION_OPERATION_TOO_LARGE"


def test_factory_context_cannot_be_forged_or_replayed() -> None:
    with pytest.raises(TypeError):
        VerifiedHostSnapshotPublicationOperationRequestContext()
    with pytest.raises(DirectPathVerificationError) as caught:
        replay_host_snapshot_publication_operation_request(object())
    assert caught.value.failure.code == "PUBLICATION_OPERATION_CONTEXT_INVALID"
