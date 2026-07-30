from __future__ import annotations

import base64
import copy
from dataclasses import fields, replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

import pytest

from qman_directpath_core.canonical import (
    canonical_json_bytes,
    measure_canonical_json,
    sha256_digest,
)
from qman_directpath_core.errors import DirectPathVerificationError
from qman_directpath_core.inventory import VerifiedCandidateDeviceRecordSet
from qman_directpath_core.publication_capture import (
    VerifiedHostSnapshotCaptureClosureContext,
)
from qman_directpath_core.publication_decision import (
    HOST_SNAPSHOT_PUBLICATION_DECISION_AUTHORITY_BOUNDARY,
    HOST_SNAPSHOT_PUBLICATION_DECISION_PRODUCT_EVIDENCE_BLOCKERS,
    MAX_FULL_PUBLICATION_DEVICE_RECORDS,
    PublicationDecisionVerifierLimits,
    StructuralPublicationReadSet,
    VerifiedHostSnapshotPublicationDecisionContext,
    replay_host_snapshot_publication_decision,
    replay_structural_publication_read_set,
    verify_host_snapshot_publication_decision,
    verify_structural_publication_read_set,
)
from tests.test_host_snapshot_anchor import HostSnapshotAnchorFixture
from tests.test_inventory import CAPTURED_AT, InventoryFixture
from tests.test_publication_capture import PublicationFixture, thaw


ROOT = Path(__file__).resolve().parents[2]
CONTRACTS = ROOT / "contracts"
CAS_DOMAIN = (
    b"QMAN-DIRECTPATH/HOST-SNAPSHOT-PUBLICATION-CAS-EXPECTATION/V1\x00"
)
READ_RECEIPT_DOMAIN = (
    b"QMAN-DIRECTPATH/HOST-SNAPSHOT-PUBLICATION-STRUCTURAL-READ-SET/V1\x00"
)
PREFLIGHT_DOMAIN = (
    b"QMAN-DIRECTPATH/HOST-SNAPSHOT-ROLLBACK-AUTHORITY-PREFLIGHT/V1\x00"
)
DEFAULT_BEGAN_AT = datetime(
    2026,
    7,
    24,
    2,
    0,
    1,
    tzinfo=timezone.utc,
)


def digest(label: str) -> str:
    return sha256_digest(label.encode())


def timestamp(value: datetime) -> str:
    return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def artifact(schema_ref: str, state: dict) -> dict:
    raw = canonical_json_bytes(state)
    return {
        "schemaRef": schema_ref,
        "state": copy.deepcopy(state),
        "canonicalInstanceBase64": base64.b64encode(raw).decode("ascii"),
        "instanceBytesSha256": sha256_digest(raw),
    }


def preflight_artifact(
    *,
    host_id: str,
    authority_id: str,
    predecessor_digest: str | None,
    began_at: datetime,
) -> dict:
    checked_at = began_at - timedelta(seconds=1)
    expires_at = began_at + timedelta(seconds=60)
    state = {
        "schemaVersion": 1,
        "receiptType": "HOST_SNAPSHOT_ROLLBACK_AUTHORITY_PREFLIGHT",
        "receiptId": f"preflight-{int(began_at.timestamp())}",
        "hostId": host_id,
        "authorityId": authority_id,
        "predecessorAnchorDigestOrNull": predecessor_digest,
        "checkedAt": timestamp(checked_at),
        "expiresAt": timestamp(expires_at),
        "verifierNonce": "AAAAAAAAAAAAAAAAAAAAAA",
        "unresolvedReservationCount": 0,
        "trustRootDigest": digest("root"),
        "receiptDigest": None,
        "rootSignatures": [],
    }
    state["receiptDigest"] = sha256_digest(
        PREFLIGHT_DOMAIN + canonical_json_bytes(state)
    )
    state["rootSignatures"] = [
        {
            "rootKeyId": "root-a",
            "signedAt": timestamp(began_at),
            "algorithm": "Ed25519",
            "signature": f"ed25519:{'A' * 86}",
        }
    ]
    return artifact(
        (
            "contracts/directpath-host-snapshot-rollback-anchor.schema.json"
            "#/$defs/rollbackAuthorityPreflightReceipt"
        ),
        state,
    )


def reseal_anchor_freshness(
    fixture: HostSnapshotAnchorFixture,
    *,
    observed_at: str,
    expires_at: str,
) -> dict:
    state = copy.deepcopy(fixture.freshness)
    state.update(
        {
            "authorityId": fixture.anchor["authorityId"],
            "subjectId": fixture.anchor["hostId"],
            "anchorBlobSha256": sha256_digest(
                canonical_json_bytes(fixture.anchor)
            ),
            "anchorDigest": fixture.anchor["anchorDigest"],
            "anchorVersion": fixture.anchor["anchorVersion"],
            "resourceVersion": fixture.anchor["resourceVersion"],
            "observedAt": observed_at,
            "expiresAt": expires_at,
            "freshnessReceiptDigest": None,
            "rootSignatures": [],
        }
    )
    state["freshnessReceiptDigest"] = sha256_digest(canonical_json_bytes(state))
    state["rootSignatures"] = [
        {
            "rootKeyId": "root-a",
            "signedAt": observed_at,
            "algorithm": "Ed25519",
            "signature": f"ed25519:{'A' * 86}",
        }
    ]
    return state


def stamp_candidate(
    fixture: PublicationFixture,
    *,
    snapshot_epoch: int,
    resource_version: int,
) -> None:
    for record in fixture.inventory.records:
        record["generations"].update(
            {
                "snapshotEpoch": snapshot_epoch,
                "deviceGeneration": snapshot_epoch,
                "resourceVersion": resource_version,
            }
        )
    fixture.rebuild_capture_from_records()


def current_inventory_for(
    publication: PublicationFixture,
    *,
    freshness_policy_hash: str | None = None,
):
    fixture = InventoryFixture()
    fixture.snapshot["policyHash"] = publication.capability_policy.policy_hash
    fixture.snapshot["snapshotFreshnessPolicyHash"] = (
        freshness_policy_hash or publication.freshness_policy["policyHash"]
    )
    fixture.reseal()
    return fixture, fixture.verify()


def unpublished_host_authority(
    publication: PublicationFixture,
    *,
    resource_version: int = 1,
) -> dict:
    value = copy.deepcopy(publication.inventory.authority)
    value.update(
        {
            "cooperationState": "RECONCILING",
            "lastSnapshotEpoch": 0,
            "currentSnapshotContentHash": None,
            "lastObservedAt": "2026-07-24T01:59:30.000000Z",
            "resourceVersion": resource_version,
        }
    )
    return value


def cas_expectation(
    *,
    repository_id: str,
    host_artifact: dict,
    availability_artifact: dict,
    capability_policy_authority_artifact: dict,
    capability_policy_hash: str,
    freshness_policy_authority_artifact: dict,
    freshness_policy_hash: str,
) -> dict:
    host = host_artifact["state"]
    availability = availability_artifact["state"]
    capability = capability_policy_authority_artifact["state"]
    freshness = freshness_policy_authority_artifact["state"]
    value = {
        "subjectType": "HOST_SNAPSHOT_PUBLICATION_CAS_EXPECTATION",
        "schemaVersion": 1,
        "repositoryId": repository_id,
        "hostAuthority": {
            "authorityId": host["hostId"],
            "resourceVersion": host["resourceVersion"],
            "instanceBytesSha256": host_artifact["instanceBytesSha256"],
        },
        "availabilityAuthority": {
            "authorityId": availability["availabilityAuthorityId"],
            "resourceVersion": availability["resourceVersion"],
            "instanceBytesSha256": availability_artifact["instanceBytesSha256"],
        },
        "capabilityPolicyAuthority": {
            "authorityId": capability["policyAuthorityId"],
            "resourceVersion": capability["resourceVersion"],
            "policyHash": capability_policy_hash,
            "instanceBytesSha256": (
                capability_policy_authority_artifact["instanceBytesSha256"]
            ),
        },
        "freshnessPolicyAuthority": {
            "authorityId": freshness["freshnessPolicyAuthorityId"],
            "resourceVersion": freshness["resourceVersion"],
            "policyHash": freshness_policy_hash,
            "instanceBytesSha256": (
                freshness_policy_authority_artifact["instanceBytesSha256"]
            ),
        },
        "expectationHash": None,
    }
    value["expectationHash"] = sha256_digest(
        CAS_DOMAIN + canonical_json_bytes(value)
    )
    return value


class ReadSetFixture:
    def __init__(
        self,
        publication: PublicationFixture,
        *,
        current=None,
        host_authority: dict | None = None,
        predecessor: HostSnapshotAnchorFixture | None = None,
        began_at: datetime = DEFAULT_BEGAN_AT,
        authority_versions: tuple[int, int, int] = (17, 23, 29),
    ) -> None:
        self.schemas = publication.schemas
        self.publication = publication
        self.current = current
        self.began_at = began_at
        self.host_authority_state = thaw(
            host_authority
            or (
                current.host_authority
                if current is not None
                else unpublished_host_authority(publication)
            )
        )
        availability_version, capability_version, freshness_version = (
            authority_versions
        )
        self.host = artifact(
            (
                "contracts/directpath-authority-entities.schema.json"
                "#/$defs/ENTITY-HOST-AUTHORITY"
            ),
            self.host_authority_state,
        )
        self.availability = artifact(
            (
                "contracts/directpath-authority-entities.schema.json"
                "#/$defs/ENTITY-AVAILABILITY-AUTHORITY"
            ),
            {
                "availabilityAuthorityId": "availability-global",
                "clusterId": "cluster-test",
                "authorityScope": "GLOBAL_DIRECTPATH_AVAILABILITY",
                "lastMutationDigest": digest("last-availability-mutation"),
                "lastMutatedAt": "2026-07-24T01:59:20.000000Z",
                "resourceVersion": availability_version,
            },
        )
        policy_state = thaw(publication.capability_policy.document)
        self.capability_policy = artifact(
            "contracts/directpath-capability-policy.schema.json",
            policy_state,
        )
        self.capability_policy_authority = artifact(
            (
                "contracts/directpath-authority-entities.schema.json"
                "#/$defs/ENTITY-CAPABILITY-POLICY-AUTHORITY"
            ),
            {
                "policyAuthorityId": "capability-policy-authority",
                "policyId": policy_state["policyId"],
                "policyVersion": policy_state["policyVersion"],
                "policyDigest": policy_state["policyHash"],
                "resourceVersion": capability_version,
            },
        )
        freshness_state = copy.deepcopy(publication.freshness_policy)
        self.freshness_policy = artifact(
            (
                "contracts/directpath-host-snapshot-publication-trace."
                "schema.json#/$defs/freshnessPolicy"
            ),
            freshness_state,
        )
        self.freshness_policy_authority = artifact(
            (
                "contracts/directpath-authority-entities.schema.json"
                "#/$defs/ENTITY-HOST-SNAPSHOT-FRESHNESS-POLICY-AUTHORITY"
            ),
            {
                "freshnessPolicyAuthorityId": "freshness-policy-authority",
                "policyId": freshness_state["policyId"],
                "policyVersion": freshness_state["policyVersion"],
                "policyDigest": freshness_state["policyHash"],
                "resourceVersion": freshness_version,
            },
        )
        self.predecessor_anchor = (
            None
            if predecessor is None
            else artifact(
                "contracts/directpath-host-snapshot-rollback-anchor.schema.json",
                predecessor.anchor,
            )
        )
        self.predecessor_freshness = (
            None
            if predecessor is None
            else artifact(
                "contracts/directpath-anchor-freshness-envelope.schema.json",
                predecessor.freshness,
            )
        )
        predecessor_digest = (
            None if predecessor is None else predecessor.anchor["anchorDigest"]
        )
        authority_id = (
            "external-host-snapshot-authority-test"
            if predecessor is None
            else predecessor.anchor["authorityId"]
        )
        self.preflight = preflight_artifact(
            host_id=self.host_authority_state["hostId"],
            authority_id=authority_id,
            predecessor_digest=predecessor_digest,
            began_at=began_at,
        )
        self.receipt = self._receipt()

    def _receipt(self) -> dict:
        repository_id = "directpath-repository-test"
        expectation = cas_expectation(
            repository_id=repository_id,
            host_artifact=self.host,
            availability_artifact=self.availability,
            capability_policy_authority_artifact=(
                self.capability_policy_authority
            ),
            capability_policy_hash=self.capability_policy["state"]["policyHash"],
            freshness_policy_authority_artifact=(
                self.freshness_policy_authority
            ),
            freshness_policy_hash=self.freshness_policy["state"]["policyHash"],
        )

        def artifact_sha(value: dict | None) -> str | None:
            return (
                None
                if value is None
                else sha256_digest(canonical_json_bytes(value))
            )

        receipt = {
            "subjectType": (
                "HOST_SNAPSHOT_PUBLICATION_STRUCTURAL_READ_RECEIPT"
            ),
            "schemaVersion": 1,
            "repositoryId": repository_id,
            "transactionId": "publication-transaction-test",
            "isolation": "SERIALIZABLE",
            "beganAt": timestamp(self.began_at),
            "hostAuthorityArtifactCanonicalSha256": artifact_sha(self.host),
            "availabilityAuthorityArtifactCanonicalSha256": artifact_sha(
                self.availability
            ),
            "capabilityPolicyArtifactCanonicalSha256": artifact_sha(
                self.capability_policy
            ),
            "capabilityPolicyAuthorityArtifactCanonicalSha256": artifact_sha(
                self.capability_policy_authority
            ),
            "freshnessPolicyArtifactCanonicalSha256": artifact_sha(
                self.freshness_policy
            ),
            "freshnessPolicyAuthorityArtifactCanonicalSha256": artifact_sha(
                self.freshness_policy_authority
            ),
            "currentInventoryVerificationReceiptDigestOrNull": (
                None
                if self.current is None
                else self.current.inventory_verification_receipt_digest
            ),
            "predecessorRollbackAnchorArtifactCanonicalSha256OrNull": (
                artifact_sha(self.predecessor_anchor)
            ),
            "predecessorRollbackFreshnessArtifactCanonicalSha256OrNull": (
                artifact_sha(self.predecessor_freshness)
            ),
            "rollbackAuthorityPreflightArtifactCanonicalSha256": artifact_sha(
                self.preflight
            ),
            "expectationHash": expectation["expectationHash"],
            "receiptDigest": None,
        }
        receipt["receiptDigest"] = sha256_digest(
            READ_RECEIPT_DOMAIN + canonical_json_bytes(receipt)
        )
        return receipt

    def reseal_receipt(self) -> None:
        self.receipt = self._receipt()

    def verify(self, *, limits: PublicationDecisionVerifierLimits | None = None):
        return verify_structural_publication_read_set(
            self.schemas,
            host_authority_before=canonical_json_bytes(self.host),
            availability_authority_before=canonical_json_bytes(
                self.availability
            ),
            capability_policy=canonical_json_bytes(self.capability_policy),
            capability_policy_authority=canonical_json_bytes(
                self.capability_policy_authority
            ),
            freshness_policy=canonical_json_bytes(self.freshness_policy),
            freshness_policy_authority=canonical_json_bytes(
                self.freshness_policy_authority
            ),
            current_inventory=self.current,
            predecessor_rollback_anchor=(
                None
                if self.predecessor_anchor is None
                else canonical_json_bytes(self.predecessor_anchor)
            ),
            predecessor_rollback_freshness=(
                None
                if self.predecessor_freshness is None
                else canonical_json_bytes(self.predecessor_freshness)
            ),
            rollback_authority_preflight=canonical_json_bytes(self.preflight),
            structural_transaction_read_receipt=canonical_json_bytes(
                self.receipt
            ),
            limits=limits,
        )


def move_preflight_before_capture(read_fixture: ReadSetFixture) -> None:
    state = copy.deepcopy(read_fixture.preflight["state"])
    signatures = state["rootSignatures"]
    state["checkedAt"] = "2026-07-24T01:59:29.000000Z"
    state["receiptDigest"] = None
    state["rootSignatures"] = []
    state["receiptDigest"] = sha256_digest(
        PREFLIGHT_DOMAIN + canonical_json_bytes(state)
    )
    state["rootSignatures"] = signatures
    read_fixture.preflight = artifact(
        read_fixture.preflight["schemaRef"],
        state,
    )
    read_fixture.reseal_receipt()


def current_decision_fixture(
    *,
    began_at: datetime = DEFAULT_BEGAN_AT,
    semantic_change: bool = False,
    nonsemantic_change: bool = False,
    maximum_evidence_age_micros: int = 32_000_000,
):
    publication = PublicationFixture(
        maximum_evidence_age_micros=maximum_evidence_age_micros
    )
    _, current = current_inventory_for(publication)
    if semantic_change or nonsemantic_change:
        record = publication.inventory.records[0]
        raw = bytearray.fromhex(
            record["role"]["pciStructureFact"]["rawConfigSpaceHexOrNull"]
        )
        raw[0x0E if semantic_change else 0x80] ^= 0x80 if semantic_change else 0x5A
        publication.inventory.bind_pci_capture(record, bytes(raw))
    stamp_candidate(publication, snapshot_epoch=8, resource_version=12)
    capture = publication.verify()
    predecessor = HostSnapshotAnchorFixture(
        genesis=False,
        inventory=current,
    )
    read_fixture = ReadSetFixture(
        publication,
        current=current,
        predecessor=predecessor,
        began_at=began_at,
    )
    return publication, current, capture, read_fixture


def incarnation_decision_fixture(
    *,
    host_epoch: int,
    agent_generation: int,
    kernel_boot_id: str = "boot-test-2",
):
    predecessor = HostSnapshotAnchorFixture(genesis=False)
    publication = PublicationFixture()
    publication.inventory.snapshot.update(
        {
            "kernelBootId": kernel_boot_id,
            "hostEpoch": host_epoch,
            "agentGeneration": agent_generation,
        }
    )
    publication.inventory.authority.update(
        {
            "kernelBootId": kernel_boot_id,
            "hostEpoch": host_epoch,
            "agentGeneration": agent_generation,
        }
    )
    for record in publication.inventory.records:
        record["generations"].update(
            {
                "hostEpoch": host_epoch,
                "agentGeneration": agent_generation,
            }
        )
    stamp_candidate(publication, snapshot_epoch=1, resource_version=15)
    capture = publication.verify()
    host = unpublished_host_authority(publication, resource_version=14)
    read_fixture = ReadSetFixture(
        publication,
        host_authority=host,
        predecessor=predecessor,
    )
    return capture, read_fixture


@pytest.mark.parametrize(
    ("branch", "expected"),
    (
        ("GENESIS", "GENESIS_COMMITTED"),
        ("INCARNATION_GENESIS", "INCARNATION_GENESIS_COMMITTED"),
        ("SUCCESSOR", "SUCCESSOR_COMMITTED"),
        ("REFRESH", "REFRESH_COMMITTED"),
        ("NO_CHANGE", "NO_CHANGE"),
    ),
)
def test_five_positive_branches_are_derived_and_component_only(
    branch: str,
    expected: str,
) -> None:
    if branch == "GENESIS":
        publication = PublicationFixture()
        stamp_candidate(publication, snapshot_epoch=1, resource_version=2)
        capture = publication.verify()
        read_fixture = ReadSetFixture(
            publication,
            host_authority=unpublished_host_authority(publication),
        )
    elif branch == "INCARNATION_GENESIS":
        predecessor = HostSnapshotAnchorFixture(genesis=False)
        publication = PublicationFixture()
        publication.inventory.snapshot.update(
            {
                "kernelBootId": "boot-test-2",
                "hostEpoch": 4,
                "agentGeneration": 6,
            }
        )
        publication.inventory.authority.update(
            {
                "kernelBootId": "boot-test-2",
                "hostEpoch": 4,
                "agentGeneration": 6,
            }
        )
        for record in publication.inventory.records:
            record["generations"].update(
                {
                    "hostEpoch": 4,
                    "agentGeneration": 6,
                }
            )
        stamp_candidate(publication, snapshot_epoch=1, resource_version=15)
        capture = publication.verify()
        host = unpublished_host_authority(publication, resource_version=14)
        read_fixture = ReadSetFixture(
            publication,
            host_authority=host,
            predecessor=predecessor,
        )
    elif branch == "SUCCESSOR":
        publication, _, capture, read_fixture = current_decision_fixture(
            semantic_change=True
        )
    elif branch == "REFRESH":
        publication, _, capture, read_fixture = current_decision_fixture(
            began_at=datetime(
                2026,
                7,
                24,
                2,
                0,
                2,
                tzinfo=timezone.utc,
            )
        )
    else:
        publication, _, capture, read_fixture = current_decision_fixture()

    read_set = read_fixture.verify()
    decision = verify_host_snapshot_publication_decision(capture, read_set)

    assert decision.decision_kind == branch
    assert decision.publication_decision == expected
    assert decision.product_authorized is False
    assert read_set.product_authorized is False
    assert (
        decision.authority_boundary
        == HOST_SNAPSHOT_PUBLICATION_DECISION_AUTHORITY_BOUNDARY
    )
    assert set(HOST_SNAPSHOT_PUBLICATION_DECISION_PRODUCT_EVIDENCE_BLOCKERS) <= set(
        decision.product_evidence_blockers
    )
    assert decision.write_required is (branch != "NO_CHANGE")
    replayed_read = replay_structural_publication_read_set(read_set)
    replayed_decision = replay_host_snapshot_publication_decision(decision)
    assert replayed_read.context_digest == read_set.context_digest
    assert replayed_decision.context_digest == decision.context_digest


def test_preflight_root_signature_cannot_postdate_caller_began_at() -> None:
    publication = PublicationFixture()
    read_fixture = ReadSetFixture(
        publication,
        host_authority=unpublished_host_authority(publication),
    )
    state = copy.deepcopy(read_fixture.preflight["state"])
    state["rootSignatures"][0]["signedAt"] = timestamp(
        read_fixture.began_at + timedelta(microseconds=1)
    )
    read_fixture.preflight = artifact(
        read_fixture.preflight["schemaRef"],
        state,
    )
    read_fixture.reseal_receipt()

    with pytest.raises(DirectPathVerificationError) as raised:
        read_fixture.verify()

    assert raised.value.code == "PUBLICATION_DECISION_ROLLBACK_TIME_INVALID"


def test_predecessor_freshness_and_preflight_require_distinct_nonces() -> None:
    publication = PublicationFixture(maximum_evidence_age_micros=60_000_000)
    _, current = current_inventory_for(publication)
    predecessor = HostSnapshotAnchorFixture(genesis=False, inventory=current)
    read_fixture = ReadSetFixture(
        publication,
        current=current,
        predecessor=predecessor,
    )
    state = copy.deepcopy(read_fixture.preflight["state"])
    signatures = state["rootSignatures"]
    state["verifierNonce"] = predecessor.freshness["verifierNonce"]
    state["receiptDigest"] = None
    state["rootSignatures"] = []
    state["receiptDigest"] = sha256_digest(
        PREFLIGHT_DOMAIN + canonical_json_bytes(state)
    )
    state["rootSignatures"] = signatures
    read_fixture.preflight = artifact(
        read_fixture.preflight["schemaRef"],
        state,
    )
    read_fixture.reseal_receipt()

    with pytest.raises(DirectPathVerificationError) as raised:
        read_fixture.verify()

    assert raised.value.code == "PUBLICATION_DECISION_ROLLBACK_NONCE_REUSE"


@pytest.mark.parametrize(
    ("host_epoch", "agent_generation"),
    ((3, 5), (2, 6), (4, 4)),
)
def test_incarnation_genesis_requires_monotonic_counters(
    host_epoch: int,
    agent_generation: int,
) -> None:
    capture, read_fixture = incarnation_decision_fixture(
        host_epoch=host_epoch,
        agent_generation=agent_generation,
    )

    with pytest.raises(DirectPathVerificationError) as raised:
        verify_host_snapshot_publication_decision(
            capture,
            read_fixture.verify(),
        )

    assert raised.value.code == "PUBLICATION_DECISION_INCARNATION_INVALID"


def test_incarnation_genesis_cannot_reuse_exact_incarnation_tuple() -> None:
    capture, read_fixture = incarnation_decision_fixture(
        host_epoch=3,
        agent_generation=5,
        kernel_boot_id="boot-test-1",
    )

    with pytest.raises(DirectPathVerificationError) as raised:
        verify_host_snapshot_publication_decision(
            capture,
            read_fixture.verify(),
        )

    assert raised.value.code == "PUBLICATION_DECISION_INCARNATION_INVALID"


@pytest.mark.parametrize("position", ("BEFORE_VERIFICATION", "AFTER_TRUST"))
def test_current_inventory_must_be_live_at_read_set_began_at(
    position: str,
) -> None:
    publication = PublicationFixture(maximum_evidence_age_micros=60_000_000)
    _, current = current_inventory_for(publication)
    predecessor = HostSnapshotAnchorFixture(genesis=False, inventory=current)
    began_at = (
        current.verified_at - timedelta(microseconds=1)
        if position == "BEFORE_VERIFICATION"
        else current.trust.freshness_expires_at + timedelta(microseconds=1)
    )
    read_fixture = ReadSetFixture(
        publication,
        current=current,
        predecessor=predecessor,
        began_at=began_at,
    )

    with pytest.raises(DirectPathVerificationError) as raised:
        read_fixture.verify()

    assert (
        raised.value.code
        == "PUBLICATION_DECISION_CURRENT_INVENTORY_TIME_INVALID"
    )


def test_predecessor_freshness_binds_loaded_anchor_schema_bytes() -> None:
    publication = PublicationFixture(maximum_evidence_age_micros=60_000_000)
    _, current = current_inventory_for(publication)
    predecessor = HostSnapshotAnchorFixture(genesis=False, inventory=current)
    read_fixture = ReadSetFixture(
        publication,
        current=current,
        predecessor=predecessor,
    )
    state = copy.deepcopy(read_fixture.predecessor_freshness["state"])
    signatures = state["rootSignatures"]
    state["anchorSchemaSha256"] = digest("substituted-anchor-schema")
    state["freshnessReceiptDigest"] = None
    state["rootSignatures"] = []
    state["freshnessReceiptDigest"] = sha256_digest(canonical_json_bytes(state))
    state["rootSignatures"] = signatures
    read_fixture.predecessor_freshness = artifact(
        read_fixture.predecessor_freshness["schemaRef"],
        state,
    )
    read_fixture.reseal_receipt()

    with pytest.raises(DirectPathVerificationError) as raised:
        read_fixture.verify()

    assert raised.value.code == "PUBLICATION_DECISION_ROLLBACK_BINDING_MISMATCH"


def test_byte_receipt_wrapper_and_decoded_state_use_caller_json_limits() -> None:
    publication = PublicationFixture()
    read_fixture = ReadSetFixture(
        publication,
        host_authority=unpublished_host_authority(publication),
    )
    limits = PublicationDecisionVerifierLimits(
        max_json_nodes=100_000,
        max_json_depth=20,
    )

    with patch(
        "qman_directpath_core.publication_decision.measure_canonical_json",
        wraps=measure_canonical_json,
    ) as measured:
        read_fixture.verify(limits=limits)

    measured_documents = [
        call.args[0]
        for call in measured.call_args_list
        if call.args and isinstance(call.args[0], dict)
    ]
    assert any(
        document.get("subjectType")
        == "HOST_SNAPSHOT_PUBLICATION_STRUCTURAL_READ_RECEIPT"
        for document in measured_documents
    )
    assert any(
        document.get("subjectType") == "DIRECTPATH_CAPABILITY_POLICY"
        for document in measured_documents
    )
    assert any("state" in document for document in measured_documents)
    assert all(
        call.kwargs["max_nodes"] == limits.max_json_nodes
        and call.kwargs["max_depth"] == limits.max_json_depth
        for call in measured.call_args_list
    )


def test_caller_tightened_depth_rejects_byte_artifact_before_schema_walk() -> None:
    publication = PublicationFixture()
    read_fixture = ReadSetFixture(
        publication,
        host_authority=unpublished_host_authority(publication),
    )

    with pytest.raises(DirectPathVerificationError) as raised:
        read_fixture.verify(
            limits=PublicationDecisionVerifierLimits(max_json_depth=2)
        )

    assert raised.value.code == "PUBLICATION_DECISION_TOO_LARGE"


def test_policy_selector_rollout_does_not_scan_old_records() -> None:
    publication = PublicationFixture(generic_provider=True)
    generic = next(
        fact
        for fact in publication.inventory.records[0]["provenance"][
            "providerFacts"
        ]
        if fact["providerId"] == "linux-owner-provider"
    )
    publication.freshness_policy["mandatoryProviderFacts"] = [
        {
            "providerId": generic["providerId"],
            "factId": generic["factId"],
        }
    ]
    publication.reseal_freshness_policy()
    _, current = current_inventory_for(
        publication,
        freshness_policy_hash=digest("old-freshness-policy"),
    )
    stamp_candidate(publication, snapshot_epoch=8, resource_version=12)
    capture = publication.verify()
    predecessor = HostSnapshotAnchorFixture(genesis=False, inventory=current)
    read_set = ReadSetFixture(
        publication,
        current=current,
        predecessor=predecessor,
    ).verify()

    decision = verify_host_snapshot_publication_decision(capture, read_set)

    assert decision.decision_kind == "SUCCESSOR"
    assert (
        decision.freshness_decision["evaluationDisposition"]
        == "ACTIVE_POLICY_CHANGED_FORCES_SUCCESSOR"
    )
    assert (
        decision.freshness_decision[
            "oldestMandatoryEvidenceObservedAtOrNull"
        ]
        is None
    )
    assert decision.freshness_decision["refreshRequired"] is False


def test_same_policy_missing_selector_is_rejected() -> None:
    publication = PublicationFixture(generic_provider=True)
    generic = next(
        fact
        for fact in publication.inventory.records[0]["provenance"][
            "providerFacts"
        ]
        if fact["providerId"] == "linux-owner-provider"
    )
    publication.freshness_policy["mandatoryProviderFacts"] = [
        {
            "providerId": generic["providerId"],
            "factId": generic["factId"],
        }
    ]
    publication.reseal_freshness_policy()
    _, current = current_inventory_for(publication)
    stamp_candidate(publication, snapshot_epoch=8, resource_version=12)
    capture = publication.verify()
    predecessor = HostSnapshotAnchorFixture(genesis=False, inventory=current)
    read_set = ReadSetFixture(
        publication,
        current=current,
        predecessor=predecessor,
    ).verify()

    with pytest.raises(DirectPathVerificationError) as raised:
        verify_host_snapshot_publication_decision(capture, read_set)

    assert raised.value.code == "PUBLICATION_DECISION_MANDATORY_FACT_MISSING"


@pytest.mark.parametrize(
    ("offset_micros", "expected"),
    (
        (1_999_999, "NO_CHANGE"),
        (2_000_000, "REFRESH"),
    ),
)
def test_freshness_threshold_minus_one_and_equality(
    offset_micros: int,
    expected: str,
) -> None:
    observed = datetime.strptime(
        CAPTURED_AT,
        "%Y-%m-%dT%H:%M:%S.%fZ",
    ).replace(tzinfo=timezone.utc)
    threshold = 32_000_000
    _, _, capture, read_fixture = current_decision_fixture(
        began_at=observed
        + timedelta(microseconds=threshold - 2_000_000 + offset_micros),
        maximum_evidence_age_micros=threshold,
    )
    decision = verify_host_snapshot_publication_decision(
        capture,
        read_fixture.verify(),
    )

    assert decision.decision_kind == expected
    assert decision.freshness_decision["refreshRequired"] is (
        expected == "REFRESH"
    )


@pytest.mark.parametrize(
    ("delta_micros", "accepted"),
    ((-1, True), (0, False)),
)
def test_capability_policy_expiry_boundary(
    delta_micros: int,
    accepted: bool,
) -> None:
    publication = PublicationFixture()
    stamp_candidate(publication, snapshot_epoch=1, resource_version=2)
    capture = publication.verify()
    expiry = publication.capability_policy.expires_at
    read_fixture = ReadSetFixture(
        publication,
        host_authority=unpublished_host_authority(publication),
        began_at=expiry + timedelta(microseconds=delta_micros),
    )

    if accepted:
        decision = verify_host_snapshot_publication_decision(
            capture,
            read_fixture.verify(),
        )
        assert decision.decision_kind == "GENESIS"
    else:
        with pytest.raises(DirectPathVerificationError) as raised:
            read_fixture.verify()
        assert raised.value.code == "CAPABILITY_POLICY_EXPIRED"


@pytest.mark.parametrize("delta", (-1, 1))
def test_candidate_coordinate_plus_or_minus_one_is_rejected(delta: int) -> None:
    publication = PublicationFixture()
    _, current = current_inventory_for(publication)
    stamp_candidate(
        publication,
        snapshot_epoch=8 + delta,
        resource_version=12,
    )
    capture = publication.verify()
    predecessor = HostSnapshotAnchorFixture(genesis=False, inventory=current)
    read_set = ReadSetFixture(
        publication,
        current=current,
        predecessor=predecessor,
    ).verify()

    with pytest.raises(DirectPathVerificationError) as raised:
        verify_host_snapshot_publication_decision(capture, read_set)

    assert raised.value.code == "PUBLICATION_DECISION_COORDINATE_MISMATCH"


def test_candidate_resource_coordinate_mismatch_is_rejected() -> None:
    publication = PublicationFixture()
    _, current = current_inventory_for(publication)
    stamp_candidate(publication, snapshot_epoch=8, resource_version=13)
    capture = publication.verify()
    predecessor = HostSnapshotAnchorFixture(genesis=False, inventory=current)
    read_set = ReadSetFixture(
        publication,
        current=current,
        predecessor=predecessor,
    ).verify()

    with pytest.raises(DirectPathVerificationError) as raised:
        verify_host_snapshot_publication_decision(capture, read_set)

    assert raised.value.code == "PUBLICATION_DECISION_COORDINATE_MISMATCH"


@pytest.mark.parametrize("authority_index", (0, 1, 2, 3))
def test_four_authority_expectation_hash_is_substitution_sensitive(
    authority_index: int,
) -> None:
    publication = PublicationFixture()
    base = ReadSetFixture(
        publication,
        host_authority=unpublished_host_authority(publication),
    ).verify()
    versions = [17, 23, 29]
    if authority_index > 0:
        versions[authority_index - 1] += 1
    changed = ReadSetFixture(
        publication,
        host_authority=unpublished_host_authority(
            publication,
            resource_version=2,
        )
        if authority_index == 0
        else unpublished_host_authority(publication),
        authority_versions=tuple(versions),
    ).verify()

    assert changed.expectation_hash != base.expectation_hash


def test_unbound_authority_wrapper_substitution_is_rejected() -> None:
    publication = PublicationFixture()
    read_fixture = ReadSetFixture(
        publication,
        host_authority=unpublished_host_authority(publication),
    )
    read_fixture.availability["state"]["resourceVersion"] += 1
    read_fixture.availability = artifact(
        read_fixture.availability["schemaRef"],
        read_fixture.availability["state"],
    )

    with pytest.raises(DirectPathVerificationError) as raised:
        read_fixture.verify()

    assert raised.value.code in {
        "PUBLICATION_DECISION_EXPECTATION_MISMATCH",
        "PUBLICATION_DECISION_RECEIPT_BINDING_MISMATCH",
    }


def test_future_capture_basis_is_rejected() -> None:
    publication = PublicationFixture()
    stamp_candidate(publication, snapshot_epoch=1, resource_version=2)
    capture = publication.verify()
    host = unpublished_host_authority(publication)
    host["lastObservedAt"] = "2026-07-24T01:59:20.000000Z"
    read_set = ReadSetFixture(
        publication,
        host_authority=host,
        began_at=datetime(
            2026,
            7,
            24,
            1,
            59,
            29,
            500_000,
            tzinfo=timezone.utc,
        ),
    ).verify()

    with pytest.raises(DirectPathVerificationError) as raised:
        verify_host_snapshot_publication_decision(capture, read_set)

    assert raised.value.code == "PUBLICATION_DECISION_FUTURE_BASIS"


def test_write_required_capture_must_complete_before_preflight_scan() -> None:
    _, _, capture, read_fixture = current_decision_fixture(
        semantic_change=True
    )
    move_preflight_before_capture(read_fixture)
    read_set = read_fixture.verify()

    with pytest.raises(DirectPathVerificationError) as raised:
        verify_host_snapshot_publication_decision(capture, read_set)

    assert (
        raised.value.code
        == "PUBLICATION_DECISION_CAPTURE_PREFLIGHT_ORDER_INVALID"
    )


def test_no_change_does_not_invent_committed_capture_preflight_order() -> None:
    _, _, capture, read_fixture = current_decision_fixture()
    move_preflight_before_capture(read_fixture)
    read_set = read_fixture.verify()

    decision = verify_host_snapshot_publication_decision(capture, read_set)

    assert decision.decision_kind == "NO_CHANGE"
    assert decision.write_required is False


def test_final_receipt_signature_after_issued_at_is_bounded_by_freshness() -> None:
    publication = PublicationFixture(maximum_evidence_age_micros=60_000_000)
    _, current = current_inventory_for(publication)
    stamp_candidate(publication, snapshot_epoch=8, resource_version=12)
    predecessor = HostSnapshotAnchorFixture(genesis=False, inventory=current)
    predecessor.anchor["receipt"]["rootSignatures"][0][
        "signedAt"
    ] = "2026-07-24T02:00:01.000000Z"
    predecessor.freshness = reseal_anchor_freshness(
        predecessor,
        observed_at="2026-07-24T02:00:02.000000Z",
        expires_at="2026-07-24T02:02:30.000000Z",
    )

    read_set = ReadSetFixture(
        publication,
        current=current,
        predecessor=predecessor,
        began_at=datetime(
            2026,
            7,
            24,
            2,
            0,
            3,
            tzinfo=timezone.utc,
        ),
    ).verify()

    assert read_set.product_authorized is False


def test_final_receipt_signature_before_issued_at_is_rejected() -> None:
    publication = PublicationFixture(maximum_evidence_age_micros=60_000_000)
    _, current = current_inventory_for(publication)
    predecessor = HostSnapshotAnchorFixture(genesis=False, inventory=current)
    predecessor.anchor["receipt"]["rootSignatures"][0][
        "signedAt"
    ] = "2026-07-24T01:59:59.999999Z"
    read_fixture = ReadSetFixture(
        publication,
        current=current,
        predecessor=predecessor,
    )

    with pytest.raises(DirectPathVerificationError) as raised:
        read_fixture.verify()

    assert raised.value.code == "PUBLICATION_DECISION_ROLLBACK_TIME_INVALID"


def test_predecessor_finalization_after_prepare_expiry_is_accepted() -> None:
    publication = PublicationFixture(maximum_evidence_age_micros=300_000_000)
    _, current = current_inventory_for(publication)
    predecessor = HostSnapshotAnchorFixture(genesis=False, inventory=current)
    late = copy.deepcopy(predecessor.anchor)
    late["updatedAt"] = "2026-07-24T02:03:00.000000Z"
    late["receipt"]["issuedAt"] = "2026-07-24T02:03:01.000000Z"
    predecessor.anchor = predecessor.reseal_anchor(late)
    predecessor.anchor["receipt"]["rootSignatures"][0][
        "signedAt"
    ] = "2026-07-24T02:03:02.000000Z"
    predecessor.freshness = reseal_anchor_freshness(
        predecessor,
        observed_at="2026-07-24T02:03:03.000000Z",
        expires_at="2026-07-24T02:05:00.000000Z",
    )

    read_set = ReadSetFixture(
        publication,
        current=current,
        predecessor=predecessor,
        began_at=datetime(
            2026,
            7,
            24,
            2,
            3,
            4,
            tzinfo=timezone.utc,
        ),
    ).verify()

    assert read_set.predecessor_rollback_anchor_or_null is not None


def test_no_change_persists_current_not_new_candidate_provenance() -> None:
    _, current, capture, read_fixture = current_decision_fixture(
        nonsemantic_change=True
    )
    decision = verify_host_snapshot_publication_decision(
        capture,
        read_fixture.verify(),
    )

    assert decision.decision_kind == "NO_CHANGE"
    assert decision.persisted_device_record_source == "currentDeviceRecordsOrNull"
    assert (
        decision.persisted_device_records[0].canonical_bytes
        == current.device_records[0].canonical_bytes
    )
    assert (
        capture.candidate_device_records.device_records[0].canonical_bytes
        != current.device_records[0].canonical_bytes
    )


def factory_values(instance) -> dict:
    return {descriptor.name: getattr(instance, descriptor.name) for descriptor in fields(instance)}


def test_4097_gate_fails_before_capture_replay() -> None:
    _, _, capture, read_fixture = current_decision_fixture()
    read_set = read_fixture.verify()
    candidate = capture.candidate_device_records
    candidate_values = factory_values(candidate)
    candidate_values["device_records"] = candidate.device_records * 4097
    oversized_candidate = VerifiedCandidateDeviceRecordSet._construct(
        **candidate_values
    )
    capture_values = factory_values(capture)
    capture_values["candidate_device_records"] = oversized_candidate
    oversized_capture = VerifiedHostSnapshotCaptureClosureContext._construct(
        **capture_values
    )

    with patch(
        "qman_directpath_core.publication_decision."
        "replay_host_snapshot_capture_closure"
    ) as replay:
        with pytest.raises(DirectPathVerificationError) as raised:
            verify_host_snapshot_publication_decision(
                oversized_capture,
                read_set,
            )

    assert raised.value.code == "PUBLICATION_DECISION_TOO_LARGE"
    replay.assert_not_called()


def test_factory_values_have_no_public_constructor_or_replace_path() -> None:
    publication = PublicationFixture()
    stamp_candidate(publication, snapshot_epoch=1, resource_version=2)
    capture = publication.verify()
    read_set = ReadSetFixture(
        publication,
        host_authority=unpublished_host_authority(publication),
    ).verify()
    decision = verify_host_snapshot_publication_decision(capture, read_set)

    with pytest.raises(TypeError):
        StructuralPublicationReadSet()
    with pytest.raises(TypeError):
        VerifiedHostSnapshotPublicationDecisionContext()
    with pytest.raises(TypeError):
        replace(read_set, product_authorized=True)
    with pytest.raises(TypeError):
        replace(decision, product_authorized=True)
    assert read_set.product_authorized is False
    assert decision.product_authorized is False
    assert MAX_FULL_PUBLICATION_DEVICE_RECORDS == 4096
