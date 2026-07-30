from __future__ import annotations

import base64
import copy
from dataclasses import FrozenInstanceError, replace

import pytest

from qman_directpath_core.canonical import (
    canonical_json_bytes,
    sha256_digest,
)
from qman_directpath_core.contracts import ContractSchemas
from qman_directpath_core.errors import DirectPathVerificationError
from qman_directpath_core.host_snapshot_anchor import (
    HOST_SNAPSHOT_ANCHOR_AUTHORITY_BOUNDARY,
    HOST_SNAPSHOT_ANCHOR_CANDIDATE_DOMAIN,
    HOST_SNAPSHOT_ANCHOR_PREPARE_DOMAIN,
    HOST_SNAPSHOT_ANCHOR_RECEIPT_DOMAIN,
    HOST_SNAPSHOT_ANCHOR_SCHEMA_REF,
    verify_host_snapshot_anchor_binding,
)
from qman_directpath_core.trust import verify_trust_context
from tests.test_inventory import (
    CONTRACTS,
    NOW,
    InventoryFixture,
)
from tests.test_trust import (
    NONCE,
    NOW_TEXT,
    TrustFixture,
    projected_digest,
    signature_text,
)


ANCHOR_PATH = "external/host-snapshot/host-test"
PREPARED_AT = "2026-07-24T01:59:35.000000Z"
PREPARE_SIGNED_AT = "2026-07-24T01:59:36.000000Z"
UPDATED_AT = "2026-07-24T01:59:40.000000Z"
ISSUED_AT = NOW_TEXT
EXPIRES_AT = "2026-07-24T02:02:30.000000Z"
OBSERVED_AT = NOW_TEXT
FRESHNESS_EXPIRES_AT = "2026-07-24T02:02:00.000000Z"


def digest(label: str) -> str:
    return sha256_digest(label.encode("utf-8"))


class HostSnapshotAnchorFixture:
    def __init__(
        self,
        *,
        genesis: bool = True,
        schemas=None,
        trust_fixture=None,
        trust=None,
        inventory=None,
    ) -> None:
        self.schemas = schemas or ContractSchemas(CONTRACTS)
        self.trust_fixture = trust_fixture or TrustFixture(
            include_inventory_key=True
        )
        self.trust = trust or verify_trust_context(
            self.schemas,
            pinned_root_set=self.trust_fixture.root,
            pinned_root_digest=self.trust_fixture.root["rootSetDigest"],
            key_ring_documents=[self.trust_fixture.ring],
            external_trust_anchor=self.trust_fixture.anchor,
            trust_anchor_freshness=self.trust_fixture.freshness,
            verifier_nonce=NONCE,
            now=NOW,
        )
        self.inventory_fixture = None
        if inventory is None:
            if self.trust_fixture.inventory_private is None:
                raise AssertionError("inventory signing key is missing")
            self.inventory_fixture = InventoryFixture(
                private=self.trust_fixture.inventory_private,
                trust=self.trust,
            )
            if genesis:
                self.inventory_fixture.snapshot.update(
                    {
                        "snapshotEpoch": 1,
                        "previousSnapshotContentHashOrNull": None,
                        "hostAuthorityResourceVersion": 2,
                    }
                )
                self.inventory_fixture.authority.update(
                    {
                        "lastSnapshotEpoch": 1,
                        "resourceVersion": 2,
                    }
                )
                for record in self.inventory_fixture.records:
                    record["generations"]["snapshotEpoch"] = 1
                self.inventory_fixture.reseal()
            self.inventory = self.inventory_fixture.verify()
        else:
            self.inventory = inventory
        if genesis and self.inventory.snapshot_epoch != 1:
            raise AssertionError("a genesis anchor requires snapshot epoch one")
        self.anchor_version = 1 if genesis else 2
        self.anchor = self._anchor()
        self.freshness = self._freshness()

    def _root_signature(
        self,
        *,
        domain: bytes,
        digest_field: str,
        digest_value: str,
        signed_at: str = NOW_TEXT,
    ) -> dict:
        subject = {
            "rootKeyId": "root-a",
            "signedAt": signed_at,
            digest_field: digest_value,
        }
        return {
            "rootKeyId": "root-a",
            "signedAt": signed_at,
            "algorithm": "Ed25519",
            "signature": signature_text(
                self.trust_fixture.root_private,
                domain + canonical_json_bytes(subject),
            ),
        }

    def _cas(self) -> dict:
        if self.anchor_version == 1:
            return {
                "expectedAnchorVersionOrNull": None,
                "expectedResourceVersionOrNull": None,
                "expectedKernelBootIdOrNull": None,
                "expectedHostEpochOrNull": None,
                "expectedAgentIdentityOrNull": None,
                "expectedAgentGenerationOrNull": None,
                "expectedSnapshotEpochOrNull": None,
                "expectedSnapshotContentHashOrNull": None,
                "expectedHostAuthorityResourceVersionOrNull": None,
                "expectedAnchorDigestOrNull": None,
            }
        return {
            "expectedAnchorVersionOrNull": self.anchor_version - 1,
            "expectedResourceVersionOrNull": self.anchor_version - 1,
            "expectedKernelBootIdOrNull": self.inventory.kernel_boot_id,
            "expectedHostEpochOrNull": self.inventory.host_epoch,
            "expectedAgentIdentityOrNull": self.inventory.agent_identity,
            "expectedAgentGenerationOrNull": (
                self.inventory.agent_generation
            ),
            "expectedSnapshotEpochOrNull": self.inventory.snapshot_epoch - 1,
            "expectedSnapshotContentHashOrNull": self.inventory.host_snapshot[
                "previousSnapshotContentHashOrNull"
            ],
            "expectedHostAuthorityResourceVersionOrNull": (
                self.inventory.snapshot_authority_resource_version - 1
            ),
            "expectedAnchorDigestOrNull": digest("predecessor-anchor"),
        }

    def _anchor(self) -> dict:
        cas = self._cas()
        previous = cas["expectedAnchorDigestOrNull"]
        document = {
            "schemaVersion": 1,
            "recordType": "DIRECTPATH_HOST_SNAPSHOT_ROLLBACK_ANCHOR",
            "canonicalProfileId": "CANONICAL-JSON-V1",
            "recordState": "COMMITTED",
            "hostId": self.inventory.host_id,
            "kernelBootId": self.inventory.kernel_boot_id,
            "hostEpoch": self.inventory.host_epoch,
            "agentIdentity": self.inventory.agent_identity,
            "agentGeneration": self.inventory.agent_generation,
            "acceptedSnapshotEpoch": self.inventory.snapshot_epoch,
            "acceptedSnapshotContentHash": (
                self.inventory.snapshot_content_hash
            ),
            "acceptedHostAuthorityResourceVersion": (
                self.inventory.snapshot_authority_resource_version
            ),
            "candidateProjectionDigest": digest("placeholder-candidate"),
            "anchorVersion": self.anchor_version,
            "resourceVersion": self.anchor_version,
            "previousAnchorDigestOrNull": previous,
            "updatedAt": UPDATED_AT,
            "authorityId": "external-host-snapshot-authority-test",
            "casPrecondition": cas,
            "prepareReceipt": {
                "schemaVersion": 1,
                "reservationId": f"reservation-{self.anchor_version}",
                "hostId": self.inventory.host_id,
                "candidateProjectionDigest": digest(
                    "placeholder-candidate"
                ),
                "predecessorAnchorDigestOrNull": previous,
                "authorityId": "external-host-snapshot-authority-test",
                "preparedAt": PREPARED_AT,
                "expiresAt": EXPIRES_AT,
                "retentionPolicy": (
                    "DURABLE_NON_REUSABLE_RECOVERY_TOMBSTONE"
                ),
                "rollbackAuthorityPreflightReceiptDigest": digest(
                    "rollback-preflight"
                ),
                "trustRootDigest": self.trust.root_set_digest,
                "receiptDigest": None,
                "rootSignatures": [],
            },
            "anchorDigest": None,
            "receipt": None,
        }
        candidate_fields = (
            "hostId",
            "kernelBootId",
            "hostEpoch",
            "agentIdentity",
            "agentGeneration",
            "acceptedSnapshotEpoch",
            "acceptedSnapshotContentHash",
            "acceptedHostAuthorityResourceVersion",
            "anchorVersion",
            "resourceVersion",
            "previousAnchorDigestOrNull",
            "authorityId",
            "casPrecondition",
        )
        candidate = {
            name: copy.deepcopy(document[name]) for name in candidate_fields
        }
        candidate_digest = sha256_digest(
            HOST_SNAPSHOT_ANCHOR_CANDIDATE_DOMAIN
            + canonical_json_bytes(candidate)
        )
        document["candidateProjectionDigest"] = candidate_digest
        prepare = document["prepareReceipt"]
        prepare["candidateProjectionDigest"] = candidate_digest
        prepare_digest, _ = projected_digest(
            prepare,
            null_fields=("receiptDigest",),
            empty_fields=("rootSignatures",),
        )
        prepare["receiptDigest"] = prepare_digest
        prepare["rootSignatures"] = [
            self._root_signature(
                domain=HOST_SNAPSHOT_ANCHOR_PREPARE_DOMAIN,
                digest_field="receiptDigest",
                digest_value=prepare_digest,
                signed_at=PREPARE_SIGNED_AT,
            )
        ]
        anchor_digest, _ = projected_digest(
            document,
            null_fields=("anchorDigest", "receipt"),
        )
        document["anchorDigest"] = anchor_digest
        receipt = {
            "schemaVersion": 1,
            "receiptId": f"host-snapshot-anchor-receipt-{self.anchor_version}",
            "subjectAnchorDigest": anchor_digest,
            "hostId": document["hostId"],
            "kernelBootId": document["kernelBootId"],
            "hostEpoch": document["hostEpoch"],
            "agentIdentity": document["agentIdentity"],
            "agentGeneration": document["agentGeneration"],
            "acceptedSnapshotEpoch": document["acceptedSnapshotEpoch"],
            "acceptedSnapshotContentHash": document[
                "acceptedSnapshotContentHash"
            ],
            "acceptedHostAuthorityResourceVersion": document[
                "acceptedHostAuthorityResourceVersion"
            ],
            "anchorVersion": document["anchorVersion"],
            "resourceVersion": document["resourceVersion"],
            "authorityId": document["authorityId"],
            "issuedAt": ISSUED_AT,
            "trustRootDigest": self.trust.root_set_digest,
            "receiptDigest": None,
            "rootSignatures": [],
        }
        receipt_digest, _ = projected_digest(
            receipt,
            null_fields=("receiptDigest",),
            empty_fields=("rootSignatures",),
        )
        receipt["receiptDigest"] = receipt_digest
        receipt["rootSignatures"] = [
            self._root_signature(
                domain=HOST_SNAPSHOT_ANCHOR_RECEIPT_DOMAIN,
                digest_field="receiptDigest",
                digest_value=receipt_digest,
            )
        ]
        document["receipt"] = receipt
        return document

    def _freshness(self) -> dict:
        document = {
            "schemaVersion": 1,
            "envelopeId": f"host-snapshot-freshness-{self.anchor_version}",
            "anchorKind": "HOST_SNAPSHOT",
            "authorityId": self.anchor["authorityId"],
            "subjectId": self.anchor["hostId"],
            "anchorPath": ANCHOR_PATH,
            "anchorBlobSha256": sha256_digest(
                canonical_json_bytes(self.anchor)
            ),
            "anchorSchemaRef": HOST_SNAPSHOT_ANCHOR_SCHEMA_REF,
            "anchorSchemaSha256": self.schemas.digest_for_ref(
                HOST_SNAPSHOT_ANCHOR_SCHEMA_REF,
                path="test.hostSnapshotAnchor.schema",
            ),
            "anchorDigest": self.anchor["anchorDigest"],
            "anchorVersion": self.anchor["anchorVersion"],
            "resourceVersion": self.anchor["resourceVersion"],
            "observedAt": OBSERVED_AT,
            "expiresAt": FRESHNESS_EXPIRES_AT,
            "verifierNonce": NONCE,
            "trustRootDigest": self.trust.root_set_digest,
            "freshnessReceiptDigest": None,
            "rootSignatures": [],
        }
        freshness_digest, _ = projected_digest(
            document,
            null_fields=("freshnessReceiptDigest",),
            empty_fields=("rootSignatures",),
        )
        document["freshnessReceiptDigest"] = freshness_digest
        document["rootSignatures"] = [
            self._root_signature(
                domain=b"QMAN-DIRECTPATH/ANCHOR-FRESHNESS/V1\x00",
                digest_field="freshnessReceiptDigest",
                digest_value=freshness_digest,
            )
        ]
        return document

    def reseal_anchor(
        self,
        value: dict,
        *,
        prepare_signed_at: str = PREPARE_SIGNED_AT,
    ) -> dict:
        document = copy.deepcopy(value)
        candidate_fields = (
            "hostId",
            "kernelBootId",
            "hostEpoch",
            "agentIdentity",
            "agentGeneration",
            "acceptedSnapshotEpoch",
            "acceptedSnapshotContentHash",
            "acceptedHostAuthorityResourceVersion",
            "anchorVersion",
            "resourceVersion",
            "previousAnchorDigestOrNull",
            "authorityId",
            "casPrecondition",
        )
        candidate = {
            name: copy.deepcopy(document[name]) for name in candidate_fields
        }
        candidate_digest = sha256_digest(
            HOST_SNAPSHOT_ANCHOR_CANDIDATE_DOMAIN
            + canonical_json_bytes(candidate)
        )
        document["candidateProjectionDigest"] = candidate_digest
        prepare = document["prepareReceipt"]
        prepare.update(
            {
                "hostId": document["hostId"],
                "candidateProjectionDigest": candidate_digest,
                "predecessorAnchorDigestOrNull": document[
                    "previousAnchorDigestOrNull"
                ],
                "authorityId": document["authorityId"],
            }
        )
        prepare_digest, _ = projected_digest(
            prepare,
            null_fields=("receiptDigest",),
            empty_fields=("rootSignatures",),
        )
        prepare["receiptDigest"] = prepare_digest
        prepare["rootSignatures"] = [
            self._root_signature(
                domain=HOST_SNAPSHOT_ANCHOR_PREPARE_DOMAIN,
                digest_field="receiptDigest",
                digest_value=prepare_digest,
                signed_at=prepare_signed_at,
            )
        ]
        document["anchorDigest"], _ = projected_digest(
            document,
            null_fields=("anchorDigest", "receipt"),
        )
        receipt = document["receipt"]
        receipt.update(
            {
                "subjectAnchorDigest": document["anchorDigest"],
                "hostId": document["hostId"],
                "kernelBootId": document["kernelBootId"],
                "hostEpoch": document["hostEpoch"],
                "agentIdentity": document["agentIdentity"],
                "agentGeneration": document["agentGeneration"],
                "acceptedSnapshotEpoch": document[
                    "acceptedSnapshotEpoch"
                ],
                "acceptedSnapshotContentHash": document[
                    "acceptedSnapshotContentHash"
                ],
                "acceptedHostAuthorityResourceVersion": document[
                    "acceptedHostAuthorityResourceVersion"
                ],
                "anchorVersion": document["anchorVersion"],
                "resourceVersion": document["resourceVersion"],
                "authorityId": document["authorityId"],
            }
        )
        receipt_digest, _ = projected_digest(
            receipt,
            null_fields=("receiptDigest",),
            empty_fields=("rootSignatures",),
        )
        receipt["receiptDigest"] = receipt_digest
        receipt["rootSignatures"] = [
            self._root_signature(
                domain=HOST_SNAPSHOT_ANCHOR_RECEIPT_DOMAIN,
                digest_field="receiptDigest",
                digest_value=receipt_digest,
            )
        ]
        return document

    def verify(self, **changes):
        arguments = {
            "external_host_snapshot_anchor": self.anchor,
            "host_snapshot_anchor_freshness": self.freshness,
            "verifier_nonce": NONCE,
            "expected_anchor_path": ANCHOR_PATH,
            "now": NOW,
        }
        arguments.update(changes)
        return verify_host_snapshot_anchor_binding(
            self.schemas,
            self.trust,
            self.inventory,
            **arguments,
        )


def incarnation_genesis_fixture() -> HostSnapshotAnchorFixture:
    seed = HostSnapshotAnchorFixture(genesis=False)
    inventory_fixture = seed.inventory_fixture
    if inventory_fixture is None:
        raise AssertionError("expected a mutable inventory fixture")
    inventory_fixture.snapshot.update(
        {
            "kernelBootId": "boot-test-2",
            "hostEpoch": 4,
            "agentGeneration": 6,
            "hostAuthorityResourceVersion": 14,
            "snapshotEpoch": 1,
            "previousSnapshotContentHashOrNull": None,
        }
    )
    inventory_fixture.authority.update(
        {
            "kernelBootId": "boot-test-2",
            "hostEpoch": 4,
            "agentGeneration": 6,
            "lastSnapshotEpoch": 1,
            "resourceVersion": 14,
        }
    )
    for record in inventory_fixture.records:
        record["generations"].update(
            {
                "hostEpoch": 4,
                "agentGeneration": 6,
                "snapshotEpoch": 1,
            }
        )
    inventory_fixture.reseal()
    fixture = HostSnapshotAnchorFixture(
        genesis=False,
        schemas=seed.schemas,
        trust_fixture=seed.trust_fixture,
        trust=seed.trust,
        inventory=inventory_fixture.verify(),
    )
    cas = fixture.anchor["casPrecondition"]
    cas.update(
        {
            "expectedKernelBootIdOrNull": "boot-test-1",
            "expectedHostEpochOrNull": 3,
            "expectedAgentIdentityOrNull": fixture.inventory.agent_identity,
            "expectedAgentGenerationOrNull": 5,
            "expectedSnapshotEpochOrNull": 7,
            "expectedSnapshotContentHashOrNull": digest(
                "previous-incarnation-snapshot"
            ),
            "expectedHostAuthorityResourceVersionOrNull": 11,
        }
    )
    fixture.anchor = fixture.reseal_anchor(fixture.anchor)
    fixture.freshness = fixture._freshness()
    return fixture


def test_committed_genesis_is_factory_bound_and_stable() -> None:
    fixture = HostSnapshotAnchorFixture()

    first = fixture.verify()
    second = fixture.verify()

    assert first == second
    assert first.binding_digest == second.binding_digest
    assert first.authority_boundary == (
        HOST_SNAPSHOT_ANCHOR_AUTHORITY_BOUNDARY
    )
    assert not first.product_authorized
    assert first.accepted_snapshot_content_hash == (
        fixture.inventory.snapshot_content_hash
    )
    with pytest.raises(TypeError):
        replace(first, anchor_version=2)
    with pytest.raises(FrozenInstanceError):
        first.anchor_version = 2  # type: ignore[misc]
    with pytest.raises(TypeError):
        first.external_anchor["hostId"] = "other"


def test_same_incarnation_successor_binds_exact_predecessor_cas() -> None:
    fixture = HostSnapshotAnchorFixture(genesis=False)

    binding = fixture.verify()

    assert binding.anchor_version == 2
    assert fixture.anchor["casPrecondition"][
        "expectedSnapshotEpochOrNull"
    ] == (fixture.inventory.snapshot_epoch - 1)


def test_incarnation_genesis_allows_monotonic_version_gap() -> None:
    fixture = incarnation_genesis_fixture()

    binding = fixture.verify()

    assert binding.accepted_snapshot_epoch == 1
    assert binding.accepted_host_authority_resource_version == 14
    assert (
        fixture.anchor["casPrecondition"][
            "expectedHostAuthorityResourceVersionOrNull"
        ]
        == 11
    )


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("expectedHostEpochOrNull", 5),
        ("expectedAgentGenerationOrNull", 7),
    ),
)
def test_incarnation_generation_rollback_is_rejected(
    field: str,
    value: int,
) -> None:
    fixture = incarnation_genesis_fixture()
    anchor = copy.deepcopy(fixture.anchor)
    anchor["casPrecondition"][field] = value
    anchor = fixture.reseal_anchor(anchor)

    with pytest.raises(DirectPathVerificationError) as error:
        fixture.verify(external_host_snapshot_anchor=anchor)

    assert error.value.code == "HOST_SNAPSHOT_ANCHOR_CAS_INVALID"


def test_prepared_reservation_is_not_rollback_authority() -> None:
    fixture = HostSnapshotAnchorFixture()
    prepared = copy.deepcopy(fixture.anchor)
    prepared["recordState"] = "PREPARED"
    prepared["anchorDigest"] = None
    prepared["receipt"] = None

    with pytest.raises(DirectPathVerificationError) as error:
        fixture.verify(external_host_snapshot_anchor=prepared)

    assert error.value.code == "HOST_SNAPSHOT_ANCHOR_NOT_COMMITTED"


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("hostId", "other-host"),
        ("kernelBootId", "other-boot"),
        ("hostEpoch", 99),
        ("agentIdentity", "other-agent"),
        ("agentGeneration", 99),
        ("acceptedSnapshotEpoch", 99),
        ("acceptedSnapshotContentHash", digest("other-snapshot")),
        ("acceptedHostAuthorityResourceVersion", 99),
    ),
)
def test_every_inventory_coordinate_is_exact(
    field: str,
    value: object,
) -> None:
    fixture = HostSnapshotAnchorFixture()
    anchor = copy.deepcopy(fixture.anchor)
    anchor[field] = value
    # Rebuilding all dependent signatures would produce a structurally valid
    # but inventory-mismatched record.  The candidate check is intentionally
    # earlier, so an unresealed mutation must fail even more conservatively.

    with pytest.raises(DirectPathVerificationError) as error:
        fixture.verify(external_host_snapshot_anchor=anchor)

    assert error.value.code in {
        "HOST_SNAPSHOT_ANCHOR_CANDIDATE_DIGEST_INVALID",
        "HOST_SNAPSHOT_ANCHOR_INVENTORY_MISMATCH",
    }


def test_fully_resealed_cross_host_anchor_is_rejected() -> None:
    fixture = HostSnapshotAnchorFixture()
    anchor = copy.deepcopy(fixture.anchor)
    anchor["hostId"] = "other-host"
    anchor = fixture.reseal_anchor(anchor)

    with pytest.raises(DirectPathVerificationError) as error:
        fixture.verify(external_host_snapshot_anchor=anchor)

    assert error.value.code == "HOST_SNAPSHOT_ANCHOR_INVENTORY_MISMATCH"
    assert error.value.path == "hostSnapshotAnchor.externalAnchor.hostId"


def test_signed_snapshot_predecessor_chain_is_exact() -> None:
    fixture = HostSnapshotAnchorFixture(genesis=False)
    anchor = copy.deepcopy(fixture.anchor)
    anchor["casPrecondition"]["expectedSnapshotContentHashOrNull"] = digest(
        "unrelated-predecessor"
    )
    anchor = fixture.reseal_anchor(anchor)

    with pytest.raises(DirectPathVerificationError) as error:
        fixture.verify(external_host_snapshot_anchor=anchor)

    assert error.value.code == "HOST_SNAPSHOT_ANCHOR_CAS_INVALID"
    assert error.value.path.endswith(
        "casPrecondition.expectedSnapshotContentHashOrNull"
    )


def test_anchor_preparation_cannot_predate_inventory_capture() -> None:
    fixture = HostSnapshotAnchorFixture()
    anchor = copy.deepcopy(fixture.anchor)
    anchor["prepareReceipt"]["preparedAt"] = (
        "2026-07-24T01:59:20.000000Z"
    )
    anchor = fixture.reseal_anchor(anchor)

    with pytest.raises(DirectPathVerificationError) as error:
        fixture.verify(external_host_snapshot_anchor=anchor)

    assert error.value.code == "HOST_SNAPSHOT_ANCHOR_PREPARE_TIME_INVALID"
    assert error.value.path.endswith("prepareReceipt.preparedAt")


def test_prepare_quorum_cannot_complete_after_anchor_update() -> None:
    fixture = HostSnapshotAnchorFixture()
    anchor = fixture.reseal_anchor(
        fixture.anchor,
        prepare_signed_at="2026-07-24T01:59:50.000000Z",
    )

    with pytest.raises(DirectPathVerificationError) as error:
        fixture.verify(external_host_snapshot_anchor=anchor)

    assert error.value.code == "SIGNATURE_TIME_INVALID"
    assert error.value.path.endswith("rootSignatures[0].signedAt")


def test_nonce_path_expiry_and_signature_tamper_fail_closed() -> None:
    fixture = HostSnapshotAnchorFixture()
    wrong_nonce = base64.urlsafe_b64encode(
        b"fedcba9876543210"
    ).decode().rstrip("=")
    with pytest.raises(DirectPathVerificationError) as nonce_error:
        fixture.verify(verifier_nonce=wrong_nonce)
    assert nonce_error.value.code == "ANCHOR_FRESHNESS_BINDING_MISMATCH"

    with pytest.raises(DirectPathVerificationError) as path_error:
        fixture.verify(expected_anchor_path="external/wrong/path")
    assert path_error.value.code == "HOST_SNAPSHOT_ANCHOR_PATH_MISMATCH"

    expired = copy.deepcopy(fixture.freshness)
    expired["observedAt"] = "2026-07-24T01:50:00.000000Z"
    expired["expiresAt"] = "2026-07-24T01:55:00.000000Z"
    freshness_digest, _ = projected_digest(
        expired,
        null_fields=("freshnessReceiptDigest",),
        empty_fields=("rootSignatures",),
    )
    expired["freshnessReceiptDigest"] = freshness_digest
    expired["rootSignatures"] = [
        fixture._root_signature(
            domain=b"QMAN-DIRECTPATH/ANCHOR-FRESHNESS/V1\x00",
            digest_field="freshnessReceiptDigest",
            digest_value=freshness_digest,
        )
    ]
    with pytest.raises(DirectPathVerificationError) as expiry_error:
        fixture.verify(host_snapshot_anchor_freshness=expired)
    assert expiry_error.value.code in {
        "ANCHOR_FRESHNESS_EXPIRED",
        "SIGNATURE_TIME_INVALID",
    }

    signature_tamper = copy.deepcopy(fixture.anchor)
    signature_tamper["receipt"]["rootSignatures"][0]["signature"] = (
        "ed25519:" + ("A" * 86)
    )
    with pytest.raises(DirectPathVerificationError) as signature_error:
        fixture.verify(external_host_snapshot_anchor=signature_tamper)
    assert signature_error.value.code == "SIGNATURE_INVALID"


def test_successor_version_skip_is_rejected_after_resealing() -> None:
    fixture = HostSnapshotAnchorFixture(genesis=False)
    fixture.anchor_version = 3
    fixture.anchor = fixture._anchor()
    fixture.anchor["casPrecondition"]["expectedAnchorVersionOrNull"] = 1
    fixture.anchor = fixture.reseal_anchor(fixture.anchor)

    with pytest.raises(DirectPathVerificationError) as error:
        fixture.verify(external_host_snapshot_anchor=fixture.anchor)

    assert error.value.code == "HOST_SNAPSHOT_ANCHOR_CAS_INVALID"
