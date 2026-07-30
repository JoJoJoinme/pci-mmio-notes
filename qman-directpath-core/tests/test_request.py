from __future__ import annotations

from dataclasses import FrozenInstanceError
import json
from pathlib import Path
import unittest

from qman_directpath_core.canonical import (
    canonical_json_bytes,
    sha256_digest,
)
from qman_directpath_core.contracts import ContractSchemas
from qman_directpath_core.errors import DirectPathVerificationError
from qman_directpath_core.request import verify_static_request


ROOT = Path(__file__).resolve().parents[2]
CONTRACTS = ROOT / "contracts"


def _digest(character: str) -> str:
    return "sha256:" + character * 64


def _uid(character: str) -> str:
    return f"urn:qman:directpath:device:v1:host-a:sha256:{character * 64}"


def _profile_binding() -> dict[str, object]:
    return {
        "profileId": "profile-a",
        "profileHash": _digest("a"),
        "verificationReceiptHash": _digest("b"),
        "requiredSupportStatus": "QUALIFIED",
    }


def _policy_binding() -> dict[str, object]:
    return {
        "policyId": "policy-a",
        "policyVersion": 3,
        "policyHash": _digest("c"),
        "admissionMode": "PRODUCTION",
        "supportedCatalogDigest": _digest("d"),
        "catalogSequence": 5,
        "trustKeyRingSequence": 7,
        "qualificationCaseMatrixHash": _digest("e"),
    }


def _static_lifecycle() -> dict[str, object]:
    return {
        "operations": ["GUEST_REBOOT", "POWER_OFF", "POWER_ON"],
        "guestRuntimePciHotplug": False,
        "liveMigration": False,
        "snapshotWhileAttached": False,
        "suspendWhileAttached": False,
        "automaticHostFailureRestart": False,
        "coldRelocationMode": "DISABLED_STATIC_HOST_AFFINITY",
    }


def _dynamic_lifecycle() -> dict[str, object]:
    return {
        "operations": [
            "COLD_RELOCATE",
            "GUEST_REBOOT",
            "POWER_OFF",
            "POWER_ON",
        ],
        "guestRuntimePciHotplug": False,
        "liveMigration": False,
        "snapshotWhileAttached": False,
        "suspendWhileAttached": False,
        "automaticHostFailureRestart": False,
        "coldRelocationMode": "DUAL_ONLINE_COOPERATIVE_ONLY",
    }


def _static_member(
    suffix: str,
    *,
    address: str,
    device_uid: str,
) -> dict[str, object]:
    return {
        "requirementId": f"req-{suffix}",
        "deviceUid": device_uid,
        "identityFingerprint": _digest(suffix),
        "enrolledHostId": "host-a",
        "expectedPhysicalPathProvider": {
            "providerId": "ACPI_FIRMWARE_PATH_V1",
            "providerVersion": 1,
            "providerDefinitionDigest": (
                "sha256:"
                "61b92f14fcd158f7885ec07d0a375324e051e3b2f936c748ac103b4a230203e4"
            ),
        },
        "expectedPhysicalPath": (f"acpi:/_SB_/PCI0#adr={address}"),
        "expectedCurrentBdf": ("0000:65:00.0" if suffix == "1" else "0000:65:01.0"),
        "guestSlot": f"slot-{suffix}",
    }


def _rehash(request: dict[str, object]) -> None:
    request["requestHash"] = sha256_digest(
        canonical_json_bytes(request["canonicalRequest"])
    )


def _static_request() -> dict[str, object]:
    lifecycle = _static_lifecycle()
    canonical_request = {
        "schemaVersion": 1,
        "vmId": "vm-a",
        "requestVersion": 1,
        "requestType": "STATIC",
        "selector": {
            "selectorType": "STATIC_FIXED_IDENTITY_SET",
            "members": [
                _static_member(
                    "1",
                    address="0000000000000000",
                    device_uid=_uid("1"),
                ),
                _static_member(
                    "2",
                    address="0000000000000001",
                    device_uid=_uid("2"),
                ),
            ],
        },
        "hostAffinity": {"mode": "EXACT_HOST", "hostId": "host-a"},
        "requiredGuestAbiClass": "abi-v1",
        "lifecyclePolicy": lifecycle,
        "profileBinding": _profile_binding(),
        "snapshotConstraint": {
            "mode": "PINNED_CURRENT_SNAPSHOT",
            "maximumAgeMicros": 5_000_000,
            "binding": {
                "hostId": "host-a",
                "kernelBootId": "boot-a",
                "hostEpoch": 11,
                "agentGeneration": 12,
                "hostAuthorityResourceVersion": 13,
                "snapshotEpoch": 14,
                "snapshotContentHash": _digest("f"),
            },
        },
        "policyBinding": _policy_binding(),
        "mutationPrecondition": {
            "expectedExistingRequestVersionOrNull": None,
            "expectedExistingResourceVersionOrNull": None,
        },
        "idempotency": {
            "mode": "EXACTLY_ONCE_BY_SCOPE_KEY_AND_REQUEST_HASH",
            "idempotencyKey": "request-key-0001",
            "idempotencyScopeHash": _digest("0"),
        },
        "requestedBy": "principal-a",
        "issuedAt": "2026-07-24T00:00:00.000000Z",
    }
    request = {
        "subjectType": "VM_DIRECTPATH_REQUEST",
        "schemaVersion": 1,
        "vmId": canonical_request["vmId"],
        "requestVersion": canonical_request["requestVersion"],
        "requestType": canonical_request["requestType"],
        "canonicalRequest": canonical_request,
        "requestHash": _digest("9"),
        "requiredGuestAbiClass": canonical_request["requiredGuestAbiClass"],
        "lifecyclePolicy": lifecycle,
        "requestedBy": canonical_request["requestedBy"],
        "createdAt": canonical_request["issuedAt"],
        "resourceVersion": 19,
    }
    _rehash(request)
    return request


def _dynamic_request() -> dict[str, object]:
    lifecycle = _dynamic_lifecycle()
    canonical_request = {
        "schemaVersion": 1,
        "vmId": "vm-a",
        "requestVersion": 1,
        "requestType": "DYNAMIC",
        "selector": {
            "selectorType": "DYNAMIC_ALLOWED_DEVICE_REQUIREMENTS",
            "requirements": [
                {
                    "requirementId": "req-1",
                    "allowedDevices": [{"vendorId": "10de", "deviceId": "1db6"}],
                    "customLabelOrNull": None,
                    "requiredGuestAbiClass": "abi-v1",
                    "count": 1,
                    "guestSlots": ["slot-1"],
                    "equivalencePolicyHash": _digest("8"),
                }
            ],
        },
        "hostAffinity": {"mode": "ANY_ONLINE_COOPERATIVE_HOST"},
        "requiredGuestAbiClass": "abi-v1",
        "lifecyclePolicy": lifecycle,
        "profileBinding": _profile_binding(),
        "snapshotConstraint": {
            "mode": "RESOLVE_CURRENT_AT_OPERATION",
            "maximumAgeMicros": 5_000_000,
        },
        "policyBinding": _policy_binding(),
        "mutationPrecondition": {
            "expectedExistingRequestVersionOrNull": None,
            "expectedExistingResourceVersionOrNull": None,
        },
        "idempotency": {
            "mode": "EXACTLY_ONCE_BY_SCOPE_KEY_AND_REQUEST_HASH",
            "idempotencyKey": "request-key-0001",
            "idempotencyScopeHash": _digest("0"),
        },
        "requestedBy": "principal-a",
        "issuedAt": "2026-07-24T00:00:00.000000Z",
    }
    request = {
        "subjectType": "VM_DIRECTPATH_REQUEST",
        "schemaVersion": 1,
        "vmId": canonical_request["vmId"],
        "requestVersion": canonical_request["requestVersion"],
        "requestType": canonical_request["requestType"],
        "canonicalRequest": canonical_request,
        "requestHash": _digest("9"),
        "requiredGuestAbiClass": canonical_request["requiredGuestAbiClass"],
        "lifecyclePolicy": lifecycle,
        "requestedBy": canonical_request["requestedBy"],
        "createdAt": canonical_request["issuedAt"],
        "resourceVersion": 19,
    }
    _rehash(request)
    return request


class StaticRequestVerificationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.schemas = ContractSchemas(CONTRACTS)

    def assert_failure(
        self,
        request: dict[str, object] | bytes,
        code: str,
    ) -> None:
        with self.assertRaises(DirectPathVerificationError) as raised:
            verify_static_request(self.schemas, request)
        self.assertEqual(raised.exception.code, code)

    def test_valid_mapping_derives_exact_immutable_context(self) -> None:
        request = _static_request()
        raw = canonical_json_bytes(request)
        canonical_request_raw = canonical_json_bytes(request["canonicalRequest"])

        verified = verify_static_request(self.schemas, request)

        self.assertEqual(verified.canonical_bytes, raw)
        self.assertEqual(verified.entity_digest, sha256_digest(raw))
        self.assertEqual(
            verified.canonical_request_bytes,
            canonical_request_raw,
        )
        self.assertEqual(
            verified.request_hash,
            sha256_digest(canonical_request_raw),
        )
        self.assertEqual(verified.policy_hash, _digest("c"))
        self.assertEqual(verified.profile_hash, _digest("a"))
        self.assertEqual(
            verified.payload_device_uids,
            (_uid("1"), _uid("2")),
        )
        self.assertEqual(verified.maximum_age_micros, 5_000_000)
        self.assertEqual(verified.request_version, 1)
        self.assertEqual(verified.resource_version, 19)
        self.assertEqual(verified.host_id, "host-a")
        self.assertEqual(
            verified.policy_binding["policyId"],
            "policy-a",
        )
        self.assertEqual(
            verified.profile_binding["profileId"],
            "profile-a",
        )
        with self.assertRaises(TypeError):
            verified.document["vmId"] = "mutated"
        with self.assertRaises(TypeError):
            verified.policy_binding["policyId"] = "mutated"
        with self.assertRaises(FrozenInstanceError):
            verified.host_id = "mutated"

    def test_canonical_bytes_are_preserved_and_noncanonical_bytes_fail(self) -> None:
        request = _static_request()
        raw = canonical_json_bytes(request)
        self.assertEqual(
            verify_static_request(self.schemas, raw).canonical_bytes,
            raw,
        )

        noncanonical = json.dumps(request).encode("utf-8")
        self.assertNotEqual(noncanonical, raw)
        self.assert_failure(noncanonical, "CANONICAL_JSON_INVALID")

    def test_schema_valid_dynamic_request_is_explicitly_unsupported(self) -> None:
        self.assert_failure(
            _dynamic_request(),
            "REQUEST_TYPE_UNSUPPORTED",
        )

    def test_request_hash_is_recomputed(self) -> None:
        request = _static_request()
        request["requestHash"] = _digest("7")
        self.assert_failure(request, "REQUEST_HASH_MISMATCH")

    def test_indexed_projection_mismatches_fail_closed(self) -> None:
        cases = {
            "vmId": "vm-b",
            "requestVersion": 2,
            "requiredGuestAbiClass": "abi-v2",
            "requestedBy": "principal-b",
            "createdAt": "2026-07-24T00:00:01.000000Z",
        }
        for field, replacement in cases.items():
            with self.subTest(field=field):
                request = _static_request()
                request[field] = replacement
                self.assert_failure(
                    request,
                    "REQUEST_PROJECTION_MISMATCH",
                )

    def test_static_members_require_canonical_key_order(self) -> None:
        request = _static_request()
        members = request["canonicalRequest"]["selector"]["members"]
        members.reverse()
        _rehash(request)
        self.assert_failure(
            request,
            "REQUEST_STATIC_MEMBER_ORDER_INVALID",
        )

    def test_static_member_identity_fields_are_independently_unique(self) -> None:
        for field in ("requirementId", "guestSlot", "deviceUid"):
            with self.subTest(field=field):
                request = _static_request()
                members = request["canonicalRequest"]["selector"]["members"]
                members[1][field] = members[0][field]
                if field == "requirementId":
                    members.sort(
                        key=lambda member: canonical_json_bytes(
                            [
                                member["requirementId"],
                                member["guestSlot"],
                                member["deviceUid"],
                            ]
                        )
                    )
                _rehash(request)
                self.assert_failure(
                    request,
                    "REQUEST_STATIC_MEMBER_DUPLICATE",
                )

    def test_all_members_must_match_exact_host_affinity(self) -> None:
        request = _static_request()
        request["canonicalRequest"]["selector"]["members"][1]["enrolledHostId"] = (
            "host-b"
        )
        _rehash(request)
        self.assert_failure(
            request,
            "REQUEST_STATIC_HOST_AFFINITY_MISMATCH",
        )

    def test_pinned_snapshot_must_match_exact_host_affinity(self) -> None:
        request = _static_request()
        request["canonicalRequest"]["snapshotConstraint"]["binding"]["hostId"] = (
            "host-b"
        )
        _rehash(request)
        self.assert_failure(
            request,
            "REQUEST_STATIC_HOST_AFFINITY_MISMATCH",
        )

    def test_creation_and_update_version_relations_are_enforced(self) -> None:
        creation = _static_request()
        creation["requestVersion"] = 2
        creation["canonicalRequest"]["requestVersion"] = 2
        _rehash(creation)
        self.assert_failure(
            creation,
            "REQUEST_MUTATION_PRECONDITION_INVALID",
        )

        update = _static_request()
        update["requestVersion"] = 2
        update["canonicalRequest"]["requestVersion"] = 2
        update["canonicalRequest"]["mutationPrecondition"] = {
            "expectedExistingRequestVersionOrNull": 1,
            "expectedExistingResourceVersionOrNull": 18,
        }
        _rehash(update)
        verified = verify_static_request(self.schemas, update)
        self.assertEqual(verified.request_version, 2)

        update["canonicalRequest"]["mutationPrecondition"][
            "expectedExistingRequestVersionOrNull"
        ] = 2
        _rehash(update)
        self.assert_failure(
            update,
            "REQUEST_MUTATION_PRECONDITION_INVALID",
        )


if __name__ == "__main__":
    unittest.main()
