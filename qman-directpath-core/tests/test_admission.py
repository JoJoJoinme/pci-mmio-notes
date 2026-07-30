from __future__ import annotations

import copy
from datetime import datetime, timezone
from pathlib import Path
import unittest

from qman_directpath_core.admission import bind_static_request_policy
from qman_directpath_core.canonical import (
    canonical_json_bytes,
    sha256_digest,
)
from qman_directpath_core.contracts import ContractSchemas
from qman_directpath_core.errors import DirectPathVerificationError
from qman_directpath_core.policy import verify_capability_policy
from qman_directpath_core.request import verify_static_request
from tests.test_policy import policy_document
from tests.test_request import _rehash, _static_request


ROOT = Path(__file__).resolve().parents[2]
CONTRACTS = ROOT / "contracts"
NOW = datetime(2026, 7, 24, 8, 0, 0, tzinfo=timezone.utc)


def _bound_documents() -> tuple[dict, dict]:
    request = _static_request()
    binding = request["canonicalRequest"]["policyBinding"]
    policy = policy_document()
    for source, target in (
        ("policyId", "policyId"),
        ("policyVersion", "policyVersion"),
        ("admissionMode", "admissionMode"),
        ("supportedCatalogDigest", "supportedCatalogDigest"),
        ("catalogSequence", "catalogSequence"),
        ("trustKeyRingSequence", "trustKeyRingSequence"),
        (
            "qualificationCaseMatrixHash",
            "qualificationCaseMatrixHash",
        ),
    ):
        policy[target] = binding[source]
    policy["policyHash"] = None
    policy["policyHash"] = sha256_digest(canonical_json_bytes(policy))
    binding["policyHash"] = policy["policyHash"]
    _rehash(request)
    return request, policy


class StaticAdmissionContextTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.schemas = ContractSchemas(CONTRACTS)

    def _verified_pair(self):
        request_document, policy_document_value = _bound_documents()
        return (
            verify_static_request(self.schemas, request_document),
            verify_capability_policy(
                self.schemas,
                policy_document_value,
                verified_at=NOW,
            ),
        )

    def test_derives_roots_and_limits_without_raw_arguments(self) -> None:
        request, policy = self._verified_pair()
        context = bind_static_request_policy(request, policy)
        closure_request = context.closure_request

        self.assertEqual(
            request.payload_device_uids,
            closure_request.payload_device_uids,
        )
        self.assertEqual(
            request.request_hash,
            closure_request.request_provenance_digest,
        )
        self.assertEqual(
            policy.policy_hash,
            closure_request.policy_provenance_digest,
        )
        self.assertIs(policy.closure_limits, closure_request.limits)
        self.assertEqual(
            context.context_digest,
            sha256_digest(
                canonical_json_bytes(
                    {
                        **context.to_subject(),
                        "contextDigest": None,
                    }
                )
            ),
        )

    def test_every_request_policy_projection_field_is_exact(self) -> None:
        fields = (
            "policyId",
            "policyVersion",
            "policyHash",
            "admissionMode",
            "supportedCatalogDigest",
            "catalogSequence",
            "trustKeyRingSequence",
            "qualificationCaseMatrixHash",
        )
        for field in fields:
            with self.subTest(field=field):
                request_document, policy_document_value = _bound_documents()
                request_binding = request_document["canonicalRequest"]["policyBinding"]
                if isinstance(request_binding[field], int):
                    request_binding[field] += 1
                elif field == "admissionMode":
                    request_binding[field] = "ISOLATED_UNQUALIFIED_LAB"
                else:
                    request_binding[field] = (
                        "changed-policy-id"
                        if field == "policyId"
                        else "sha256:" + "9" * 64
                    )
                _rehash(request_document)
                request = verify_static_request(
                    self.schemas,
                    request_document,
                )
                policy = verify_capability_policy(
                    self.schemas,
                    policy_document_value,
                    verified_at=NOW,
                )
                with self.assertRaises(DirectPathVerificationError) as raised:
                    bind_static_request_policy(request, policy)
                self.assertEqual(
                    "REQUEST_POLICY_BINDING_MISMATCH",
                    raised.exception.code,
                )

    def test_changed_policy_limits_require_a_new_bound_policy_hash(self) -> None:
        request_document, policy_document_value = _bound_documents()
        changed_policy = copy.deepcopy(policy_document_value)
        changed_policy["dependencyClosure"]["maxDevices"] = 128
        changed_policy["policyHash"] = None
        changed_policy["policyHash"] = sha256_digest(
            canonical_json_bytes(changed_policy)
        )

        request = verify_static_request(
            self.schemas,
            request_document,
        )
        policy = verify_capability_policy(
            self.schemas,
            changed_policy,
            verified_at=NOW,
        )
        with self.assertRaises(DirectPathVerificationError) as raised:
            bind_static_request_policy(request, policy)
        self.assertEqual(
            "REQUEST_POLICY_BINDING_MISMATCH",
            raised.exception.code,
        )


if __name__ == "__main__":
    unittest.main()
