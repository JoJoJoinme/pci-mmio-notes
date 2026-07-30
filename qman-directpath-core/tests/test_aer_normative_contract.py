from __future__ import annotations

import ast
import copy
import hashlib
import json
from pathlib import Path
import subprocess
import sys
from typing import Any

from jsonschema import Draft202012Validator, ValidationError
import pytest


ROOT = Path(__file__).resolve().parents[2]
CORE_ROOT = ROOT / "qman-directpath-core"
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
if str(CORE_ROOT) not in sys.path:
    sys.path.insert(0, str(CORE_ROOT))

from qman_directpath_core.aer_policy import (  # noqa: E402
    CORRECTABLE_ERROR_ALLOW_MASK,
    verify_aer_policy,
)
from qman_directpath_core.errors import (  # noqa: E402
    DirectPathVerificationError,
)
from tools import generate_directpath_aer_contract as generator  # noqa: E402


CONTRACTS = ROOT / "contracts"
POLICY_SCHEMA_PATH = (
    CONTRACTS / "directpath-aer-correctable-policy.schema.json"
)
MATRIX_SCHEMA_PATH = (
    CONTRACTS / "directpath-aer-case-matrix.schema.json"
)
RECEIPT_SCHEMA_PATH = (
    CONTRACTS / "directpath-aer-component-receipt.schema.json"
)
ALGORITHM_SCHEMA_PATH = (
    CONTRACTS / "directpath-aer-verifier-algorithm.schema.json"
)
MATRIX_PATH = CONTRACTS / "directpath-aer-case-matrix-v1.json"
GOLDEN_PATH = (
    CONTRACTS / "directpath-aer-correctable.golden-vectors.json"
)

POLICY_DOMAIN = b"QMAN-DIRECTPATH/AER-POLICY/V1\x00"
TUPLE_DOMAIN = b"QMAN-DIRECTPATH/AER-CASE-TUPLE/V1\x00"
MATRIX_DOMAIN = b"QMAN-DIRECTPATH/AER-CASE-MATRIX/V1\x00"
OWNER_DOMAIN = b"QMAN-DIRECTPATH/AER-OWNER-BINDING/V1\x00"
LAYOUT_DOMAIN = b"QMAN-DIRECTPATH/AER-LAYOUT-BINDING/V1\x00"
ORACLE_DOMAIN = b"QMAN-DIRECTPATH/AER-ORACLE-BINDING/V1\x00"
CASE_RESULT_DOMAIN = b"QMAN-DIRECTPATH/AER-CASE-RESULT/V1\x00"
RECEIPT_DOMAIN = b"QMAN-DIRECTPATH/AER-COMPONENT-RECEIPT/V1\x00"
ALGORITHM_DOMAIN = b"QMAN-DIRECTPATH/AER-VERIFIER-ALGORITHM/V1\x00"
GOLDEN_DOMAIN = b"QMAN-DIRECTPATH/AER-GOLDEN-VECTORS/V1\x00"

CASE_IDS = ["M24", "M25", "M26", "M27", "M28", "M29"]
CASE_COUNTS = {
    "M24": 8,
    "M25": 64,
    "M26": 24,
    "M27": 9,
    "M28": 15,
    "M29": 13,
}
CORRECTABLE_BITS = [1, 64, 128, 256, 4096, 8192, 16384, 32768]
DIMENSIONS = [
    "GUEST_WRITES",
    "IRQ_DELIVERY",
    "SERVICE_ATTRIBUTION",
    "DEVICE_HEALTH",
    "PHYSICAL_RECOVERY",
]


def _load(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    assert isinstance(value, dict)
    return value


def _canonical(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _digest(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _file_digest(path: Path) -> str:
    return _digest(path.read_bytes())


def _null_hash(
    document: dict[str, Any],
    field: str,
    domain: bytes,
) -> str:
    projection = copy.deepcopy(document)
    projection[field] = None
    return _digest(domain + _canonical(projection))


def _finalize(
    document: dict[str, Any],
    field: str,
    domain: bytes,
) -> dict[str, Any]:
    result = copy.deepcopy(document)
    result[field] = _null_hash(result, field, domain)
    return result


def _label_digest(label: str) -> str:
    return _digest(label.encode("ascii"))


@pytest.fixture(scope="module")
def schemas() -> dict[str, dict[str, Any]]:
    return {
        "policy": _load(POLICY_SCHEMA_PATH),
        "matrix": _load(MATRIX_SCHEMA_PATH),
        "receipt": _load(RECEIPT_SCHEMA_PATH),
        "algorithm": _load(ALGORITHM_SCHEMA_PATH),
    }


@pytest.fixture(scope="module")
def matrix() -> dict[str, Any]:
    return _load(MATRIX_PATH)


@pytest.fixture(scope="module")
def golden() -> dict[str, Any]:
    return _load(GOLDEN_PATH)


def test_candidate_schemas_are_closed_draft_2020_12(
    schemas: dict[str, dict[str, Any]],
    golden: dict[str, Any],
) -> None:
    for schema in schemas.values():
        Draft202012Validator.check_schema(schema)
        assert schema["$schema"].endswith("/draft/2020-12/schema")

    assert schemas["policy"]["x-qmanDigestDomain"].endswith("\x00")
    assert schemas["matrix"]["x-qmanTupleDigestDomain"].endswith("\x00")
    assert (
        schemas["receipt"]["properties"]["authorityBoundary"]["const"]
        == "COMPONENT_PREMISE"
    )
    assert (
        schemas["receipt"]["properties"]["productAuthorized"]["const"]
        is False
    )
    candidate_oracle = schemas["receipt"]["$defs"][
        "candidateOracleBinding"
    ]["allOf"][1]["properties"]
    reference_oracle = schemas["receipt"]["$defs"][
        "referenceOracleBinding"
    ]["allOf"][1]["properties"]
    assert candidate_oracle["environmentKind"]["const"] == "SYNTHETIC"
    assert candidate_oracle["authorityClosure"]["const"] == "NONE"
    assert reference_oracle["environmentKind"]["const"] == "PHYSICAL"
    assert (
        reference_oracle["authorityClosure"]["const"]
        == "REFERENCE_BEHAVIOR_ONLY"
    )
    assert (
        schemas["algorithm"]["properties"]["productAuthorized"]["const"]
        is False
    )
    Draft202012Validator(schemas["algorithm"]).evolve(
        schema=schemas["algorithm"]["$defs"]["goldenVectorSet"]
    ).validate(golden)


def test_matrix_materializes_exact_m24_m29_tuple_closure(
    schemas: dict[str, dict[str, Any]],
    matrix: dict[str, Any],
) -> None:
    Draft202012Validator(schemas["matrix"]).validate(matrix)
    assert matrix["authorityBoundary"] == "COMPONENT_PREMISE"
    assert matrix["productAuthorized"] is False
    assert matrix["correctableBits"] == CORRECTABLE_BITS
    assert matrix["requiredCaseIds"] == CASE_IDS
    assert matrix["caseTupleCounts"] == CASE_COUNTS
    assert matrix["tupleCount"] == 133
    assert [case["caseId"] for case in matrix["cases"]] == CASE_IDS

    tuple_ids: set[str] = set()
    tuple_digests: set[str] = set()
    for case in matrix["cases"]:
        expected_count = CASE_COUNTS[case["caseId"]]
        assert case["tupleCount"] == expected_count
        assert len(case["tuples"]) == expected_count
        for ordinal, row in enumerate(case["tuples"], start=1):
            assert row["caseId"] == case["caseId"]
            assert row["ordinal"] == ordinal
            assert row["tupleDigest"] == _null_hash(
                row,
                "tupleDigest",
                TUPLE_DOMAIN,
            )
            assert row["tupleId"] not in tuple_ids
            assert row["tupleDigest"] not in tuple_digests
            tuple_ids.add(row["tupleId"])
            tuple_digests.add(row["tupleDigest"])
    assert len(tuple_ids) == 133
    assert matrix["matrixDigest"] == _null_hash(
        matrix,
        "matrixDigest",
        MATRIX_DOMAIN,
    )

    m24 = matrix["cases"][0]["tuples"]
    assert [row["correctableBit"] for row in m24] == CORRECTABLE_BITS
    assert all(row["expectedEndpointDeposition"] for row in m24)
    assert all(not row["expectedRootDeposition"] for row in m24)
    assert all(row["expectedIndependentCesCedW1c"] for row in m24)

    m25 = matrix["cases"][1]["tuples"]
    actual_gates = [
        (
            row["correctableBit"],
            row["endpointCere"],
            row["controlledBitMasked"],
            row["rootCorEnabled"],
        )
        for row in m25
    ]
    expected_gates = [
        (bit, endpoint_cere, masked, root_enabled)
        for bit in CORRECTABLE_BITS
        for endpoint_cere in (False, True)
        for masked in (False, True)
        for root_enabled in (False, True)
    ]
    assert actual_gates == expected_gates
    for row in m25:
        routed = row["endpointCere"] and not row["controlledBitMasked"]
        assert row["expectedRootDeposition"] is routed
        assert row["expectedNotificationEligible"] is (
            routed and row["rootCorEnabled"]
        )

    m26 = matrix["cases"][2]["tuples"]
    assert {
        (
            row["referenceOwnerPhase"],
            row["ownerSemanticClass"],
            row["gateId"],
            row["sequence"],
            row["repeatIndex"],
        )
        for row in m26
    } == {
        (phase, semantic, "g101", sequence, repeat_index)
        for phase, semantic in (
            ("O0", "HOST_OWNED_IDLE"),
            ("O4", "ACTIVE_DIRECTPATH"),
        )
        for sequence in (
            "FIRST_MULTIPLE",
            "INDEPENDENT_W1C",
            "BIT_OR",
            "REARM",
        )
        for repeat_index in range(1, 4)
    }


def test_fixed_matrix_rejects_duplicate_omission_and_semantic_rewrite(
    matrix: dict[str, Any],
    golden: dict[str, Any],
) -> None:
    policy = golden["positivePolicyVectors"][0]["document"]
    receipt = _component_receipt(matrix, golden)

    duplicate = copy.deepcopy(matrix)
    duplicate_row = duplicate["cases"][0]["tuples"][1]
    duplicate_row["tupleId"] = duplicate["cases"][0]["tuples"][0][
        "tupleId"
    ]
    duplicate_row["tupleDigest"] = _null_hash(
        duplicate_row,
        "tupleDigest",
        TUPLE_DOMAIN,
    )
    duplicate["matrixDigest"] = _null_hash(
        duplicate,
        "matrixDigest",
        MATRIX_DOMAIN,
    )
    with pytest.raises(ValueError, match="duplicate tuple ID"):
        _verify_receipt(receipt, policy, duplicate, golden)

    omission = copy.deepcopy(matrix)
    omission["cases"][5]["tuples"].pop()
    omission["cases"][5]["tupleCount"] -= 1
    omission["caseTupleCounts"]["M29"] -= 1
    omission["tupleCount"] -= 1
    omission["matrixDigest"] = _null_hash(
        omission,
        "matrixDigest",
        MATRIX_DOMAIN,
    )
    with pytest.raises(ValidationError):
        _verify_receipt(receipt, policy, omission, golden)

    semantic_mutations = [
        (0, 0, "correctableBit", 64, "M24 Correctable bit"),
        (1, 0, "expectedRootDeposition", True, "root route truth"),
        (2, 0, "sequence", "BIT_OR", "fixed M24-M29 declarative"),
        (3, 0, "expectedOutcome", "DENIED", "fixed M24-M29 declarative"),
        (4, 0, "expectedOutcome", "DENIED", "fixed M24-M29 declarative"),
        (
            5,
            1,
            "expectedComponentEligible",
            False,
            "fixed M24-M29 declarative",
        ),
    ]
    for (
        case_index,
        tuple_index,
        field,
        replacement,
        message,
    ) in semantic_mutations:
        semantic_rewrite = copy.deepcopy(matrix)
        row = semantic_rewrite["cases"][case_index]["tuples"][
            tuple_index
        ]
        row[field] = replacement
        row["tupleDigest"] = _null_hash(
            row,
            "tupleDigest",
            TUPLE_DOMAIN,
        )
        semantic_rewrite["matrixDigest"] = _null_hash(
            semantic_rewrite,
            "matrixDigest",
            MATRIX_DOMAIN,
        )
        with pytest.raises(ValueError, match=message):
            _verify_receipt(
                receipt,
                policy,
                semantic_rewrite,
                golden,
            )

    oversized_m29_reason = copy.deepcopy(matrix)
    oversized_m29_reason["cases"][5]["tuples"][0][
        "expectedDenyReasonOrNull"
    ] = "A" * 129
    with pytest.raises(ValidationError):
        Draft202012Validator(
            _load(MATRIX_SCHEMA_PATH)
        ).validate(oversized_m29_reason)


def test_golden_policy_vectors_match_independent_and_core_verifiers(
    schemas: dict[str, dict[str, Any]],
    golden: dict[str, Any],
) -> None:
    assert golden["authorityBoundary"] == "COMPONENT_PREMISE"
    assert golden["productAuthorized"] is False
    assert golden["normativeSourceState"] == (
        "CANDIDATE_NOT_IN_PORTABLE_CLOSURE"
    )
    assert golden["digestDomains"]["policy"].encode("ascii") == POLICY_DOMAIN
    policy_validator = Draft202012Validator(schemas["policy"])

    assert len(golden["positivePolicyVectors"]) == 3
    for vector in golden["positivePolicyVectors"]:
        document = vector["document"]
        policy_validator.validate(document)
        assert generator.policy_semantic_error(document) is None
        assert document["aerPolicyDigest"] == _null_hash(
            document,
            "aerPolicyDigest",
            POLICY_DOMAIN,
        )
        verified = verify_aer_policy(document)
        assert (
            verified.aer_policy_digest
            == vector["expectedAerPolicyDigest"]
            == document["aerPolicyDigest"]
        )

    assert CORRECTABLE_ERROR_ALLOW_MASK == 0xF1C1
    expected_negative_codes = {
        "AER_UNCORRECTABLE_FORBIDDEN",
        "AER_WRITE_ORDER_INVALID",
        "AER_UNKNOWN_FIELD_POLICY_INVALID",
        "AER_W1C_MASK_OVERLAP",
        "AER_HIDDEN_WRITE_LEAK",
    }
    actual_codes: set[str] = set()
    for vector in golden["negativePolicyVectors"]:
        document = vector["document"]
        assert bool(not list(policy_validator.iter_errors(document))) is (
            vector["expectedSchemaValid"]
        )
        assert generator.policy_semantic_error(document) == (
            vector["expectedErrorCode"]
        )
        with pytest.raises(DirectPathVerificationError) as raised:
            verify_aer_policy(document)
        assert raised.value.code == vector["expectedErrorCode"]
        actual_codes.add(raised.value.code)
    assert actual_codes == expected_negative_codes


def test_policy_field_order_is_not_a_semantic_key_set(
    schemas: dict[str, dict[str, Any]],
    golden: dict[str, Any],
) -> None:
    policy = copy.deepcopy(
        golden["positivePolicyVectors"][0]["document"]
    )
    policy["fields"] = dict(reversed(list(policy["fields"].items())))
    policy["aerPolicyDigest"] = _null_hash(
        policy,
        "aerPolicyDigest",
        POLICY_DOMAIN,
    )
    Draft202012Validator(schemas["policy"]).validate(policy)
    assert generator.policy_semantic_error(policy) is None
    assert verify_aer_policy(policy).aer_policy_digest == (
        policy["aerPolicyDigest"]
    )

    missing = copy.deepcopy(policy)
    missing["fields"].pop("ERROR_SOURCE_ID")
    missing["aerPolicyDigest"] = _null_hash(
        missing,
        "aerPolicyDigest",
        POLICY_DOMAIN,
    )
    assert generator.policy_semantic_error(missing) == (
        "AER_POLICY_SHAPE_INVALID"
    )
    with pytest.raises(ValidationError):
        Draft202012Validator(schemas["policy"]).validate(missing)

    extra = copy.deepcopy(policy)
    extra["fields"]["CALLER_DEFINED_FIELD"] = copy.deepcopy(
        extra["fields"]["PCIE_DEVICE_CONTROL"]
    )
    extra["aerPolicyDigest"] = _null_hash(
        extra,
        "aerPolicyDigest",
        POLICY_DOMAIN,
    )
    assert generator.policy_semantic_error(extra) == (
        "AER_POLICY_SHAPE_INVALID"
    )
    with pytest.raises(ValidationError):
        Draft202012Validator(schemas["policy"]).validate(extra)


def test_algorithm_identity_is_self_bound_and_target_independent(
    schemas: dict[str, dict[str, Any]],
    matrix: dict[str, Any],
    golden: dict[str, Any],
) -> None:
    algorithm = golden["verifierAlgorithm"]["document"]
    Draft202012Validator(schemas["algorithm"]).validate(algorithm)
    assert algorithm["authorityBoundary"] == "COMPONENT_PREMISE"
    assert algorithm["productAuthorized"] is False
    assert algorithm["targetImplementationImportsAllowed"] is False
    assert algorithm["resourceBudgets"] == generator.RESOURCE_BUDGETS
    assert algorithm["caseMatrixDigest"] == matrix["matrixDigest"]
    assert algorithm["requiredCaseIds"] == CASE_IDS
    assert algorithm["requiredDimensions"] == DIMENSIONS
    assert algorithm["algorithmDigest"] == _null_hash(
        algorithm,
        "algorithmDigest",
        ALGORITHM_DOMAIN,
    )
    assert (
        golden["verifierAlgorithm"]["expectedAlgorithmDigest"]
        == algorithm["algorithmDigest"]
    )
    for binding in algorithm["schemaBindings"]:
        assert binding["sha256"] == _file_digest(ROOT / binding["path"])
    for binding in algorithm["implementationBindings"]:
        assert binding["sha256"] == _file_digest(ROOT / binding["path"])
    assert golden["implementationBindings"] == (
        algorithm["implementationBindings"]
    )

    source = (ROOT / "tools/generate_directpath_aer_contract.py").read_text(
        encoding="utf-8"
    )
    tree = ast.parse(source)
    imported_roots = {
        alias.name.split(".", 1)[0]
        for node in ast.walk(tree)
        if isinstance(node, (ast.Import, ast.ImportFrom))
        for alias in (
            node.names
            if isinstance(node, ast.Import)
            else [
                ast.alias(
                    name=node.module or "",
                    asname=None,
                )
            ]
        )
    }
    assert "qman_directpath_core" not in imported_roots


def test_fixed_source_bundle_is_consumed_from_one_frozen_snapshot(
    matrix: dict[str, Any],
    golden: dict[str, Any],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    snapshot = generator.capture_source_snapshot()
    with pytest.raises(TypeError, match="exact tuple"):
        generator.ContractSourceSnapshot(
            entries=list(snapshot.entries),  # type: ignore[arg-type]
        )
    mutable_payload = list(snapshot.entries)
    relative, payload = mutable_payload[0]
    mutable_payload[0] = (relative, bytearray(payload))  # type: ignore[assignment]
    with pytest.raises(TypeError, match="not exact bytes"):
        generator.ContractSourceSnapshot(entries=tuple(mutable_payload))

    def path_reopen_forbidden(*args: Any, **kwargs: Any) -> Any:
        raise AssertionError("fixed source path was reopened")

    monkeypatch.setattr(Path, "open", path_reopen_forbidden)
    algorithm = generator.build_algorithm(matrix, snapshot=snapshot)
    rebuilt_golden = generator.build_golden(
        matrix,
        algorithm,
        snapshot=snapshot,
    )
    assert rebuilt_golden == golden
    generator.validate_generated(
        matrix,
        golden,
        snapshot=snapshot,
    )


def _component_receipt(
    matrix: dict[str, Any],
    golden: dict[str, Any],
) -> dict[str, Any]:
    owners = [
        _finalize(
            {
                "referenceOwnerPhase": "O0",
                "ownerSemanticClass": "HOST_OWNED_IDLE",
                "assignmentId": "host-idle",
                "leaseGeneration": 1,
                "ownerEpoch": 1,
                "hostBootId": "boot-a",
                "ownerBindingDigest": None,
            },
            "ownerBindingDigest",
            OWNER_DOMAIN,
        ),
        _finalize(
            {
                "referenceOwnerPhase": "O4",
                "ownerSemanticClass": "ACTIVE_DIRECTPATH",
                "assignmentId": "assignment-a",
                "leaseGeneration": 7,
                "ownerEpoch": 11,
                "hostBootId": "boot-a",
                "ownerBindingDigest": None,
            },
            "ownerBindingDigest",
            OWNER_DOMAIN,
        ),
    ]
    layouts = [
        _finalize(
            {
                "functionRole": "ENDPOINT",
                "bdf": "0000:01:00.1",
                "deviceIdentityDigest": _label_digest("endpoint-identity"),
                "pcieCapabilityOffset": 0x70,
                "aerCapabilityOffset": 0x180,
                "layoutDigest": _label_digest("endpoint-layout"),
                "layoutBindingDigest": None,
            },
            "layoutBindingDigest",
            LAYOUT_DOMAIN,
        ),
        _finalize(
            {
                "functionRole": "ROOT_PORT",
                "bdf": "0000:00:08.0",
                "deviceIdentityDigest": _label_digest("root-identity"),
                "pcieCapabilityOffset": 0x40,
                "aerCapabilityOffset": 0x100,
                "layoutDigest": _label_digest("root-layout"),
                "layoutBindingDigest": None,
            },
            "layoutBindingDigest",
            LAYOUT_DOMAIN,
        ),
    ]
    oracles = [
        _finalize(
            {
                "oracleRole": "CANDIDATE_RUNTIME",
                "environmentKind": "SYNTHETIC",
                "authorityClosure": "NONE",
                "artifactManifestDigest": _label_digest(
                    "candidate-manifest"
                ),
                "oracleDigest": _label_digest("candidate-oracle"),
                "oracleBindingDigest": None,
            },
            "oracleBindingDigest",
            ORACLE_DOMAIN,
        ),
        _finalize(
            {
                "oracleRole": "REFERENCE_BEHAVIOR",
                "environmentKind": "PHYSICAL",
                "authorityClosure": "REFERENCE_BEHAVIOR_ONLY",
                "artifactManifestDigest": _label_digest(
                    "reference-manifest"
                ),
                "oracleDigest": _label_digest("reference-oracle"),
                "oracleBindingDigest": None,
            },
            "oracleBindingDigest",
            ORACLE_DOMAIN,
        ),
    ]

    case_results = []
    owners_by_phase = {
        owner["referenceOwnerPhase"]: owner["ownerBindingDigest"]
        for owner in owners
    }
    layouts_by_role = {
        layout["functionRole"]: layout["layoutBindingDigest"]
        for layout in layouts
    }
    for case in matrix["cases"]:
        tuple_results = []
        for row in case["tuples"]:
            label = row["tupleId"]
            tuple_results.append(
                {
                    "tupleId": label,
                    "tupleDigest": row["tupleDigest"],
                    "ownerBindingDigests": [
                        owners_by_phase[phase]
                        for phase in row["expectedOwnerPhases"]
                    ],
                    "layoutBindingDigests": [
                        layouts_by_role[role]
                        for role in row["expectedLayoutRoles"]
                    ],
                    "candidateOracleBindingDigest": oracles[0][
                        "oracleBindingDigest"
                    ],
                    "referenceOracleBindingDigest": oracles[1][
                        "oracleBindingDigest"
                    ],
                    "runResultBinding": {
                        "artifactType": "RUN_RESULT",
                        "digest": _label_digest(f"run-{label}"),
                    },
                    "artifactManifestBinding": {
                        "artifactType": "ARTIFACT_MANIFEST",
                        "digest": _label_digest(f"manifest-{label}"),
                    },
                    "evidenceIndexBinding": {
                        "artifactType": "EVIDENCE_INDEX",
                        "digest": _label_digest(f"index-{label}"),
                    },
                    "result": "MATCH",
                }
            )
        case_results.append(
            _finalize(
                {
                    "caseId": case["caseId"],
                    "expectedTupleCount": case["tupleCount"],
                    "tupleResults": tuple_results,
                    "result": "MATCH",
                    "caseResultDigest": None,
                },
                "caseResultDigest",
                CASE_RESULT_DOMAIN,
            )
        )

    algorithm = golden["verifierAlgorithm"]["document"]
    receipt = {
        "subjectType": "QMAN_AER_COMPONENT_PREMISE_RECEIPT",
        "schemaVersion": 1,
        "receiptId": "component-receipt-test",
        "authorityBoundary": "COMPONENT_PREMISE",
        "productAuthorized": False,
        "normativeSourceState": "CANDIDATE_NOT_IN_PORTABLE_CLOSURE",
        "verificationDisposition": "STRUCTURALLY_VALID",
        "artifactAuthority": {
            "resolverState": "UNAVAILABLE",
            "resolverIdentityDigestOrNull": None,
            "typedAuthorityReceiptDigests": [],
        },
        "contractBinding": {
            "aerPolicyDigest": golden["positivePolicyVectors"][0][
                "expectedAerPolicyDigest"
            ],
            "aerPolicySchemaSha256": _file_digest(POLICY_SCHEMA_PATH),
            "caseMatrixDigest": matrix["matrixDigest"],
            "caseMatrixSchemaSha256": _file_digest(MATRIX_SCHEMA_PATH),
            "verifierAlgorithmDigest": algorithm["algorithmDigest"],
            "verifierAlgorithmSchemaSha256": _file_digest(
                ALGORITHM_SCHEMA_PATH
            ),
            "componentReceiptSchemaSha256": _file_digest(
                RECEIPT_SCHEMA_PATH
            ),
            "goldenVectorSetDigest": golden["goldenVectorSetDigest"],
            "generatorRawSha256": _file_digest(
                ROOT / "tools/generate_directpath_aer_contract.py"
            ),
            "conformanceTestRawSha256": _file_digest(Path(__file__)),
        },
        "implementationBinding": {
            "qmanBuildDigest": _label_digest("qman-build"),
            "implementationDigest": _label_digest("implementation"),
            "sourceTreeManifestDigest": _label_digest("source-tree"),
            "buildAttestationDigest": _label_digest("build-attestation"),
        },
        "ownerBindings": owners,
        "layoutBindings": layouts,
        "oracleBindings": oracles,
        "caseResults": case_results,
        "dimensions": {
            dimension: {
                "result": "STRUCTURALLY_VALID",
                "receiptDigestOrNull": None,
            }
            for dimension in DIMENSIONS
        },
        "cleanup": {
            "result": "STRUCTURALLY_VALID",
            "receiptDigestOrNull": None,
        },
        "reuse": {
            "result": "STRUCTURALLY_VALID",
            "receiptDigestOrNull": None,
        },
        "classification": "MATCH",
        "componentEligible": False,
        "denyReasons": generator.structural_deny_reasons("MATCH"),
        "unverifiedDimensions": DIMENSIONS,
        "receiptDigest": None,
    }
    receipt["receiptDigest"] = _null_hash(
        receipt,
        "receiptDigest",
        RECEIPT_DOMAIN,
    )
    return receipt


def _verify_receipt(
    receipt: dict[str, Any],
    policy: dict[str, Any],
    matrix: dict[str, Any],
    golden: dict[str, Any],
) -> generator.ComponentReceiptVerification:
    return generator.verify_component_receipt(
        receipt_bytes=generator.render(receipt),
        policy_bytes=generator.render(policy),
        matrix_bytes=generator.render(matrix),
        golden_bytes=generator.render(golden),
    )


def _rehash_receipt_case(
    receipt: dict[str, Any],
    case_index: int,
) -> None:
    case = receipt["caseResults"][case_index]
    case["caseResultDigest"] = _null_hash(
        case,
        "caseResultDigest",
        CASE_RESULT_DOMAIN,
    )
    receipt["receiptDigest"] = _null_hash(
        receipt,
        "receiptDigest",
        RECEIPT_DOMAIN,
    )


def _rehash_all_receipt_cases(receipt: dict[str, Any]) -> None:
    for case in receipt["caseResults"]:
        case["caseResultDigest"] = _null_hash(
            case,
            "caseResultDigest",
            CASE_RESULT_DOMAIN,
        )
    receipt["receiptDigest"] = _null_hash(
        receipt,
        "receiptDigest",
        RECEIPT_DOMAIN,
    )


def test_component_receipt_is_exact_but_never_self_authorizing(
    schemas: dict[str, dict[str, Any]],
    matrix: dict[str, Any],
    golden: dict[str, Any],
) -> None:
    receipt = _component_receipt(matrix, golden)
    policy = golden["positivePolicyVectors"][0]["document"]
    receipt_validator = Draft202012Validator(schemas["receipt"])
    receipt_validator.validate(receipt)
    result = _verify_receipt(receipt, policy, matrix, golden)
    assert result.verification_disposition == "STRUCTURALLY_VALID"
    assert result.component_eligible is False
    assert result.authority_boundary == "COMPONENT_PREMISE"
    assert result.product_authorized is False
    assert receipt["componentEligible"] is False
    assert receipt["productAuthorized"] is False
    assert sum(
        len(case["tupleResults"]) for case in receipt["caseResults"]
    ) == 133

    forged_product = copy.deepcopy(receipt)
    forged_product["productAuthorized"] = True
    with pytest.raises(ValidationError):
        receipt_validator.validate(forged_product)

    forged_e4 = copy.deepcopy(receipt)
    forged_e4["authorityBoundary"] = "E4"
    with pytest.raises(ValidationError):
        receipt_validator.validate(forged_e4)

    injected_e4_receipt = copy.deepcopy(receipt)
    injected_e4_receipt["e4ReplayReceiptDigest"] = _label_digest("fake-e4")
    with pytest.raises(ValidationError):
        receipt_validator.validate(injected_e4_receipt)

    self_authorized = copy.deepcopy(receipt)
    self_authorized["componentEligible"] = True
    with pytest.raises(ValidationError):
        receipt_validator.validate(self_authorized)

    tuple_substitution = copy.deepcopy(receipt)
    tuple_substitution["caseResults"][0]["tupleResults"][0][
        "tupleDigest"
    ] = matrix["cases"][0]["tuples"][1]["tupleDigest"]
    _rehash_receipt_case(tuple_substitution, 0)
    with pytest.raises(ValueError, match="tuple digest coverage drift"):
        _verify_receipt(tuple_substitution, policy, matrix, golden)


def test_typed_owner_layout_and_oracle_bindings_fail_closed(
    matrix: dict[str, Any],
    golden: dict[str, Any],
) -> None:
    policy = golden["positivePolicyVectors"][0]["document"]
    receipt = _component_receipt(matrix, golden)

    wrong_owner = copy.deepcopy(receipt)
    wrong_owner["caseResults"][0]["tupleResults"][0][
        "ownerBindingDigests"
    ] = [receipt["ownerBindings"][0]["ownerBindingDigest"]]
    _rehash_receipt_case(wrong_owner, 0)
    with pytest.raises(ValueError, match="owner phase binding mismatch"):
        _verify_receipt(wrong_owner, policy, matrix, golden)

    missing_root_layout = copy.deepcopy(receipt)
    missing_root_layout["caseResults"][1]["tupleResults"][0][
        "layoutBindingDigests"
    ] = [receipt["layoutBindings"][0]["layoutBindingDigest"]]
    _rehash_receipt_case(missing_root_layout, 1)
    with pytest.raises(ValueError, match="layout role binding mismatch"):
        _verify_receipt(missing_root_layout, policy, matrix, golden)

    m28_both = next(
        index
        for index, row in enumerate(matrix["cases"][4]["tuples"])
        if row["functionRole"] == "BOTH"
    )
    missing_m28_root = copy.deepcopy(receipt)
    missing_m28_root["caseResults"][4]["tupleResults"][m28_both][
        "layoutBindingDigests"
    ] = [receipt["layoutBindings"][0]["layoutBindingDigest"]]
    _rehash_receipt_case(missing_m28_root, 4)
    with pytest.raises(ValueError, match="layout role binding mismatch"):
        _verify_receipt(missing_m28_root, policy, matrix, golden)

    same_oracle = copy.deepcopy(receipt)
    row = same_oracle["caseResults"][0]["tupleResults"][0]
    row["referenceOracleBindingDigest"] = (
        row["candidateOracleBindingDigest"]
    )
    _rehash_receipt_case(same_oracle, 0)
    with pytest.raises(ValueError, match="oracle roles are not distinct"):
        _verify_receipt(same_oracle, policy, matrix, golden)

    swapped_oracle = copy.deepcopy(receipt)
    row = swapped_oracle["caseResults"][0]["tupleResults"][0]
    (
        row["candidateOracleBindingDigest"],
        row["referenceOracleBindingDigest"],
    ) = (
        row["referenceOracleBindingDigest"],
        row["candidateOracleBindingDigest"],
    )
    _rehash_receipt_case(swapped_oracle, 0)
    with pytest.raises(ValueError, match="candidate oracle role mismatch"):
        _verify_receipt(swapped_oracle, policy, matrix, golden)

    relabeled_artifact = copy.deepcopy(receipt)
    row = relabeled_artifact["caseResults"][0]["tupleResults"][0]
    row["evidenceIndexBinding"]["digest"] = row[
        "runResultBinding"
    ]["digest"]
    _rehash_receipt_case(relabeled_artifact, 0)
    with pytest.raises(ValueError, match="artifact digests not distinct"):
        _verify_receipt(relabeled_artifact, policy, matrix, golden)


def test_underlying_layout_and_oracle_identities_cannot_be_relabeled(
    matrix: dict[str, Any],
    golden: dict[str, Any],
) -> None:
    policy = golden["positivePolicyVectors"][0]["document"]

    for identity_member in (
        "bdf",
        "deviceIdentityDigest",
        "layoutDigest",
    ):
        same_layout_identity = _component_receipt(matrix, golden)
        endpoint = same_layout_identity["layoutBindings"][0]
        root = same_layout_identity["layoutBindings"][1]
        old_digest = root["layoutBindingDigest"]
        root[identity_member] = endpoint[identity_member]
        root["layoutBindingDigest"] = _null_hash(
            root,
            "layoutBindingDigest",
            LAYOUT_DOMAIN,
        )
        new_digest = root["layoutBindingDigest"]
        for case in same_layout_identity["caseResults"]:
            for row in case["tupleResults"]:
                row["layoutBindingDigests"] = [
                    new_digest if digest == old_digest else digest
                    for digest in row["layoutBindingDigests"]
                ]
        _rehash_all_receipt_cases(same_layout_identity)
        with pytest.raises(
            ValueError,
            match=(
                "endpoint/root layout identities not distinct: "
                + identity_member
            ),
        ):
            _verify_receipt(
                same_layout_identity,
                policy,
                matrix,
                golden,
            )

    invalid_endpoint_extent = _component_receipt(matrix, golden)
    endpoint = invalid_endpoint_extent["layoutBindings"][0]
    old_digest = endpoint["layoutBindingDigest"]
    endpoint["aerCapabilityOffset"] = 4056
    endpoint["layoutBindingDigest"] = _null_hash(
        endpoint,
        "layoutBindingDigest",
        LAYOUT_DOMAIN,
    )
    new_digest = endpoint["layoutBindingDigest"]
    for case in invalid_endpoint_extent["caseResults"]:
        for row in case["tupleResults"]:
            row["layoutBindingDigests"] = [
                new_digest if digest == old_digest else digest
                for digest in row["layoutBindingDigests"]
            ]
    _rehash_all_receipt_cases(invalid_endpoint_extent)
    with pytest.raises(ValueError, match="component receipt schema failure"):
        _verify_receipt(
            invalid_endpoint_extent,
            policy,
            matrix,
            golden,
        )

    invalid_root_extent = _component_receipt(matrix, golden)
    root = invalid_root_extent["layoutBindings"][1]
    old_digest = root["layoutBindingDigest"]
    root["aerCapabilityOffset"] = 4044
    root["layoutBindingDigest"] = _null_hash(
        root,
        "layoutBindingDigest",
        LAYOUT_DOMAIN,
    )
    new_digest = root["layoutBindingDigest"]
    for case in invalid_root_extent["caseResults"]:
        for row in case["tupleResults"]:
            row["layoutBindingDigests"] = [
                new_digest if digest == old_digest else digest
                for digest in row["layoutBindingDigests"]
            ]
    _rehash_all_receipt_cases(invalid_root_extent)
    with pytest.raises(ValueError, match="component receipt schema failure"):
        _verify_receipt(
            invalid_root_extent,
            policy,
            matrix,
            golden,
        )

    wrong_candidate_environment = _component_receipt(matrix, golden)
    candidate = wrong_candidate_environment["oracleBindings"][0]
    old_digest = candidate["oracleBindingDigest"]
    candidate["environmentKind"] = "NESTED"
    candidate["oracleBindingDigest"] = _null_hash(
        candidate,
        "oracleBindingDigest",
        ORACLE_DOMAIN,
    )
    new_digest = candidate["oracleBindingDigest"]
    for case in wrong_candidate_environment["caseResults"]:
        for row in case["tupleResults"]:
            if row["candidateOracleBindingDigest"] == old_digest:
                row["candidateOracleBindingDigest"] = new_digest
    _rehash_all_receipt_cases(wrong_candidate_environment)
    with pytest.raises(ValueError, match="component receipt schema failure"):
        _verify_receipt(
            wrong_candidate_environment,
            policy,
            matrix,
            golden,
        )

    for identity_member in ("artifactManifestDigest", "oracleDigest"):
        same_oracle_identity = _component_receipt(matrix, golden)
        candidate = same_oracle_identity["oracleBindings"][0]
        reference = same_oracle_identity["oracleBindings"][1]
        old_digest = reference["oracleBindingDigest"]
        reference[identity_member] = candidate[identity_member]
        reference["oracleBindingDigest"] = _null_hash(
            reference,
            "oracleBindingDigest",
            ORACLE_DOMAIN,
        )
        new_digest = reference["oracleBindingDigest"]
        for case in same_oracle_identity["caseResults"]:
            for row in case["tupleResults"]:
                if row["referenceOracleBindingDigest"] == old_digest:
                    row["referenceOracleBindingDigest"] = new_digest
        _rehash_all_receipt_cases(same_oracle_identity)
        with pytest.raises(
            ValueError,
            match=(
                "candidate/reference oracle identities not distinct: "
                + identity_member
            ),
        ):
            _verify_receipt(
                same_oracle_identity,
                policy,
                matrix,
                golden,
            )


def test_run_results_are_tuple_specific_but_batch_containers_may_repeat(
    matrix: dict[str, Any],
    golden: dict[str, Any],
) -> None:
    policy = golden["positivePolicyVectors"][0]["document"]

    duplicate_run = _component_receipt(matrix, golden)
    first, second = duplicate_run["caseResults"][0]["tupleResults"][:2]
    second["runResultBinding"]["digest"] = first[
        "runResultBinding"
    ]["digest"]
    _rehash_receipt_case(duplicate_run, 0)
    with pytest.raises(ValueError, match="run-result digest is not"):
        _verify_receipt(duplicate_run, policy, matrix, golden)

    cross_role_alias = _component_receipt(matrix, golden)
    first, second = cross_role_alias["caseResults"][0]["tupleResults"][:2]
    second["evidenceIndexBinding"]["digest"] = first[
        "artifactManifestBinding"
    ]["digest"]
    _rehash_receipt_case(cross_role_alias, 0)
    with pytest.raises(ValueError, match="reused across roles"):
        _verify_receipt(cross_role_alias, policy, matrix, golden)

    shared_batches = _component_receipt(matrix, golden)
    first = shared_batches["caseResults"][0]["tupleResults"][0]
    shared_manifest = first["artifactManifestBinding"]["digest"]
    shared_index = first["evidenceIndexBinding"]["digest"]
    for case in shared_batches["caseResults"]:
        for row in case["tupleResults"]:
            row["artifactManifestBinding"]["digest"] = shared_manifest
            row["evidenceIndexBinding"]["digest"] = shared_index
    _rehash_all_receipt_cases(shared_batches)
    result = _verify_receipt(shared_batches, policy, matrix, golden)
    assert result.verification_disposition == "STRUCTURALLY_VALID"
    assert result.component_eligible is False


def test_case_and_top_classification_are_deterministic(
    matrix: dict[str, Any],
    golden: dict[str, Any],
) -> None:
    policy = golden["positivePolicyVectors"][0]["document"]
    stale_case = _component_receipt(matrix, golden)
    stale_case["caseResults"][0]["tupleResults"][0]["result"] = "MISMATCH"
    _rehash_receipt_case(stale_case, 0)
    with pytest.raises(ValueError, match="Case result aggregation mismatch"):
        _verify_receipt(stale_case, policy, matrix, golden)

    exact_mismatch = _component_receipt(matrix, golden)
    exact_mismatch["caseResults"][0]["tupleResults"][0][
        "result"
    ] = "MISMATCH"
    exact_mismatch["caseResults"][0]["result"] = "MISMATCH"
    exact_mismatch["classification"] = "MISMATCH"
    exact_mismatch["denyReasons"] = generator.structural_deny_reasons(
        "MISMATCH"
    )
    _rehash_receipt_case(exact_mismatch, 0)
    result = _verify_receipt(exact_mismatch, policy, matrix, golden)
    assert result.component_eligible is False
    assert exact_mismatch["componentEligible"] is False

    stale_top = copy.deepcopy(exact_mismatch)
    stale_top["classification"] = "MATCH"
    stale_top["receiptDigest"] = _null_hash(
        stale_top,
        "receiptDigest",
        RECEIPT_DOMAIN,
    )
    with pytest.raises(ValueError, match="top classification aggregation"):
        _verify_receipt(stale_top, policy, matrix, golden)

    relabeled_denial = _component_receipt(matrix, golden)
    relabeled_denial["denyReasons"].append("ORACLE_BOUNDARY_INVALID")
    relabeled_denial["receiptDigest"] = _null_hash(
        relabeled_denial,
        "receiptDigest",
        RECEIPT_DOMAIN,
    )
    with pytest.raises(ValueError, match="denyReasons aggregation"):
        _verify_receipt(relabeled_denial, policy, matrix, golden)


def test_result_aggregation_precedence_is_closed() -> None:
    assert generator.aggregate_results(["MATCH", "MATCH"]) == "MATCH"
    assert generator.aggregate_results(["MATCH", "CANDIDATE"]) == (
        "CANDIDATE"
    )
    assert generator.aggregate_results(
        ["MATCH", "CANDIDATE", "INCONCLUSIVE"]
    ) == "INCONCLUSIVE"
    assert generator.aggregate_results(
        ["MATCH", "CANDIDATE", "INCONCLUSIVE", "MISMATCH"]
    ) == "MISMATCH"
    with pytest.raises(ValueError, match="empty"):
        generator.aggregate_results([])
    with pytest.raises(ValueError, match="unknown"):
        generator.aggregate_results(["MATCH", "QUALIFIED"])


def test_raw_verifier_applies_all_resource_budgets_before_schema(
    matrix: dict[str, Any],
    golden: dict[str, Any],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    policy = golden["positivePolicyVectors"][0]["document"]
    valid_inputs = {
        "policy_bytes": generator.render(policy),
        "matrix_bytes": generator.render(matrix),
        "golden_bytes": generator.render(golden),
    }

    class BytesSubclass(bytes):
        """A caller-defined byte view may override decode/equality methods."""

    with pytest.raises(TypeError, match="expected immutable raw bytes"):
        generator.verify_component_receipt(
            receipt_bytes=BytesSubclass(b"{}"),
            **valid_inputs,
        )

    with pytest.raises(ValueError, match="byte budget exceeded"):
        generator.verify_component_receipt(
            receipt_bytes=(
                b"{" + b" " * generator.RESOURCE_BUDGETS[
                    "receiptMaxBytes"
                ] + b"}"
            ),
            **valid_inputs,
        )

    nested: dict[str, Any] = {}
    for _ in range(generator.RESOURCE_BUDGETS["maxDepth"] + 2):
        nested = {"x": nested}
    with pytest.raises(ValueError, match="depth budget exceeded"):
        generator.verify_component_receipt(
            receipt_bytes=generator.render(nested),
            **valid_inputs,
        )

    with pytest.raises(ValueError, match="string budget exceeded"):
        generator.verify_component_receipt(
            receipt_bytes=generator.render(
                {
                    "x": (
                        "A"
                        * (
                            generator.RESOURCE_BUDGETS[
                                "maxStringUtf8Bytes"
                            ]
                            + 1
                        )
                    )
                }
            ),
            **valid_inputs,
        )

    node_bomb = json.dumps(
        {
            "x": [
                0
                for _ in range(
                    generator.RESOURCE_BUDGETS["maxNodes"] + 1
                )
            ]
        },
        separators=(",", ":"),
    ).encode("ascii")
    with pytest.raises(ValueError, match="node budget exceeded"):
        generator.verify_component_receipt(
            receipt_bytes=node_bomb,
            **valid_inputs,
        )

    with pytest.raises(generator.DuplicateKeyError):
        generator.verify_component_receipt(
            receipt_bytes=b'{"x":1,"x":2}',
            **valid_inputs,
        )

    empty_container_bomb = (
        "["
        + ",".join(
            "{}"
            for _ in range(
                generator.RESOURCE_BUDGETS["maxNodes"] + 1
            )
        )
        + "]"
    ).encode("ascii")

    def json_loads_must_not_run(*args: Any, **kwargs: Any) -> Any:
        raise AssertionError("json.loads ran before lexical node rejection")

    monkeypatch.setattr(generator.json, "loads", json_loads_must_not_run)
    with pytest.raises(ValueError, match="node budget exceeded"):
        generator.verify_component_receipt(
            receipt_bytes=empty_container_bomb,
            **valid_inputs,
        )


def test_golden_rejects_generator_or_test_binding_relabel(
    matrix: dict[str, Any],
    golden: dict[str, Any],
) -> None:
    policy = golden["positivePolicyVectors"][0]["document"]
    receipt = _component_receipt(matrix, golden)
    relabeled = copy.deepcopy(golden)
    relabeled["verifierAlgorithm"]["document"][
        "implementationBindings"
    ][0]["sha256"] = _label_digest("fake-generator")
    algorithm = relabeled["verifierAlgorithm"]["document"]
    algorithm["algorithmDigest"] = _null_hash(
        algorithm,
        "algorithmDigest",
        ALGORITHM_DOMAIN,
    )
    relabeled["verifierAlgorithm"]["expectedAlgorithmDigest"] = (
        algorithm["algorithmDigest"]
    )
    relabeled["goldenVectorSetDigest"] = _null_hash(
        relabeled,
        "goldenVectorSetDigest",
        GOLDEN_DOMAIN,
    )
    with pytest.raises(ValueError, match="implementation binding drift"):
        _verify_receipt(receipt, policy, matrix, relabeled)


def test_generator_check_eagerly_checks_both_outputs(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    checked: list[Path] = []

    def fail_and_record(
        path: Path,
        expected: bytes,
        *,
        max_bytes: int,
    ) -> bool:
        assert expected
        assert max_bytes > 0
        checked.append(path)
        return False

    monkeypatch.setattr(generator, "_check_output", fail_and_record)
    assert generator.main(["--check"]) == 1
    assert checked == [generator.MATRIX_OUTPUT, generator.GOLDEN_OUTPUT]

    class UnreadablePath:
        def relative_to(self, root: Path) -> Path:
            assert root == ROOT
            return Path("unreadable.json")

        def is_file(self) -> bool:
            return True

        def open(self, mode: str) -> Any:
            assert mode == "rb"
            raise OSError("injected read failure")

        def __str__(self) -> str:
            return "unreadable.json"

    assert generator._check_output(
        UnreadablePath(),  # type: ignore[arg-type]
        b"expected",
        max_bytes=128,
    ) is False


def test_golden_set_and_generator_are_byte_exact(
    matrix: dict[str, Any],
    golden: dict[str, Any],
) -> None:
    assert golden["matrixVector"]["matrixDigest"] == matrix["matrixDigest"]
    assert golden["matrixVector"]["matrixDocumentSha256"] == _digest(
        MATRIX_PATH.read_bytes()
    )
    assert golden["goldenVectorSetDigest"] == _null_hash(
        golden,
        "goldenVectorSetDigest",
        GOLDEN_DOMAIN,
    )
    completed = subprocess.run(
        [
            sys.executable,
            str(ROOT / "tools/generate_directpath_aer_contract.py"),
            "--check",
        ],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )
    assert completed.returncode == 0, completed.stdout + completed.stderr


def test_candidate_files_are_not_portable_normative_sources() -> None:
    portable = _load(
        CONTRACTS / "directpath-portable-control-contract.json"
    )
    candidate_paths = {
        "contracts/directpath-aer-correctable-policy.schema.json",
        "contracts/directpath-aer-case-matrix.schema.json",
        "contracts/directpath-aer-case-matrix-v1.json",
        "contracts/directpath-aer-component-receipt.schema.json",
        "contracts/directpath-aer-verifier-algorithm.schema.json",
        "contracts/directpath-aer-correctable.golden-vectors.json",
    }
    assert candidate_paths.isdisjoint(portable["normativeSources"])
