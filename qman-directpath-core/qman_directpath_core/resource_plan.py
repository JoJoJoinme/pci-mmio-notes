"""Factory-only structural verification for a retained guest resource plan.

The verifier closes the current component gap where a caller could provide an
arbitrary syntactically valid ``resourcePlanHash``.  It validates exact
CANONICAL-JSON-V1 bytes against the portable ``guestResourcePlan`` schema,
recomputes ``planHash``, checks window arithmetic/order, and binds the plan to
the same verified inventory, static admission, dependency closure, reset set,
and qualification profile used by the capability read.

This is deliberately a structural component boundary.  It does not run the
MMIO/RMRR/interrupt solver, prove that every BAR demand was supplied, observe
firmware/QEMU placement, or authorize a product side effect.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
import copy
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any

from ._verified import FactoryVerified, require_factory_verified
from .canonical import (
    CanonicalizationError,
    canonical_json_bytes,
    load_canonical_json,
    sha256_digest,
)
from .contracts import ContractSchemas
from .errors import DirectPathVerificationError, fail, require
from .inventory_closure_factory import (
    VerifiedStaticInventoryClosureContext,
)
from .qualification_profile import (
    StructuralStaticQualificationBindingContext,
)


GUEST_RESOURCE_PLAN_SCHEMA_REF = (
    "contracts/directpath-portable-hash-subjects.schema.json"
    "#/$defs/guestResourcePlan"
)
GUEST_RESOURCE_PLAN_SCHEMA_DOCUMENT_REF = (
    "contracts/directpath-portable-hash-subjects.schema.json"
)
GUEST_RESOURCE_PLAN_CONTEXT_DOMAIN = (
    b"QMAN-DIRECTPATH/VERIFIED-GUEST-RESOURCE-PLAN-CONTEXT/V1\x00"
)
GUEST_RESOURCE_PLAN_AUTHORITY_BOUNDARY = (
    "COMPONENT_CALLER_SUPPLIED_RESOURCE_PLAN_BYTES_ONLY"
)
GUEST_RESOURCE_PLAN_PRODUCT_AUTHORIZED = False
MAX_GUEST_RESOURCE_PLAN_BYTES = 8 * 1024 * 1024
MAX_GUEST_RESOURCE_PLAN_NODES = 200_000
MAX_GUEST_RESOURCE_PLAN_DEPTH = 64
MAX_ROOT_WINDOWS = 4096
MAX_BRIDGE_WINDOWS = 16384
MAX_BAR_PLACEMENTS = 32768
_SAFE_INTEGER = 9_007_199_254_740_991

JsonDocument = Mapping[str, Any] | bytes | bytearray | memoryview


def _clone_json(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {key: _clone_json(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_clone_json(item) for item in value]
    return value


def _freeze_json(value: Any) -> Any:
    if isinstance(value, Mapping):
        return MappingProxyType(
            {key: _freeze_json(item) for key, item in value.items()}
        )
    if isinstance(value, list):
        return tuple(_freeze_json(item) for item in value)
    return value


def _preflight_plan(value: Any) -> None:
    stack: list[tuple[Any, int]] = [(value, 0)]
    nodes = 0
    while stack:
        current, depth = stack.pop()
        nodes += 1
        require(
            nodes <= MAX_GUEST_RESOURCE_PLAN_NODES,
            "RESOURCE_PLAN_TOO_LARGE",
            "resourcePlan",
            "resource plan exceeds the closed node budget",
        )
        require(
            depth <= MAX_GUEST_RESOURCE_PLAN_DEPTH,
            "RESOURCE_PLAN_TOO_LARGE",
            "resourcePlan",
            "resource plan exceeds the closed nesting-depth budget",
        )
        if isinstance(current, Mapping):
            stack.extend((item, depth + 1) for item in current.values())
        elif isinstance(current, (list, tuple)):
            stack.extend((item, depth + 1) for item in current)

    if isinstance(value, Mapping):
        for field, maximum in (
            ("rootWindows", MAX_ROOT_WINDOWS),
            ("bridgeWindows", MAX_BRIDGE_WINDOWS),
            ("barPlacements", MAX_BAR_PLACEMENTS),
        ):
            candidate = value.get(field)
            if isinstance(candidate, (list, tuple)):
                require(
                    len(candidate) <= maximum,
                    "RESOURCE_PLAN_TOO_LARGE",
                    f"resourcePlan.{field}",
                    f"{field} exceeds its closed {maximum}-item limit",
                )


def _document(value: JsonDocument) -> tuple[dict[str, Any], bytes]:
    try:
        if isinstance(value, Mapping):
            _preflight_plan(value)
            document = _clone_json(value)
            raw = canonical_json_bytes(document)
        elif isinstance(value, (bytes, bytearray, memoryview)):
            raw = bytes(value)
            require(
                len(raw) <= MAX_GUEST_RESOURCE_PLAN_BYTES,
                "RESOURCE_PLAN_TOO_LARGE",
                "resourcePlan",
                "canonical resource plan exceeds the closed byte budget",
            )
            document = load_canonical_json(raw)
            _preflight_plan(document)
        else:
            raise TypeError("expected a JSON mapping or canonical bytes")
    except DirectPathVerificationError:
        raise
    except (CanonicalizationError, RecursionError, TypeError, ValueError) as exc:
        fail(
            "RESOURCE_PLAN_INVALID",
            "resourcePlan",
            f"cannot decode exact CANONICAL-JSON-V1 plan bytes: {exc}",
        )
    require(
        len(raw) <= MAX_GUEST_RESOURCE_PLAN_BYTES,
        "RESOURCE_PLAN_TOO_LARGE",
        "resourcePlan",
        "canonical resource plan exceeds the closed byte budget",
    )
    require(
        isinstance(document, dict),
        "RESOURCE_PLAN_INVALID",
        "resourcePlan",
        "guest resource plan must be one JSON object",
    )
    return document, raw


def _is_power_of_two(value: int) -> bool:
    return value > 0 and value & (value - 1) == 0


def _window_key(window: Mapping[str, Any]) -> bytes:
    return canonical_json_bytes(
        [
            window["ownerId"],
            window["resourceClass"],
            window["base"],
        ]
    )


def _verify_windows(
    windows: Sequence[Mapping[str, Any]],
    *,
    path: str,
    reject_peer_overlap: bool,
) -> None:
    keys = [_window_key(window) for window in windows]
    require(
        keys == sorted(keys),
        "RESOURCE_PLAN_INVALID",
        path,
        "windows are not in canonical [ownerId,resourceClass,base] order",
    )
    intervals: dict[str, list[tuple[int, int, str]]] = {}
    for index, window in enumerate(windows):
        base = window["base"]
        size = window["size"]
        alignment = window["alignment"]
        require(
            _is_power_of_two(size) and _is_power_of_two(alignment),
            "RESOURCE_PLAN_INVALID",
            f"{path}[{index}]",
            "size and alignment must be positive powers of two",
        )
        require(
            base % alignment == 0 and base + size <= _SAFE_INTEGER,
            "RESOURCE_PLAN_INVALID",
            f"{path}[{index}]",
            "window base must be aligned and its half-open end must be safe",
        )
        intervals.setdefault(window["resourceClass"], []).append(
            (base, base + size, window["ownerId"])
        )
    if not reject_peer_overlap:
        return
    for resource_class, values in intervals.items():
        ordered = sorted(values)
        for previous, current in zip(ordered, ordered[1:]):
            require(
                previous[1] <= current[0],
                "RESOURCE_PLAN_INVALID",
                path,
                (
                    f"peer {resource_class} windows overlap: "
                    f"{previous[2]!r} and {current[2]!r}"
                ),
            )


def _context_subject(
    *,
    inventory_closure: VerifiedStaticInventoryClosureContext,
    qualification_binding: StructuralStaticQualificationBindingContext,
    schema_ref: str,
    schema_digest: str,
    plan_hash: str,
    canonical_bytes_sha256: str,
    authority_boundary: str,
    product_authorized: bool,
    context_digest: str | None,
) -> dict[str, Any]:
    result = inventory_closure.result
    require(
        result.success and result.bundle is not None,
        "RESOURCE_PLAN_BINDING_MISMATCH",
        "resourcePlan.dependencyBundle",
        "a resource plan requires one complete successful dependency closure",
    )
    require(
        result.reset_contract_set_digest is not None,
        "RESOURCE_PLAN_BINDING_MISMATCH",
        "resourcePlan.resetContractSet",
        "a resource plan requires one complete reset-contract set",
    )
    return {
        "subjectType": "VERIFIED_GUEST_RESOURCE_PLAN_CONTEXT",
        "schemaVersion": 1,
        "staticAdmissionContextDigest": (
            inventory_closure.admission.context_digest
        ),
        "inventorySnapshotDigest": (
            inventory_closure.inventory.snapshot_content_hash
        ),
        "inventoryVerificationReceiptDigest": (
            inventory_closure.inventory.inventory_verification_receipt_digest
        ),
        "inventoryVerifierIdentityDigest": (
            inventory_closure.inventory.inventory_verifier_identity_digest
        ),
        "closureRequestDigest": result.closure_request.request_digest,
        "dependencyBundleDigest": result.bundle.bundle_hash,
        "resetContractSetDigest": result.reset_contract_set_digest,
        "qualificationBindingContextDigest": (
            qualification_binding.context_digest
        ),
        "profileHash": qualification_binding.profile.profile_hash,
        "guestAbiClass": qualification_binding.profile.guest_abi_class,
        "planSchemaRef": schema_ref,
        "planSchemaBytesSha256": schema_digest,
        "planHash": plan_hash,
        "canonicalPlanBytesSha256": canonical_bytes_sha256,
        "authorityBoundary": authority_boundary,
        "productAuthorized": product_authorized,
        "contextDigest": context_digest,
    }


@dataclass(frozen=True, slots=True, init=False)
class VerifiedGuestResourcePlanContext(FactoryVerified):
    """Exact structural plan binding; never planner or product authority."""

    schemas: ContractSchemas
    inventory_closure: VerifiedStaticInventoryClosureContext
    qualification_binding: StructuralStaticQualificationBindingContext
    document: Mapping[str, Any]
    canonical_bytes: bytes
    canonical_bytes_sha256: str
    schema_ref: str
    schema_digest: str
    plan_hash: str
    authority_boundary: str
    product_authorized: bool
    context_digest: str

    def to_subject(self) -> dict[str, Any]:
        return _context_subject(
            inventory_closure=self.inventory_closure,
            qualification_binding=self.qualification_binding,
            schema_ref=self.schema_ref,
            schema_digest=self.schema_digest,
            plan_hash=self.plan_hash,
            canonical_bytes_sha256=self.canonical_bytes_sha256,
            authority_boundary=self.authority_boundary,
            product_authorized=self.product_authorized,
            context_digest=self.context_digest,
        )


def verify_guest_resource_plan(
    schemas: ContractSchemas,
    inventory_closure: VerifiedStaticInventoryClosureContext,
    qualification_binding: StructuralStaticQualificationBindingContext,
    plan_document: JsonDocument,
) -> VerifiedGuestResourcePlanContext:
    """Validate and bind one exact retained plan without running a solver."""

    require(
        isinstance(schemas, ContractSchemas),
        "RESOURCE_PLAN_INPUT_INVALID",
        "schemas",
        "expected ContractSchemas",
    )
    require_factory_verified(
        inventory_closure,
        VerifiedStaticInventoryClosureContext,
        code="RESOURCE_PLAN_INPUT_INVALID",
        path="inventory_closure",
        message="inventory closure must come from resolve_static_inventory_closure",
    )
    require_factory_verified(
        qualification_binding,
        StructuralStaticQualificationBindingContext,
        code="RESOURCE_PLAN_INPUT_INVALID",
        path="qualification_binding",
        message=(
            "qualification binding must come from "
            "bind_static_qualification_profile"
        ),
    )
    require(
        inventory_closure.admission == qualification_binding.admission,
        "RESOURCE_PLAN_BINDING_MISMATCH",
        "resourcePlan.staticAdmission",
        "plan inputs must bind the same exact static admission",
    )
    plan, raw = _document(plan_document)
    schemas.validate_ref(
        GUEST_RESOURCE_PLAN_SCHEMA_REF,
        plan,
        "resourcePlan",
    )
    schema_digest = schemas.digest_for_ref(
        GUEST_RESOURCE_PLAN_SCHEMA_DOCUMENT_REF,
        path="resourcePlan.schemaRef",
    )
    null_hash_plan = copy.deepcopy(plan)
    null_hash_plan["planHash"] = None
    expected_plan_hash = sha256_digest(canonical_json_bytes(null_hash_plan))
    require(
        plan["planHash"] == expected_plan_hash,
        "RESOURCE_PLAN_HASH_INVALID",
        "resourcePlan.planHash",
        "planHash does not match the closed null-hash projection",
    )
    _verify_windows(
        plan["rootWindows"],
        path="resourcePlan.rootWindows",
        reject_peer_overlap=True,
    )
    _verify_windows(
        plan["bridgeWindows"],
        path="resourcePlan.bridgeWindows",
        reject_peer_overlap=False,
    )
    _verify_windows(
        plan["barPlacements"],
        path="resourcePlan.barPlacements",
        reject_peer_overlap=True,
    )

    inventory = inventory_closure.inventory
    profile = qualification_binding.profile
    runtime = profile.qualification_record["kernelQemuFirmwareBackend"]
    for actual, expected, path, description in (
        (
            plan["snapshotEpoch"],
            inventory.snapshot_epoch,
            "resourcePlan.snapshotEpoch",
            "verified inventory snapshot",
        ),
        (
            plan["profileHash"],
            profile.profile_hash,
            "resourcePlan.profileHash",
            "verified qualification profile",
        ),
        (
            plan["guestAbiClass"],
            profile.guest_abi_class,
            "resourcePlan.guestAbiClass",
            "verified guest ABI",
        ),
        (
            plan["machineType"],
            runtime["machineType"],
            "resourcePlan.machineType",
            "qualified machine type",
        ),
        (
            plan["firmwareKind"],
            runtime["firmwareKind"],
            "resourcePlan.firmwareKind",
            "qualified firmware kind",
        ),
    ):
        require(
            actual == expected,
            "RESOURCE_PLAN_BINDING_MISMATCH",
            path,
            f"plan does not bind the {description}",
        )

    canonical_bytes_sha256 = sha256_digest(raw)
    subject = _context_subject(
        inventory_closure=inventory_closure,
        qualification_binding=qualification_binding,
        schema_ref=GUEST_RESOURCE_PLAN_SCHEMA_REF,
        schema_digest=schema_digest,
        plan_hash=expected_plan_hash,
        canonical_bytes_sha256=canonical_bytes_sha256,
        authority_boundary=GUEST_RESOURCE_PLAN_AUTHORITY_BOUNDARY,
        product_authorized=GUEST_RESOURCE_PLAN_PRODUCT_AUTHORIZED,
        context_digest=None,
    )
    context_digest = sha256_digest(
        GUEST_RESOURCE_PLAN_CONTEXT_DOMAIN + canonical_json_bytes(subject)
    )
    return VerifiedGuestResourcePlanContext._construct(
        schemas=schemas,
        inventory_closure=inventory_closure,
        qualification_binding=qualification_binding,
        document=_freeze_json(plan),
        canonical_bytes=raw,
        canonical_bytes_sha256=canonical_bytes_sha256,
        schema_ref=GUEST_RESOURCE_PLAN_SCHEMA_REF,
        schema_digest=schema_digest,
        plan_hash=expected_plan_hash,
        authority_boundary=GUEST_RESOURCE_PLAN_AUTHORITY_BOUNDARY,
        product_authorized=GUEST_RESOURCE_PLAN_PRODUCT_AUTHORIZED,
        context_digest=context_digest,
    )


def replay_guest_resource_plan_context(
    context: VerifiedGuestResourcePlanContext,
) -> VerifiedGuestResourcePlanContext:
    """Re-verify all retained plan bytes and exact upstream bindings."""

    require_factory_verified(
        context,
        VerifiedGuestResourcePlanContext,
        code="RESOURCE_PLAN_INPUT_INVALID",
        path="resource_plan",
        message="resource plan must come from verify_guest_resource_plan",
    )
    replayed = verify_guest_resource_plan(
        context.schemas,
        context.inventory_closure,
        context.qualification_binding,
        context.canonical_bytes,
    )
    require(
        replayed == context,
        "RESOURCE_PLAN_REPLAY_MISMATCH",
        "resource_plan",
        "retained plan context does not exactly replay",
    )
    return replayed


__all__ = [
    "GUEST_RESOURCE_PLAN_AUTHORITY_BOUNDARY",
    "GUEST_RESOURCE_PLAN_CONTEXT_DOMAIN",
    "GUEST_RESOURCE_PLAN_PRODUCT_AUTHORIZED",
    "GUEST_RESOURCE_PLAN_SCHEMA_DOCUMENT_REF",
    "GUEST_RESOURCE_PLAN_SCHEMA_REF",
    "JsonDocument",
    "MAX_BAR_PLACEMENTS",
    "MAX_BRIDGE_WINDOWS",
    "MAX_GUEST_RESOURCE_PLAN_BYTES",
    "MAX_GUEST_RESOURCE_PLAN_DEPTH",
    "MAX_GUEST_RESOURCE_PLAN_NODES",
    "MAX_ROOT_WINDOWS",
    "VerifiedGuestResourcePlanContext",
    "replay_guest_resource_plan_context",
    "verify_guest_resource_plan",
]
