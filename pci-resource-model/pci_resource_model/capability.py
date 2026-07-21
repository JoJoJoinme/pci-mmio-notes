from __future__ import annotations

import hashlib
import hmac
import json
import re
from dataclasses import dataclass, field, replace
from typing import Any, Iterable, Protocol, Sequence

from .allocator import AllocationPolicy, AllocationResult, plan_mmio
from .model import (
    AddressRange,
    DeviceInventory,
    DmaIsolationMode,
    FactEvidence,
    FunctionRole,
    HostInventory,
    IsolationProvenance,
    MemberAction,
    unique_sorted,
)


FUNCTION_RESET_ORDER = (
    "device_specific",
    "acpi",
    "flr",
    "af_flr",
    "pm",
)
BUS_RESET_METHODS = ("bus", "cxl_bus", "bridge", "slot", "hot")
TRUSTED_ISOLATION = {
    IsolationProvenance.NATIVE_ACS,
    IsolationProvenance.NATURAL_TOPOLOGY,
    IsolationProvenance.KERNEL_GROUP,
}
TRUSTED_PHYSICAL_DOMAIN_SOURCES = {
    "stock-kernel-iommu-group",
    "kernel-no-override-iommu-group",
    "kernel-acs-provenance-topology-conservative",
    "qualification-snapshot",
    "manual-audited",
}
OVERRIDE_INDEPENDENT_SOURCES = {
    "kernel-no-override-iommu-group",
    "qualification-snapshot",
    "manual-audited",
}
HASH_RE = re.compile(r"^[0-9a-f]{64}$")
DEFAULT_TRUSTED_DMA_SOURCES = (
    "linux-iommu-group",
    "qualification-snapshot",
    "reference-iommu-provider",
)
DEFAULT_TRUSTED_DEPENDENCY_SOURCES = (
    "kernel-native",
    "linux-slot-scan",
    "manual-audited",
    "pci-config-function-set",
    "qualification-snapshot",
    "vfio-reset-parent",
)
DEFAULT_TRUSTED_RESET_SOURCES = (
    "manual-audited",
    "pci-config-flr",
    "qualification-snapshot",
    "sysfs-function-reset",
    "vfio-cdev-hot-reset-info",
    "vfio-hot-reset-info",
    "vfio-legacy-hot-reset-info",
)
DEFAULT_TRUSTED_FACT_SOURCES = (
    "manual-audited",
    "qualification-snapshot",
    "signed-policy",
)


class FactEvidenceVerifier(Protocol):
    """External authenticity boundary for published capability facts."""

    @property
    def identifier(self) -> str:
        """Stable identifier included in the capability policy hash."""
        ...

    def verify(self, fact: FactEvidence) -> bool:
        """Return true only after authenticating the retained evidence object."""
        ...


@dataclass(frozen=True)
class CapabilityPolicy:
    require_interrupt_remapping: bool = True
    allow_acs_override: bool = True
    allow_bus_reset: bool = True
    allow_estimated_reset_domain: bool = False
    allow_host_driver_rebind: bool = True
    qualified_shared_attach_groups: tuple[str, ...] = ()
    trust_domain: str = "untrusted-vm"
    max_dependency_members: int = 256
    max_dependency_edges: int = 4096
    trusted_dma_sources: tuple[str, ...] = DEFAULT_TRUSTED_DMA_SOURCES
    trusted_dependency_sources: tuple[str, ...] = (
        DEFAULT_TRUSTED_DEPENDENCY_SOURCES
    )
    trusted_reset_sources: tuple[str, ...] = DEFAULT_TRUSTED_RESET_SOURCES
    trusted_fact_sources: tuple[str, ...] = DEFAULT_TRUSTED_FACT_SOURCES

    def __post_init__(self) -> None:
        for name in (
            "qualified_shared_attach_groups",
            "trusted_dma_sources",
            "trusted_dependency_sources",
            "trusted_reset_sources",
            "trusted_fact_sources",
        ):
            object.__setattr__(self, name, unique_sorted(getattr(self, name)))
        if self.max_dependency_members <= 0 or self.max_dependency_edges <= 0:
            raise ValueError("dependency member and edge limits must be positive")


@dataclass(frozen=True)
class CapabilityReason:
    code: str
    stage: str
    message: str
    devices: tuple[str, ...] = ()
    details: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "code": self.code,
            "stage": self.stage,
            "message": self.message,
            "devices": list(self.devices),
            "details": self.details,
        }


@dataclass(frozen=True)
class CapabilityResult:
    target: str
    payload_devices: tuple[str, ...]
    eligible: bool
    available: bool
    attachable: bool
    verdict: str
    required_lease: tuple[str, ...]
    reset_methods: dict[str, str]
    reasons: tuple[CapabilityReason, ...]
    warnings: tuple[CapabilityReason, ...]
    allocation: AllocationResult | None
    # Appended defaults preserve the pre-C20 public constructor.
    member_actions: dict[str, str] = field(default_factory=dict)
    bundle_hash: str = ""
    capability_hash: str = ""
    policy_hash: str = ""
    snapshot_epoch: int | None = None
    snapshot_hash: str = ""
    bundle_edges: tuple[tuple[str, str, str, str], ...] = ()
    decision_hash: str = ""

    def to_dict(
        self,
        *,
        firmware: str = "ovmf",
        host_bridge: str = "q35-pcihost",
    ) -> dict[str, Any]:
        return {
            "target": self.target,
            "payloadDevices": list(self.payload_devices),
            "passthroughCapable": self.eligible,
            "eligible": self.eligible,
            "available": self.available,
            "attachable": self.attachable,
            "verdict": self.verdict,
            "requiredLease": list(self.required_lease),
            "memberActions": dict(sorted(self.member_actions.items())),
            "selectedResetMethods": dict(sorted(self.reset_methods.items())),
            "bundleHash": self.bundle_hash,
            "capabilityHash": self.capability_hash,
            "policyHash": self.policy_hash,
            "snapshotEpoch": self.snapshot_epoch,
            "snapshotHash": self.snapshot_hash,
            "bundleEdges": [
                {
                    "kind": kind,
                    "from": source,
                    "to": target,
                    "provenance": provenance,
                }
                for kind, source, target, provenance in self.bundle_edges
            ],
            "decisionHash": self.decision_hash,
            "reasons": [reason.to_dict() for reason in self.reasons],
            "warnings": [warning.to_dict() for warning in self.warnings],
            "allocation": (
                None
                if self.allocation is None
                else self.allocation.to_dict(firmware=firmware, host_bridge=host_bridge)
            ),
        }


@dataclass(frozen=True)
class _CapabilityClosure:
    members: tuple[str, ...]
    payload: tuple[str, ...]
    actions: dict[str, MemberAction]
    reset_methods: dict[str, str]
    edges: tuple[tuple[str, str, str, str], ...]
    reasons: tuple[CapabilityReason, ...]


def _reason(
    code: str,
    stage: str,
    message: str,
    devices: Iterable[str] = (),
    **details: Any,
) -> CapabilityReason:
    return CapabilityReason(
        code=code,
        stage=stage,
        message=message,
        devices=unique_sorted(devices),
        details=details,
    )


def _select_reset(
    device: DeviceInventory,
    policy: CapabilityPolicy,
    host: HostInventory,
    fact_verifier: FactEvidenceVerifier | None,
) -> tuple[str | None, CapabilityReason | None]:
    methods = tuple(method.lower() for method in device.reset_methods)
    for method in FUNCTION_RESET_ORDER:
        if method in methods:
            error = _validate_reset_contract(
                host, device, method, policy, fact_verifier
            )
            return (None, error) if error is not None else (method, None)
    for method in BUS_RESET_METHODS:
        if method not in methods:
            continue
        if not policy.allow_bus_reset:
            return None, _reason(
                "BUS_RESET_NOT_ALLOWED",
                "eligible",
                f"{device.bdf} only has a shared reset path disabled by policy",
                (device.bdf,),
                resetMethod=method,
            )
        if not device.reset_domain:
            return None, _reason(
                "RESET_DOMAIN_UNKNOWN",
                "eligible",
                f"{device.bdf} advertises {method} reset without an affected set",
                (device.bdf,),
            )
        if (
            device.reset_domain_source in {"unknown", "sysfs-parent-topology-estimate"}
            and not policy.allow_estimated_reset_domain
        ):
            return None, _reason(
                "RESET_DOMAIN_UNVERIFIED",
                "eligible",
                f"{device.bdf} shared reset affected set is only an estimate",
                device.reset_domain,
                resetDomainSource=device.reset_domain_source,
            )
        error = _validate_reset_contract(host, device, method, policy, fact_verifier)
        return (None, error) if error is not None else (method, None)
    return None, _reason(
        "RESET_NOT_SUPPORTED",
        "eligible",
        f"{device.bdf} has no accepted function or shared reset path",
        (device.bdf,),
        resetMethods=list(methods),
    )


def _canonical_hash(value: Any) -> str:
    encoded = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _device_identity_input(device: DeviceInventory) -> dict[str, Any]:
    return {
        "bdf": device.bdf,
        "vendorId": device.vendor_id,
        "deviceId": device.device_id,
        "classCode": device.class_code,
        "headerType": device.header_type,
        "functionRole": device.function_role.value,
        "deviceGeneration": device.device_generation,
    }


def _dependency_action_subject_hash(device: DeviceInventory) -> str:
    return _canonical_hash(
        {
            "factKind": "dependency-action",
            "identity": _device_identity_input(device),
            "action": device.dependency_action.value,
        }
    )


def _qualification_subject_hash(device: DeviceInventory) -> str:
    return _canonical_hash(
        {
            "factKind": "member-action-qualification",
            "identity": _device_identity_input(device),
            "qualifiedActions": [
                action.value for action in device.qualified_actions
            ],
        }
    )


def _reset_contract_subject_hash(
    device: DeviceInventory,
    inventory_epoch: int | None,
    topology_hash: str,
) -> str:
    return _canonical_hash(
        {
            "factKind": "reset-contract",
            "identity": _device_identity_input(device),
            "resetMethods": list(device.reset_methods),
            "affectedDevices": list(device.reset_domain),
            "source": device.reset_domain_source,
            "inventoryEpoch": inventory_epoch,
            "topologyHash": topology_hash,
        }
    )


def _reference_fact(
    *,
    source: str,
    rule_id: str,
    subject_hash: str,
    inventory_epoch: int | None = None,
    topology_hash: str | None = None,
) -> FactEvidence:
    """Create deterministic E2 fixture provenance, never a production signature."""

    evidence_hash = _canonical_hash(
        {
            "issuer": "qman-reference-fixture-v1",
            "source": source,
            "ruleId": rule_id,
            "subjectHash": subject_hash,
            "inventoryEpoch": inventory_epoch,
            "topologyHash": topology_hash,
        }
    )
    return FactEvidence(
        source=source,
        rule_id=rule_id,
        subject_hash=subject_hash,
        evidence_hash=evidence_hash,
        inventory_epoch=inventory_epoch,
        topology_hash=topology_hash,
    )


@dataclass(frozen=True)
class ReferenceFixtureFactVerifier:
    """Lab-only verifier for deterministic E2 fixture envelopes.

    This proves that an envelope is bound to its serialized fields.  It is not
    a signature, MAC, trust store, or acceptable production evidence provider.
    Callers must opt in explicitly.
    """

    identifier: str = "qman-reference-fixture-verifier-v1"

    def verify(self, fact: FactEvidence) -> bool:
        expected = _canonical_hash(
            {
                "issuer": "qman-reference-fixture-v1",
                "source": fact.source,
                "ruleId": fact.rule_id,
                "subjectHash": fact.subject_hash,
                "inventoryEpoch": fact.inventory_epoch,
                "topologyHash": fact.topology_hash,
            }
        )
        return hmac.compare_digest(expected, fact.evidence_hash)


REFERENCE_FACT_VERIFIER = ReferenceFixtureFactVerifier()


def seal_reference_device_facts(
    device: DeviceInventory,
    *,
    inventory_epoch: int,
    topology_hash: str,
) -> DeviceInventory:
    """Seal deterministic fact envelopes for E2 fixtures and examples.

    The helper deliberately says ``reference``: product inventory must obtain
    these envelopes from its signed action, qualification, and reset providers.
    """

    action_fact = (
        None
        if device.dependency_action in {MemberAction.NONE, MemberAction.UNKNOWN}
        else _reference_fact(
            source="qualification-snapshot",
            rule_id="reference-dependency-action-v1",
            subject_hash=_dependency_action_subject_hash(device),
            inventory_epoch=inventory_epoch,
            topology_hash=topology_hash,
        )
    )
    qualification_fact = (
        None
        if not device.qualified_actions
        else _reference_fact(
            source="qualification-snapshot",
            rule_id="reference-member-action-qualification-v1",
            subject_hash=_qualification_subject_hash(device),
            inventory_epoch=inventory_epoch,
            topology_hash=topology_hash,
        )
    )
    reset_fact = (
        None
        if not device.reset_methods
        else _reference_fact(
            source=device.reset_domain_source,
            rule_id="reference-reset-contract-v1",
            subject_hash=_reset_contract_subject_hash(
                device, inventory_epoch, topology_hash
            ),
            inventory_epoch=inventory_epoch,
            topology_hash=topology_hash,
        )
    )
    return replace(
        device,
        dependency_action_fact=action_fact,
        qualification_fact=qualification_fact,
        reset_contract_fact=reset_fact,
    )


def _semantic_reason(reason: CapabilityReason) -> dict[str, Any]:
    """Hash stable semantics, excluding localizable explanatory prose."""

    return {
        "code": reason.code,
        "stage": reason.stage,
        "devices": list(reason.devices),
        "details": reason.details,
    }


def _snapshot_identity_reasons(host: HostInventory) -> tuple[CapabilityReason, ...]:
    missing: list[str] = []
    if host.inventory_epoch is None or host.inventory_epoch < 0:
        missing.append("inventoryEpoch")
    if not host.host_id or host.host_id.lower() == "unknown":
        missing.append("hostId")
    if not host.kernel_boot_id or host.kernel_boot_id.lower() == "unknown":
        missing.append("kernelBootId")
    if not HASH_RE.fullmatch(host.topology_hash):
        missing.append("topologyHash")
    if not missing:
        return ()
    return (
        _reason(
            "SNAPSHOT_IDENTITY_INCOMPLETE",
            "eligible",
            "capability evaluation requires a versioned immutable snapshot identity",
            detailsFields=missing,
            schemaVersion=host.schema_version,
        ),
    )


def _validate_fact_envelope(
    fact: FactEvidence | None,
    *,
    host: HostInventory,
    fact_verifier: FactEvidenceVerifier | None,
    trusted_sources: Iterable[str],
    expected_subject_hash: str,
    device: DeviceInventory,
    provenance_code: str,
    stale_code: str,
    fact_name: str,
) -> CapabilityReason | None:
    trusted = set(trusted_sources)
    verifier_id = _fact_verifier_identifier(fact_verifier)
    invalid = (
        fact is None
        or fact.source not in trusted
        or not fact.rule_id
        or not HASH_RE.fullmatch(fact.subject_hash)
        or not HASH_RE.fullmatch(fact.evidence_hash)
        or verifier_id in {"none", "invalid"}
    )
    if invalid:
        return _reason(
            provenance_code,
            "eligible",
            f"{device.bdf} has no trusted {fact_name} provenance envelope",
            (device.bdf,),
            source=None if fact is None else fact.source,
            ruleId=None if fact is None else fact.rule_id,
            verifierId=verifier_id,
        )
    assert fact is not None
    try:
        verified = (
            fact_verifier is not None
            and fact_verifier.verify(fact) is True
        )
    except Exception:
        verified = False
    if not verified:
        return _reason(
            provenance_code,
            "eligible",
            f"{device.bdf} {fact_name} evidence was not authenticated",
            (device.bdf,),
            source=fact.source,
            ruleId=fact.rule_id,
            verifierId=verifier_id,
        )
    if (
        fact.inventory_epoch != host.inventory_epoch
        or fact.topology_hash != host.topology_hash
    ):
        return _reason(
            stale_code,
            "eligible",
            f"{device.bdf} {fact_name} belongs to another snapshot",
            (device.bdf,),
            contractEpoch=fact.inventory_epoch,
            inventoryEpoch=host.inventory_epoch,
            contractTopologyHash=fact.topology_hash,
            topologyHash=host.topology_hash,
        )
    if fact.subject_hash != expected_subject_hash:
        return _reason(
            stale_code,
            "eligible",
            f"{device.bdf} {fact_name} no longer matches its exact subject",
            (device.bdf,),
            expectedSubjectHash=expected_subject_hash,
            observedSubjectHash=fact.subject_hash,
        )
    return None


def _validate_reset_contract(
    host: HostInventory,
    device: DeviceInventory,
    method: str,
    policy: CapabilityPolicy,
    fact_verifier: FactEvidenceVerifier | None,
) -> CapabilityReason | None:
    fact = device.reset_contract_fact
    error = _validate_fact_envelope(
        fact,
        host=host,
        fact_verifier=fact_verifier,
        trusted_sources=policy.trusted_reset_sources,
        expected_subject_hash=_reset_contract_subject_hash(
            device, host.inventory_epoch, host.topology_hash
        ),
        device=device,
        provenance_code="RESET_CONTRACT_PROVENANCE_UNTRUSTED",
        stale_code="RESET_CONTRACT_STALE",
        fact_name="reset contract",
    )
    if error is not None:
        return error
    assert fact is not None
    if (
        fact.source != device.reset_domain_source
        or fact.inventory_epoch != host.inventory_epoch
        or fact.topology_hash != host.topology_hash
    ):
        return _reason(
            "RESET_CONTRACT_STALE",
            "eligible",
            f"{device.bdf} reset contract belongs to another snapshot",
            (device.bdf,),
            method=method,
            contractSource=fact.source,
            resetDomainSource=device.reset_domain_source,
            contractEpoch=fact.inventory_epoch,
            inventoryEpoch=host.inventory_epoch,
            contractTopologyHash=fact.topology_hash,
            topologyHash=host.topology_hash,
        )
    return None


def _append_reason_once(
    reasons: list[CapabilityReason],
    reason: CapabilityReason,
) -> None:
    key = (
        reason.code,
        reason.stage,
        reason.devices,
        _canonical_hash(reason.details),
    )
    if any(
        (
            current.code,
            current.stage,
            current.devices,
            _canonical_hash(current.details),
        )
        == key
        for current in reasons
    ):
        return
    reasons.append(reason)


_ACTION_RANK = {
    MemberAction.NONE: 0,
    MemberAction.LOCK_ONLY: 1,
    MemberAction.VFIO_HOLD_IN_SAME_IOAS: 2,
    MemberAction.ASSIGN_TO_GUEST: 3,
}


def _merge_member_action(
    current: MemberAction,
    required: MemberAction,
) -> MemberAction | None:
    if required in {MemberAction.NONE, MemberAction.UNKNOWN}:
        return None
    if current in {MemberAction.NONE, MemberAction.UNKNOWN}:
        return required
    if current == required:
        return current
    if current == MemberAction.QUIESCE_HOST or required == MemberAction.QUIESCE_HOST:
        return None
    return current if _ACTION_RANK[current] >= _ACTION_RANK[required] else required


def _domain_edges(
    device: DeviceInventory,
) -> tuple[tuple[str, tuple[str, ...], str], ...]:
    return (
        (
            "iommu",
            device.iommu_group,
            f"{device.isolation_provenance.value}:{device.dma_isolation_source}",
        ),
        (
            "physical-isolation",
            device.physical_isolation_domain,
            device.physical_isolation_domain_source,
        ),
        (
            "multifunction",
            device.multifunction_aliases,
            device.multifunction_source,
        ),
        (
            "platform",
            device.platform_dependencies,
            device.platform_dependency_source,
        ),
    )


def _domain_provenance_error(
    device: DeviceInventory,
    kind: str,
    peers: tuple[str, ...],
    provenance: str,
    policy: CapabilityPolicy,
) -> CapabilityReason | None:
    if not peers:
        return None
    if kind == "iommu":
        trusted = (
            device.dma_isolation_mode == DmaIsolationMode.IOMMU
            and device.dma_isolation_source in policy.trusted_dma_sources
            and device.isolation_provenance
            not in {IsolationProvenance.UNKNOWN, IsolationProvenance.MISSING}
        )
    elif kind == "physical-isolation":
        trusted = device.physical_isolation_domain_source in (
            TRUSTED_PHYSICAL_DOMAIN_SOURCES
            | set(policy.trusted_dependency_sources)
        )
    else:
        trusted = provenance in policy.trusted_dependency_sources
    if trusted:
        return None
    return _reason(
        "DEPENDENCY_PROVENANCE_UNKNOWN",
        "eligible",
        f"{device.bdf} has an untrusted or incomplete {kind} dependency fact",
        (device.bdf,),
        dependencyKind=kind,
        provenance=provenance,
    )


def _resolve_capability_closure(
    host: HostInventory,
    seeds: Iterable[str],
    policy: CapabilityPolicy,
    fact_verifier: FactEvidenceVerifier | None,
) -> _CapabilityClosure:
    """Resolve owner-independent member actions and reset domains to a fixed point."""

    seed_values = unique_sorted(seeds)
    initial_payload = set(seed_values[: policy.max_dependency_members])
    members = set(initial_payload)
    actions = {bdf: MemberAction.ASSIGN_TO_GUEST for bdf in initial_payload}
    reset_methods: dict[str, str] = {}
    edges: set[tuple[str, str, str, str]] = set()
    reasons: list[CapabilityReason] = []
    limit_exceeded = False

    def reject_limit(
        *,
        candidate: str,
        attempted_member_count: int,
        attempted_edge_count: int,
    ) -> None:
        nonlocal limit_exceeded
        limit_exceeded = True
        _append_reason_once(
            reasons,
            _reason(
                "DEPENDENCY_CLOSURE_LIMIT",
                "eligible",
                "capability closure exceeded its configured member or edge limit",
                (candidate,),
                memberCount=len(members),
                edgeCount=len(edges),
                attemptedMemberCount=attempted_member_count,
                attemptedEdgeCount=attempted_edge_count,
                maxMembers=policy.max_dependency_members,
                maxEdges=policy.max_dependency_edges,
            ),
        )

    def add_edge_and_member(
        kind: str,
        source: str,
        target: str,
        provenance: str,
    ) -> bool:
        edge = (kind, source, target, provenance)
        attempted_member_count = len(members) + (target not in members)
        attempted_edge_count = len(edges) + (edge not in edges)
        if (
            attempted_member_count > policy.max_dependency_members
            or attempted_edge_count > policy.max_dependency_edges
        ):
            reject_limit(
                candidate=target,
                attempted_member_count=attempted_member_count,
                attempted_edge_count=attempted_edge_count,
            )
            return False
        members.add(target)
        edges.add(edge)
        return True

    if len(seed_values) > policy.max_dependency_members:
        reject_limit(
            candidate=seed_values[policy.max_dependency_members],
            attempted_member_count=policy.max_dependency_members + 1,
            attempted_edge_count=0,
        )

    max_iterations = (
        policy.max_dependency_edges + 4 * policy.max_dependency_members + 2
    )
    for _ in range(max_iterations if not limit_exceeded else 0):
        before = (
            tuple(sorted(members)),
            tuple(sorted((bdf, action.value) for bdf, action in actions.items())),
            tuple(sorted(reset_methods.items())),
            tuple(sorted(edges)),
        )

        for bdf in sorted(members):
            device = host.devices.get(bdf)
            if device is None:
                if bdf not in initial_payload:
                    _append_reason_once(
                        reasons,
                        _reason(
                            "DEPENDENCY_NOT_IN_INVENTORY",
                            "eligible",
                            "the capability closure references an absent device",
                            (bdf,),
                        ),
                    )
                continue

            for kind, peers, provenance in _domain_edges(device):
                provenance_error = _domain_provenance_error(
                    device, kind, peers, provenance, policy
                )
                if provenance_error is not None:
                    _append_reason_once(reasons, provenance_error)
                for peer in peers:
                    if not add_edge_and_member(kind, bdf, peer, provenance):
                        break
                    if peer == bdf:
                        continue
                    peer_device = host.devices.get(peer)
                    if peer_device is None:
                        continue
                    required = peer_device.dependency_action
                    if required in {MemberAction.NONE, MemberAction.UNKNOWN}:
                        _append_reason_once(
                            reasons,
                            _reason(
                                "DEPENDENCY_ACTION_UNKNOWN",
                                "eligible",
                                f"{peer} has no safe action for a {kind} dependency",
                                (peer,),
                                dependencyKind=kind,
                                fromDevice=bdf,
                            ),
                        )
                        continue
                    action_fact_error = _validate_fact_envelope(
                        peer_device.dependency_action_fact,
                        host=host,
                        fact_verifier=fact_verifier,
                        trusted_sources=policy.trusted_fact_sources,
                        expected_subject_hash=_dependency_action_subject_hash(
                            peer_device
                        ),
                        device=peer_device,
                        provenance_code="DEPENDENCY_ACTION_PROVENANCE_UNTRUSTED",
                        stale_code="DEPENDENCY_ACTION_STALE",
                        fact_name="dependency action",
                    )
                    if action_fact_error is not None:
                        _append_reason_once(reasons, action_fact_error)
                        continue
                    current = actions.get(peer, MemberAction.NONE)
                    merged = _merge_member_action(current, required)
                    if merged is None:
                        _append_reason_once(
                            reasons,
                            _reason(
                                "DEPENDENCY_ACTION_CONFLICT",
                                "eligible",
                                f"{peer} has incompatible dependency actions",
                                (peer,),
                                currentAction=current.value,
                                requiredAction=required.value,
                            ),
                        )
                        continue
                    actions[peer] = merged
                if limit_exceeded:
                    break
            if limit_exceeded:
                break
        if limit_exceeded:
            break

        reset_targets = sorted(
            bdf
            for bdf, action in actions.items()
            if action == MemberAction.ASSIGN_TO_GUEST
        )
        for bdf in reset_targets:
            device = host.devices.get(bdf)
            if device is None:
                continue
            method, error = _select_reset(
                device, policy, host, fact_verifier
            )
            if error is not None:
                _append_reason_once(reasons, error)
                continue
            assert method is not None
            reset_methods[bdf] = method
            affected = device.reset_domain or (bdf,)
            for peer in affected:
                if not add_edge_and_member(
                    "reset", bdf, peer, device.reset_domain_source
                ):
                    break
                if peer == bdf:
                    continue
                current = actions.get(peer, MemberAction.NONE)
                merged = _merge_member_action(current, MemberAction.LOCK_ONLY)
                if merged is None:
                    _append_reason_once(
                        reasons,
                        _reason(
                            "DEPENDENCY_ACTION_CONFLICT",
                            "eligible",
                            f"{peer} cannot be held for the selected reset contract",
                            (peer,),
                            currentAction=current.value,
                            requiredAction=MemberAction.LOCK_ONLY.value,
                        ),
                    )
                    continue
                actions[peer] = merged
            if limit_exceeded:
                break
        if limit_exceeded:
            break

        after = (
            tuple(sorted(members)),
            tuple(sorted((bdf, action.value) for bdf, action in actions.items())),
            tuple(sorted(reset_methods.items())),
            tuple(sorted(edges)),
        )
        if after == before:
            break
    else:
        if limit_exceeded:
            pass
        else:
            _append_reason_once(
                reasons,
                _reason(
                    "DEPENDENCY_CLOSURE_LIMIT",
                    "eligible",
                    "capability closure did not converge within its deterministic bound",
                    (),
                    memberCount=len(members),
                    edgeCount=len(edges),
                    maxIterations=max_iterations,
                ),
            )

    for bdf in sorted(members):
        if bdf not in host.devices or bdf in actions:
            continue
        _append_reason_once(
            reasons,
            _reason(
                "DEPENDENCY_ACTION_UNKNOWN",
                "eligible",
                f"{bdf} entered the closure without a resolved member action",
                (bdf,),
            ),
        )

    payload = tuple(
        sorted(
            bdf
            for bdf, action in actions.items()
            if action == MemberAction.ASSIGN_TO_GUEST
        )
    )
    return _CapabilityClosure(
        members=tuple(sorted(members)),
        payload=payload,
        actions=dict(sorted(actions.items())),
        reset_methods=dict(sorted(reset_methods.items())),
        edges=tuple(sorted(edges)),
        reasons=tuple(reasons),
    )


def _fact_verifier_identifier(
    fact_verifier: FactEvidenceVerifier | None,
) -> str:
    if fact_verifier is None:
        return "none"
    try:
        raw_identifier = fact_verifier.identifier
    except Exception:
        return "invalid"
    if not isinstance(raw_identifier, str):
        return "invalid"
    identifier = raw_identifier.strip()
    if not identifier or len(identifier) > 256:
        return "invalid"
    return identifier


def _policy_hash(
    policy: CapabilityPolicy,
    fact_verifier: FactEvidenceVerifier | None,
) -> str:
    return _canonical_hash(
        {
            "requireInterruptRemapping": policy.require_interrupt_remapping,
            "allowAcsOverride": policy.allow_acs_override,
            "allowBusReset": policy.allow_bus_reset,
            "allowEstimatedResetDomain": policy.allow_estimated_reset_domain,
            "allowHostDriverRebind": policy.allow_host_driver_rebind,
            "qualifiedSharedAttachGroups": list(
                policy.qualified_shared_attach_groups
            ),
            "trustDomain": policy.trust_domain,
            "maxDependencyMembers": policy.max_dependency_members,
            "maxDependencyEdges": policy.max_dependency_edges,
            "trustedDmaSources": list(policy.trusted_dma_sources),
            "trustedDependencySources": list(
                policy.trusted_dependency_sources
            ),
            "trustedResetSources": list(policy.trusted_reset_sources),
            "trustedFactSources": list(policy.trusted_fact_sources),
            "factEvidenceVerifier": _fact_verifier_identifier(fact_verifier),
        }
    )


def _capability_device_input(device: DeviceInventory) -> dict[str, Any]:
    """Owner-independent facts that can affect capable/bundle semantics."""

    return {
        "identity": _device_identity_input(device),
        "iommuGroup": list(device.iommu_group),
        "physicalIsolationDomain": list(device.physical_isolation_domain),
        "physicalIsolationDomainSource": device.physical_isolation_domain_source,
        "resetMethods": list(device.reset_methods),
        "resetDomain": list(device.reset_domain),
        "resetDomainSource": device.reset_domain_source,
        "multifunctionAliases": list(device.multifunction_aliases),
        "multifunctionSource": device.multifunction_source,
        "platformDependencies": list(device.platform_dependencies),
        "platformDependencySource": device.platform_dependency_source,
        "dependencyAction": device.dependency_action.value,
        "qualifiedActions": [action.value for action in device.qualified_actions],
        "dependencyActionFact": (
            None
            if device.dependency_action_fact is None
            else device.dependency_action_fact.to_dict()
        ),
        "qualificationFact": (
            None
            if device.qualification_fact is None
            else device.qualification_fact.to_dict()
        ),
        "resetContractFact": (
            None
            if device.reset_contract_fact is None
            else device.reset_contract_fact.to_dict()
        ),
        "isolationProvenance": device.isolation_provenance.value,
        "dmaIsolationMode": device.dma_isolation_mode.value,
        "dmaIsolationSource": device.dma_isolation_source,
        "platformReserved": device.platform_reserved,
        "errataDenied": device.errata_denied,
    }


def _capability_snapshot_hash(
    host: HostInventory,
    members: Iterable[str],
) -> str:
    return _canonical_hash(
        {
            "schemaVersion": host.schema_version,
            "hostId": host.host_id,
            "kernelBootId": host.kernel_boot_id,
            "inventoryEpoch": host.inventory_epoch,
            "topologyHash": host.topology_hash,
            "hostFacts": {
                "iommuPresent": host.iommu_present,
                "interruptRemapping": host.interrupt_remapping,
                "unsafeNoIommuModeEnabled": host.no_iommu_mode,
                "acsOverrideActive": host.acs_override_active,
            },
            "devices": {
                bdf: (
                    None
                    if bdf not in host.devices
                    else _capability_device_input(host.devices[bdf])
                )
                for bdf in sorted(set(members))
            },
        }
    )


def _bundle_hash(
    closure: _CapabilityClosure,
    policy_hash: str,
    snapshot_hash: str,
    inventory_epoch: int | None,
) -> str:
    return _canonical_hash(
        {
            "members": list(closure.members),
            "payload": list(closure.payload),
            "actions": {
                bdf: action.value for bdf, action in closure.actions.items()
            },
            "edges": [list(edge) for edge in closure.edges],
            "selectedResetMethods": closure.reset_methods,
            "inventoryEpoch": inventory_epoch,
            "snapshotHash": snapshot_hash,
            "policyHash": policy_hash,
        }
    )


def _allocation_hash_input(
    allocation: AllocationResult | None,
) -> dict[str, Any] | None:
    if allocation is None:
        return None
    return {
        "success": allocation.success,
        "allocations": [
            {
                "bar": item.bar.key,
                "address": item.address,
                "end": item.end,
                "size": item.bar.size,
                "pool": item.pool,
            }
            for item in allocation.allocations
        ],
        "issues": [
            {
                "code": issue.code,
                "bar": issue.bar,
                "details": issue.details,
            }
            for issue in allocation.issues
        ],
        "lowFree": [item.to_dict() for item in allocation.low_free],
        "highFree": [item.to_dict() for item in allocation.high_free],
        "highApertureBytes": allocation.high_aperture_bytes,
        "highApertureAlignment": allocation.high_aperture_alignment,
    }


def _decision_hash(
    *,
    host: HostInventory,
    capability_hash: str,
    required_lease: Iterable[str],
    lease_owner: str,
    low_windows: Sequence[AddressRange],
    high_windows: Sequence[AddressRange],
    reserved: Sequence[AddressRange],
    allocation_policy: AllocationPolicy,
    eligible: bool,
    available: bool,
    attachable: bool,
    verdict: str,
    reasons: Iterable[CapabilityReason],
    warnings: Iterable[CapabilityReason],
    allocation: AllocationResult | None,
) -> str:
    members = tuple(sorted(set(required_lease)))
    return _canonical_hash(
        {
            "capabilityHash": capability_hash,
            "leaseOwner": lease_owner,
            "availabilityFacts": {
                bdf: {
                    "lease": host.leases.get(bdf),
                    "hostReservation": (
                        None
                        if bdf not in host.devices
                        else host.devices[bdf].host_reservation
                    ),
                    "driver": (
                        None if bdf not in host.devices else host.devices[bdf].driver
                    ),
                    "rmrrConflict": (
                        None
                        if bdf not in host.devices
                        else host.devices[bdf].rmrr_conflict
                    ),
                    "exclusiveAttachGroup": (
                        None
                        if bdf not in host.devices
                        else host.devices[bdf].exclusive_attach_group
                    ),
                    "ownerActivationGroup": (
                        None
                        if bdf not in host.devices
                        else host.devices[bdf].owner_activation_group
                    ),
                    "bars": (
                        None
                        if bdf not in host.devices
                        else [bar.to_dict() for bar in host.devices[bdf].bars]
                    ),
                }
                for bdf in members
            },
            "mmio": {
                "lowWindows": [item.to_dict() for item in low_windows],
                "highWindows": [item.to_dict() for item in high_windows],
                "reserved": [item.to_dict() for item in reserved],
                "allocationPolicy": {
                    "prefer64bitHigh": allocation_policy.prefer_64bit_high,
                    "force64bitHigh": allocation_policy.force_64bit_high,
                    "topDownHigh": allocation_policy.top_down_high,
                    "highApertureGranularity": (
                        allocation_policy.high_aperture_granularity
                    ),
                    "powerOfTwoHighAperture": (
                        allocation_policy.power_of_two_high_aperture
                    ),
                },
            },
            "eligible": eligible,
            "available": available,
            "attachable": attachable,
            "verdict": verdict,
            "reasons": [_semantic_reason(reason) for reason in reasons],
            "warnings": [_semantic_reason(warning) for warning in warnings],
            "allocation": _allocation_hash_input(allocation),
        }
    )


def _check_isolation(
    host: HostInventory,
    device: DeviceInventory,
    policy: CapabilityPolicy,
) -> tuple[CapabilityReason | None, CapabilityReason | None]:
    provenance = device.isolation_provenance
    if (
        host.acs_override_active
        and provenance == IsolationProvenance.KERNEL_GROUP
        and device.physical_isolation_domain_source not in OVERRIDE_INDEPENDENT_SOURCES
    ):
        provenance = IsolationProvenance.ACS_OVERRIDE

    if provenance in TRUSTED_ISOLATION:
        if not device.iommu_group:
            return (
                _reason(
                    "IOMMU_GROUP_MISSING",
                    "eligible",
                    f"{device.bdf} has no kernel IOMMU group",
                    (device.bdf,),
                ),
                None,
            )
        return None, None

    if provenance == IsolationProvenance.ACS_OVERRIDE:
        if not policy.allow_acs_override:
            return (
                _reason(
                    "ACS_OVERRIDE_NOT_ALLOWED",
                    "eligible",
                    f"{device.bdf} isolation depends on an ACS override",
                    (device.bdf,),
                    trustDomain=policy.trust_domain,
                ),
                None,
            )
        if not device.physical_isolation_domain:
            return (
                _reason(
                    "PHYSICAL_ISOLATION_DOMAIN_UNKNOWN",
                    "eligible",
                    f"{device.bdf} needs an override-independent physical domain",
                    (device.bdf,),
                ),
                None,
            )
        if device.bdf not in device.physical_isolation_domain:
            return (
                _reason(
                    "PHYSICAL_ISOLATION_DOMAIN_INVALID",
                    "eligible",
                    f"{device.bdf} is absent from its physical isolation domain",
                    device.physical_isolation_domain,
                    physicalDomainSource=device.physical_isolation_domain_source,
                ),
                None,
            )
        if (
            device.physical_isolation_domain_source
            not in TRUSTED_PHYSICAL_DOMAIN_SOURCES
        ):
            return (
                _reason(
                    "PHYSICAL_ISOLATION_DOMAIN_UNTRUSTED",
                    "eligible",
                    f"{device.bdf} physical isolation domain has no trusted provenance",
                    device.physical_isolation_domain,
                    physicalDomainSource=device.physical_isolation_domain_source,
                ),
                None,
            )
        return (
            None,
            _reason(
                "ACS_OVERRIDE_REQUIRES_WHOLE_PHYSICAL_DOMAIN",
                "eligible",
                f"{device.bdf} is conditional on leasing its complete physical domain",
                device.physical_isolation_domain,
                trustDomain=policy.trust_domain,
                physicalDomainSource=device.physical_isolation_domain_source,
            ),
        )

    code = (
        "ACS_OR_TOPOLOGY_ISOLATION_MISSING"
        if provenance == IsolationProvenance.MISSING
        else "ISOLATION_PROVENANCE_UNKNOWN"
    )
    return (
        _reason(
            code,
            "eligible",
            f"{device.bdf} lacks a trustworthy DMA isolation provenance",
            (device.bdf,),
            isolationProvenance=provenance.value,
        ),
        None,
    )


def evaluate_passthrough(
    host: HostInventory,
    target_bdf: str,
    *,
    low_windows: Sequence[AddressRange],
    high_windows: Sequence[AddressRange] = (),
    reserved: Sequence[AddressRange] = (),
    payload_devices: Sequence[str] | None = None,
    lease_owner: str = "candidate-vm",
    policy: CapabilityPolicy | None = None,
    allocation_policy: AllocationPolicy | None = None,
    fact_verifier: FactEvidenceVerifier | None = None,
) -> CapabilityResult:
    """Evaluate static eligibility, current availability, and VM attachability."""

    policy = policy or CapabilityPolicy()
    resolved_allocation_policy = allocation_policy or AllocationPolicy()
    target = target_bdf.lower()
    requested_payload = unique_sorted((target,) + tuple(payload_devices or ()))
    reasons: list[CapabilityReason] = []
    warnings: list[CapabilityReason] = []
    reasons.extend(_snapshot_identity_reasons(host))

    missing_payload = [bdf for bdf in requested_payload if bdf not in host.devices]
    if missing_payload:
        reasons.append(
            _reason(
                "DEVICE_NOT_IN_INVENTORY",
                "eligible",
                "one or more payload devices are absent from inventory",
                missing_payload,
            )
        )

    closure = _resolve_capability_closure(
        host, requested_payload, policy, fact_verifier
    )
    reasons.extend(closure.reasons)
    payload = closure.payload
    required_lease = closure.members
    selected_resets = closure.reset_methods
    resolved_policy_hash = _policy_hash(policy, fact_verifier)
    resolved_snapshot_hash = _capability_snapshot_hash(host, required_lease)
    resolved_bundle_hash = _bundle_hash(
        closure,
        resolved_policy_hash,
        resolved_snapshot_hash,
        host.inventory_epoch,
    )

    if host.no_iommu_mode:
        warnings.append(
            _reason(
                "HOST_UNSAFE_NOIOMMU_MODE_ENABLED",
                "eligible",
                "host permits unsafe VFIO for a separate trusted host dataplane; "
                "guest devices are still checked individually",
            )
        )
    if not host.iommu_present:
        reasons.append(
            _reason(
                "HOST_IOMMU_MISSING",
                "eligible",
                "host IOMMU is not available",
                payload,
            )
        )

    if policy.require_interrupt_remapping:
        if host.interrupt_remapping is False:
            reasons.append(
                _reason(
                    "INTERRUPT_REMAP_MISSING",
                    "eligible",
                    "interrupt remapping is disabled",
                    payload,
                )
            )
        elif host.interrupt_remapping is None:
            reasons.append(
                _reason(
                    "INTERRUPT_REMAP_UNKNOWN",
                    "eligible",
                    "interrupt remapping state is unknown",
                    payload,
                )
            )

    for bdf in payload:
        device = host.devices.get(bdf)
        if device is None:
            continue
        if device.header_type != 0 or device.function_role == FunctionRole.FABRIC:
            reasons.append(
                _reason(
                    "STRUCTURAL_FABRIC_NODE",
                    "eligible",
                    f"{bdf} is a Type-1 or topology-bearing fabric function",
                    (bdf,),
                    headerType=device.header_type,
                    functionRole=device.function_role.value,
                )
            )
        elif device.function_role not in {
            FunctionRole.ENDPOINT,
            FunctionRole.VIRTUAL_FUNCTION,
        }:
            reasons.append(
                _reason(
                    "FUNCTION_ROLE_NOT_ASSIGNABLE",
                    "eligible",
                    f"{bdf} is not classified as an assignable payload",
                    (bdf,),
                    functionRole=device.function_role.value,
                )
            )
        if device.platform_reserved:
            reasons.append(
                _reason(
                    "PLATFORM_RESERVED",
                    "eligible",
                    f"{bdf} is retained by the host platform",
                    (bdf,),
                )
            )
        if device.dma_isolation_mode == DmaIsolationMode.NO_IOMMU:
            reasons.append(
                _reason(
                    "DEVICE_NO_IOMMU_DMA_ISOLATION",
                    "eligible",
                    f"{bdf} would DMA without an IOMMU translation domain",
                    (bdf,),
                    dmaIsolationSource=device.dma_isolation_source,
                )
            )
        elif device.dma_isolation_mode != DmaIsolationMode.IOMMU:
            reasons.append(
                _reason(
                    "DEVICE_IOMMU_BACKING_UNKNOWN",
                    "eligible",
                    f"{bdf} has no proven IOMMU-backed DMA path",
                    (bdf,),
                    dmaIsolationSource=device.dma_isolation_source,
                )
            )
        if device.errata_denied:
            reasons.append(
                _reason(
                    "DEVICE_ERRATA_DENY",
                    "eligible",
                    f"{bdf} matches an audited device erratum deny entry",
                    (bdf,),
                    vendorId=device.vendor_id,
                    deviceId=device.device_id,
                )
            )

        isolation_error, isolation_warning = _check_isolation(host, device, policy)
        if isolation_error:
            reasons.append(isolation_error)
        if isolation_warning:
            warnings.append(isolation_warning)

    for bdf, action in closure.actions.items():
        device = host.devices.get(bdf)
        if device is None or action in {MemberAction.NONE, MemberAction.UNKNOWN}:
            continue
        if action not in device.qualified_actions:
            reasons.append(
                _reason(
                    "QUALIFICATION_MISSING",
                    "eligible",
                    f"{bdf} is not qualified for its exact bundle action",
                    (bdf,),
                    requiredAction=action.value,
                )
            )
            continue
        qualification_error = _validate_fact_envelope(
            device.qualification_fact,
            host=host,
            fact_verifier=fact_verifier,
            trusted_sources=policy.trusted_fact_sources,
            expected_subject_hash=_qualification_subject_hash(device),
            device=device,
            provenance_code="QUALIFICATION_PROVENANCE_UNTRUSTED",
            stale_code="QUALIFICATION_STALE",
            fact_name="member-action qualification",
        )
        if qualification_error is not None:
            reasons.append(qualification_error)

    eligibility_reasons = [reason for reason in reasons if reason.stage == "eligible"]
    eligible = not eligibility_reasons
    resolved_capability_hash = _canonical_hash(
        {
            "target": target,
            "payload": list(payload),
            "passthroughCapable": eligible,
            "bundleHash": resolved_bundle_hash,
            "policyHash": resolved_policy_hash,
            "eligibleReasons": [
                _semantic_reason(reason) for reason in eligibility_reasons
            ],
            "eligibleWarnings": [
                _semantic_reason(warning)
                for warning in warnings
                if warning.stage == "eligible"
            ],
        }
    )

    if eligible:
        host_reserved = {
            bdf: device.host_reservation
            for bdf in required_lease
            if (device := host.devices.get(bdf)) is not None and device.host_reservation
        }
        if host_reserved:
            reasons.append(
                _reason(
                    "HOST_DEVICE_RESERVED",
                    "available",
                    "one or more dependency functions are reserved for a host workload",
                    host_reserved,
                    reservations=host_reserved,
                )
            )
        busy = {
            bdf: owner
            for bdf in required_lease
            if (owner := host.leases.get(bdf)) not in (None, "", "free", lease_owner)
        }
        if busy:
            reasons.append(
                _reason(
                    "DEPENDENCY_BUSY",
                    "available",
                    "one or more dependency functions are leased by another owner",
                    busy,
                    owners=busy,
                )
            )

        for bdf in payload:
            device = host.devices[bdf]
            if device.driver and device.driver != "vfio-pci":
                if policy.allow_host_driver_rebind:
                    warnings.append(
                        _reason(
                            "HOST_DRIVER_REBIND_REQUIRED",
                            "available",
                            f"{bdf} must be detached from {device.driver}",
                            (bdf,),
                            driver=device.driver,
                        )
                    )
                else:
                    reasons.append(
                        _reason(
                            "HOST_DRIVER_BOUND",
                            "available",
                            f"{bdf} is still bound to {device.driver}",
                            (bdf,),
                            driver=device.driver,
                        )
                    )

    available = eligible and not any(reason.stage == "available" for reason in reasons)
    allocation: AllocationResult | None = None

    if available:
        missing_attach_groups = [
            bdf for bdf in payload if not host.devices[bdf].exclusive_attach_group
        ]
        if missing_attach_groups:
            reasons.append(
                _reason(
                    "EXCLUSIVE_ATTACH_GROUP_UNKNOWN",
                    "attachable",
                    "exclusive attach group is not proven",
                    missing_attach_groups,
                )
            )

        attach_groups: dict[str, list[str]] = {}
        for bdf in payload:
            group = host.devices[bdf].exclusive_attach_group
            if group:
                attach_groups.setdefault(group, []).append(bdf)
        collisions = {
            group: tuple(sorted(devices))
            for group, devices in attach_groups.items()
            if len(devices) > 1
        }
        qualified_groups = {
            group.lower() for group in policy.qualified_shared_attach_groups
        }
        unqualified_collisions = {
            group: devices
            for group, devices in collisions.items()
            if group not in qualified_groups
        }
        if unqualified_collisions:
            reasons.append(
                _reason(
                    "EXCLUSIVE_ATTACH_GROUP_COLLISION",
                    "attachable",
                    "multiple payload devices require the same exclusive attach resource",
                    (
                        bdf
                        for devices in unqualified_collisions.values()
                        for bdf in devices
                    ),
                    groups=unqualified_collisions,
                )
            )

        rmrr_devices = [bdf for bdf in payload if host.devices[bdf].rmrr_conflict]
        if rmrr_devices:
            reasons.append(
                _reason(
                    "RMRR_CONFLICT",
                    "attachable",
                    "reserved DMA region conflicts with the guest memory layout",
                    rmrr_devices,
                )
            )
        else:
            bars = tuple(bar for bdf in payload for bar in host.devices[bdf].bars)
            allocation = plan_mmio(
                bars,
                low_windows=low_windows,
                high_windows=high_windows,
                reserved=reserved,
                policy=resolved_allocation_policy,
            )
            if not allocation.success:
                issue = allocation.issues[0]
                reasons.append(
                    _reason(
                        issue.code,
                        "attachable",
                        issue.message,
                        payload,
                        bar=issue.bar,
                        **issue.details,
                    )
                )

    attachable = available and not any(
        reason.stage == "attachable" for reason in reasons
    )
    if attachable and any(
        warning.code == "ACS_OVERRIDE_REQUIRES_WHOLE_PHYSICAL_DOMAIN"
        for warning in warnings
    ):
        verdict = "conditional"
    elif attachable:
        verdict = "true"
    else:
        verdict = "false"

    resolved_decision_hash = _decision_hash(
        host=host,
        capability_hash=resolved_capability_hash,
        required_lease=required_lease,
        lease_owner=lease_owner,
        low_windows=low_windows,
        high_windows=high_windows,
        reserved=reserved,
        allocation_policy=resolved_allocation_policy,
        eligible=eligible,
        available=available,
        attachable=attachable,
        verdict=verdict,
        reasons=reasons,
        warnings=warnings,
        allocation=allocation,
    )

    return CapabilityResult(
        target=target,
        payload_devices=payload,
        eligible=eligible,
        available=available,
        attachable=attachable,
        verdict=verdict,
        required_lease=required_lease,
        member_actions={
            bdf: action.value for bdf, action in closure.actions.items()
        },
        reset_methods=selected_resets,
        bundle_hash=resolved_bundle_hash,
        capability_hash=resolved_capability_hash,
        policy_hash=resolved_policy_hash,
        snapshot_epoch=host.inventory_epoch,
        snapshot_hash=resolved_snapshot_hash,
        bundle_edges=closure.edges,
        decision_hash=resolved_decision_hash,
        reasons=tuple(reasons),
        warnings=tuple(warnings),
        allocation=allocation,
    )
