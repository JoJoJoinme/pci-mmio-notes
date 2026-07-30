from __future__ import annotations

from dataclasses import replace
import inspect
import json
from pathlib import Path
from unittest.mock import patch
import unittest

from jsonschema import Draft202012Validator
from referencing import Registry, Resource

from qman_directpath_core.canonical import (
    canonical_json_bytes,
    sha256_digest,
)
from qman_directpath_core.closure import (
    ClosureLimits,
    DependencyAction,
    DependencyKind,
    FactState,
    ResetMethod,
    VerifiedClosureFacts,
    VerifiedDependencyDomain,
    VerifiedDependencyEdge,
    VerifiedDeviceFacts,
    VerifiedResetContract,
    resolve_dependency_closure,
)
from qman_directpath_core.errors import DirectPathVerificationError


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
CONTRACT_DIRECTORY = REPOSITORY_ROOT / "contracts"


def digest(label: str) -> str:
    return sha256_digest(label.encode("utf-8"))


def uid(label: str) -> str:
    return (
        "urn:qman:directpath:device:v1:"
        f"{label}:sha256:{digest(label).removeprefix('sha256:')}"
    )


def canonical(values, wire):
    return tuple(sorted(values, key=lambda value: canonical_json_bytes(wire(value))))


def edge(
    target: str,
    *,
    action: DependencyAction | None = DependencyAction.LEASE_ONLY,
    state: FactState = FactState.KNOWN,
    label: str | None = None,
) -> VerifiedDependencyEdge:
    return VerifiedDependencyEdge(
        target_device_uid=target,
        action_state=state,
        required_action=action,
        provenance_digest=digest(label or f"action:{target}:{state.value}"),
    )


def domain(
    kind: DependencyKind,
    *,
    edges: tuple[VerifiedDependencyEdge, ...] = (),
    state: FactState = FactState.KNOWN,
    label: str | None = None,
) -> VerifiedDependencyDomain:
    ordered = canonical(edges, lambda item: item.to_subject())
    return VerifiedDependencyDomain(
        kind=kind,
        state=state,
        provenance_digest=digest(label or f"domain:{kind.value}:{state.value}"),
        edges=ordered,
    )


def all_domains(
    device_uid: str,
    *,
    overrides: dict[DependencyKind, VerifiedDependencyDomain] | None = None,
) -> tuple[VerifiedDependencyDomain, ...]:
    values: list[VerifiedDependencyDomain] = []
    selected = overrides or {}
    for kind in DependencyKind:
        if kind in selected:
            values.append(selected[kind])
            continue
        self_edges = (
            (edge(device_uid, label=f"{kind.value}:{device_uid}:self"),)
            if kind
            in {
                DependencyKind.IOMMU,
                DependencyKind.PHYSICAL_ISOLATION,
            }
            else ()
        )
        values.append(
            domain(
                kind,
                edges=self_edges,
                label=f"{kind.value}:{device_uid}",
            )
        )
    return canonical(values, lambda item: item.kind.value)


def reset(
    target: str,
    *,
    affected: tuple[str, ...] | None = None,
    state: FactState = FactState.KNOWN,
    supported: bool = True,
    method: ResetMethod | None = ResetMethod.PCI_FLR,
    label: str | None = None,
) -> VerifiedResetContract:
    if state is not FactState.KNOWN:
        supported = False
    if not supported:
        method = None
    selected_affected = (
        (() if state is not FactState.KNOWN else (target,))
        if affected is None
        else affected
    )
    selected_affected = canonical(selected_affected, lambda item: item)
    name = label or f"reset:{target}:{state.value}:{supported}"
    return VerifiedResetContract(
        state=state,
        supported=supported,
        selected_method=method,
        affected_device_uids=selected_affected,
        contract_digest=digest(f"{name}:contract"),
        provenance_digest=digest(f"{name}:provenance"),
    )


def device(
    device_uid: str,
    *,
    overrides: dict[DependencyKind, VerifiedDependencyDomain] | None = None,
    reset_contract: VerifiedResetContract | None = None,
) -> VerifiedDeviceFacts:
    return VerifiedDeviceFacts(
        device_uid=device_uid,
        device_record_digest=digest(f"record:{device_uid}"),
        device_generation=3,
        resource_version=11,
        domains=all_domains(device_uid, overrides=overrides),
        reset_contract=reset_contract or reset(device_uid),
    )


def facts(*devices: VerifiedDeviceFacts) -> VerifiedClosureFacts:
    ordered = canonical(devices, lambda item: item.device_uid)
    return VerifiedClosureFacts(
        snapshot_epoch=7,
        snapshot_digest=digest("snapshot"),
        inventory_verification_receipt_digest=digest("inventory-receipt"),
        inventory_verifier_identity_digest=digest("inventory-verifier"),
        request_provenance_digest=digest("request"),
        policy_provenance_digest=digest("policy"),
        devices=ordered,
    )


def bundle_validator() -> Draft202012Validator:
    registry = Registry()
    for path in CONTRACT_DIRECTORY.glob("*.schema.json"):
        schema = json.loads(path.read_text(encoding="utf-8"))
        if "$id" in schema:
            registry = registry.with_resource(
                schema["$id"],
                Resource.from_contents(schema),
            )
    schema = json.loads(
        (
            CONTRACT_DIRECTORY / "directpath-portable-hash-subjects.schema.json"
        ).read_text(encoding="utf-8")
    )
    return Draft202012Validator(
        {"$ref": f"{schema['$id']}#/$defs/dependencyBundle"},
        registry=registry,
    )


def reason_codes(result) -> set[str]:
    return {reason.code for reason in result.reasons}


class DependencyClosureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.validator = bundle_validator()
        cls.reset_validator = Draft202012Validator(
            json.loads(
                (
                    CONTRACT_DIRECTORY / "directpath-reset-contract-set.schema.json"
                ).read_text(encoding="utf-8")
            )
        )
        cls.request_validator = Draft202012Validator(
            json.loads(
                (
                    CONTRACT_DIRECTORY
                    / "directpath-dependency-closure-request.schema.json"
                ).read_text(encoding="utf-8")
            )
        )

    def test_canonical_bundle_and_reset_set_match_contract(self) -> None:
        a = uid("device-a")
        b = uid("device-b")
        iommu = domain(
            DependencyKind.IOMMU,
            edges=(
                edge(a, label="iommu-a"),
                edge(b, label="iommu-b"),
            ),
            label="iommu-domain",
        )
        physical = domain(
            DependencyKind.PHYSICAL_ISOLATION,
            edges=(
                edge(a, label="physical-a"),
                edge(b, label="physical-b"),
            ),
            label="physical-domain",
        )
        source = device(
            a,
            overrides={
                DependencyKind.IOMMU: iommu,
                DependencyKind.PHYSICAL_ISOLATION: physical,
            },
            reset_contract=reset(
                a,
                affected=(a, b),
                method=ResetMethod.VFIO_HOT_RESET,
            ),
        )
        peer = device(
            b,
            reset_contract=reset(b, supported=False),
        )

        result = resolve_dependency_closure(
            facts=facts(source, peer),
            payload_device_uids=(a,),
        )

        self.assertTrue(result.success)
        self.assertEqual(result.reasons, ())
        self.assertEqual(
            result.closure_request.payload_device_uids,
            (a,),
        )
        self.assertEqual(
            result.closure_request.request_provenance_digest,
            digest("request"),
        )
        self.assertEqual(
            result.closure_request.policy_provenance_digest,
            digest("policy"),
        )
        self.assertIsNotNone(result.bundle)
        assert result.bundle is not None
        wire = result.bundle.to_wire()
        self.validator.validate(wire)
        self.assertEqual(result.bundle.member_device_uids, (a, b))
        self.assertEqual(result.bundle.reset_affected_set, (a, b))
        self.assertEqual(
            tuple(item.target_device_uid for item in result.reset_contracts),
            (a,),
        )
        actions = {
            (item.device_uid, item.action.value)
            for item in result.bundle.dependency_actions
        }
        self.assertIn((a, "PAYLOAD"), actions)
        self.assertIn((b, "LEASE_ONLY"), actions)
        self.assertNotIn((a, "LEASE_ONLY"), actions)

        unhashed = dict(wire)
        unhashed["bundleHash"] = None
        self.assertEqual(
            result.bundle.bundle_hash,
            sha256_digest(canonical_json_bytes(unhashed)),
        )
        reset_subject = {
            "subjectType": "RESET_CONTRACT_SET",
            "schemaVersion": 1,
            "contracts": [item.to_subject() for item in result.reset_contracts],
        }
        self.assertEqual(
            result.reset_contract_set_digest,
            sha256_digest(canonical_json_bytes(reset_subject)),
        )
        self.reset_validator.validate(result.reset_contract_set_wire())
        self.assertEqual(
            result.dependency_bundle_reference().content_hash,
            result.bundle.bundle_hash,
        )
        self.assertEqual(
            result.reset_contract_reference().content_hash,
            result.reset_contract_set_digest,
        )
        self.assertTrue(result.action_provenance_sets)

    def test_all_seven_dependency_domains_are_expanded(self) -> None:
        root = uid("root")
        peers = {
            kind: uid(f"peer-{kind.value.lower().replace('_', '-')}")
            for kind in DependencyKind
        }
        overrides: dict[DependencyKind, VerifiedDependencyDomain] = {}
        for kind, peer_uid in peers.items():
            domain_edges = [edge(peer_uid, label=f"{kind.value}:peer")]
            if kind in {
                DependencyKind.IOMMU,
                DependencyKind.PHYSICAL_ISOLATION,
            }:
                domain_edges.append(edge(root, label=f"{kind.value}:self"))
            overrides[kind] = domain(
                kind,
                edges=tuple(domain_edges),
                label=f"{kind.value}:domain",
            )
        source = device(root, overrides=overrides)
        peer_devices = tuple(
            device(peer_uid, reset_contract=reset(peer_uid, supported=False))
            for peer_uid in peers.values()
        )

        result = resolve_dependency_closure(
            facts=facts(source, *peer_devices),
            payload_device_uids=(root,),
        )

        self.assertTrue(result.success)
        kinds = {item.kind for item in result.edges}
        self.assertTrue({kind.value for kind in DependencyKind}.issubset(kinds))
        self.assertIn("RESET", kinds)
        assert result.bundle is not None
        self.assertEqual(
            set(result.bundle.member_device_uids),
            {root, *peers.values()},
        )

    def test_payload_promotion_reaches_reset_fixed_point(self) -> None:
        a = uid("promote-a")
        b = uid("promote-b")
        c = uid("reset-peer-c")
        d = uid("reset-peer-d")
        functional = domain(
            DependencyKind.FUNCTIONAL,
            edges=(
                edge(
                    b,
                    action=DependencyAction.PAYLOAD,
                    label="promote-b",
                ),
            ),
            label="functional-promote",
        )
        source = device(
            a,
            overrides={DependencyKind.FUNCTIONAL: functional},
            reset_contract=reset(a, affected=(a, c), label="reset-a"),
        )
        promoted = device(
            b,
            reset_contract=reset(b, affected=(b, d), label="reset-b"),
        )
        reset_peer_c = device(
            c,
            reset_contract=reset(c, supported=False),
        )
        reset_peer_d = device(
            d,
            reset_contract=reset(d, supported=False),
        )

        result = resolve_dependency_closure(
            facts=facts(source, promoted, reset_peer_c, reset_peer_d),
            payload_device_uids=(a,),
        )

        self.assertTrue(result.success)
        self.assertEqual(
            tuple(item.target_device_uid for item in result.reset_contracts),
            (a, b),
        )
        assert result.bundle is not None
        actions = {
            item.device_uid: item.action
            for item in result.bundle.dependency_actions
            if item.action
            in {
                DependencyAction.PAYLOAD,
                DependencyAction.DETACH,
                DependencyAction.LEASE_ONLY,
            }
        }
        self.assertIs(actions[a], DependencyAction.PAYLOAD)
        self.assertIs(actions[b], DependencyAction.PAYLOAD)
        self.assertIs(actions[c], DependencyAction.LEASE_ONLY)
        self.assertIs(actions[d], DependencyAction.LEASE_ONLY)

    def test_unknown_domain_provenance_fails_closed(self) -> None:
        a = uid("unknown-domain")
        unknown = domain(
            DependencyKind.REQUESTER_ALIAS,
            state=FactState.UNKNOWN,
            label="unknown-requester-alias",
        )
        source = device(
            a,
            overrides={DependencyKind.REQUESTER_ALIAS: unknown},
        )

        result = resolve_dependency_closure(
            facts=facts(source),
            payload_device_uids=(a,),
        )

        self.assertFalse(result.success)
        self.assertIsNone(result.bundle)
        self.assertIn(
            "DEPENDENCY_PROVENANCE_UNKNOWN",
            reason_codes(result),
        )

    def test_missing_member_fails_with_closed_inventory_reason(self) -> None:
        a = uid("source-present")
        missing = uid("member-missing")
        functional = domain(
            DependencyKind.FUNCTIONAL,
            edges=(edge(missing, label="missing-member-edge"),),
            label="missing-member-domain",
        )
        source = device(
            a,
            overrides={DependencyKind.FUNCTIONAL: functional},
        )

        result = resolve_dependency_closure(
            facts=facts(source),
            payload_device_uids=(a,),
        )

        self.assertFalse(result.success)
        self.assertIn("DEVICE_NOT_IN_INVENTORY", reason_codes(result))
        self.assertNotIn(
            "DEPENDENCY_NOT_IN_INVENTORY",
            reason_codes(result),
        )

    def test_unknown_and_conflicting_actions_fail_closed(self) -> None:
        a = uid("action-source")
        b = uid("action-target")
        for state, expected in (
            (FactState.UNKNOWN, "DEPENDENCY_ACTION_UNKNOWN"),
            (FactState.CONFLICT, "DEPENDENCY_ACTION_CONFLICT"),
        ):
            with self.subTest(state=state):
                unresolved = domain(
                    DependencyKind.PLATFORM,
                    edges=(
                        edge(
                            b,
                            action=None,
                            state=state,
                            label=f"action-{state.value}",
                        ),
                    ),
                    label=f"platform-{state.value}",
                )
                result = resolve_dependency_closure(
                    facts=facts(
                        device(
                            a,
                            overrides={DependencyKind.PLATFORM: unresolved},
                        ),
                        device(
                            b,
                            reset_contract=reset(b, supported=False),
                        ),
                    ),
                    payload_device_uids=(a,),
                )
                self.assertFalse(result.success)
                self.assertIn(expected, reason_codes(result))
                retained = tuple(
                    item
                    for item in result.edges
                    if item.target_device_uid == b
                    and item.kind == DependencyKind.PLATFORM.value
                )
                self.assertEqual(len(retained), 1)
                self.assertIsNone(retained[0].required_action)
                self.assertIs(retained[0].action_state, state)

    def test_deny_if_present_is_an_action_conflict(self) -> None:
        a = uid("deny-source")
        b = uid("deny-target")
        denied = domain(
            DependencyKind.PF_VF,
            edges=(
                edge(
                    b,
                    action=DependencyAction.DENY_IF_PRESENT,
                    label="deny-rule",
                ),
            ),
            label="deny-domain",
        )
        result = resolve_dependency_closure(
            facts=facts(
                device(a, overrides={DependencyKind.PF_VF: denied}),
                device(b, reset_contract=reset(b, supported=False)),
            ),
            payload_device_uids=(a,),
        )

        self.assertFalse(result.success)
        self.assertIn(
            "DEPENDENCY_ACTION_CONFLICT",
            reason_codes(result),
        )

    def test_reset_failures_use_only_closed_capability_reasons(self) -> None:
        target = uid("reset-negative")
        cases = (
            (
                reset(target, supported=False),
                "RESET_NOT_SUPPORTED",
            ),
            (
                reset(target, state=FactState.UNKNOWN),
                "RESET_DOMAIN_UNVERIFIED",
            ),
            (
                reset(target, affected=(uid("other-reset-member"),)),
                "RESET_DOMAIN_UNVERIFIED",
            ),
        )
        for contract, expected in cases:
            with self.subTest(expected=expected):
                result = resolve_dependency_closure(
                    facts=facts(
                        device(target, reset_contract=contract),
                    ),
                    payload_device_uids=(target,),
                )
                self.assertFalse(result.success)
                self.assertIn(expected, reason_codes(result))
                self.assertIsNone(result.reset_contract_set_digest)
                self.assertEqual(result.reset_contracts, ())

    def test_cycles_are_finite_and_byte_deterministic(self) -> None:
        a = uid("cycle-a")
        b = uid("cycle-b")
        a_to_b = domain(
            DependencyKind.FUNCTIONAL,
            edges=(edge(b, label="cycle-a-b"),),
            label="cycle-functional",
        )
        b_to_a = domain(
            DependencyKind.PF_VF,
            edges=(edge(a, label="cycle-b-a"),),
            label="cycle-pf-vf",
        )
        source = facts(
            device(a, overrides={DependencyKind.FUNCTIONAL: a_to_b}),
            device(
                b,
                overrides={DependencyKind.PF_VF: b_to_a},
                reset_contract=reset(b, supported=False),
            ),
        )

        first = resolve_dependency_closure(
            facts=source,
            payload_device_uids=(a,),
        )
        second = resolve_dependency_closure(
            facts=source,
            payload_device_uids=(a,),
        )

        self.assertTrue(first.success)
        self.assertEqual(first, second)
        self.assertLess(len(first.edges), 32)
        assert first.bundle is not None
        self.assertEqual(
            first.bundle.to_wire(),
            second.bundle.to_wire(),  # type: ignore[union-attr]
        )

    def test_device_and_edge_limits_never_return_partial_bundle(self) -> None:
        a = uid("limit-a")
        b = uid("limit-b")
        dependency = domain(
            DependencyKind.PLATFORM,
            edges=(edge(b, label="limit-edge"),),
            label="limit-domain",
        )
        source = facts(
            device(a, overrides={DependencyKind.PLATFORM: dependency}),
            device(b, reset_contract=reset(b, supported=False)),
        )

        for limits in (
            ClosureLimits(max_devices=1, max_edges=32),
            ClosureLimits(max_devices=8, max_edges=1),
        ):
            with self.subTest(limits=limits):
                result = resolve_dependency_closure(
                    facts=source,
                    payload_device_uids=(a,),
                    limits=limits,
                )
                self.assertFalse(result.success)
                self.assertIsNone(result.bundle)
                self.assertIsNone(result.reset_contract_set_digest)
                self.assertIn(
                    "DEPENDENCY_CLOSURE_LIMIT",
                    reason_codes(result),
                )

        for invalid in (
            {"max_devices": 4097, "max_edges": 4096},
            {"max_devices": 256, "max_edges": 65537},
        ):
            with self.subTest(invalid=invalid):
                with self.assertRaises(DirectPathVerificationError) as raised:
                    ClosureLimits(**invalid)
                self.assertEqual(
                    raised.exception.code,
                    "CAPABILITY_INPUT_INVALID",
                )

    def test_closure_request_binds_roots_limits_and_policy(self) -> None:
        a = uid("request-root-a")
        b = uid("request-root-b")
        source = facts(device(a), device(b))
        root_a = resolve_dependency_closure(
            facts=source,
            payload_device_uids=(a,),
        )
        root_b = resolve_dependency_closure(
            facts=source,
            payload_device_uids=(b,),
        )
        relaxed = resolve_dependency_closure(
            facts=source,
            payload_device_uids=(a,),
            limits=ClosureLimits(max_devices=512, max_edges=8192),
        )
        revised_policy = replace(
            source,
            policy_provenance_digest=digest("policy-v2"),
        )
        policy_change = resolve_dependency_closure(
            facts=revised_policy,
            payload_device_uids=(a,),
        )

        self.assertTrue(root_a.success)
        self.assertTrue(root_b.success)
        self.assertTrue(relaxed.success)
        self.assertTrue(policy_change.success)
        request_digests = {
            result.closure_request.request_digest
            for result in (root_a, root_b, relaxed, policy_change)
        }
        self.assertEqual(len(request_digests), 4)
        self.assertEqual(
            root_a.closure_request.to_subject(),
            {
                "subjectType": "DEPENDENCY_CLOSURE_REQUEST",
                "schemaVersion": 1,
                "requestProvenanceDigest": digest("request"),
                "policyProvenanceDigest": digest("policy"),
                "payloadDeviceUids": [a],
                "limits": {
                    "maxDevices": 256,
                    "maxEdges": 4096,
                },
            },
        )
        self.request_validator.validate(root_a.closure_request.to_subject())

    def test_reset_set_digest_changes_with_selected_contract(self) -> None:
        target = uid("reset-digest")
        baseline = resolve_dependency_closure(
            facts=facts(
                device(
                    target,
                    reset_contract=reset(target, label="reset-v1"),
                )
            ),
            payload_device_uids=(target,),
        )
        revised = resolve_dependency_closure(
            facts=facts(
                device(
                    target,
                    reset_contract=reset(target, label="reset-v2"),
                )
            ),
            payload_device_uids=(target,),
        )

        self.assertTrue(baseline.success)
        self.assertTrue(revised.success)
        self.assertNotEqual(
            baseline.reset_contracts[0].contract_digest,
            revised.reset_contracts[0].contract_digest,
        )
        self.assertNotEqual(
            baseline.reset_contract_set_digest,
            revised.reset_contract_set_digest,
        )

        source_contract = reset(target, label="same-source-digest")
        same_digest_different_method = replace(
            source_contract,
            selected_method=ResetMethod.VFIO_DEVICE_RESET,
        )
        first_semantics = resolve_dependency_closure(
            facts=facts(device(target, reset_contract=source_contract)),
            payload_device_uids=(target,),
        )
        second_semantics = resolve_dependency_closure(
            facts=facts(
                device(
                    target,
                    reset_contract=same_digest_different_method,
                )
            ),
            payload_device_uids=(target,),
        )
        self.assertEqual(
            first_semantics.reset_contracts[0].contract_digest,
            second_semantics.reset_contracts[0].contract_digest,
        )
        self.assertNotEqual(
            first_semantics.reset_contract_set_digest,
            second_semantics.reset_contract_set_digest,
        )

    def test_domain_provenance_changes_bundle_semantics(self) -> None:
        a = uid("domain-digest-a")
        b = uid("domain-digest-b")

        def evaluate(domain_label: str):
            dependency = domain(
                DependencyKind.FUNCTIONAL,
                edges=(
                    edge(
                        b,
                        label="stable-action-provenance",
                    ),
                ),
                label=domain_label,
            )
            return resolve_dependency_closure(
                facts=facts(
                    device(
                        a,
                        overrides={DependencyKind.FUNCTIONAL: dependency},
                    ),
                    device(
                        b,
                        reset_contract=reset(b, supported=False),
                    ),
                ),
                payload_device_uids=(a,),
            )

        baseline = evaluate("functional-domain-v1")
        revised = evaluate("functional-domain-v2")

        self.assertTrue(baseline.success)
        self.assertTrue(revised.success)
        assert baseline.bundle is not None
        assert revised.bundle is not None
        self.assertNotEqual(
            baseline.bundle.bundle_hash,
            revised.bundle.bundle_hash,
        )

    def test_api_has_no_provider_callback_or_io(self) -> None:
        parameters = inspect.signature(resolve_dependency_closure).parameters
        self.assertEqual(
            tuple(parameters),
            ("facts", "payload_device_uids", "limits"),
        )
        self.assertTrue(
            all(
                parameter.kind is inspect.Parameter.KEYWORD_ONLY
                for parameter in parameters.values()
            )
        )
        target = uid("pure-api")
        with (
            patch(
                "builtins.open",
                side_effect=AssertionError("unexpected provider I/O"),
            ),
            patch(
                "pathlib.Path.open",
                side_effect=AssertionError("unexpected provider I/O"),
            ),
        ):
            result = resolve_dependency_closure(
                facts=facts(device(target)),
                payload_device_uids=(target,),
            )
        self.assertTrue(result.success)

    def test_verified_input_shape_rejects_missing_domain_kind(self) -> None:
        target = uid("missing-domain-shape")
        complete = all_domains(target)
        with self.assertRaises(DirectPathVerificationError) as raised:
            VerifiedDeviceFacts(
                device_uid=target,
                device_record_digest=digest("record"),
                device_generation=3,
                resource_version=11,
                domains=complete[:-1],
                reset_contract=reset(target),
            )
        self.assertEqual(raised.exception.code, "CAPABILITY_INPUT_INVALID")

    def test_free_busy_state_is_not_a_closure_input(self) -> None:
        fields = set(VerifiedClosureFacts.__dataclass_fields__)
        self.assertFalse(
            fields
            & {
                "available",
                "lease_owner",
                "busy",
                "health",
                "admin_enabled",
            }
        )
        target = uid("owner-independent")
        source = facts(device(target))
        first = resolve_dependency_closure(
            facts=source,
            payload_device_uids=(target,),
        )
        second = resolve_dependency_closure(
            facts=replace(source),
            payload_device_uids=(target,),
        )
        self.assertEqual(first, second)

        advanced_device = replace(
            source.devices[0],
            device_generation=4,
            resource_version=12,
        )
        advanced = replace(source, devices=(advanced_device,))
        self.assertEqual(
            source.hardware_semantic_digest,
            advanced.hardware_semantic_digest,
        )
        self.assertNotEqual(source.facts_digest, advanced.facts_digest)


if __name__ == "__main__":
    unittest.main()
