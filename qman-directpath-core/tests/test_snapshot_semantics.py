from __future__ import annotations

import copy
import unittest

from qman_directpath_core.snapshot_semantics import (
    derive_host_snapshot_semantics,
    derive_no_change_projection,
)
from tests.test_inventory import InventoryFixture


class SnapshotSemanticProjectionTests(unittest.TestCase):
    def semantics(self, fixture: InventoryFixture):
        return derive_host_snapshot_semantics(
            fixture.snapshot,
            fixture.records,
        )

    def no_change(self, fixture: InventoryFixture, semantics):
        return derive_no_change_projection(
            snapshot=fixture.snapshot,
            agent_identity=fixture.authority["agentIdentity"],
            topology_digest=semantics.topology_digest,
            provider_facts_digest=semantics.provider_facts_digest,
        )

    def test_nonsemantic_raw_and_evidence_change_is_no_change(self) -> None:
        fixture = InventoryFixture()
        before_record_hash = fixture.records[0]["deviceRecordHash"]
        before = self.semantics(fixture)
        before_device = before.device_projections[0]
        before_no_change = self.no_change(fixture, before)

        raw = bytearray.fromhex(
            fixture.records[0]["role"]["pciStructureFact"][
                "rawConfigSpaceHexOrNull"
            ]
        )
        raw[0x80] = 0x5A
        fixture.bind_pci_capture(fixture.records[0], bytes(raw))
        fixture.reseal()
        after = self.semantics(fixture)
        after_device = after.device_projections[0]
        after_no_change = self.no_change(fixture, after)

        self.assertNotEqual(
            before_record_hash,
            fixture.records[0]["deviceRecordHash"],
        )
        self.assertNotEqual(
            before_device["role"]["pciStructureFact"][
                "rawConfigSpaceSha256OrNull"
            ],
            after_device["role"]["pciStructureFact"][
                "rawConfigSpaceSha256OrNull"
            ],
        )
        self.assertEqual(
            before_device["deviceSemanticDigest"],
            after_device["deviceSemanticDigest"],
        )
        self.assertEqual(before.topology_digest, after.topology_digest)
        self.assertEqual(
            before.provider_facts_digest,
            after.provider_facts_digest,
        )
        self.assertEqual(
            before_no_change["noChangeProjectionHash"],
            after_no_change["noChangeProjectionHash"],
        )

    def test_header_layout_change_advances_semantic_chain(self) -> None:
        fixture = InventoryFixture()
        before = self.semantics(fixture)
        before_no_change = self.no_change(fixture, before)

        record = fixture.records[0]
        fixture.bind_pci_capture(
            record,
            fixture.raw_config(
                fixture.identity,
                raw_header_type=0x01,
                pcie_port_type=0x6,
            ),
        )
        record["role"]["structuralRole"] = "FABRIC_DEPENDENCY"
        record["resetContract"]["selectedMethodOrNull"] = "VFIO_HOT_RESET"
        fixture.reseal()
        after = self.semantics(fixture)
        after_no_change = self.no_change(fixture, after)

        self.assertEqual(
            "TYPE_1",
            after.device_projections[0]["role"]["pciStructureFact"][
                "headerLayout"
            ],
        )
        self.assertNotEqual(
            before.device_projections[0]["deviceSemanticDigest"],
            after.device_projections[0]["deviceSemanticDigest"],
        )
        self.assertNotEqual(before.topology_digest, after.topology_digest)
        self.assertNotEqual(
            before_no_change["noChangeProjectionHash"],
            after_no_change["noChangeProjectionHash"],
        )

    def test_provider_fact_id_rotation_is_evidence_only(self) -> None:
        fixture = InventoryFixture()
        before = self.semantics(fixture)
        before_no_change = self.no_change(fixture, before)
        record = fixture.records[0]
        record["provenance"]["providerFacts"][0]["factId"] = (
            "pci-config-rotated"
        )
        raw = bytes.fromhex(
            record["role"]["pciStructureFact"]["rawConfigSpaceHexOrNull"]
        )
        fixture.bind_pci_capture(record, raw)
        fixture.reseal()

        after = self.semantics(fixture)
        after_no_change = self.no_change(fixture, after)
        self.assertEqual(
            before.device_projections[0]["deviceSemanticDigest"],
            after.device_projections[0]["deviceSemanticDigest"],
        )
        self.assertEqual(before.topology_digest, after.topology_digest)
        self.assertEqual(
            before.provider_facts_digest,
            after.provider_facts_digest,
        )
        self.assertEqual(
            before_no_change["noChangeProjectionHash"],
            after_no_change["noChangeProjectionHash"],
        )

    def test_flr_loss_advances_semantics_even_with_another_reset_method(
        self,
    ) -> None:
        fixture = InventoryFixture()
        before = self.semantics(fixture)
        record = fixture.records[0]
        fixture.bind_pci_capture(
            record,
            fixture.raw_config(
                fixture.identity,
                flr_capable=False,
            ),
        )
        record["resetContract"]["selectedMethodOrNull"] = "VFIO_DEVICE_RESET"
        fixture.reseal()
        after = self.semantics(fixture)

        self.assertFalse(
            after.device_projections[0]["resetContract"][
                "pciFlrCapabilityFact"
            ]["functionLevelResetCapableOrNull"]
        )
        self.assertNotEqual(
            before.device_projections[0]["deviceSemanticDigest"],
            after.device_projections[0]["deviceSemanticDigest"],
        )
        self.assertNotEqual(before.topology_digest, after.topology_digest)

    def test_evidence_only_copy_changes_do_not_mutate_input(self) -> None:
        fixture = InventoryFixture()
        before = copy.deepcopy(fixture.records[0])
        self.semantics(fixture)
        self.assertEqual(before, fixture.records[0])


if __name__ == "__main__":
    unittest.main()
