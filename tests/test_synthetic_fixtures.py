from __future__ import annotations

import hashlib
import json
import re
import unittest
import uuid
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
MEMORY_PATH = ROOT / "fixtures" / "synthetic" / "memory_records.json"
APPROVAL_PATH = ROOT / "fixtures" / "synthetic" / "derivative_approvals.json"
SOURCE_PATH = ROOT / "fixtures" / "synthetic" / "public_sources.json"
SCENARIO_PATH = ROOT / "fixtures" / "synthetic" / "demo_scenarios.json"

REQUIRED_STATES = {
    "active",
    "revoked",
    "quarantined",
    "forgotten",
    "proposed",
}
REQUIRED_ROOMS = {
    "clinical-restricted",
    "research-confidential",
    "external-approved",
}
FORBIDDEN_PATTERNS = {
    "private key": re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    "AWS access key": re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    "database URL": re.compile(r"\b(?:postgres(?:ql)?|cockroachdb)://", re.I),
    "assigned secret": re.compile(
        r"\b(?:api[_-]?key|password|secret|token)\s*[:=]\s*[^\s,]+", re.I
    ),
    "US SSN": re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
}
EMAIL_PATTERN = re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.I)
PHONE_PATTERN = re.compile(r"\+1 202-555-\d{4}\b")


def load_json(path: Path) -> dict[str, Any]:
    with path.open(encoding="utf-8") as fixture_file:
        return json.load(fixture_file)


def assert_uuid(test: unittest.TestCase, value: str) -> None:
    parsed = uuid.UUID(value)
    test.assertEqual(str(parsed), value)


def walk_keys(value: Any) -> list[str]:
    if isinstance(value, dict):
        keys = list(value)
        for nested in value.values():
            keys.extend(walk_keys(nested))
        return keys
    if isinstance(value, list):
        keys: list[str] = []
        for nested in value:
            keys.extend(walk_keys(nested))
        return keys
    return []


class SyntheticFixtureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.memory_fixture = load_json(MEMORY_PATH)
        cls.approval_fixture = load_json(APPROVAL_PATH)
        cls.source_fixture = load_json(SOURCE_PATH)
        cls.scenario_fixture = load_json(SCENARIO_PATH)
        cls.records = cls.memory_fixture["records"]
        cls.approvals = cls.approval_fixture["approvals"]
        cls.sources = cls.source_fixture["sources"]
        cls.personas = cls.scenario_fixture["personas"]
        cls.journeys = cls.scenario_fixture["journeys"]
        cls.by_id = {record["memory_id"]: record for record in cls.records}
        cls.by_role = {record["fixture_role"]: record for record in cls.records}

    def test_fixture_and_every_row_are_explicitly_synthetic(self) -> None:
        self.assertIs(self.memory_fixture["synthetic_data"], True)
        self.assertIs(self.approval_fixture["synthetic_data"], True)
        self.assertIs(self.source_fixture["synthetic_data"], True)
        self.assertIs(self.scenario_fixture["synthetic_data"], True)
        self.assertGreaterEqual(len(self.records), 30)
        for record in self.records:
            self.assertIs(record["synthetic_data"], True)
            self.assertIn("Synthetic", record["tenant_name"])
            if record["content"] is not None:
                self.assertTrue(record["content"].startswith("SYNTHETIC DATA: "))
        for approval in self.approvals:
            self.assertIs(approval["synthetic_data"], True)
            self.assertTrue(
                approval["exact_derivative_text"].startswith("SYNTHETIC DATA: ")
            )
        self.assertTrue(all(persona["synthetic_data"] for persona in self.personas))
        self.assertTrue(all(journey["synthetic_data"] for journey in self.journeys))

    def test_identifiers_are_unique_canonical_uuids(self) -> None:
        memory_ids = [record["memory_id"] for record in self.records]
        self.assertEqual(len(memory_ids), len(set(memory_ids)))
        approval_ids = [approval["approval_id"] for approval in self.approvals]
        self.assertEqual(len(approval_ids), len(set(approval_ids)))
        reviewer_ids = {
            approval["reviewer"]["reviewer_id"] for approval in self.approvals
        }
        self.assertEqual(len(reviewer_ids), 1)

        uuid_values = set(memory_ids)
        uuid_values.update(record["tenant_id"] for record in self.records)
        uuid_values.update(record["program_id"] for record in self.records)
        for approval in self.approvals:
            uuid_values.update(
                {
                    approval["approval_id"],
                    approval["tenant_id"],
                    approval["program_id"],
                    approval["source_memory_id"],
                    approval["derivative_memory_id"],
                    approval["reviewer"]["reviewer_id"],
                }
            )
        for value in uuid_values:
            with self.subTest(value=value):
                assert_uuid(self, value)

    def test_lifecycle_content_and_hash_invariants(self) -> None:
        self.assertEqual({record["state"] for record in self.records}, REQUIRED_STATES)
        self.assertEqual({record["room"] for record in self.records}, REQUIRED_ROOMS)

        for record in self.records:
            with self.subTest(memory_id=record["memory_id"]):
                if record["state"] == "forgotten":
                    self.assertIsNone(record["content"])
                    self.assertIsNone(record["content_sha256"])
                    self.assertIn("forgotten_at", record)
                else:
                    self.assertIsInstance(record["content"], str)
                    actual_hash = hashlib.sha256(record["content"].encode()).hexdigest()
                    self.assertEqual(record["content_sha256"], actual_hash)

        self.assertIn("revoked_at", self.by_role["revoked_source"])
        self.assertIn("quarantined_at", self.by_role["quarantined_derivative"])
        self.assertEqual(self.by_role["expired_record"]["state"], "active")
        self.assertEqual(self.by_role["expired_record"]["lifecycle_case"], "expired")
        self.assertLess(
            self.by_role["expired_record"]["expires_at"],
            "2026-08-15T00:00:00Z",
        )

    def test_safe_derivative_relationships_and_exact_approvals(self) -> None:
        self.assertEqual(len(self.approvals), 3)
        self.assertEqual(
            {approval["derivative_class"] for approval in self.approvals},
            {"program_overview", "cohort_status", "stability_status"},
        )
        for approval in self.approvals:
            with self.subTest(approval_id=approval["approval_id"]):
                source = self.by_id[approval["source_memory_id"]]
                derivative = self.by_id[approval["derivative_memory_id"]]

                self.assertIn(
                    source["room"], {"research-confidential", "clinical-restricted"}
                )
                self.assertEqual(source["state"], "active")
                self.assertEqual(derivative["room"], "external-approved")
                self.assertEqual(derivative["state"], "active")
                self.assertEqual(derivative["source_memory_id"], source["memory_id"])
                self.assertEqual(
                    derivative["content"], approval["exact_derivative_text"]
                )
                self.assertEqual(
                    source["content_sha256"], approval["source_content_sha256"]
                )
                self.assertEqual(
                    derivative["content_sha256"],
                    approval["derivative_content_sha256"],
                )
                self.assertEqual(
                    derivative["purpose_scopes"], approval["purpose_scopes"]
                )
                self.assertEqual(
                    derivative["audience_scopes"], approval["audience_scopes"]
                )
                self.assertEqual(source["tenant_id"], approval["tenant_id"])
                self.assertEqual(source["program_id"], approval["program_id"])
                self.assertEqual(derivative["tenant_id"], approval["tenant_id"])
                self.assertEqual(derivative["program_id"], approval["program_id"])
                self.assertEqual(approval["reviewer"]["reviewer_type"], "human")
                self.assertTrue(
                    approval["reviewer"]["reviewer_handle"].startswith("human-")
                )
                self.assertEqual(
                    approval["audience_display_name"], "Argent Bridge Biologics"
                )
                self.assertEqual(approval["expires_at"], "2027-02-15T16:00:00Z")

    def test_dependent_quarantine_tracks_revoked_source(self) -> None:
        source = self.by_role["revoked_source"]
        derivative = self.by_role["quarantined_derivative"]
        self.assertEqual(source["state"], "revoked")
        self.assertEqual(derivative["state"], "quarantined")
        self.assertEqual(derivative["source_memory_id"], source["memory_id"])
        self.assertEqual(derivative["tenant_id"], source["tenant_id"])
        self.assertEqual(derivative["program_id"], source["program_id"])

    def test_tenant_and_program_isolation_decoys_are_present(self) -> None:
        tenant_programs: dict[str, set[str]] = {}
        for record in self.records:
            tenant_programs.setdefault(record["tenant_id"], set()).add(
                record["program_id"]
            )
        self.assertGreaterEqual(len(tenant_programs), 2)
        self.assertTrue(
            any(len(programs) >= 2 for programs in tenant_programs.values())
        )

        source = self.by_role["restricted_source"]
        wrong_program = self.by_role["wrong_program_decoy"]
        cross_tenant = self.by_role["cross_tenant_semantic_decoy"]
        safe_derivative = self.by_role["safe_derivative"]
        self.assertEqual(source["tenant_id"], wrong_program["tenant_id"])
        self.assertNotEqual(source["program_id"], wrong_program["program_id"])
        self.assertNotEqual(source["tenant_id"], cross_tenant["tenant_id"])
        self.assertIn(
            "Argent Bridge workstreams remain on schedule", safe_derivative["content"]
        )
        self.assertIn("Week 8 stability review", cross_tenant["content"])

    def test_expanded_corpus_has_editorial_provenance_and_control_cases(self) -> None:
        source_ids = {source["source_id"] for source in self.sources}
        self.assertEqual(
            {record["workstream"] for record in self.records},
            {"program", "formulation", "clinical", "partner"},
        )
        for record in self.records:
            with self.subTest(memory_id=record["memory_id"]):
                self.assertIsInstance(record["display_title"], str)
                self.assertTrue(record["display_title"].strip())
                self.assertIsInstance(record["record_type"], str)
                self.assertTrue(record["record_type"].strip())
                self.assertIsInstance(record["realism_note"], str)
                note = record["realism_note"].casefold()
                self.assertTrue(
                    "fictional" in note
                    or "no real" in note
                    or "not a real" in note
                    or "no public clinical source" in note
                )
                self.assertFalse(set(record["source_basis_ids"]) - source_ids)
                if not record["source_basis_ids"]:
                    self.assertIn("no public clinical source", record["realism_note"])

        self.assertEqual(self.by_role["program_pending_milestone"]["state"], "proposed")
        self.assertEqual(self.by_role["formulation_pending_b9"]["state"], "proposed")
        self.assertEqual(
            self.by_role["clinical_pending_safety_summary"]["state"], "proposed"
        )
        self.assertEqual(
            self.by_role["prompt_injection_as_data"]["state"], "quarantined"
        )
        self.assertIn(
            "ignore policy",
            self.by_role["prompt_injection_as_data"]["content"].casefold(),
        )
        self.assertEqual(
            self.by_role["wrong_audience_decoy"]["audience_scopes"],
            ["partner-other-synthetic"],
        )
        self.assertEqual(self.by_role["wrong_audience_decoy"]["state"], "proposed")
        self.assertIsNone(self.by_role["wrong_audience_decoy"]["source_memory_id"])
        self.assertIn(
            "SYN-HX17-004", self.by_role["synthetic_detector_candidate"]["content"]
        )

    def test_fixed_training_world_and_reserved_contacts_are_coherent(self) -> None:
        world = self.scenario_fixture["training_world"]
        self.assertEqual(world["review_anchor"], "2026-08-15T18:00:00Z")
        self.assertEqual(len(world["organizations"]), 4)
        self.assertEqual(len(world["people"]), 8)
        self.assertEqual(world["program"]["enrollment"], "6 actual / 24 anticipated")

        serialized = json.dumps(
            {
                "memories": self.memory_fixture,
                "training_world": world,
            },
            sort_keys=True,
        )
        self.assertIn("HC-HX17-101", serialized)
        self.assertIn("SYN-HX17-F3-L2406", serialized)
        self.assertIn("Harborlight Research Center", serialized)
        self.assertIn("Maya Ellison", serialized)
        self.assertIn("2026-08-15", serialized)

        emails = EMAIL_PATTERN.findall(serialized)
        phones = PHONE_PATTERN.findall(serialized)
        self.assertTrue(emails)
        self.assertTrue(phones)
        self.assertTrue(all(email.casefold().endswith(".test") for email in emails))
        self.assertTrue(all("555-01" in phone for phone in phones))

        for approval in self.approvals:
            text = approval["exact_derivative_text"]
            self.assertIsNone(EMAIL_PATTERN.search(text))
            self.assertIsNone(PHONE_PATTERN.search(text))
            self.assertNotIn("Maya Ellison", text)

    def test_public_sources_are_authoritative_links_with_bounded_use(self) -> None:
        expected_urls = {
            "https://www.fda.gov/regulatory-information/search-fda-guidance-documents/m11-clinical-electronic-structured-harmonised-protocol",
            "https://clinicaltrials.gov/policy/protocol-definitions",
            "https://www.fda.gov/regulatory-information/search-fda-guidance-documents/q5c-quality-biotechnological-products-stability-testing-biotechnologicalbiological-products",
            "https://www.grants.nih.gov/policy-and-compliance/policy-topics/clinical-trials/protocol-template",
        }
        self.assertEqual(len(self.sources), 4)
        self.assertEqual({source["url"] for source in self.sources}, expected_urls)
        self.assertEqual(
            len({source["source_id"] for source in self.sources}), len(self.sources)
        )
        for source in self.sources:
            self.assertIs(source["generic_structure_only"], True)
            self.assertIs(source["endorsement"], False)
            self.assertTrue(source["used_for"])
        boundary = self.source_fixture["use_boundary"].casefold()
        self.assertIn("generic structure", boundary)
        self.assertIn("do not endorse", boundary)

    def test_persona_first_journeys_cover_all_outcomes_without_exposing_them(
        self,
    ) -> None:
        outcomes = {"ALLOW", "MODIFY", "STEP_UP", "DEFER", "DENY"}
        persona_ids = {persona["persona_id"] for persona in self.personas}
        source_ids = {source["source_id"] for source in self.sources}
        approval_ids = {approval["approval_id"] for approval in self.approvals}
        approvals_by_id = {
            approval["approval_id"]: approval for approval in self.approvals
        }
        approved_derivative_ids = {
            approval["derivative_memory_id"] for approval in self.approvals
        }
        self.assertEqual(
            persona_ids,
            {
                "program_lead",
                "formulation_scientist",
                "clinical_operations_lead",
                "authorized_external_partner",
            },
        )
        self.assertEqual(len(self.journeys), 20)
        self.assertEqual(len({journey["journey_id"] for journey in self.journeys}), 20)
        for persona in self.personas:
            journeys = [
                journey
                for journey in self.journeys
                if journey["persona_id"] == persona["persona_id"]
            ]
            self.assertEqual(len(journeys), 5)
            self.assertEqual(
                {journey["expected_outcome"] for journey in journeys}, outcomes
            )
            self.assertIn(
                persona["default_journey_id"],
                {journey["journey_id"] for journey in journeys},
            )

        for journey in self.journeys:
            with self.subTest(journey_id=journey["journey_id"]):
                self.assertIn(journey["persona_id"], persona_ids)
                self.assertIs(journey["expose_expected_outcome_before_run"], False)
                self.assertNotIn(journey["expected_outcome"], journey["label"].upper())
                self.assertNotIn(journey["expected_outcome"], journey["prompt"].upper())
                self.assertTrue(journey["requested_fixture_roles"])
                self.assertFalse(
                    set(journey["requested_fixture_roles"]) - set(self.by_role)
                )
                self.assertFalse(set(journey["source_basis_ids"]) - source_ids)
                approval_id = journey["approval_id"]
                if approval_id is not None:
                    self.assertIn(approval_id, approval_ids)
                if journey["expected_outcome"] == "MODIFY":
                    self.assertIsNotNone(approval_id)
                    requested_ids = {
                        self.by_role[role]["memory_id"]
                        for role in journey["requested_fixture_roles"]
                    }
                    self.assertIn(
                        approvals_by_id[approval_id]["source_memory_id"], requested_ids
                    )
                if journey["expected_outcome"] == "STEP_UP":
                    self.assertIs(journey["human_review_allowed"], True)
                    self.assertIsNone(approval_id)
                if journey["expected_outcome"] == "DEFER":
                    self.assertTrue(journey["missing_context"])
                if (
                    journey["expected_outcome"] == "ALLOW"
                    and journey["destination"] == "external"
                ):
                    requested = [
                        self.by_role[role]
                        for role in journey["requested_fixture_roles"]
                    ]
                    self.assertTrue(
                        all(item["room"] == "external-approved" for item in requested)
                    )
                    self.assertTrue(
                        all(
                            item["memory_id"] in approved_derivative_ids
                            for item in requested
                        )
                    )

    def test_participant_specific_external_journeys_are_phi_candidates(self) -> None:
        journeys = {journey["journey_id"]: journey for journey in self.journeys}
        for journey_id in (
            "clinical-partner-cohort-update",
            "partner-stability-update",
        ):
            with self.subTest(journey_id=journey_id):
                journey = journeys[journey_id]
                self.assertEqual(journey["destination"], "external")
                self.assertEqual(
                    journey["requested_fixture_roles"],
                    ["clinical_current_cohort"],
                )
                self.assertEqual(journey["data_classes"], ["PHI_CANDIDATE"])

    def test_no_embeddings_or_obvious_real_data_and_secrets(self) -> None:
        all_fixture_data = {
            "memory": self.memory_fixture,
            "approvals": self.approval_fixture,
            "sources": self.source_fixture,
            "scenarios": self.scenario_fixture,
        }
        self.assertFalse(
            {key.casefold() for key in walk_keys(all_fixture_data)}
            & {"embedding", "embeddings", "vector"}
        )

        serialized = json.dumps(all_fixture_data, sort_keys=True)
        for label, pattern in FORBIDDEN_PATTERNS.items():
            with self.subTest(pattern=label):
                self.assertIsNone(pattern.search(serialized))


if __name__ == "__main__":
    unittest.main()
