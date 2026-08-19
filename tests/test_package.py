from __future__ import annotations

import unittest
from dataclasses import asdict
from datetime import UTC, datetime, timedelta

import gluevenir
from gluevenir import Gluevenir, MemoryContext, RecallRequest
from gluevenir._ports import MemoryOperation
from gluevenir.testing import (
    FakeClock,
    FakeDetector,
    FakeEmbedder,
    FakeSigner,
    FakeTextModel,
    FakeToolAdapter,
    RecordingGateway,
)


def _context() -> MemoryContext:
    return MemoryContext(
        tenant_id="tenant-synthetic",
        program_id="program-synthetic",
        actor_id="actor-synthetic",
        actor_role="program_lead",
        agent_id="gluevenir-bio",
        purpose="program_status",
        audience="internal",
    )


class PublicSurfaceTests(unittest.TestCase):
    def test_public_surface_is_intentionally_small(self) -> None:
        self.assertEqual(
            set(gluevenir.__all__), {"Gluevenir", "MemoryContext", "RecallRequest"}
        )

    def test_recall_enters_gateway_once(self) -> None:
        expected = object()
        gateway = RecordingGateway(expected)
        client = Gluevenir(gateway=gateway)
        request = RecallRequest("What changed?", top_k=3)
        context = _context()

        self.assertIs(client.recall(request, context=context), expected)
        self.assertEqual(len(gateway.calls), 1)
        self.assertEqual(gateway.calls[0].operation, MemoryOperation.RECALL)
        self.assertIs(gateway.calls[0].payload, request)
        self.assertIs(gateway.calls[0].context, context)

    def test_context_and_request_reject_missing_or_unbounded_values(self) -> None:
        with self.assertRaises(ValueError):
            RecallRequest(" ")
        with self.assertRaises(ValueError):
            RecallRequest("query", top_k=6)
        with self.assertRaises(TypeError):
            RecallRequest("query", top_k=True)
        with self.assertRaises(ValueError):
            RecallRequest("x" * 4_001)
        values = asdict(_context())
        values["purpose"] = ""
        with self.assertRaises(ValueError):
            MemoryContext(**values)
        values = asdict(_context())
        values["actor_id"] = "x" * 257
        with self.assertRaises(ValueError):
            MemoryContext(**values)


class DeterministicFakeTests(unittest.TestCase):
    def test_clock_is_utc_and_controlled(self) -> None:
        clock = FakeClock(datetime(2026, 8, 15, 12, tzinfo=UTC))
        clock.advance(timedelta(seconds=5))
        self.assertEqual(clock.now(), datetime(2026, 8, 15, 12, 0, 5, tzinfo=UTC))

    def test_embedder_is_stable_and_bounded(self) -> None:
        embedder = FakeEmbedder(dimensions=4)
        self.assertEqual(embedder.embed("synthetic"), embedder.embed("synthetic"))
        self.assertEqual(len(embedder.embed("synthetic")), 4)
        self.assertNotEqual(embedder.embed("synthetic"), embedder.embed("other"))

    def test_detector_omits_matched_text(self) -> None:
        detector = FakeDetector({"SECRET": "DEMO_TOKEN"})
        detection = detector.detect("prefix DEMO_TOKEN suffix")[0]
        self.assertEqual(detection.label, "SECRET")
        self.assertFalse(hasattr(detection, "match"))

    def test_model_is_scripted_and_records_calls(self) -> None:
        model = FakeTextModel({"prompt": "response"})
        self.assertEqual(model.generate("prompt"), "response")
        self.assertEqual(model.prompts, ["prompt"])
        with self.assertRaises(KeyError):
            model.generate("unscripted")

    def test_signer_is_deterministic_and_detects_mutation(self) -> None:
        signer = FakeSigner()
        signature = signer.sign(b"payload")
        self.assertEqual(signature, signer.sign(b"payload"))
        self.assertTrue(signer.verify(b"payload", signature))
        self.assertFalse(signer.verify(b"changed", signature))

    def test_tool_fake_is_allowlisted_and_copies_data(self) -> None:
        tool = FakeToolAdapter({"inspect": {"status": "ok"}})
        arguments = {"receipt_id": "synthetic-id"}
        response = tool.invoke("inspect", arguments)
        arguments["receipt_id"] = "changed"
        self.assertEqual(response, {"status": "ok"})
        self.assertEqual(tool.calls[0].arguments["receipt_id"], "synthetic-id")
        with self.assertRaises(KeyError):
            tool.invoke("write", {})


if __name__ == "__main__":
    unittest.main()
