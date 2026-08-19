from __future__ import annotations

import importlib.util
from copy import deepcopy
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[1]
LOADER_PATH = ROOT / "scripts" / "load_synthetic_fixtures.py"


def _loader() -> ModuleType:
    spec = importlib.util.spec_from_file_location(
        "synthetic_fixture_loader", LOADER_PATH
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_loader_prepares_schema_compatible_synthetic_rows() -> None:
    loader = _loader()
    memories = loader._memory_rows()
    approvals = loader._approval_rows()

    assert len(memories) == 30
    assert len(approvals) == 3
    assert {row["state"] for row in memories} == {
        "active",
        "proposed",
        "revoked",
        "quarantined",
        "forgotten",
    }
    forgotten = next(row for row in memories if row["state"] == "forgotten")
    assert forgotten["content"] is None
    assert forgotten["content_sha256"] is None
    assert approvals[0]["decision"] == "approved"
    assert approvals[0]["reviewed_by"].startswith("human-")
    assert approvals[0]["purpose_scopes"] == ["partner_status"]
    assert approvals[0]["audience_scopes"] == ["partner-alpha-synthetic"]
    assert approvals[0]["expires_at"] == "2027-02-15T16:00:00Z"
    assert {row["audience_scopes"][0] for row in approvals} == {
        "partner-alpha-synthetic",
    }


def test_loader_avoids_rls_unsafe_conflict_suppression() -> None:
    source = LOADER_PATH.read_text(encoding="utf-8").casefold()
    assert "on conflict do nothing" not in source
    assert "run_transaction" in source


def test_fixture_drift_fingerprint_covers_scopes_provenance_and_review() -> None:
    loader = _loader()
    memory = loader._memory_rows()[0]
    changed_memory = deepcopy(memory)
    changed_memory["program_id"] = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa2"
    assert loader._memory_fingerprint(memory) != loader._memory_fingerprint(
        changed_memory
    )

    approval = loader._approval_rows()[0]
    changed_approval = deepcopy(approval)
    changed_approval["purpose_scopes"] = ["program_status"]
    assert loader._approval_fingerprint(approval) != loader._approval_fingerprint(
        changed_approval
    )


class _Rows:
    def __init__(self, rows: list[dict[str, Any]]) -> None:
        self._rows = rows

    def mappings(self) -> _Rows:
        return self

    def all(self) -> list[dict[str, Any]]:
        return deepcopy(self._rows)


class _FixtureConnection:
    def __init__(
        self,
        *,
        memories: list[dict[str, Any]] | None = None,
        approvals: list[dict[str, Any]] | None = None,
    ) -> None:
        self.memories = {str(row["id"]): deepcopy(row) for row in memories or []}
        self.approvals = {str(row["id"]): deepcopy(row) for row in approvals or []}
        self.memory_inserts = 0
        self.approval_inserts = 0

    def execute(self, statement: Any, parameters: dict[str, Any]) -> _Rows:
        sql = str(statement).casefold()
        if sql.lstrip().startswith("select"):
            fixture_ids = {str(row_id) for row_id in parameters["fixture_ids"]}
            store = self.memories if "from memory_records" in sql else self.approvals
            return _Rows(
                [row for row_id, row in store.items() if row_id in fixture_ids]
            )
        if "insert into memory_records" in sql:
            self.memory_inserts += 1
            self.memories[str(parameters["id"])] = deepcopy(parameters)
            return _Rows([])
        if "insert into derivative_approvals" in sql:
            self.approval_inserts += 1
            self.approvals[str(parameters["id"])] = deepcopy(parameters)
            return _Rows([])
        raise AssertionError(f"unexpected fixture loader statement: {statement}")


def test_loader_appends_missing_rows_and_preserves_unrelated_rows() -> None:
    loader = _loader()
    memories = loader._memory_rows()
    approvals = loader._approval_rows()
    unrelated_memory = deepcopy(memories[0])
    unrelated_memory["id"] = "90000000-0000-4000-8000-000000000001"
    unrelated_approval = deepcopy(approvals[0])
    unrelated_approval["id"] = "90000000-0000-4000-8000-000000000002"
    connection = _FixtureConnection(
        memories=[memories[0], unrelated_memory],
        approvals=[approvals[0], unrelated_approval],
    )

    assert loader._load(connection) == (30, 3)
    assert connection.memory_inserts == 29
    assert connection.approval_inserts == 2
    assert str(unrelated_memory["id"]) in connection.memories
    assert str(unrelated_approval["id"]) in connection.approvals

    assert loader._load(connection) == (30, 3)
    assert connection.memory_inserts == 29
    assert connection.approval_inserts == 2


def test_loader_rejects_drift_for_fixture_owned_id_before_inserting() -> None:
    loader = _loader()
    drifted = deepcopy(loader._memory_rows()[0])
    drifted["room"] = "external-approved"
    connection = _FixtureConnection(memories=[drifted])

    with pytest.raises(RuntimeError, match="memory fixture rows differ"):
        loader._load(connection)

    assert connection.memory_inserts == 0
    assert connection.approval_inserts == 0
