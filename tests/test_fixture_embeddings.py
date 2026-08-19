from __future__ import annotations

import importlib.util
import sys
from copy import deepcopy
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "embed_synthetic_fixtures.py"


def _module() -> ModuleType:
    spec = importlib.util.spec_from_file_location("fixture_embeddings", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class _Rows:
    def __init__(self, rows: list[dict[str, Any]]) -> None:
        self._rows = rows

    def mappings(self) -> _Rows:
        return self

    def all(self) -> list[dict[str, Any]]:
        return deepcopy(self._rows)


class _Connection:
    def __init__(
        self,
        rows: list[dict[str, Any]],
        *,
        reject_update_id: str | None = None,
    ) -> None:
        self.rows = {str(row["id"]): deepcopy(row) for row in rows}
        self.updates: list[dict[str, Any]] = []
        self.reject_update_id = reject_update_id

    def execute(self, statement: object, parameters: dict[str, Any]) -> _Rows:
        sql = str(statement).casefold()
        if sql.lstrip().startswith("select"):
            fixture_ids = {str(value) for value in parameters["fixture_ids"]}
            return _Rows(
                [row for row_id, row in self.rows.items() if row_id in fixture_ids]
            )
        if sql.lstrip().startswith("update"):
            self.updates.append(deepcopy(parameters))
            if parameters["id"] == self.reject_update_id:
                return _Rows([])
            row = self.rows[parameters["id"]]
            if row["has_embedding"] is False:
                row["has_embedding"] = True
            return _Rows([{"id": parameters["id"]}])
        raise AssertionError(f"unexpected statement: {statement}")


class _Runner:
    def __init__(self, connection: _Connection) -> None:
        self.connection = connection
        self.options: list[dict[str, object]] = []

    def __call__(self, engine: object, callback: object, **options: object):
        del engine
        self.options.append(options)
        return callback(self.connection)


class _Embedder:
    def __init__(self) -> None:
        self.calls: list[str] = []

    def embed(self, text: str) -> tuple[float, ...]:
        self.calls.append(text)
        return (0.25,) * 256


def _database_rows(module: ModuleType) -> list[dict[str, object]]:
    return [
        {
            "id": memory_id,
            "tenant_id": row["tenant_id"],
            "program_id": row["program_id"],
            "content": row["content"],
            "content_sha256": row["content_sha256"],
            "state": row["state"],
            "has_embedding": False,
        }
        for memory_id, row in module._fixture_rows().items()
    ]


def test_population_embeds_active_content_outside_retry_callbacks_once() -> None:
    module = _module()
    connection = _Connection(_database_rows(module))
    read_runner = _Runner(connection)
    write_runner = _Runner(connection)
    embedder = _Embedder()
    expected_count = sum(
        row["state"] == "active" and isinstance(row["content"], str)
        for row in connection.rows.values()
    )

    count = module.populate_missing_embeddings(
        object(),
        embedder,
        _read_runner=read_runner,
        _write_runner=write_runner,
    )

    assert count == expected_count
    assert len(embedder.calls) == expected_count
    assert len(connection.updates) == expected_count
    assert all("SYNTHETIC DATA" in value for value in embedder.calls)
    assert read_runner.options == [{"max_retries": 3, "max_backoff": 1}]
    assert write_runner.options == [{"max_retries": 3, "max_backoff": 1}]
    assert all("content" not in parameters for parameters in connection.updates)

    second_embedder = _Embedder()
    assert (
        module.populate_missing_embeddings(
            object(),
            second_embedder,
            _read_runner=read_runner,
            _write_runner=write_runner,
        )
        == 0
    )
    assert second_embedder.calls == []


def test_release_refresh_reembeds_existing_active_vectors() -> None:
    module = _module()
    rows = _database_rows(module)
    for row in rows:
        row["has_embedding"] = True
    connection = _Connection(rows)
    read_runner = _Runner(connection)
    write_runner = _Runner(connection)
    embedder = _Embedder()
    expected_count = sum(
        row["state"] == "active" and isinstance(row["content"], str)
        for row in connection.rows.values()
    )

    count = module.populate_missing_embeddings(
        object(),
        embedder,
        refresh_existing=True,
        _read_runner=read_runner,
        _write_runner=write_runner,
    )

    assert count == expected_count
    assert len(embedder.calls) == expected_count
    assert len(connection.updates) == expected_count
    assert all("content" not in parameters for parameters in connection.updates)


def test_release_refresh_rejects_a_guarded_update_that_matches_no_row() -> None:
    module = _module()
    rows = _database_rows(module)
    for row in rows:
        row["has_embedding"] = True
    rejected_id = next(
        str(row["id"])
        for row in rows
        if row["state"] == "active" and isinstance(row["content"], str)
    )
    connection = _Connection(rows, reject_update_id=rejected_id)

    with pytest.raises(RuntimeError, match="embedding update was rejected"):
        module.populate_missing_embeddings(
            object(),
            _Embedder(),
            refresh_existing=True,
            _read_runner=_Runner(connection),
            _write_runner=_Runner(connection),
        )


def test_population_rejects_fixture_drift_before_embedding() -> None:
    module = _module()
    rows = _database_rows(module)
    rows[0]["content_sha256"] = "0" * 64
    connection = _Connection(rows)
    embedder = _Embedder()

    with pytest.raises(RuntimeError, match="differ from source"):
        module.populate_missing_embeddings(
            object(),
            embedder,
            _read_runner=_Runner(connection),
            _write_runner=_Runner(connection),
        )

    assert embedder.calls == []
    assert connection.updates == []


@pytest.mark.parametrize(
    "vector",
    [
        (0.0,) * 255,
        (0.0,) * 255 + (1,),
        (0.0,) * 255 + (float("inf"),),
    ],
)
def test_vector_serialization_fails_closed(vector: tuple[object, ...]) -> None:
    module = _module()

    with pytest.raises(ValueError, match="embedding"):
        module._vector_json(vector)


def test_script_never_logs_or_binds_raw_content_on_database_write() -> None:
    source = SCRIPT.read_text(encoding="utf-8")

    assert "hide_parameters=True" in source
    assert '"content": candidate.content' not in source
    assert "print(candidate" not in source
    assert "RETURNING id" in source
