from __future__ import annotations

import os
from pathlib import Path

import pytest

from scripts.bootstrap_local import (
    _migration_environment,
    _owner,
)


def test_migration_environment_restores_process_configuration(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("DATABASE_URL", "before")
    monkeypatch.delenv("GLUEVENIR_DATABASE", raising=False)
    with _migration_environment("local-development-url"):
        assert os.environ["DATABASE_URL"] == "local-development-url"
        assert os.environ["GLUEVENIR_DATABASE"] == "gluevenir"
    assert os.environ["DATABASE_URL"] == "before"
    assert "GLUEVENIR_DATABASE" not in os.environ


@pytest.mark.parametrize("value", ("0:1", "1:0", "name:1", "1", "1:2:3"))
def test_signing_key_owner_is_exact_numeric_user_and_group(value: str) -> None:
    with pytest.raises(ValueError, match="numeric user:group"):
        _owner(value)
    assert _owner("10001:10001") == (10001, 10001)


def test_bootstrap_reuses_reviewed_migrations_and_retry_safe_loaders() -> None:
    source = (Path(__file__).parents[1] / "scripts" / "bootstrap_local.py").read_text(
        encoding="utf-8"
    )
    assert "command.upgrade" in source
    assert "scripts.load_synthetic_fixtures import _load" in source
    assert "populate_missing_embeddings" in source
    assert "run_transaction" in source
    assert "on conflict do nothing" not in source.casefold()
    assert 'state == "partial"' in source
    assert "NOBYPASSRLS" in source
    assert "_VERIFY_RUNTIME_PRINCIPAL" in source
    assert "relforcerowsecurity" in source
