from __future__ import annotations

import importlib.util
from pathlib import Path

SCRIPT = Path(__file__).parents[1] / "scripts" / "check_live_migration_state.py"
SPEC = importlib.util.spec_from_file_location("check_live_migration_state", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)
PROJECT_TABLES = MODULE.PROJECT_TABLES
REVISION = MODULE.REVISION
classify_migration_state = MODULE.classify_migration_state


def test_clean_migration_state_is_exact() -> None:
    assert classify_migration_state([], revision=None, role_exists=False) == "clean"
    assert (
        classify_migration_state({"alembic_version"}, revision=None, role_exists=False)
        == "clean"
    )


def test_current_migration_state_is_exact() -> None:
    tables = PROJECT_TABLES | {"alembic_version"}
    assert (
        classify_migration_state(tables, revision=REVISION, role_exists=True)
        == "current"
    )


def test_partial_or_drifted_states_fail_closed() -> None:
    tables = PROJECT_TABLES | {"alembic_version"}
    cases = (
        (PROJECT_TABLES, None, True),
        (tables, None, True),
        (tables, "wrong_revision", True),
        (tables, REVISION, False),
        (tables | {"unexpected"}, REVISION, True),
    )
    for found_tables, revision, role_exists in cases:
        assert (
            classify_migration_state(
                found_tables,
                revision=revision,
                role_exists=role_exists,
            )
            == "partial"
        )
