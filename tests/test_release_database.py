from __future__ import annotations

import ast
import importlib.util
import subprocess
import sys
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from types import ModuleType

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "prepare_release_database.py"


def _module() -> ModuleType:
    spec = importlib.util.spec_from_file_location("prepare_release_database", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _urls(
    database: str = "gluevenir_release_20260817_abcd",
) -> tuple[str, str]:
    admin = (
        "postgresql"
        f"://migration:admin-secret@new.example:26257/{database}"
        "?sslmode=verify-full"
    )
    runtime = (
        "postgresql"
        f"://gluevenir_runtime:runtime-secret@new.example:26257/{database}"
        "?sslmode=verify-full"
    )
    return admin, runtime


class _Embedder:
    def embed(self, value: str) -> tuple[float, ...]:
        del value
        return (0.25,) * 256


@dataclass
class _FakeOperations:
    module: ModuleType
    state: str = "clean"
    fail_stage: str | None = None
    load_counts: tuple[int, int] = (30, 3)
    verify_counts: tuple[int, int, int, bool] | None = None
    calls: list[str] = field(default_factory=list)

    def operations(self):
        return self.module.PreparationOperations(
            inspect=self.inspect,
            migrate=self.migrate,
            bind_runtime=self.bind_runtime,
            load=self.load,
            embed=self.embed,
            verify=self.verify,
        )

    def _call(self, stage: str) -> None:
        self.calls.append(stage)
        if self.fail_stage == stage:
            raise RuntimeError(
                "synthetic-sensitive-content "
                + "postgresql"
                + "://user:secret@leak.invalid/db"
            )

    def inspect(self, target):
        del target
        self._call("inspect")
        return self.state

    def migrate(self, target) -> None:
        del target
        self._call("migrate")
        self.state = "current"

    def bind_runtime(self, target) -> None:
        del target
        self._call("bind_runtime")

    def load(self, target) -> tuple[int, int]:
        del target
        self._call("load")
        return self.load_counts

    def embed(self, target, embedder) -> int:
        del target, embedder
        self._call("embed")
        return self.module._active_count()

    def verify(self, target):
        del target
        self._call("verify")
        values = self.verify_counts or (
            30,
            3,
            self.module._active_count(),
            True,
        )
        return self.module.VerificationSummary(*values)


def _target(module: ModuleType):
    admin, runtime = _urls()
    return module.validate_target(
        admin,
        runtime,
        acknowledged_database="gluevenir_release_20260817_abcd",
    )


@pytest.mark.parametrize(
    "database",
    (
        "defaultdb",
        "postgres",
        "system",
        "gluevenir",
        "gluevenir_release_latest",
        "gluevenir-release-20260817-abcd",
    ),
)
def test_target_rejects_system_default_and_unreviewed_names(database: str) -> None:
    module = _module()
    admin, runtime = _urls(database)

    with pytest.raises(module.PreparationError, match="explicitly reviewed"):
        module.validate_target(
            admin,
            runtime,
            acknowledged_database=database,
        )


def test_target_requires_exact_acknowledgement_and_bounded_runtime() -> None:
    module = _module()
    admin, runtime = _urls()

    with pytest.raises(module.PreparationError, match="explicitly reviewed"):
        module.validate_target(
            admin,
            runtime,
            acknowledged_database="gluevenir_release_20260817_wxyz",
        )
    with pytest.raises(module.PreparationError, match="reviewed principal"):
        module.validate_target(
            admin,
            runtime.replace("gluevenir_runtime", "root"),
            acknowledged_database="gluevenir_release_20260817_abcd",
        )
    with pytest.raises(module.PreparationError, match="different clusters"):
        module.validate_target(
            admin,
            runtime.replace("new.example", "old.example"),
            acknowledged_database="gluevenir_release_20260817_abcd",
        )
    with pytest.raises(module.PreparationError, match="verified TLS"):
        module.validate_target(
            admin.replace("verify-full", "disable"),
            runtime,
            acknowledged_database="gluevenir_release_20260817_abcd",
        )


def test_clean_target_migrates_then_prepares_and_verifies() -> None:
    module = _module()
    fake = _FakeOperations(module)

    result = module.prepare_release_database(
        _target(module),
        _Embedder(),
        operations=fake.operations(),
    )

    assert result == module.PreparationResult(
        initial_state="clean",
        migrated=True,
        memories=30,
        approvals=3,
        embeddings_populated=module._active_count(),
        verified=True,
    )
    assert fake.calls == [
        "inspect",
        "migrate",
        "inspect",
        "bind_runtime",
        "load",
        "embed",
        "verify",
    ]


def test_current_target_refreshes_embeddings_and_never_reapplies_migrations() -> None:
    module = _module()
    fake = _FakeOperations(module, state="current")
    target = _target(module)

    first = module.prepare_release_database(
        target,
        _Embedder(),
        operations=fake.operations(),
    )
    second = module.prepare_release_database(
        target,
        _Embedder(),
        operations=fake.operations(),
    )

    assert first.verified is second.verified is True
    assert first.migrated is second.migrated is False
    assert first.embeddings_populated == module._active_count()
    assert second.embeddings_populated == module._active_count()
    assert "migrate" not in fake.calls
    assert fake.calls == [
        "inspect",
        "bind_runtime",
        "load",
        "embed",
        "verify",
        "inspect",
        "bind_runtime",
        "load",
        "embed",
        "verify",
    ]


def test_partial_state_fails_before_every_mutating_stage() -> None:
    module = _module()
    fake = _FakeOperations(module, state="partial")

    with pytest.raises(module.PreparationError, match="partial state"):
        module.prepare_release_database(
            _target(module),
            _Embedder(),
            operations=fake.operations(),
        )

    assert fake.calls == ["inspect"]


def test_fixture_drift_fails_before_embedding_or_verification() -> None:
    module = _module()
    fake = _FakeOperations(module, state="current", fail_stage="load")

    with pytest.raises(
        module.PreparationError, match="fixture loading failed"
    ) as error:
        module.prepare_release_database(
            _target(module),
            _Embedder(),
            operations=fake.operations(),
        )

    assert fake.calls == ["inspect", "bind_runtime", "load"]
    assert "synthetic-sensitive-content" not in str(error.value)
    assert "secret" not in str(error.value)


@pytest.mark.parametrize(
    "stage", ("inspect", "migrate", "bind_runtime", "embed", "verify")
)
def test_failures_are_redacted_and_stop_the_pipeline(stage: str) -> None:
    module = _module()
    fake = _FakeOperations(module, fail_stage=stage)

    with pytest.raises(module.PreparationError) as error:
        module.prepare_release_database(
            _target(module),
            _Embedder(),
            operations=fake.operations(),
        )

    message = str(error.value)
    assert "secret" not in message
    assert "leak.invalid" not in message
    assert "synthetic-sensitive-content" not in message
    assert fake.calls[-1] == stage


def test_unexpected_counts_fail_closed() -> None:
    module = _module()
    wrong_load = _FakeOperations(module, state="current", load_counts=(29, 3))
    with pytest.raises(module.PreparationError, match="unexpected counts"):
        module.prepare_release_database(
            _target(module),
            _Embedder(),
            operations=wrong_load.operations(),
        )
    assert wrong_load.calls == ["inspect", "bind_runtime", "load"]

    wrong_verify = _FakeOperations(
        module,
        state="current",
        verify_counts=(30, 3, 17, True),
    )
    with pytest.raises(module.PreparationError, match="did not match"):
        module.prepare_release_database(
            _target(module),
            _Embedder(),
            operations=wrong_verify.operations(),
        )
    assert wrong_verify.calls == [
        "inspect",
        "bind_runtime",
        "load",
        "embed",
        "verify",
    ]


def test_plan_mode_is_network_free_and_never_emits_urls_or_credentials(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    module = _module()
    admin, runtime = _urls()
    admin_file = tmp_path / "admin-url"
    runtime_file = tmp_path / "runtime-url"
    admin_file.write_text(admin, encoding="utf-8")
    runtime_file.write_text(runtime, encoding="utf-8")

    module.main(
        [
            "plan",
            "--admin-url-file",
            str(admin_file),
            "--runtime-url-file",
            str(runtime_file),
            "--acknowledge-database",
            "gluevenir_release_20260817_abcd",
        ]
    )

    output = capsys.readouterr().out
    assert "no network or mutation" in output
    assert "postgresql://" not in output
    assert "admin-secret" not in output
    assert "runtime-secret" not in output
    assert "drop" not in output.casefold()


def test_script_has_no_database_creation_cutover_or_secret_mutation() -> None:
    source = SCRIPT.read_text(encoding="utf-8").casefold()

    for forbidden in (
        "create database",
        "drop database",
        "alter database",
        "put_secret_value",
        "update_secret",
        "delete_secret",
        'boto3.client("secretsmanager"',
    ):
        assert forbidden not in source
    assert "run_transaction" in source
    assert "hide_parameters=true" in source
    assert "populate_missing_embeddings" in source
    assert "_verify_runtime_principal" in source
    assert "alter role gluevenir_runtime nobypassrls" in source
    assert "revoke admin from gluevenir_runtime" in source
    assert "grant gluevenir_app to gluevenir_runtime" in source
    assert "revoke create on schema public from gluevenir_runtime" in source


def test_runtime_role_ddl_uses_one_plain_transaction(monkeypatch) -> None:
    module = _module()
    statements: list[str] = []

    class _Connection:
        def exec_driver_sql(self, statement: str) -> None:
            statements.append(statement)

    class _Engine:
        begin_calls = 0
        disposed = False

        @contextmanager
        def begin(self):
            self.begin_calls += 1
            yield _Connection()

        def dispose(self) -> None:
            self.disposed = True

    engine = _Engine()
    monkeypatch.setattr(module, "_engine", lambda url: engine)

    module._bind_runtime_principal(_target(module))

    assert engine.begin_calls == 1
    assert engine.disposed is True
    assert statements == [
        "ALTER ROLE gluevenir_runtime NOBYPASSRLS",
        "REVOKE admin FROM gluevenir_runtime",
        "GRANT gluevenir_app TO gluevenir_runtime",
        "REVOKE CREATE ON DATABASE gluevenir_release_20260817_abcd FROM PUBLIC",
        "REVOKE CREATE ON DATABASE gluevenir_release_20260817_abcd "
        "FROM gluevenir_runtime",
        "REVOKE CREATE ON SCHEMA public FROM gluevenir_runtime",
    ]


def test_public_runbook_uses_importable_module_invocation() -> None:
    runbook = (ROOT / "docs" / "wave-e-fixture-cutover.md").read_text(encoding="utf-8")

    assert "python -m scripts.prepare_release_database plan" in runbook
    assert "python -m scripts.prepare_release_database prepare" in runbook
    assert "python scripts/prepare_release_database.py" not in runbook


def test_live_release_verifier_uses_explicit_checks_in_optimized_mode() -> None:
    verifier = ROOT / "scripts" / "verify_live_memory_core.py"
    parsed = ast.parse(verifier.read_text(encoding="utf-8"))
    assert not any(isinstance(node, ast.Assert) for node in ast.walk(parsed))

    result = subprocess.run(
        [
            sys.executable,
            "-O",
            "-c",
            (
                "from scripts.verify_live_memory_core import _require; "
                "_require(False, 'optimized verification failed')"
            ),
        ],
        cwd=ROOT,
        capture_output=True,
        check=False,
        text=True,
    )
    assert result.returncode != 0
    assert "optimized verification failed" in result.stderr


def test_live_release_verifier_explicit_check_is_content_free() -> None:
    from scripts.verify_live_memory_core import LiveVerificationError, _require

    with pytest.raises(LiveVerificationError, match="catalog boundary failed"):
        _require(False, "catalog boundary failed")
