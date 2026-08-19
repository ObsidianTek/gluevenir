from __future__ import annotations

import pytest

from gluevenir._database import cockroach_url


def test_cockroach_url_normalizes_postgresql_without_losing_components() -> None:
    url = cockroach_url(
        "postgresql://demo:" + "placeholder" + "@example.invalid:26257/defaultdb"
        "?sslmode=verify-full",
        database_name="gluevenir",
    )

    assert url.drivername == "cockroachdb+psycopg"
    assert url.database == "gluevenir"
    assert url.username == "demo"
    assert url.password == "placeholder"
    assert url.query["sslmode"] == "verify-full"
    assert "placeholder" not in str(url)


@pytest.mark.parametrize(
    "raw_url",
    ["", "sqlite:///tmp/demo.db", "cockroachdb+psycopg://demo@localhost"],
)
def test_cockroach_url_rejects_missing_or_wrong_database_urls(raw_url: str) -> None:
    with pytest.raises(ValueError):
        cockroach_url(raw_url)
