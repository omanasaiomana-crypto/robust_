"""Pytest fixtures for IdentityShield v3 test suite."""
from datetime import UTC, datetime
from pathlib import Path

import pytest


class FixedDatetime(datetime):
    """A datetime subclass that is also callable, satisfying both datetime and clock callable interfaces."""

    def __call__(self) -> "FixedDatetime":
        return self


@pytest.fixture
def tmp_db(tmp_path: Path):
    """Fixture providing a temporary SQLite database path."""
    path = tmp_path / "test_v3.db"
    yield path
    from app.v3.store import close_connection
    close_connection(path)


@pytest.fixture
def fixed_clock() -> FixedDatetime:
    """Fixture providing a fixed UTC clock / datetime for reproducible testing."""
    return FixedDatetime(2026, 10, 28, 12, 0, 0, tzinfo=UTC)
