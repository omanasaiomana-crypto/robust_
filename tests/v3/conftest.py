"""Pytest fixtures for IdentityShield v3 test suite."""
from datetime import UTC, datetime
from pathlib import Path

import pytest


class FixedDatetime(datetime):
    """A datetime subclass that is also callable, satisfying both datetime and clock callable interfaces."""

    def __call__(self) -> "FixedDatetime":
        return self


@pytest.fixture
def tmp_db(tmp_path: Path) -> Path:
    """Fixture providing a temporary SQLite database path."""
    return tmp_path / "test_v3.db"


@pytest.fixture
def fixed_clock() -> FixedDatetime:
    """Fixture providing a fixed UTC clock / datetime for reproducible testing."""
    return FixedDatetime(2026, 10, 28, 12, 0, 0, tzinfo=UTC)
