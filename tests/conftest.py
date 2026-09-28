from pathlib import Path

import pytest

from porthunter.db import Database

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture
def fixture_text():
    def read(name: str) -> str:
        return (FIXTURES / name).read_text(encoding="utf-8")
    return read


@pytest.fixture
def db(tmp_path):
    return Database(tmp_path / "test.db")
