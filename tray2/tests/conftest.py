import os
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


@pytest.fixture(autouse=True)
def isolated_data_dir(tmp_path, monkeypatch):
    """테스트가 실제 %LOCALAPPDATA%\\MailShield2를 건드리지 않게 한다."""
    monkeypatch.setenv("MAILSHIELD2_DATA_DIR", str(tmp_path))
    yield tmp_path
