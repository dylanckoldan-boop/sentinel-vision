import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

# The EICAR test string is assembled at runtime so this repository itself never contains it
# (otherwise antivirus products would flag the source checkout).
EICAR = (
    bytes.fromhex("58354F2150254041505B345C505A58353428505E2937434329377D24")
    + b"EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
)


@pytest.fixture(autouse=True)
def isolated_home(tmp_path, monkeypatch):
    home = tmp_path / "svhome"
    monkeypatch.setenv("SENTINEL_VISION_HOME", str(home))
    return home


@pytest.fixture
def eicar() -> bytes:
    return EICAR


@pytest.fixture
def sentinel():
    from sentinel_vision.config import Settings
    from sentinel_vision.core import Sentinel

    s = Settings()
    s.clamav_enabled = False  # deterministic: tests must not depend on a local ClamAV install
    s.realtime_enabled = False
    s.network_enabled = False
    s.feeds = []
    # never touch the real user's folders or devices from tests
    s.ransomware_enabled = False
    s.ransomware_folders = []
    s.usb_autoscan = False
    s.privacy_monitor = False
    s.netsec_enabled = False
    s.behavior_enabled = False
    s.watch_paths = []
    sv = Sentinel(s)
    yield sv
    sv.shutdown()


@pytest.fixture
def workdir(tmp_path) -> Path:
    d = tmp_path / "files"
    d.mkdir()
    return d
