"""pytest 公共夹具。"""

from __future__ import annotations

import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from wraith.authorization import AuthorizationGate  # noqa: E402
from wraith.config import Config  # noqa: E402
from wraith.events import EventBus  # noqa: E402
from wraith.models import Session  # noqa: E402
from wraith.recon.demo import DEMO_WORDLIST  # noqa: E402
from wraith.store import Store  # noqa: E402
from wraith.system.iface import IfaceManager  # noqa: E402
from wraith.system.runner import Runner  # noqa: E402


@pytest.fixture()
def wordlist(tmp_path: Path) -> Path:
    path = tmp_path / "words.txt"
    path.write_text("\n".join(DEMO_WORDLIST) + "\n", encoding="utf-8")
    return path


@pytest.fixture()
def cfg(tmp_path: Path, wordlist: Path) -> Config:
    config = Config(
        mode="demo",
        data_dir=str(tmp_path / "data"),
        capture_dir=str(tmp_path / "captures"),
        wordlist=str(wordlist),
        operator="pytest",
    )
    config.ensure_dirs()
    return config


@pytest.fixture()
def parts(cfg: Config) -> SimpleNamespace:
    store = Store(cfg.db_path)
    bus = EventBus()
    runner = Runner(dry_run=True)
    iface = IfaceManager(runner)
    gate = AuthorizationGate(cfg, bus)
    session_id = store.create_session(
        Session(name="pytest", mode=cfg.mode, iface="demo0", operator="pytest")
    )
    yield SimpleNamespace(
        config=cfg,
        store=store,
        bus=bus,
        runner=runner,
        iface=iface,
        gate=gate,
        session_id=session_id,
    )
    store.close()
