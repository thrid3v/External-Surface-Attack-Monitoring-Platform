"""Shared pytest fixtures for the API test suite.

Puts the API root and the local scanner_core package on sys.path (mirroring
workers/scan_worker.py) and provides an isolated in-memory SQLite session so
tests never touch a real Postgres instance.
"""

import sys
from pathlib import Path

API_ROOT = Path(__file__).resolve().parents[1]
PACKAGES_ROOT = API_ROOT.parent.parent / "packages"
for _p in (str(API_ROOT), str(PACKAGES_ROOT)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from db.models import Base


@pytest.fixture
def db():
    """An isolated in-memory SQLite session with all tables created.

    Uses a StaticPool with ``check_same_thread=False`` so the single in-memory
    connection is shared across threads — required because Starlette's TestClient
    dispatches request handlers on a threadpool.
    """
    engine = create_engine(
        "sqlite:///:memory:",
        future=True,
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(bind=engine)
    Session = sessionmaker(bind=engine, autoflush=False, future=True)
    session = Session()
    try:
        yield session
    finally:
        session.close()
        engine.dispose()
