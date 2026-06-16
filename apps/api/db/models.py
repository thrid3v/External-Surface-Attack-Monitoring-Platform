import json
import os
import uuid
from datetime import datetime, timezone

from dotenv import load_dotenv
from sqlalchemy import Column, DateTime, Integer, String, Text, create_engine
from sqlalchemy.orm import declarative_base, sessionmaker

load_dotenv()

# Lazy engine/session setup: don't require DATABASE_URL at import time so
# Alembic can import `Base` and inspect `Base.metadata` without a DB.
DATABASE_URL = os.getenv("DATABASE_URL")
engine = None
# Create an unbound sessionmaker; it will be configured when an engine is
# available via `init_db()`.
SessionLocal = sessionmaker(autocommit=False, autoflush=False, future=True)
Base = declarative_base()


def init_db(database_url: str | None = None):
    """Initialize the SQLAlchemy engine and bind it to SessionLocal.

    If `database_url` is omitted, the `DATABASE_URL` environment variable
    will be used. This function is idempotent and safe to call multiple
    times; it only creates the engine on first call when a URL is present.
    Returns the engine object or None if no URL was available.
    """
    global engine
    if engine is not None:
        return engine

    url = database_url or os.getenv("DATABASE_URL")
    if not url:
        return None

    engine = create_engine(url, future=True)
    SessionLocal.configure(bind=engine)
    return engine


def get_engine():
    """Return the active SQLAlchemy engine, or None if not initialised."""
    return engine


class Scan(Base):
    __tablename__ = "scans"

    id = Column(String(36), primary_key=True, nullable=False)
    owner_email = Column(String(320), nullable=True, index=True)
    target = Column(String(512), nullable=False, index=True)
    status = Column(String(20), nullable=False, index=True)
    port_range = Column(String(100), nullable=True)
    risk_score = Column(Integer, nullable=True)
    risk_label = Column(String(20), nullable=True)
    current_module = Column(String(50), nullable=True)
    result_json = Column(Text, nullable=True)
    error_message = Column(Text, nullable=True)
    started_at = Column(DateTime(timezone=True), nullable=True, index=True)
    completed_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)

    @property
    def duration_seconds(self) -> float | None:
        if self.started_at is None or self.completed_at is None:
            return None
        return (self.completed_at - self.started_at).total_seconds()

    @property
    def result(self) -> dict | None:
        if not self.result_json:
            return None
        try:
            return json.loads(self.result_json)
        except json.JSONDecodeError:
            return None

    def __repr__(self) -> str:
        return f"<Scan id={self.id} target={self.target} status={self.status}>"
