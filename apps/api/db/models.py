"""
db/models.py
------------
SQLAlchemy ORM models — the database table definitions.
This file defines what gets stored in PostgreSQL.
 
Also contains the database engine setup and session factory
used across the application.
 
CONTAINS:
 
  Engine and session setup
  ------------------------
  DATABASE_URL = os.getenv("DATABASE_URL")
  engine = create_engine(DATABASE_URL)
  SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
  Base = declarative_base()
 
  These three are imported by:
    - main.py         (to create tables on startup)
    - deps.py         (to get DB sessions per request)
    - scan_worker.py  (to write scan results)
 
  class Scan(Base)
  ----------------
  The main table. One row per scan run.
 
  Columns:
    id            String (UUID)     primary key, generated in Python with uuid4()
    target        String(512)       the domain or IP being scanned
                                    add an Index on this column for fast lookups
    status        String(20)        "pending" | "running" | "complete" | "failed"
    port_range    String(100)       e.g. "1-1000", stored for reference
    risk_score    Integer           nullable, populated when scan completes
    risk_label    String(20)        nullable, "CRITICAL"|"HIGH"|"MEDIUM"|"LOW"|"MINIMAL"
    current_module String(50)       the module currently running, for progress updates
    result_json   Text              the full ScanReport as a JSON string
                                    nullable — only set when status="complete"
    error_message Text              nullable — only set when status="failed"
    started_at    DateTime          when the scan started, timezone-aware UTC
    completed_at  DateTime          nullable, when the scan finished
    created_at    DateTime          when the row was inserted (for ordering history)
 
  Table name: "scans"
 
  Add these indexes for query performance:
    Index on target    — GET /api/targets/{target}/history queries by target
    Index on status    — filtering pending/running scans
    Index on started_at — ordering by recency
 
  Properties / helper methods on the Scan class:
    @property
    def duration_seconds(self) -> float | None:
      Returns completed_at - started_at in seconds.
      Returns None if scan is not complete.
 
    @property
    def result(self) -> dict | None:
      Deserialises result_json back to a dict using json.loads().
      Returns None if result_json is not set.
      Use this in routes instead of manually parsing JSON everywhere.
 
  def __repr__(self):
    Return a readable string like:
    <Scan id=abc123 target=example.com status=complete>
 
NOTE ON MIGRATIONS:
  After defining this model, run Alembic to create the table:
    alembic revision --autogenerate -m "create scans table"
    alembic upgrade head
 
  The alembic.ini file in apps/api/ must point to the same DATABASE_URL.
  In alembic/env.py set:
    from db.models import Base
    target_metadata = Base.metadata
 
  This tells Alembic to detect changes to the ORM models automatically.
 
IMPORTS NEEDED:
  import os, uuid, json
  from datetime import datetime, timezone
  from sqlalchemy import (
      Column, String, Integer, Text, DateTime, Index, create_engine
  )
  from sqlalchemy.orm import sessionmaker, declarative_base
  from dotenv import load_dotenv
"""