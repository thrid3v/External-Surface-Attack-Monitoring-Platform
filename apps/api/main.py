import os
from dotenv import load_dotenv
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from db.models import Base, init_db, get_engine
from routers.scans import router as scans_router
from routers.targets import router as targets_router

load_dotenv()

app = FastAPI(
    title="EASM API",
    version="0.1.0",
    description="External attack surface management API for EASM scans."
)

frontend_url = os.getenv("FRONTEND_URL", "http://localhost:3000")
allowed_origins = [origin.strip() for origin in frontend_url.split(",") if origin.strip()]

app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(scans_router, prefix="/api/scans", tags=["scans"])
app.include_router(targets_router, prefix="/api/targets", tags=["targets"])


@app.on_event("startup")
def on_startup() -> None:
    # Initialise DB engine if DATABASE_URL is available and create tables.
    engine = init_db()
    if engine is None:
        # DB not configured — skip table creation. Alembic/AWS env may handle migrations.
        return
    Base.metadata.create_all(bind=get_engine())


@app.get("/health")
def health_check() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/")
def root() -> dict[str, str]:
    return {
        "message": "EASM API is running.",
        "documentation": "/docs",
    }
