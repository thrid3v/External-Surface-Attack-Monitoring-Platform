from dotenv import load_dotenv

load_dotenv()


def get_db():
    # Lazy-init DB engine before creating a session.
    from db.models import init_db, SessionLocal

    engine = init_db()
    if engine is None:
        raise RuntimeError("DATABASE_URL is not configured; cannot create DB session")

    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
