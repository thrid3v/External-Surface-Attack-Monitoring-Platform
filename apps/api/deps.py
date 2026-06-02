"""
deps.py
-------
FastAPI dependency functions — small reusable pieces injected into
routes via FastAPI's Depends() system.
 
Think of these as middleware that runs before your route handler.
Instead of opening a database connection inside every route function,
you define it once here and inject it wherever it is needed.
 
CONTAINS:
 
  def get_db() -> Generator[Session, None, None]
  -----------------------------------------------
  Yields a SQLAlchemy database session for use within a single request.
  Automatically closes the session when the request is done,
  whether it succeeded or raised an exception.
 
  Pattern:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
 
  HOW TO USE IN A ROUTE:
    from fastapi import Depends
    from sqlalchemy.orm import Session
    from deps import get_db
 
    @router.get("/scans/{scan_id}")
    def get_scan(scan_id: str, db: Session = Depends(get_db)):
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        ...
 
  Every route that touches the database injects this.
  Never create SessionLocal() directly inside a route function.
 
FUTURE ADDITIONS:
  If you add authentication later, put the get_current_user()
  dependency here too. It will validate the JWT token and return
  the current user, injectable the same way as get_db().
"""
 