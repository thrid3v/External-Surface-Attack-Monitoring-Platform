"""
main.py
-------
Entry point for the FastAPI application. This is the file uvicorn runs.
It creates the FastAPI app instance, registers all routers, sets up CORS,
connects to the database on startup, and defines global middleware.
 
CONTAINS:
 
  app = FastAPI(...)
    Create the app instance with title, version, and description.
    These appear in the auto-generated docs at /docs.
 
  CORS middleware
    Allow requests from the Next.js frontend (localhost:3000 in dev,
    your production domain in prod). Without this the browser will
    block all API calls from the frontend.
    Use CORSMiddleware from fastapi.middleware.cors.
    In dev: allow_origins=["http://localhost:3000"]
    Read the frontend URL from an env variable for production.
 
  @app.on_event("startup")
    Runs once when the server starts.
    Use this to:
      - Create all database tables via SQLAlchemy (Base.metadata.create_all)
      - Log that the server is ready
    Import Base and engine from db/models.py here.
 
  @app.on_event("shutdown")
    Runs once when the server stops.
    Use this to close the database connection pool cleanly.
 
  Router registration
    Include the two routers:
      app.include_router(scans.router,   prefix="/api/scans",   tags=["scans"])
      app.include_router(targets.router, prefix="/api/targets", tags=["targets"])
 
  @app.get("/health")
    A simple health check endpoint that returns {"status": "ok"}.
    Used by Docker and monitoring tools to verify the server is alive.
    No auth required.
 
  @app.get("/")
    Root endpoint, returns a welcome message and link to /docs.
 
ENVIRONMENT VARIABLES USED:
  DATABASE_URL    postgresql://user:password@localhost:5432/easm
  REDIS_URL       redis://localhost:6379/0
  FRONTEND_URL    http://localhost:3000 (for CORS)
 
HOW TO RUN:
  cd apps/api
  uvicorn main:app --reload --port 8000
 
  API docs available at: http://localhost:8000/docs
  OpenAPI JSON at:        http://localhost:8000/openapi.json
"""