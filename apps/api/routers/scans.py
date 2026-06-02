"""
routers/scans.py
----------------
All API routes related to creating and retrieving scans.
This is the most important router — it is the primary interface
between the Next.js frontend and the scanning backend.
 
Every route in this file lives under the /api/scans prefix
(set in main.py when the router is registered).
 
CONTAINS:
 
  POST /api/scans
  ---------------
  Accepts a scan request from the frontend and queues it for processing.
 
  Request body:
    {
      "target": "example.com",           required — URL, domain, or IP
      "port_range": "1-1000",            optional — defaults to "1-1000"
      "modules": ["ports","cves","dns"]  optional — defaults to all modules
    }
 
  Steps:
    1. Validate the target string — must be a valid domain, IP, or URL.
       Strip protocol (https://) and path (/about) if present.
       Return 422 if the target is empty or clearly invalid.
    2. CONSENT CHECK — this is mandatory.
       For now implement as a simple flag in the request body:
         "i_own_this_target": true
       If false or missing, return 403 with message:
         "You must confirm you own or have permission to scan this target."
       This is the legal gate. Do not skip it.
    3. Create a new Scan record in the database with status="pending".
    4. Queue the Celery task: run_scan.delay(scan_id, target, port_range)
    5. Return immediately with:
       {
         "scan_id": "uuid-here",
         "status": "pending",
         "message": "Scan queued. Poll /api/scans/{scan_id} for results."
       }
    Do NOT wait for the scan to finish — return as soon as it is queued.
    Scans take 30-120 seconds. The frontend polls for results.
 
  GET /api/scans/{scan_id}
  ------------------------
  Returns the current state of a scan by its ID.
 
  If status is "pending" or "running":
    Return:
    {
      "scan_id": "...",
      "status": "running",
      "started_at": "2024-01-01T00:00:00Z"
    }
 
  If status is "complete":
    Return the full ScanReport JSON from the database.
    This is the same shape as scanner_core's ScanReport model.
 
  If status is "failed":
    Return:
    {
      "scan_id": "...",
      "status": "failed",
      "error": "the error message stored in the db"
    }
 
  If scan_id does not exist in the database: return 404.
 
  GET /api/scans/{scan_id}/status
  --------------------------------
  Lightweight polling endpoint — returns only the status and progress,
  not the full result. The frontend calls this every 3 seconds while
  the scan is running to update the progress bar.
 
  Returns:
    {
      "scan_id": "...",
      "status": "running",
      "current_module": "port_scanner",
      "modules_complete": ["dns_enum"],
      "started_at": "..."
    }
 
  GET /api/scans
  --------------
  Returns a list of recent scans (last 20), ordered by started_at descending.
  Used by the frontend to show scan history on the homepage.
 
  Returns:
    [
      { "scan_id": "...", "target": "example.com", "status": "complete",
        "risk_score": 72, "risk_label": "HIGH", "started_at": "..." },
      ...
    ]
  Do NOT return full ScanReport here — just the summary fields.
 
  DELETE /api/scans/{scan_id}
  ---------------------------
  Deletes a scan record from the database.
  Returns 404 if scan_id not found.
  Returns 200 with {"deleted": true} on success.
 
VALIDATION HELPER:
  def _validate_and_clean_target(raw_target: str) -> str:
    Private helper used by POST /api/scans.
    Strips protocol: "https://example.com/path" → "example.com"
    Validates the result is a plausible domain or IP.
    Returns the cleaned target string or raises HTTPException(422).
 
DEPENDENCIES:
  - db session from deps.py (see note below)
  - Celery task from workers/scan_worker.py
  - Scan ORM model from db/models.py
 
NOTE — database session dependency:
  Create a file apps/api/deps.py with a get_db() generator function
  that yields a SQLAlchemy session and closes it after the request.
  Inject it into routes with: db: Session = Depends(get_db)
  Every route that touches the database uses this pattern.
"""