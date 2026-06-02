"""
routers/targets.py
------------------
Routes for viewing scan history grouped by target.
While scans.py is about individual scan runs, this router
is about the targets themselves across multiple scans over time.
 
Every route in this file lives under the /api/targets prefix.
 
CONTAINS:
 
  GET /api/targets
  ----------------
  Returns all unique targets that have ever been scanned,
  with the most recent scan result for each.
 
  Returns:
    [
      {
        "target": "example.com",
        "last_scanned": "2024-01-15T10:30:00Z",
        "last_risk_score": 72,
        "last_risk_label": "HIGH",
        "total_scans": 5
      },
      ...
    ]
 
  Use a GROUP BY query on the scans table, grouping by target,
  selecting the max started_at as last_scanned and the corresponding
  risk_score from that most recent scan.
 
  GET /api/targets/{target}/history
  -----------------------------------
  Returns all scan runs ever performed against a specific target,
  ordered by started_at descending.
 
  Path parameter:
    target — the domain or IP string e.g. "example.com"
             URL-encode dots if needed: "example%2Ecom"
 
  Returns:
    {
      "target": "example.com",
      "scans": [
        {
          "scan_id": "...",
          "status": "complete",
          "risk_score": 72,
          "risk_label": "HIGH",
          "started_at": "...",
          "completed_at": "..."
        },
        ...
      ]
    }
 
  If no scans exist for this target, return 404.
 
  GET /api/targets/{target}/latest
  ---------------------------------
  Returns the most recent COMPLETE scan result for a target.
  Skips failed or pending scans.
 
  Returns the full ScanReport JSON of the latest completed scan.
  Returns 404 if no completed scan exists for this target.
 
  This is useful for the MCP server — when Claude asks
  "what is the current security posture of example.com?",
  the MCP tool calls this endpoint to get the latest result
  without triggering a new scan.
 
NOTE:
  These routes are read-only — no scanning happens here.
  All routes just query the database and return stored results.
  Keep the queries efficient — add a database index on the
  target column of the scans table (done in db/models.py).
"""