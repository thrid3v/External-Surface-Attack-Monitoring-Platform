"""
workers/scan_worker.py
-----------------------
The Celery task that actually runs the scan.
This is the bridge between the API (which queues jobs) and
scanner_core (which does the work).
 
When POST /api/scans is called, it queues this task.
Celery picks it up from the Redis queue and runs it in a
background worker process — completely separate from the API process.
 
HOW CELERY WORKS HERE:
  The API process calls:     run_scan.delay(scan_id, target, port_range)
  Celery worker picks it up: runs run_scan(scan_id, target, port_range)
  Results are written to:    PostgreSQL (not Celery's result backend)
 
CONTAINS:
 
  celery_app = Celery(...)
    Create the Celery app instance.
    Broker:  Redis (REDIS_URL from env) — where tasks are queued
    Backend: Redis (REDIS_URL from env) — where task states are stored
    Configure task_serializer="json" and accept_content=["json"]
 
  @celery_app.task(bind=True, name="run_scan")
  def run_scan(self, scan_id: str, target: str, port_range: str = "1-1000")
  ---------------------------------------------------------------------------
  The main Celery task. bind=True gives access to self for status updates.
 
  Steps in order:
    1. Open a database session
       Update the scan record: status="running", started_at=now()
 
    2. Initialize an errors dict: errors = {}
 
    3. Run port_scanner
       Try:
         ports = scan_ports(target, port_range)
         _update_scan_progress(scan_id, "port_scanner", db)
       Except:
         errors["port_scanner"] = str(e)
         ports = []
 
    4. Run cve_lookup for each port that has a product+version
       Try:
         for port in ports:
             if port.product and port.version:
                 port.cves = lookup_cves(port.product, port.version)
         _update_scan_progress(scan_id, "cve_lookup", db)
       Except:
         errors["cve_lookup"] = str(e)
 
    5. Run dns_enum
       Try:
         dns_data = run_dns_enum(target)
         dns_records = dns_data.get("dns_records", [])
         subdomains = dns_data.get("subdomains", [])
         _update_scan_progress(scan_id, "dns_enum", db)
       Except:
         errors["dns_enum"] = str(e)
         dns_records, subdomains = [], []
 
    6. Run osint_fetcher
       Try:
         osint = fetch_all(target)
         _update_scan_progress(scan_id, "osint_fetcher", db)
       Except:
         errors["osint_fetcher"] = str(e)
         osint = None
 
    7. Run service_probe
       Try:
         http_findings = probe_all_http_ports(target, ports)
         _update_scan_progress(scan_id, "service_probe", db)
       Except:
         errors["service_probe"] = str(e)
         http_findings = []
 
    8. Run report_gen
       report = generate_report(
           scan_id=scan_id,
           target=target,
           started_at=<the started_at from step 1>,
           ports=ports,
           osint=osint,
           dns_records=dns_records,
           subdomains=subdomains,
           http_findings=http_findings,
           errors=errors
       )
 
    9. Save report to database
       Update the scan record:
         status = "complete"
         completed_at = now()
         result_json = report.model_dump_json()
         risk_score = report.risk_score
         risk_label = report.risk_label
 
    10. Close the database session
 
  FAILURE HANDLING:
    Wrap the entire task in a top-level try/except.
    If anything catastrophic happens (db connection lost etc.):
      Update scan record: status="failed", error_message=str(e)
    Never let the task crash silently — always update the DB status.
 
  def _update_scan_progress(scan_id: str, module_name: str, db: Session)
  ------------------------------------------------------------------------
  Private helper called after each module completes.
  Updates the scan record's current_module field in the database
  so the frontend progress bar can show which module is running.
  Example: current_module = "cve_lookup"
 
HOW TO RUN THE WORKER (separate terminal from the API):
  cd apps/api
  venv/Scripts/Activate.ps1
  celery -A workers.scan_worker worker --loglevel=info
 
  You should see:
    [tasks]
      . run_scan
    [2024-...] celery@hostname ready.
 
IMPORTANT:
  - Import scanner_core modules at the top of this file — they are
    available because scanner_core is in the Python path.
  - Each step must be independent. If port_scanner fails, cve_lookup,
    dns_enum etc. must still run. The errors dict captures what failed.
  - Log the start and end of every step with logger.info() including
    how many results were returned e.g. "port_scanner: 7 open ports found"
  - Add a SCAN_TIMEOUT environment variable (default 300 seconds).
    If the full task takes longer than this, mark it as failed.
"""