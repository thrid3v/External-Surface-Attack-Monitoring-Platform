import json
import logging
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

from celery import Celery
from celery.exceptions import Reject
from dotenv import load_dotenv
from sqlalchemy.orm import Session

# Ensure the API package and local scanner_core package are on the import path.
API_ROOT = Path(__file__).resolve().parents[1]
PROJECT_ROOT = API_ROOT.parent.parent
PACKAGES_ROOT = PROJECT_ROOT / "packages"

for path in (str(API_ROOT), str(PACKAGES_ROOT)):
    if path not in sys.path:
        sys.path.insert(0, path)

from db.models import Scan, SessionLocal
from scanner_core.cve_lookup import lookup_cves
from scanner_core.dns_enum import run_dns_enum
from scanner_core.osint_fetcher import fetch_all
from scanner_core.port_scanner import scan_ports
from scanner_core.report_gen import generate_report
from scanner_core.service_probe import probe_all_http_ports

load_dotenv(dotenv_path=PROJECT_ROOT / ".env")

REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")
SCAN_TIMEOUT_SECONDS = int(os.getenv("SCAN_TIMEOUT", "300"))

# Initialise DB engine for worker process if available. Do not raise
# here — allow the worker to start even if DATABASE_URL is not set.
from db.models import init_db
init_db()

celery_app = Celery(
    "workers.scan_worker",
    broker=REDIS_URL,
    backend=REDIS_URL,
)
celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
)

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)

MODULE_ORDER = [
    "port_scanner",
    "cve_lookup",
    "dns_enum",
    "osint_fetcher",
    "service_probe",
]


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _format_datetime(value: datetime | None) -> str | None:
    return value.isoformat() if value else None


def _commit_scan(db: Session, scan: Scan) -> None:
    db.add(scan)
    db.commit()
    db.refresh(scan)


def _update_scan_progress(db: Session, scan: Scan, module_name: str) -> None:
    scan.current_module = module_name
    _commit_scan(db, scan)
    logger.info("scan_worker: scan=%s current_module=%s", scan.id, module_name)


def _maybe_fail_on_timeout(db: Session, scan: Scan, start_time: float) -> bool:
    elapsed = time.monotonic() - start_time
    if elapsed > SCAN_TIMEOUT_SECONDS:
        scan.status = "failed"
        scan.error_message = f"Scan timed out after {elapsed:.1f} seconds"
        scan.completed_at = _now()
        _commit_scan(db, scan)
        logger.error("scan_worker: scan=%s timed out after %s seconds", scan.id, elapsed)
        return True
    return False


@celery_app.task(bind=True, name="run_scan")
def run_scan(self, scan_id: str, target: str, port_range: str = "1-1000", modules: list[str] | None = None) -> dict[str, str]:
    allowed_modules = [module for module in (modules or MODULE_ORDER) if module in MODULE_ORDER]
    if not allowed_modules:
        allowed_modules = MODULE_ORDER.copy()

    db = SessionLocal()
    try:
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if scan is None:
            message = f"Scan not found: {scan_id}"
            logger.error("scan_worker: %s", message)
            raise Reject(message, requeue=False)

        scan.status = "running"
        scan.started_at = _now()
        scan.error_message = None
        scan.current_module = allowed_modules[0]
        _commit_scan(db, scan)

        start_time = time.monotonic()
        ports: list = []
        dns_records: list = []
        subdomains: list = []
        osint = None
        http_findings: list = []
        errors: dict[str, str] = {}

        if "port_scanner" in allowed_modules:
            try:
                ports = scan_ports(target, port_range)
                _update_scan_progress(db, scan, "port_scanner")
            except Exception as exc:
                errors["port_scanner"] = str(exc)
                ports = []

        if _maybe_fail_on_timeout(db, scan, start_time):
            return {"status": "failed"}

        if "cve_lookup" in allowed_modules:
            try:
                for port in ports:
                    if getattr(port, "product", None) and getattr(port, "version", None):
                        port.cves = lookup_cves(port.product, port.version)
                _update_scan_progress(db, scan, "cve_lookup")
            except Exception as exc:
                errors["cve_lookup"] = str(exc)

        if _maybe_fail_on_timeout(db, scan, start_time):
            return {"status": "failed"}

        if "dns_enum" in allowed_modules:
            try:
                dns_data = run_dns_enum(target)
                dns_records = dns_data.get("dns_records", []) if isinstance(dns_data, dict) else []
                subdomains = dns_data.get("subdomains", []) if isinstance(dns_data, dict) else []
                _update_scan_progress(db, scan, "dns_enum")
            except Exception as exc:
                errors["dns_enum"] = str(exc)
                dns_records = []
                subdomains = []

        if _maybe_fail_on_timeout(db, scan, start_time):
            return {"status": "failed"}

        if "osint_fetcher" in allowed_modules:
            try:
                osint = fetch_all(target)
                _update_scan_progress(db, scan, "osint_fetcher")
            except Exception as exc:
                errors["osint_fetcher"] = str(exc)
                osint = None

        if _maybe_fail_on_timeout(db, scan, start_time):
            return {"status": "failed"}

        if "service_probe" in allowed_modules:
            try:
                http_findings = probe_all_http_ports(target, ports)
                _update_scan_progress(db, scan, "service_probe")
            except Exception as exc:
                errors["service_probe"] = str(exc)
                http_findings = []

        if _maybe_fail_on_timeout(db, scan, start_time):
            return {"status": "failed"}

        report = generate_report(
            scan_id=scan_id,
            target=target,
            started_at=_format_datetime(scan.started_at),
            ports=ports,
            osint=osint,
            dns_records=dns_records,
            subdomains=subdomains,
            http_findings=http_findings,
            errors=errors,
        )

        scan.status = "complete"
        scan.completed_at = _now()
        scan.result_json = report.model_dump_json()
        scan.risk_score = report.risk_score
        scan.risk_label = report.risk_label
        scan.current_module = None
        _commit_scan(db, scan)

        logger.info("scan_worker: scan=%s complete status=complete", scan_id)
        return {"status": "complete"}
    except Exception as exc:
        if 'scan' in locals() and scan is not None:
            scan.status = "failed"
            scan.error_message = str(exc)
            scan.completed_at = _now()
            _commit_scan(db, scan)
        logger.exception("scan_worker: scan=%s failed with exception", scan_id)
        raise
    finally:
        db.close()
