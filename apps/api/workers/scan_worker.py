import json
import logging
import os
import sys
import time
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

from celery import Celery
from celery.exceptions import Reject
from dotenv import load_dotenv
from sqlalchemy import desc
from sqlalchemy.orm import Session

# Ensure the API package and local scanner_core package are on the import path.
API_ROOT = Path(__file__).resolve().parents[1]
PROJECT_ROOT = API_ROOT.parent.parent
PACKAGES_ROOT = PROJECT_ROOT / "packages"

for path in (str(API_ROOT), str(PACKAGES_ROOT)):
    if path not in sys.path:
        sys.path.insert(0, path)

from constants import MODULE_ORDER
from db.models import Alert, Scan, Schedule, SessionLocal
from services import notifications
from services.diff import diff_reports
from scanner_core.cve_lookup import lookup_cves
from scanner_core.dns_enum import run_dns_enum
from scanner_core.osint_fetcher import fetch_all
from scanner_core.port_scanner import scan_ports
from scanner_core.report_gen import generate_report
from scanner_core.service_probe import audit_all_tls, probe_all_http_ports
from scanner_core.web_audit import audit_web
from scanner_core.web_vuln_probe import probe_web_vulns
from scanner_core.secret_scan import scan_for_secrets
from scanner_core.takeover import check_takeovers
from scanner_core.email_audit import audit_email
from scanner_core.nuclei_scan import scan_with_nuclei

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
    # Hard/soft limits so a hung module (e.g. nmap on a huge range) can't run
    # forever. (Enforced via signals on prefork pools; on the Windows solo pool
    # the in-task _maybe_fail_on_timeout check below is the active safeguard.)
    task_soft_time_limit=SCAN_TIMEOUT_SECONDS + 30,
    task_time_limit=SCAN_TIMEOUT_SECONDS + 60,
)

# Periodic dispatcher: every 5 minutes, enqueue any recurring scans that are due.
# Run with: celery -A workers.scan_worker beat
celery_app.conf.beat_schedule = {
    "enqueue-due-scans": {
        "task": "enqueue_due_scans",
        "schedule": 300.0,
    },
    "reap-stuck-scans": {
        "task": "reap_stuck_scans",
        "schedule": 300.0,
    },
}

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)


REAP_BUFFER_SECONDS = 120

def _now() -> datetime:
    return datetime.now(timezone.utc)


def _as_utc(value: datetime | None) -> datetime | None:
    """Normalise a possibly-naive datetime to aware UTC.

    Postgres (timezone=True) returns aware datetimes; SQLite (used in tests)
    returns naive ones. Normalising lets the reaper compare safely on both.
    """
    if value is None:
        return None
    return value if value.tzinfo else value.replace(tzinfo=timezone.utc)


def _format_datetime(value: datetime | None) -> str | None:
    return value.isoformat() if value else None


def _commit_scan(db: Session, scan: Scan) -> None:
    db.add(scan)
    db.commit()
    db.refresh(scan)


def _set_module_running(db: Session, scan: Scan, module_name: str) -> None:
    """Mark *module_name* as the currently executing module.

    This is called **before** the module starts so that the status endpoint
    can correctly report which modules have already completed (everything
    before current_module in MODULE_ORDER) vs the one in progress.
    """
    scan.current_module = module_name
    _commit_scan(db, scan)
    logger.info("scan_worker: scan=%s starting_module=%s", scan.id, module_name)


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


def _check_canceled(db: Session, scan: Scan) -> bool:
    """Return True if the scan has been canceled out-of-band, finalising it.

    The cancel endpoint sets ``status='canceled'`` in a separate process; the
    worker re-reads the row at module boundaries and stops cooperatively.
    """
    db.refresh(scan)
    if scan.status == "canceled":
        scan.completed_at = _now()
        scan.current_module = None
        _commit_scan(db, scan)
        logger.info("scan_worker: scan=%s canceled cooperatively", scan.id)
        return True
    return False


def _aborted(db: Session, scan: Scan, start_time: float) -> str | None:
    """Combined module-boundary guard: returns 'failed', 'canceled', or None."""
    if _maybe_fail_on_timeout(db, scan, start_time):
        return "failed"
    if _check_canceled(db, scan):
        return "canceled"
    return None


def _create_change_alerts(db: Session, scan: Scan, report) -> None:
    """Compare the just-completed scan with the user's previous completed scan
    of the same target and record alerts for newly introduced risk."""
    if not scan.owner_email:
        return
    previous = (
        db.query(Scan)
        .filter(
            Scan.owner_email == scan.owner_email,
            Scan.target == scan.target,
            Scan.status == "complete",
            Scan.id != scan.id,
            Scan.started_at < scan.started_at,
        )
        .order_by(desc(Scan.started_at), desc(Scan.created_at))
        .first()
    )
    if previous is None or previous.result is None:
        return  # first completed scan for this target — nothing to compare against

    diff = diff_reports(previous.result, report.model_dump())
    now = _now()
    alerts: list[Alert] = []

    new_high = [c for c in diff["new_cves"] if (c.get("severity") or "").upper() in ("CRITICAL", "HIGH")]
    if new_high:
        has_critical = any((c.get("severity") or "").upper() == "CRITICAL" for c in new_high)
        alerts.append(Alert(
            id=str(uuid.uuid4()),
            owner_email=scan.owner_email,
            target=scan.target,
            scan_id=scan.id,
            type="new_cve",
            severity="critical" if has_critical else "high",
            message=f"{len(new_high)} new high/critical finding(s) on {scan.target}",
            read=False,
            created_at=now,
        ))

    risk_delta = diff.get("risk_delta")
    if isinstance(risk_delta, int) and risk_delta > 0:
        alerts.append(Alert(
            id=str(uuid.uuid4()),
            owner_email=scan.owner_email,
            target=scan.target,
            scan_id=scan.id,
            type="risk_increase",
            severity="warning",
            message=f"Risk score rose {diff['previous_risk']} -> {diff['current_risk']} on {scan.target}",
            read=False,
            created_at=now,
        ))

    for alert in alerts:
        db.add(alert)
    if alerts:
        db.commit()
        logger.info("scan_worker: scan=%s generated %d alert(s)", scan.id, len(alerts))
        # Deliver out-of-band on a separate task so slow SMTP/webhook I/O never
        # blocks scan completion and each delivery can retry independently.
        for alert in alerts:
            try:
                deliver_alert.delay(alert.id)
            except Exception:
                logger.exception("scan_worker: failed to enqueue delivery for alert=%s", alert.id)


@celery_app.task(
    bind=True,
    name="run_scan",
    max_retries=3,
    default_retry_delay=15,
)
def run_scan(
    self,
    scan_id: str,
    target: str,
    port_range: str = "1-1000",
    modules: list[str] | None = None,
) -> dict[str, str]:
    allowed_modules = [m for m in (modules or MODULE_ORDER) if m in MODULE_ORDER]
    if not allowed_modules:
        allowed_modules = list(MODULE_ORDER)

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
        scan.current_module = None  # will be set right before each module starts
        _commit_scan(db, scan)

        start_time = time.monotonic()
        ports: list = []
        dns_records: list = []
        subdomains: list = []
        zone_transfer_vulnerable: bool = False
        zone_transfer_records: list = []
        osint = None
        http_findings: list = []
        findings: list = []
        errors: dict[str, str] = {}
        # Track which modules actually executed (regardless of success/failure).
        modules_run: list[str] = []

        if "port_scanner" in allowed_modules:
            _set_module_running(db, scan, "port_scanner")
            modules_run.append("port_scanner")
            try:
                ports = scan_ports(target, port_range)
                logger.info("scan_worker: scan=%s port_scanner found %d ports", scan_id, len(ports))
            except Exception as exc:
                errors["port_scanner"] = str(exc)
                ports = []

        aborted = _aborted(db, scan, start_time)
        if aborted:
            return {"status": aborted}

        if "cve_lookup" in allowed_modules:
            _set_module_running(db, scan, "cve_lookup")
            modules_run.append("cve_lookup")
            try:
                for port in ports:
                    if getattr(port, "product", None) and getattr(port, "version", None):
                        port.cves = lookup_cves(port.product, port.version)
                logger.info("scan_worker: scan=%s cve_lookup complete", scan_id)
            except Exception as exc:
                errors["cve_lookup"] = str(exc)

        aborted = _aborted(db, scan, start_time)
        if aborted:
            return {"status": aborted}

        if "dns_enum" in allowed_modules:
            _set_module_running(db, scan, "dns_enum")
            modules_run.append("dns_enum")
            try:
                dns_data = run_dns_enum(target)
                dns_records = dns_data.get("dns_records", []) if isinstance(dns_data, dict) else []
                subdomains = dns_data.get("subdomains", []) if isinstance(dns_data, dict) else []
                zone_transfer_vulnerable = bool(dns_data.get("zone_transfer_vulnerable")) if isinstance(dns_data, dict) else False
                zone_transfer_records = dns_data.get("zone_transfer_records", []) if isinstance(dns_data, dict) else []
                logger.info(
                    "scan_worker: scan=%s dns_enum complete (zone_transfer_vulnerable=%s)",
                    scan_id,
                    zone_transfer_vulnerable,
                )
            except Exception as exc:
                errors["dns_enum"] = str(exc)
                dns_records = []
                subdomains = []
                zone_transfer_vulnerable = False
                zone_transfer_records = []

        aborted = _aborted(db, scan, start_time)
        if aborted:
            return {"status": aborted}

        if "osint_fetcher" in allowed_modules:
            _set_module_running(db, scan, "osint_fetcher")
            modules_run.append("osint_fetcher")
            try:
                osint = fetch_all(target)
                logger.info("scan_worker: scan=%s osint_fetcher complete", scan_id)
            except Exception as exc:
                errors["osint_fetcher"] = str(exc)
                osint = None

        aborted = _aborted(db, scan, start_time)
        if aborted:
            return {"status": aborted}

        if "service_probe" in allowed_modules:
            _set_module_running(db, scan, "service_probe")
            modules_run.append("service_probe")
            try:
                http_findings = probe_all_http_ports(target, ports)
                findings.extend(audit_all_tls(target, ports))
                logger.info("scan_worker: scan=%s service_probe complete", scan_id)
            except Exception as exc:
                errors["service_probe"] = str(exc)
                http_findings = []

        aborted = _aborted(db, scan, start_time)
        if aborted:
            return {"status": aborted}

        if "web_audit" in allowed_modules:
            _set_module_running(db, scan, "web_audit")
            modules_run.append("web_audit")
            try:
                findings.extend(audit_web(target, ports))
                logger.info("scan_worker: scan=%s web_audit found %d findings", scan_id, len(findings))
            except Exception as exc:
                errors["web_audit"] = str(exc)

        aborted = _aborted(db, scan, start_time)
        if aborted:
            return {"status": aborted}

        if "web_vuln_probe" in allowed_modules:
            _set_module_running(db, scan, "web_vuln_probe")
            modules_run.append("web_vuln_probe")
            try:
                findings.extend(probe_web_vulns(target, ports))
                logger.info("scan_worker: scan=%s web_vuln_probe found %d findings", scan_id, len(findings))
            except Exception as exc:
                errors["web_vuln_probe"] = str(exc)

        aborted = _aborted(db, scan, start_time)
        if aborted:
            return {"status": aborted}

        if "secret_scan" in allowed_modules:
            _set_module_running(db, scan, "secret_scan")
            modules_run.append("secret_scan")
            try:
                findings.extend(scan_for_secrets(target, ports))
                logger.info("scan_worker: scan=%s secret_scan found %d findings", scan_id, len(findings))
            except Exception as exc:
                errors["secret_scan"] = str(exc)

        aborted = _aborted(db, scan, start_time)
        if aborted:
            return {"status": aborted}

        if "takeover_check" in allowed_modules:
            _set_module_running(db, scan, "takeover_check")
            modules_run.append("takeover_check")
            try:
                names = {getattr(s, "subdomain", None) for s in subdomains if getattr(s, "subdomain", None)}
                if osint is not None and getattr(osint, "subdomains_from_certs", None):
                    names.update(osint.subdomains_from_certs)
                names.add(target)
                findings.extend(check_takeovers(sorted(n for n in names if n)))
            except Exception as exc:
                errors["takeover_check"] = str(exc)

        aborted = _aborted(db, scan, start_time)
        if aborted:
            return {"status": aborted}

        if "email_audit" in allowed_modules:
            _set_module_running(db, scan, "email_audit")
            modules_run.append("email_audit")
            try:
                findings.extend(audit_email(target))
            except Exception as exc:
                errors["email_audit"] = str(exc)

        aborted = _aborted(db, scan, start_time)
        if aborted:
            return {"status": aborted}

        if "nuclei_scan" in allowed_modules:
            _set_module_running(db, scan, "nuclei_scan")
            modules_run.append("nuclei_scan")
            try:
                nuclei_urls = [hf.url for hf in http_findings if getattr(hf, "url", None)]
                findings.extend(scan_with_nuclei(nuclei_urls))
            except Exception as exc:
                errors["nuclei_scan"] = str(exc)

        aborted = _aborted(db, scan, start_time)
        if aborted:
            return {"status": aborted}

        report = generate_report(
            scan_id=scan_id,
            target=target,
            started_at=_format_datetime(scan.started_at),
            ports=ports,
            osint=osint,
            dns_records=dns_records,
            subdomains=subdomains,
            zone_transfer_vulnerable=zone_transfer_vulnerable,
            zone_transfer_records=zone_transfer_records,
            http_findings=http_findings,
            findings=findings,
            modules_run=modules_run,
            errors=errors,
        )

        scan.status = "complete"
        scan.completed_at = _now()
        scan.result_json = report.model_dump_json()
        scan.risk_score = report.risk_score
        scan.risk_label = report.risk_label
        scan.current_module = None
        _commit_scan(db, scan)

        try:
            _create_change_alerts(db, scan, report)
        except Exception:
            logger.exception("scan_worker: scan=%s alert generation failed", scan_id)

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


def _reap_stuck_scans(db: Session, now: datetime | None = None, timeout_seconds: int | None = None) -> int:
    """Mark scans stuck in pending/running past the time limit as failed.

    Age is measured from ``started_at`` for running scans and ``created_at`` for
    pending ones (running scans always have ``started_at`` set; pending ones fall
    back to ``created_at``). Returns the number of scans reaped.
    """
    now = now or _now()
    limit = (timeout_seconds if timeout_seconds is not None else SCAN_TIMEOUT_SECONDS) + REAP_BUFFER_SECONDS
    cutoff = now - timedelta(seconds=limit)

    stuck = db.query(Scan).filter(Scan.status.in_(("pending", "running"))).all()
    reaped = 0
    for scan in stuck:
        reference = _as_utc(scan.started_at or scan.created_at)
        if reference is None or reference > cutoff:
            continue
        scan.status = "failed"
        scan.error_message = "Reaped: exceeded time limit (worker may have stopped)"
        scan.completed_at = now
        scan.current_module = None
        reaped += 1
    if reaped:
        db.commit()
        logger.info("scan_worker: reaped %d stuck scan(s)", reaped)
    return reaped


@celery_app.task(name="reap_stuck_scans")
def reap_stuck_scans() -> dict[str, int]:
    """Beat-driven recovery: fail scans that a dead worker left in pending/running."""
    db = SessionLocal()
    try:
        return {"reaped": _reap_stuck_scans(db)}
    finally:
        db.close()


@celery_app.task(name="deliver_alert", bind=True, max_retries=2, default_retry_delay=30)
def deliver_alert(self, alert_id: str) -> dict[str, bool]:
    """Deliver a single alert out-of-band via the user's configured channels."""
    db = SessionLocal()
    try:
        alert = db.query(Alert).filter(Alert.id == alert_id).first()
        if alert is None:
            logger.warning("scan_worker: deliver_alert: alert not found: %s", alert_id)
            return {"delivered": False}
        notifications.deliver_alert(db, alert)
        return {"delivered": True}
    finally:
        db.close()


@celery_app.task(name="enqueue_due_scans")
def enqueue_due_scans() -> dict[str, int]:
    """Beat-driven dispatcher: enqueue a scan for every recurring schedule whose
    next_run_at is due, then advance the schedule's next_run_at."""
    db = SessionLocal()
    queued = 0
    try:
        now = _now()
        due = (
            db.query(Schedule)
            .filter(Schedule.enabled.is_(True), Schedule.next_run_at <= now)
            .all()
        )
        for schedule in due:
            scan_id = str(uuid.uuid4())
            port_range = schedule.port_range or "1-1000"
            modules = schedule.modules_list or list(MODULE_ORDER)
            scan = Scan(
                id=scan_id,
                owner_email=schedule.owner_email,
                target=schedule.target,
                status="pending",
                port_range=port_range,
                created_at=now,
            )
            db.add(scan)
            schedule.last_run_at = now
            schedule.next_run_at = now + timedelta(minutes=schedule.interval_minutes)
            db.commit()
            run_scan.apply_async(
                args=[scan_id, schedule.target, port_range, modules],
                task_id=scan_id,
            )
            queued += 1
            logger.info("scan_worker: enqueued scheduled scan=%s target=%s", scan_id, schedule.target)
        return {"queued": queued}
    finally:
        db.close()
