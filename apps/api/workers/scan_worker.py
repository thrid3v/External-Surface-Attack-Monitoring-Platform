import json
import logging
import os
import sys
import time
import uuid
from dataclasses import dataclass, field
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
# Global per-scan time budget. The pipeline runs every module to completion;
# accuracy/coverage is prioritised over speed, so this is generous. The worker
# never *starts* a new module past this budget, then finalises a (partial)
# report from whatever ran — a scan never returns empty due to a slow host.
SCAN_TIMEOUT_SECONDS = int(os.getenv("SCAN_TIMEOUT", "1200"))
# A module already in flight when the budget is reached still runs to its own
# cap (the largest is nuclei at 240s); these slack windows keep Celery's hard
# limit and the stuck-scan reaper from killing such a legitimately long scan.
MODULE_OVERRUN_SLACK_SECONDS = 300

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
    # the in-task budget check is the active safeguard.) Sized to allow one
    # in-flight module to finish past the budget without Celery killing the task.
    task_soft_time_limit=SCAN_TIMEOUT_SECONDS + MODULE_OVERRUN_SLACK_SECONDS - 30,
    task_time_limit=SCAN_TIMEOUT_SECONDS + MODULE_OVERRUN_SLACK_SECONDS,
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


# Reaper grace must exceed the budget overrun slack so it never reaps a scan
# that is legitimately finishing a long in-flight module.
REAP_BUFFER_SECONDS = MODULE_OVERRUN_SLACK_SECONDS + 60

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


@dataclass
class ScanContext:
    """Mutable state shared across scan modules as the pipeline runs.

    Each step reads what earlier steps produced and writes its own outputs here,
    so the worker can run modules in a uniform loop and finalise a report from
    whatever has been collected — even when the run is truncated by the budget.
    """

    target: str
    port_range: str
    ports: list = field(default_factory=list)
    dns_records: list = field(default_factory=list)
    subdomains: list = field(default_factory=list)
    zone_transfer_vulnerable: bool = False
    zone_transfer_records: list = field(default_factory=list)
    osint: object | None = None
    http_findings: list = field(default_factory=list)
    findings: list = field(default_factory=list)
    errors: dict[str, str] = field(default_factory=dict)
    modules_run: list[str] = field(default_factory=list)


def _step_port_scanner(ctx: ScanContext) -> None:
    ctx.ports = scan_ports(ctx.target, ctx.port_range)
    logger.info("scan_worker: port_scanner found %d ports", len(ctx.ports))


def _step_cve_lookup(ctx: ScanContext) -> None:
    for port in ctx.ports:
        if getattr(port, "product", None) and getattr(port, "version", None):
            port.cves = lookup_cves(port.product, port.version)


def _step_dns_enum(ctx: ScanContext) -> None:
    data = run_dns_enum(ctx.target)
    if isinstance(data, dict):
        ctx.dns_records = data.get("dns_records", [])
        ctx.subdomains = data.get("subdomains", [])
        ctx.zone_transfer_vulnerable = bool(data.get("zone_transfer_vulnerable"))
        ctx.zone_transfer_records = data.get("zone_transfer_records", [])


def _step_osint_fetcher(ctx: ScanContext) -> None:
    ctx.osint = fetch_all(ctx.target)


def _step_service_probe(ctx: ScanContext) -> None:
    ctx.http_findings = probe_all_http_ports(ctx.target, ctx.ports)
    ctx.findings.extend(audit_all_tls(ctx.target, ctx.ports))


def _step_web_audit(ctx: ScanContext) -> None:
    ctx.findings.extend(audit_web(ctx.target, ctx.ports))


def _step_web_vuln_probe(ctx: ScanContext) -> None:
    ctx.findings.extend(probe_web_vulns(ctx.target, ctx.ports))


def _step_secret_scan(ctx: ScanContext) -> None:
    ctx.findings.extend(scan_for_secrets(ctx.target, ctx.ports))


def _step_takeover_check(ctx: ScanContext) -> None:
    names = {getattr(s, "subdomain", None) for s in ctx.subdomains if getattr(s, "subdomain", None)}
    if ctx.osint is not None and getattr(ctx.osint, "subdomains_from_certs", None):
        names.update(ctx.osint.subdomains_from_certs)
    names.add(ctx.target)
    ctx.findings.extend(check_takeovers(sorted(n for n in names if n)))


def _step_email_audit(ctx: ScanContext) -> None:
    ctx.findings.extend(audit_email(ctx.target))


def _step_nuclei_scan(ctx: ScanContext) -> None:
    urls = [hf.url for hf in ctx.http_findings if getattr(hf, "url", None)]
    ctx.findings.extend(scan_with_nuclei(urls))


# Maps each MODULE_ORDER entry to the function that runs it against a ScanContext.
# The worker iterates MODULE_ORDER and dispatches through this table, so a module
# is added by appending to MODULE_ORDER and registering its step here.
STEP_FUNCS = {
    "port_scanner": _step_port_scanner,
    "cve_lookup": _step_cve_lookup,
    "dns_enum": _step_dns_enum,
    "osint_fetcher": _step_osint_fetcher,
    "service_probe": _step_service_probe,
    "web_audit": _step_web_audit,
    "web_vuln_probe": _step_web_vuln_probe,
    "secret_scan": _step_secret_scan,
    "takeover_check": _step_takeover_check,
    "email_audit": _step_email_audit,
    "nuclei_scan": _step_nuclei_scan,
}


def _finalize_report(
    db: Session,
    scan: Scan,
    ctx: ScanContext,
    *,
    partial: bool = False,
    partial_reason: str | None = None,
) -> dict:
    """Build, persist, and (when complete) alert on the scan report.

    Single finalise path for both the normal end and a budget-truncated end, so
    collected results are never discarded.
    """
    report = generate_report(
        scan_id=scan.id,
        target=ctx.target,
        started_at=_format_datetime(scan.started_at),
        ports=ctx.ports,
        osint=ctx.osint,
        dns_records=ctx.dns_records,
        subdomains=ctx.subdomains,
        zone_transfer_vulnerable=ctx.zone_transfer_vulnerable,
        zone_transfer_records=ctx.zone_transfer_records,
        http_findings=ctx.http_findings,
        findings=ctx.findings,
        modules_run=ctx.modules_run,
        errors=ctx.errors,
        partial=partial,
        partial_reason=partial_reason,
    )

    scan.status = "complete"
    scan.completed_at = _now()
    scan.result_json = report.model_dump_json()
    scan.risk_score = report.risk_score
    scan.risk_label = report.risk_label
    scan.current_module = None
    _commit_scan(db, scan)

    # Change-detection alerts diff against the previous complete scan; a truncated
    # scan would emit spurious "resolved"/"closed port" alerts, so skip them.
    if not partial:
        try:
            _create_change_alerts(db, scan, report)
        except Exception:
            logger.exception("scan_worker: scan=%s alert generation failed", scan.id)

    logger.info(
        "scan_worker: scan=%s complete partial=%s modules_run=%d",
        scan.id, partial, len(ctx.modules_run),
    )
    return {"status": "complete", "partial": partial}


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
) -> dict:
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
        ctx = ScanContext(target=target, port_range=port_range)
        partial = False
        partial_reason: str | None = None

        for name in MODULE_ORDER:
            if name not in allowed_modules:
                continue
            # Cooperative cancel: stop cleanly at a module boundary.
            if _check_canceled(db, scan):
                return {"status": "canceled"}
            # Global time budget: never *start* a module once the budget is spent.
            # Whatever ran so far is still finalised below as a partial report, so a
            # slow host yields populated results instead of a discarded "failed" scan.
            elapsed = time.monotonic() - start_time
            if elapsed > SCAN_TIMEOUT_SECONDS:
                partial = True
                partial_reason = f"time budget ({SCAN_TIMEOUT_SECONDS}s) reached before {name}"
                logger.warning("scan_worker: scan=%s %s", scan_id, partial_reason)
                break
            _set_module_running(db, scan, name)
            ctx.modules_run.append(name)
            try:
                STEP_FUNCS[name](ctx)
            except Exception as exc:  # one module failing never sinks the scan
                ctx.errors[name] = str(exc)
                logger.exception("scan_worker: scan=%s module=%s failed", scan_id, name)

        return _finalize_report(db, scan, ctx, partial=partial, partial_reason=partial_reason)
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
