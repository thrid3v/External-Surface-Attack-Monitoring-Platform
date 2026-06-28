import uuid
from datetime import datetime, timezone
from scanner_core.report_gen import (
    calculate_risk_score,
    get_risk_label,
    _collect_all_cves,
    _build_severity_summary,
    _get_top_findings,
    generate_report
)

def test_risk_score_zero_with_no_findings():
    score = calculate_risk_score(cves=[], open_port_count=0, http_findings=[])
    assert score == 0

def test_risk_score_caps_at_100():
    from scanner_core.models import CVEResult
    many_criticals = [
        CVEResult(cve_id=f"CVE-2021-{i:04d}", description="x",
                  cvss_score=10.0, severity="CRITICAL")
        for i in range(20)
    ]
    score = calculate_risk_score(
        cves=many_criticals, open_port_count=500, http_findings=[]
    )
    assert score <= 100

def test_risk_label_boundaries():
    assert get_risk_label(100) == "CRITICAL"
    assert get_risk_label(80)  == "CRITICAL"
    assert get_risk_label(79)  == "HIGH"
    assert get_risk_label(60)  == "HIGH"
    assert get_risk_label(59)  == "MEDIUM"
    assert get_risk_label(40)  == "MEDIUM"
    assert get_risk_label(39)  == "LOW"
    assert get_risk_label(20)  == "LOW"
    assert get_risk_label(19)  == "MINIMAL"
    assert get_risk_label(0)   == "MINIMAL"

def test_collect_cves_deduplicates(mock_port_open, mock_cve_critical):
    """Same CVE on two ports should only appear once in output."""
    mock_port_open.cves = [mock_cve_critical]
    port2 = mock_port_open.model_copy()
    port2.port = 443
    port2.cves = [mock_cve_critical]
    result = _collect_all_cves([mock_port_open, port2])
    cve_ids = [c.cve_id for c in result]
    assert len(cve_ids) == len(set(cve_ids))

def test_collect_cves_sorted_by_score(mock_cve_critical, mock_cve_medium):
    from scanner_core.models import PortResult
    port = PortResult(port=80, protocol="tcp", state="open")
    port.cves = [mock_cve_medium, mock_cve_critical]
    result = _collect_all_cves([port])
    assert result[0].cvss_score >= result[-1].cvss_score

def test_severity_summary_always_has_all_keys():
    summary = _build_severity_summary([])
    assert "critical" in summary
    assert "high" in summary
    assert "medium" in summary
    assert "low" in summary

def test_top_findings_respects_limit(mock_cve_critical):
    cves = [mock_cve_critical] * 10
    top = _get_top_findings(cves, limit=5)
    assert len(top) == 5

def test_generate_report_never_raises():
    """generate_report should return a FAILED report, never throw."""
    report = generate_report(
        scan_id=str(uuid.uuid4()),
        target="example.com",
        started_at=datetime.now(timezone.utc).isoformat(),
        ports=None,       # intentionally wrong type
        errors={}
    )
    assert report is not None
    assert report.target == "example.com"

def test_port_scanner_error_yields_unknown_risk():
    """A scan whose foundational port_scanner module errored must not present a
    confident MINIMAL — the attack surface is unknown."""
    report = generate_report(
        scan_id=str(uuid.uuid4()),
        target="example.com",
        started_at=datetime.now(timezone.utc).isoformat(),
        ports=[],
        errors={"port_scanner": "nmap host-timeout reached; results unreliable"},
    )
    assert report.risk_label == "UNKNOWN"
    assert report.risk_score is None


def test_clean_host_without_errors_stays_minimal():
    """0 ports with NO module errors is a legitimately clean host — still MINIMAL."""
    report = generate_report(
        scan_id=str(uuid.uuid4()),
        target="example.com",
        started_at=datetime.now(timezone.utc).isoformat(),
        ports=[],
        errors={},
    )
    assert report.risk_label == "MINIMAL"
    assert report.risk_score == 0


def test_non_foundational_module_error_still_scores():
    """An error in a non-foundational module (e.g. nuclei) keeps a real score —
    the port/CVE/header signals are still meaningful."""
    from scanner_core.models import PortResult
    report = generate_report(
        scan_id=str(uuid.uuid4()),
        target="example.com",
        started_at=datetime.now(timezone.utc).isoformat(),
        ports=[PortResult(port=80, protocol="tcp", state="open")],
        errors={"nuclei_scan": "nuclei binary not found"},
    )
    assert report.risk_label != "UNKNOWN"
    assert isinstance(report.risk_score, int)


def test_generate_report_full_run(
    mock_port_open, mock_cve_critical, mock_osint, mock_http_finding
):
    mock_port_open.cves = [mock_cve_critical]
    report = generate_report(
        scan_id=str(uuid.uuid4()),
        target="example.com",
        started_at=datetime.now(timezone.utc).isoformat(),
        ports=[mock_port_open],
        osint=mock_osint,
        http_findings=[mock_http_finding]
    )
    assert report.status.value == "complete"
    assert report.risk_score > 0
    assert len(report.cves) > 0
    assert report.severity_summary["critical"] == 1

def test_generate_report_propagates_partial_flag():
    """A budget-truncated scan finalises a report flagged partial, so the worker
    can persist real results instead of discarding them."""
    report = generate_report(
        scan_id=str(uuid.uuid4()),
        target="example.com",
        started_at=datetime.now(timezone.utc).isoformat(),
        modules_run=["port_scanner", "cve_lookup"],
        partial=True,
        partial_reason="time budget (1200s) reached before dns_enum",
    )
    assert report.partial is True
    assert report.partial_reason == "time budget (1200s) reached before dns_enum"


def test_generate_report_defaults_to_not_partial():
    report = generate_report(
        scan_id=str(uuid.uuid4()),
        target="example.com",
        started_at=datetime.now(timezone.utc).isoformat(),
    )
    assert report.partial is False
    assert report.partial_reason is None
