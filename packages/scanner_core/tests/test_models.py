from scanner_core.models import (
    PortResult, CVEResult, ScanReport, ScanStatus
)

def test_port_result_defaults():
    """PortResult should instantiate with only required fields."""
    port = PortResult(port=80, protocol="tcp", state="open")
    assert port.cves == []
    assert port.service is None

def test_cve_result_severity_values():
    """CVEResult severity must be one of the valid labels."""
    valid = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE"]
    for severity in valid:
        cve = CVEResult(
            cve_id="CVE-2021-0001",
            description="test",
            severity=severity
        )
        assert cve.severity == severity

def test_scan_report_empty_is_valid():
    """ScanReport should be constructable with just target and scan_id."""
    import uuid
    report = ScanReport(
        scan_id=str(uuid.uuid4()),
        target="example.com",
        status=ScanStatus.PENDING
    )
    assert report.ports == []
    assert report.cves == []
    assert report.errors == {}

def test_scan_report_serialises_to_json():
    """ScanReport.model_dump_json() should not throw."""
    import uuid
    report = ScanReport(
        scan_id=str(uuid.uuid4()),
        target="example.com",
        status=ScanStatus.COMPLETE
    )
    json_str = report.model_dump_json()
    assert "example.com" in json_str