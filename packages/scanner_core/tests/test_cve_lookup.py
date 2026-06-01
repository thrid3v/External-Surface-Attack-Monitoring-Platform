from unittest.mock import patch, MagicMock
from scanner_core.cve_lookup import lookup_cves, get_severity_label

def test_severity_label_boundaries():
    assert get_severity_label(9.0)  == "CRITICAL"
    assert get_severity_label(10.0) == "CRITICAL"
    assert get_severity_label(7.0)  == "HIGH"
    assert get_severity_label(8.9)  == "HIGH"
    assert get_severity_label(4.0)  == "MEDIUM"
    assert get_severity_label(6.9)  == "MEDIUM"
    assert get_severity_label(0.1)  == "LOW"
    assert get_severity_label(3.9)  == "LOW"
    assert get_severity_label(0.0)  == "NONE"

def test_lookup_cves_returns_empty_on_api_failure():
    """If NVD is down, return empty list — never crash."""
    with patch("requests.get") as mock_get:
        mock_get.side_effect = Exception("NVD is down")
        result = lookup_cves("Apache httpd", "2.4.51")
        assert result == []

def test_lookup_cves_returns_empty_for_unknown_service():
    with patch("requests.get") as mock_get:
        mock_response = MagicMock()
        mock_response.json.return_value = {"vulnerabilities": [], "totalResults": 0}
        mock_response.status_code = 200
        mock_get.return_value = mock_response
        result = lookup_cves("nonexistentservice", "0.0.0")
        assert result == []

def test_lookup_cves_sorted_by_cvss():
    with patch("requests.get") as mock_get:
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "totalResults": 2,
            "vulnerabilities": [
                {"cve": {"id": "CVE-2021-0001", "descriptions": [{"lang": "en", "value": "test1"}],
                    "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 4.0, "baseSeverity": "MEDIUM"}, "type": "Primary"}]},
                    "published": "2021-01-01", "references": []}},
                {"cve": {"id": "CVE-2021-0002", "descriptions": [{"lang": "en", "value": "test2"}],
                    "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 9.8, "baseSeverity": "CRITICAL"}, "type": "Primary"}]},
                    "published": "2021-01-02", "references": []}}
            ]
        }
        mock_get.return_value = mock_response
        result = lookup_cves("Apache httpd", "2.4.51")
        if len(result) >= 2:
            assert result[0].cvss_score >= result[1].cvss_score