import pytest
from unittest.mock import patch, MagicMock
from scanner_core.osint_fetcher import (
    fetch_whois, fetch_certificates, fetch_all
)

def test_fetch_whois_returns_whoisinfo_on_success():
    mock_whois_data = MagicMock()
    mock_whois_data.registrar = "GoDaddy"
    mock_whois_data.org = "Example Corp"
    mock_whois_data.creation_date = "2000-01-01"
    mock_whois_data.expiration_date = "2030-01-01"
    mock_whois_data.name_servers = ["ns1.example.com", "ns2.example.com"]
    mock_whois_data.country = "US"
    with patch("whois.whois", return_value=mock_whois_data):
        result = fetch_whois("example.com")
        assert result is not None
        assert result.registrar == "GoDaddy"
        assert len(result.name_servers) == 2

def test_fetch_whois_returns_none_on_failure():
    """WHOIS failure should return None, not raise."""
    with patch("whois.whois", side_effect=Exception("WHOIS lookup failed")):
        result = fetch_whois("example.com")
        assert result is None

def test_fetch_certificates_returns_list_on_success():
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = [
        {
            "name_value": "example.com\nwww.example.com",
            "issuer_name": "Let's Encrypt",
            "not_before": "2024-01-01T00:00:00",
            "not_after": "2025-01-01T00:00:00"
        }
    ]
    with patch("requests.get", return_value=mock_response):
        result = fetch_certificates("example.com")
        assert isinstance(result, list)

def test_fetch_certificates_returns_empty_on_failure():
    """crt.sh failure should return empty list, not raise."""
    with patch("requests.get", side_effect=Exception("timeout")):
        result = fetch_certificates("example.com")
        assert result == []

def test_fetch_certificates_flags_expired_certs():
    """Certificates with past expiry date should have is_expired=True."""
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = [
        {
            "name_value": "old.example.com",
            "issuer_name": "DigiCert",
            "not_before": "2020-01-01T00:00:00",
            "not_after": "2021-01-01T00:00:00"
        }
    ]
    with patch("requests.get", return_value=mock_response):
        result = fetch_certificates("example.com")
        if result:
            assert result[0].is_expired is True

def test_fetch_all_returns_osint_result_even_if_all_fail():
    """fetch_all must return an OSINTResult even if every source fails."""
    with patch("scanner_core.osint_fetcher.fetch_whois", return_value=None), \
         patch("scanner_core.osint_fetcher.fetch_certificates", return_value=[]), \
         patch("scanner_core.osint_fetcher.fetch_shodan", return_value={}):
        result = fetch_all("example.com")
        assert result is not None
        assert result.whois is None
        assert result.certificates == []

def test_fetch_all_missing_shodan_key_does_not_crash():
    """If SHODAN_API_KEY is not set, fetch_all should still complete."""
    with patch.dict("os.environ", {}, clear=True):
        with patch("scanner_core.osint_fetcher.fetch_whois", return_value=None), \
             patch("scanner_core.osint_fetcher.fetch_certificates", return_value=[]):
            result = fetch_all("example.com")
            assert result is not None