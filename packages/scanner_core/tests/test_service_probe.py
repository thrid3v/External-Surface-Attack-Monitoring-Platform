from scanner_core.service_probe import check_security_headers

def test_all_headers_present_returns_empty():
    headers = {
        "Content-Security-Policy": "default-src 'self'",
        "X-Frame-Options": "DENY",
        "Strict-Transport-Security": "max-age=31536000",
        "X-Content-Type-Options": "nosniff",
        "Referrer-Policy": "strict-origin-when-cross-origin",
        "Permissions-Policy": "geolocation=()"
    }
    missing = check_security_headers(headers)
    assert missing == []

def test_missing_headers_are_reported():
    headers = {"X-Frame-Options": "DENY"}
    missing = check_security_headers(headers)
    assert "Content-Security-Policy" in missing
    assert "Strict-Transport-Security" in missing
    assert "X-Frame-Options" not in missing

def test_empty_headers_returns_all_missing():
    missing = check_security_headers({})
    assert len(missing) == 6