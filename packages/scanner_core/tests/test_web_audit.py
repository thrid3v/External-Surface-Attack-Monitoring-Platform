import httpx
import respx

from scanner_core.models import PortResult
from scanner_core.web_audit import audit_web


@respx.mock
def test_audit_web_flags_directory_listing_after_refactor():
    respx.get("http://h.test:80/").mock(
        return_value=httpx.Response(200, text="<title>Index of /</title>")
    )
    respx.get(url__regex=r".*").mock(return_value=httpx.Response(404, text="nope"))
    ports = [PortResult(port=80, protocol="tcp", state="open", service="http")]
    findings = audit_web("h.test", ports)
    assert any(f.title == "Directory listing enabled" for f in findings)
