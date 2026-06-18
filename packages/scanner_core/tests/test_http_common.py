import httpx
import respx

from scanner_core import http_common
from scanner_core.models import PortResult


def test_base_urls_derives_http_endpoints_and_skips_non_http():
    ports = [
        PortResult(port=80, protocol="tcp", state="open", service="http"),
        PortResult(port=443, protocol="tcp", state="open", service="https"),
        PortResult(port=22, protocol="tcp", state="open", service="ssh"),
    ]
    bases = http_common.base_urls("example.com", ports)
    assert "http://example.com:80" in bases
    assert "https://example.com:443" in bases
    assert all(":22" not in b for b in bases)


@respx.mock
def test_get_returns_none_on_transport_error():
    respx.get("http://down.test/").mock(side_effect=httpx.ConnectError("boom"))
    with httpx.Client() as client:
        assert http_common.get(client, "http://down.test/") is None
