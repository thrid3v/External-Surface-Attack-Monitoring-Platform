import time

import httpx
import respx

from scanner_core import web_vuln_probe as wvp


def test_detect_sqli_only_when_error_is_new():
    err = "You have an error in your SQL syntax near ''' at line 1"
    assert wvp._detect_sqli(baseline_body="welcome", injected_body=err) is True
    # FP guard: error already present in baseline -> not a finding
    assert wvp._detect_sqli(baseline_body=err, injected_body=err) is False


def test_detect_xss_requires_raw_unescaped_marker():
    assert wvp._detect_xss(f"<div>{wvp.XSS_PAYLOAD}</div>", wvp.XSS_PAYLOAD) is True
    escaped = wvp.XSS_PAYLOAD.replace("<", "&lt;").replace(">", "&gt;")
    assert wvp._detect_xss(f"<div>{escaped}</div>", wvp.XSS_PAYLOAD) is False


def test_detect_lfi_matches_passwd_signature():
    assert wvp._detect_lfi("root:x:0:0:root:/root:/bin/bash\n") is True
    assert wvp._detect_lfi("nothing interesting here") is False


def test_detect_open_redirect_only_from_location_header():
    assert wvp._detect_open_redirect("https://evil.example/") is True
    assert wvp._detect_open_redirect(None) is False
    assert wvp._detect_open_redirect("/local/path") is False


def test_detect_cmd_injection_uses_arithmetic_result():
    # The product proves execution; the literal payload never contains it.
    assert wvp.CMD_MARKER not in ";echo $((13337*31337))"
    assert wvp._detect_cmd_injection(f"output: {wvp.CMD_MARKER}") is True
    assert wvp._detect_cmd_injection("output: 13337*31337") is False


def test_input_extractor_collects_links_and_forms():
    html = """
    <html><body>
      <a href="/products.php?cat=1">cat</a>
      <a href="/about">about</a>
      <form action="/search.php" method="post">
        <input name="q" value="x">
        <textarea name="note"></textarea>
        <input name="csrf" type="hidden" value="tok">
      </form>
    </body></html>
    """
    ex = wvp._InputExtractor()
    ex.feed(html)
    assert "/products.php?cat=1" in ex.links
    assert "/about" in ex.links
    assert len(ex.forms) == 1
    form = ex.forms[0]
    assert form["action"] == "/search.php"
    assert form["method"] == "post"
    assert set(form["fields"]) == {"q", "note", "csrf"}


def _budget():
    return wvp._Budget(deadline=time.monotonic() + 30, pages_left=wvp.MAX_PAGES_CRAWLED)


@respx.mock
def test_discover_inputs_finds_query_links_and_forms_same_host_only():
    root = """
    <a href="/list.php?cat=1">x</a>
    <a href="https://other.test/evil?z=1">offsite</a>
    <form action="/search.php" method="post"><input name="q"></form>
    """
    respx.get("http://t.test:80").mock(return_value=httpx.Response(200, text=root))
    respx.get(url__regex=r"http://t\.test:80/.*").mock(return_value=httpx.Response(200, text="ok"))

    with httpx.Client() as client:
        points = wvp._discover_inputs(client, ["http://t.test:80"], _budget())

    urls = {(p.method, p.url) for p in points}
    assert ("GET", "http://t.test:80/list.php") in urls
    assert ("POST", "http://t.test:80/search.php") in urls
    # off-host link must not become an injection point
    assert all("other.test" not in p.url for p in points)


@respx.mock
def test_discover_inputs_respects_page_budget():
    # Every page links to a fresh unvisited page; with pages_left=1 only the
    # first page is fetched, so its links are discovered but none are crawled.
    respx.get(url__regex=r".*").mock(
        return_value=httpx.Response(200, text='<a href="/next.php?p=1">n</a>')
    )
    budget = wvp._Budget(deadline=time.monotonic() + 30, pages_left=1)
    with httpx.Client() as client:
        wvp._discover_inputs(client, ["http://b.test:80"], budget)
    assert budget.pages_left == 0


@respx.mock
def test_probe_web_vulns_flags_sqli():
    from scanner_core.models import PortResult

    MYSQL_ERR = "You have an error in your SQL syntax; check the manual"

    def vuln_handler(request):
        # SQL error only when a single quote is present in the cat param.
        if "'" in request.url.params.get("cat", ""):
            return httpx.Response(200, text=MYSQL_ERR)
        return httpx.Response(200, text="<html>products</html>")

    root_html = '<a href="/list.php?cat=1">items</a>'
    respx.get("http://v.test:80/").mock(return_value=httpx.Response(200, text=root_html))
    respx.get("http://v.test:80/list.php").mock(side_effect=vuln_handler)

    ports = [PortResult(port=80, protocol="tcp", state="open", service="http")]
    findings = wvp.probe_web_vulns("v.test", ports)

    sqli = [f for f in findings if f.title.lower().startswith("sql")]
    assert sqli, f"expected a SQLi finding, got {[f.title for f in findings]}"
    assert sqli[0].severity == "HIGH"
    assert sqli[0].category == "web_vuln"
    assert sqli[0].source == "web_vuln_probe"


@respx.mock
def test_probe_web_vulns_clean_target_has_no_findings():
    from scanner_core.models import PortResult
    respx.get("http://safe.test:80/").mock(
        return_value=httpx.Response(200, text='<a href="/p.php?id=1">x</a>')
    )
    respx.get("http://safe.test:80/p.php").mock(return_value=httpx.Response(200, text="all good"))
    ports = [PortResult(port=80, protocol="tcp", state="open", service="http")]
    assert wvp.probe_web_vulns("safe.test", ports) == []


def test_probe_web_vulns_returns_empty_without_http_ports():
    from scanner_core.models import PortResult
    ports = [PortResult(port=22, protocol="tcp", state="open", service="ssh")]
    assert wvp.probe_web_vulns("nohttp.test", ports) == []
