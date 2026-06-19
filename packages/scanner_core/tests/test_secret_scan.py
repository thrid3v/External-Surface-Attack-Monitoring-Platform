from scanner_core import secret_scan as ss


def test_patterns_match_representative_secrets():
    samples = {
        "AWS access key ID": "AKIAIOSFODNN7EXAMPLE",
        "Google API key": "AIzaSyA1234567890abcdefghijklmnopqrstu1",
        "GitHub token": "ghp_" + "a" * 36,
        "Private key (PEM)": "-----BEGIN RSA PRIVATE KEY-----",
        "Database connection string with credentials": "postgres://admin:s3cret@db.host:5432/app",
    }
    for name, sample in samples.items():
        findings = ss._scan_content("http://t/app.js", sample)
        assert any(name in f.title for f in findings), f"{name} not detected in {sample!r}"


def test_clean_content_yields_no_findings():
    assert ss._scan_content("http://t/app.js", "const x = 1; // nothing secret here") == []


def test_entropy_gated_to_assignment_context():
    token = "Zk8s9Qw2Lp7Xn4Vb1Tc6Yr3Hg5Df0Aj"  # 32 chars, high entropy
    # In an assignment context -> flagged
    assigned = f'api_key = "{token}"'
    assert any("entropy" in f.title.lower() for f in ss._scan_content("http://t/a.js", assigned))
    # Bare in minified JS (no assignment keyword) -> not flagged
    bare = f'function(){{return "{token}"}}'
    assert not any("entropy" in f.title.lower() for f in ss._scan_content("http://t/a.js", bare))


def test_redact_masks_middle():
    assert ss._redact("AKIAIOSFODNN7EXAMPLE") == "AKIA********MPLE"
    assert ss._redact("short") == "*****"


def test_findings_are_redacted_and_tagged():
    findings = ss._scan_content("http://t/app.js", "key=AKIAIOSFODNN7EXAMPLE")
    f = next(f for f in findings if "AWS access key" in f.title)
    assert f.category == "secret_exposure"
    assert f.source == "secret_scan"
    assert "AKIAIOSFODNN7EXAMPLE" not in (f.evidence or "")  # full secret never stored
    assert "AKIA" in (f.evidence or "")  # redacted form present


def test_asset_extractor_collects_scripts_links_and_anchors():
    html = """
    <html><head>
      <script src="/static/app.bundle.js"></script>
      <link href="/static/config.json" rel="preload">
    </head><body>
      <a href="/about">about</a>
      <a href="https://cdn.other/x.js">offsite</a>
    </body></html>
    """
    ex = ss._AssetExtractor()
    ex.feed(html)
    assert "/static/app.bundle.js" in ex.assets
    assert "/static/config.json" in ex.assets
    assert "/about" in ex.links
    assert "https://cdn.other/x.js" in ex.links


import httpx
import respx


@respx.mock
def test_scan_url_scans_text_asset_and_records_finding():
    respx.get("http://t.test/app.js").mock(
        return_value=httpx.Response(200, headers={"content-type": "application/javascript"},
                                    text='var k="AKIAIOSFODNN7EXAMPLE";')
    )
    scanned: set[str] = set()
    findings: list = []
    with httpx.Client() as client:
        resp = ss._scan_url(client, "http://t.test/app.js", scanned, findings)
    assert resp is not None and resp.status_code == 200
    assert any("AWS access key" in f.title for f in findings)
    # dedup guard: scanning the same URL again does nothing
    with httpx.Client() as client:
        assert ss._scan_url(client, "http://t.test/app.js", scanned, findings) is None


@respx.mock
def test_scan_url_skips_non_200_and_binary():
    respx.get("http://t.test/missing").mock(return_value=httpx.Response(404, text="nope"))
    respx.get("http://t.test/img.png").mock(
        return_value=httpx.Response(200, headers={"content-type": "image/png"}, text="AKIAIOSFODNN7EXAMPLE")
    )
    findings: list = []
    with httpx.Client() as client:
        assert ss._scan_url(client, "http://t.test/missing", set(), findings) is None
        # binary content-type: response returned but NOT scanned
        resp = ss._scan_url(client, "http://t.test/img.png", set(), findings)
    assert resp is not None
    assert findings == []


@respx.mock
def test_scan_for_secrets_finds_key_in_linked_js():
    from scanner_core.models import PortResult
    page = '<html><script src="/static/app.js"></script></html>'
    respx.get("http://v.test:80/").mock(return_value=httpx.Response(200, headers={"content-type": "text/html"}, text=page))
    respx.get("http://v.test:80/static/app.js").mock(
        return_value=httpx.Response(200, headers={"content-type": "application/javascript"},
                                    text='const token="ghp_' + "b" * 36 + '";')
    )
    # everything else (sensitive paths, .git, /about, etc.) -> 404
    respx.get(url__regex=r".*").mock(return_value=httpx.Response(404, text="nf"))

    ports = [PortResult(port=80, protocol="tcp", state="open", service="http")]
    findings = ss.scan_for_secrets("v.test", ports)
    gh = [f for f in findings if "GitHub token" in f.title]
    assert gh, f"expected GitHub token finding, got {[f.title for f in findings]}"
    assert gh[0].severity == "HIGH"
    assert gh[0].category == "secret_exposure"
    assert "ghp_bbbb" not in (gh[0].evidence or "")  # redacted


@respx.mock
def test_scan_for_secrets_flags_exposed_env_contents():
    from scanner_core.models import PortResult
    respx.get("http://e.test:80/.env").mock(
        return_value=httpx.Response(200, headers={"content-type": "text/plain"},
                                    text="SECRET_KEY=AKIAIOSFODNN7EXAMPLE\nDEBUG=1")
    )
    respx.get(url__regex=r".*").mock(return_value=httpx.Response(404, text="nf"))
    ports = [PortResult(port=80, protocol="tcp", state="open", service="http")]
    findings = ss.scan_for_secrets("e.test", ports)
    assert any(f.title == "Exposed sensitive file" for f in findings)
    assert any("AWS access key" in f.title for f in findings)


@respx.mock
def test_scan_for_secrets_clean_site_has_no_findings():
    from scanner_core.models import PortResult
    respx.get("http://safe.test:80/").mock(return_value=httpx.Response(200, headers={"content-type": "text/html"}, text="<html>ok</html>"))
    respx.get(url__regex=r".*").mock(return_value=httpx.Response(404, text="nf"))
    ports = [PortResult(port=80, protocol="tcp", state="open", service="http")]
    assert ss.scan_for_secrets("safe.test", ports) == []


def test_scan_for_secrets_returns_empty_without_http_ports():
    from scanner_core.models import PortResult
    ports = [PortResult(port=22, protocol="tcp", state="open", service="ssh")]
    assert ss.scan_for_secrets("nohttp.test", ports) == []


def test_aws_secret_evidence_redacts_the_key_not_the_label():
    content = 'aws_secret_access_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"'
    findings = ss._scan_content("http://t/conf.js", content)
    f = next(f for f in findings if "AWS secret access key" in f.title)
    ev = f.evidence or ""
    # full key never stored
    assert "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY" not in ev
    # evidence reflects the KEY's first4/last4, not the 'aws_secret' label
    assert "wJal" in ev and "EKEY" in ev
    assert "aws_secret" not in ev.lower()
