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
