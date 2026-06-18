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
