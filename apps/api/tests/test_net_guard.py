"""Tests for the shared network/SSRF guard used by scan target validation."""

import pytest

from services import net_guard


# --- is_public_ip ------------------------------------------------------------

def test_private_and_metadata_ips_are_not_public():
    assert net_guard.is_public_ip("10.0.0.5") is False
    assert net_guard.is_public_ip("127.0.0.1") is False
    assert net_guard.is_public_ip("192.168.1.1") is False
    assert net_guard.is_public_ip("169.254.169.254") is False  # cloud metadata
    assert net_guard.is_public_ip("::1") is False


def test_public_ip_is_public():
    assert net_guard.is_public_ip("93.184.216.34") is True


def test_garbage_is_not_public():
    assert net_guard.is_public_ip("not-an-ip") is False


# --- is_public_host ----------------------------------------------------------

def test_is_public_host_blocks_private_literal():
    assert net_guard.is_public_host("169.254.169.254") is False


def test_is_public_host_allows_public_literal():
    assert net_guard.is_public_host("93.184.216.34") is True


def test_is_public_host_blocks_hostname_resolving_to_private(monkeypatch):
    monkeypatch.setattr(net_guard, "resolve_ips", lambda h: ["10.0.0.5"])
    assert net_guard.is_public_host("internal.corp.local") is False


def test_is_public_host_blocks_when_any_record_is_private(monkeypatch):
    # A split-horizon / rebinding domain with one public and one private A record.
    monkeypatch.setattr(net_guard, "resolve_ips", lambda h: ["93.184.216.34", "10.0.0.5"])
    assert net_guard.is_public_host("evil.example") is False


def test_is_public_host_allows_hostname_resolving_to_public(monkeypatch):
    monkeypatch.setattr(net_guard, "resolve_ips", lambda h: ["93.184.216.34"])
    assert net_guard.is_public_host("example.com") is True


# --- clean_target (format normalisation, framework-agnostic) -----------------

def test_clean_target_strips_scheme_path_port_and_www():
    assert net_guard.clean_target("https://www.Example.com:8443/path?x=1") == "example.com"


def test_clean_target_accepts_bare_ip():
    assert net_guard.clean_target("93.184.216.34") == "93.184.216.34"


def test_clean_target_rejects_empty():
    with pytest.raises(ValueError):
        net_guard.clean_target("   ")


def test_clean_target_rejects_spaces_and_illegal_chars():
    with pytest.raises(ValueError):
        net_guard.clean_target("foo bar.com")
    with pytest.raises(ValueError):
        net_guard.clean_target("under_score")  # underscore illegal and no dot


# --- validate_scan_target (clean + SSRF policy) ------------------------------

def test_validate_scan_target_blocks_private_by_default(monkeypatch):
    monkeypatch.setattr(net_guard, "private_targets_allowed", lambda: False)
    with pytest.raises(ValueError):
        net_guard.validate_scan_target("169.254.169.254")


def test_validate_scan_target_allows_private_when_opted_in(monkeypatch):
    monkeypatch.setattr(net_guard, "private_targets_allowed", lambda: True)
    assert net_guard.validate_scan_target("127.0.0.1") == "127.0.0.1"


def test_validate_scan_target_allows_public_host(monkeypatch):
    monkeypatch.setattr(net_guard, "private_targets_allowed", lambda: False)
    monkeypatch.setattr(net_guard, "resolve_ips", lambda h: ["93.184.216.34"])
    assert net_guard.validate_scan_target("https://example.com") == "example.com"
