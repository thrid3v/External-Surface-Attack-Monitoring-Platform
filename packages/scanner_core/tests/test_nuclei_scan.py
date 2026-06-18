"""Tests for nuclei binary discovery (robust to venv activation state)."""

import os

from scanner_core import nuclei_scan

BIN = "nuclei.exe" if os.name == "nt" else "nuclei"


def test_nuclei_path_prefers_env_override(monkeypatch, tmp_path):
    fake = tmp_path / BIN
    fake.write_text("")
    monkeypatch.setenv("NUCLEI_PATH", str(fake))
    assert nuclei_scan._nuclei_path() == str(fake)


def test_nuclei_path_finds_binary_next_to_interpreter(monkeypatch, tmp_path):
    monkeypatch.delenv("NUCLEI_PATH", raising=False)
    (tmp_path / BIN).write_text("")
    monkeypatch.setattr(nuclei_scan.sys, "executable", str(tmp_path / "python.exe"))
    assert nuclei_scan._nuclei_path() == str(tmp_path / BIN)


def test_nuclei_path_falls_back_to_PATH(monkeypatch, tmp_path):
    monkeypatch.delenv("NUCLEI_PATH", raising=False)
    monkeypatch.setattr(nuclei_scan.sys, "executable", str(tmp_path / "python.exe"))
    monkeypatch.setattr(nuclei_scan.shutil, "which", lambda name: "/usr/bin/nuclei")
    assert nuclei_scan._nuclei_path() == "/usr/bin/nuclei"


def test_nuclei_path_none_when_unavailable(monkeypatch, tmp_path):
    monkeypatch.delenv("NUCLEI_PATH", raising=False)
    monkeypatch.setattr(nuclei_scan.sys, "executable", str(tmp_path / "python.exe"))
    monkeypatch.setattr(nuclei_scan.shutil, "which", lambda name: None)
    assert nuclei_scan._nuclei_path() is None


def test_is_nuclei_available_reflects_path(monkeypatch):
    monkeypatch.setattr(nuclei_scan, "_nuclei_path", lambda: None)
    assert nuclei_scan.is_nuclei_available() is False
    monkeypatch.setattr(nuclei_scan, "_nuclei_path", lambda: "/x/nuclei")
    assert nuclei_scan.is_nuclei_available() is True
