"""CLI smoke: version/doctor/tools run without scanners installed."""

import shutil
import sys

EXPECTED = {"scan_diff", "scan_repo", "osv_lookup", "owasp_explain", "suggest_fix"}


def test_cli_version_runs() -> None:
    from bravoguard.cli import cmd_version

    assert cmd_version(check=False) == 0


def test_cli_tools_runs() -> None:
    from bravoguard.cli import cmd_tools

    assert cmd_tools() == 0


def test_cli_doctor_core_shape() -> None:
    # Doctor may FAIL on a bare machine (missing binaries) but must not crash;
    # server + tables must at least be evaluated. Accept 0/1, reject exceptions.
    from bravoguard.cli import cmd_doctor

    assert cmd_doctor(strict=False) in (0, 1)


def test_doctor_guarddog_warns_not_fails_on_windows(monkeypatch, capsys) -> None:
    from bravoguard import cli

    monkeypatch.setattr(shutil, "which", lambda name: None if name == "guarddog" else f"/fake/{name}")
    monkeypatch.setattr(sys, "platform", "win32")
    assert cli.cmd_doctor(strict=False) == 0
    out = capsys.readouterr().out
    assert "WARN" in out and "guarddog" in out and "nono-py" in out
    assert "doctor: PASS" in out


def test_doctor_guarddog_still_fails_on_linux(monkeypatch, capsys) -> None:
    from bravoguard import cli

    monkeypatch.setattr(shutil, "which", lambda name: None if name == "guarddog" else f"/fake/{name}")
    monkeypatch.setattr(sys, "platform", "linux")
    assert cli.cmd_doctor(strict=False) == 1
    out = capsys.readouterr().out
    assert "guarddog" in out and "doctor: FAIL" in out


def test_tools_marks_guarddog_skipped_on_windows(monkeypatch, capsys) -> None:
    from bravoguard import cli

    monkeypatch.setattr(shutil, "which", lambda name: None if name == "guarddog" else f"/fake/{name}")
    monkeypatch.setattr(sys, "platform", "win32")
    assert cli.cmd_tools() == 0
    out = capsys.readouterr().out
    assert "SKIPPED" in out and "guarddog" in out


def test_release_url_rejects_non_http_schemes() -> None:
    import pytest

    from bravoguard.cli import _check_release_url

    for bad in ("file:///tmp/proof.log", "gopher://example.com/", "ftp://example.com/x"):
        with pytest.raises(ValueError, match="scheme"):
            _check_release_url(bad)
    assert _check_release_url("https://api.github.com/repos/a/b/releases/latest").startswith("https://")
    assert _check_release_url("http://example.com/x").startswith("http://")


def test_fetch_latest_release_https_proceeds(monkeypatch) -> None:
    import urllib.request

    from bravoguard import cli

    class _Resp:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def read(self):
            return b'{"tag_name": "v9.9.9"}'

    captured = {}

    def fake_urlopen(req, timeout=10):
        captured["url"] = req.full_url
        captured["timeout"] = timeout
        return _Resp()

    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)
    assert cli.fetch_latest_release() == "v9.9.9"
    assert captured["url"].startswith("https://")
    assert captured["timeout"] == 10
