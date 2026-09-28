"""CLI smoke: version/doctor/tools run without scanners installed."""

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
