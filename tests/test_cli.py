from __future__ import annotations

from evidaudit.cli import main


def test_cli_demo(capsys) -> None:
    rc = main(["demo"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "conceals 1 semantic error(s)" in out
    assert "UNSAFE=True" in out
    assert "RESTORED=True" in out
    assert "replay_missed_failure=True" in out


def test_cli_verify_ledgers(capsys) -> None:
    rc = main(["verify-ledgers"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "[PASS]" in out
