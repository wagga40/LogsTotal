"""One colour decision, on the Python side too — scripts/cli_color.py.

`scripts/lib/common.sh` resolves the palette once and exports `LT_COLOR`, precisely so a
subprocess does not form a second opinion — `task deploy:plan` and `task doctor`, typed the
same way in the same terminal, must answer the question the same way.

The tests that matter are the two the shell alone can answer: a redirected TTY (colour
must go OFF even though this process cannot see the redirection) and a piped run the
operator explicitly asked to colour (`| less -R`).
"""

from __future__ import annotations

import fnmatch
import io
import os
import re
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = REPO_ROOT / "scripts"

sys.path.insert(0, str(SCRIPTS))

from cli_color import OFF, PALETTE, colors, supports_color  # noqa: E402


class _Tty(io.StringIO):
    def isatty(self) -> bool:
        return True


class _Pipe(io.StringIO):
    def isatty(self) -> bool:
        return False


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    for key in ("LT_COLOR", "NO_COLOR", "TERM"):
        monkeypatch.delenv(key, raising=False)


class TestTheShellHasTheLastWord:
    def test_never_beats_a_terminal(self, monkeypatch):
        """`task deploy:plan > plan.txt` from an interactive shell. This process sees a
        pipe here, but the case that matters is the one where it does not: the shell
        resolved the redirection and said so."""
        monkeypatch.setenv("LT_COLOR", "never")
        assert supports_color(stream=_Tty()) is False

    def test_always_beats_a_pipe(self, monkeypatch):
        """`task doctor | less -R` — an operator who wants the escapes through the pipe."""
        monkeypatch.setenv("LT_COLOR", "always")
        assert supports_color(stream=_Pipe()) is True

    def test_an_explicit_argument_beats_the_environment(self, monkeypatch):
        """`--color` on the command line is the operator typing it just now."""
        monkeypatch.setenv("LT_COLOR", "never")
        assert supports_color("always", stream=_Pipe()) is True


class TestTheFallback:
    """With no LT_COLOR — a helper run directly, not through a task."""

    def test_a_terminal_is_coloured(self):
        assert supports_color(stream=_Tty()) is True

    def test_a_pipe_is_not(self):
        assert supports_color(stream=_Pipe()) is False

    def test_no_color_wins_over_a_terminal(self, monkeypatch):
        monkeypatch.setenv("NO_COLOR", "1")
        assert supports_color(stream=_Tty()) is False

    def test_term_dumb_wins_over_a_terminal(self, monkeypatch):
        """The third arm of common.sh's gate. Without it an Emacs shell buffer, which is
        a real tty reporting TERM=dumb, renders every escape literally."""
        monkeypatch.setenv("TERM", "dumb")
        assert supports_color(stream=_Tty()) is False

    def test_a_stream_with_no_isatty_is_not_a_terminal(self):
        """A captured buffer in a test harness. getattr rather than try/except so the
        answer is the same however the caller substituted the stream."""
        assert supports_color(stream=object()) is False


class TestThePaletteShape:
    def test_switched_off_keeps_every_key(self):
        """The whole reason call sites never guard: `c['bold']` is always subscriptable,
        so one f-string renders both ways and there is no plain-branch to drift."""
        assert set(OFF) == set(PALETTE)
        assert set(OFF.values()) == {""}

    def test_colors_returns_the_live_palette_or_the_empty_twin(self):
        assert colors("always") is PALETTE
        assert colors("never") is OFF

    def test_the_escapes_match_the_shell_palette(self):
        """A helper's output sits directly under lines common.sh printed. Two greens that
        do not match is the kind of thing you only notice side by side."""
        common = (SCRIPTS / "lib" / "common.sh").read_text(encoding="utf-8")
        for key, shell_name in (("red", "C_RED"), ("green", "C_GREEN"), ("yellow", "C_YELLOW"), ("blue", "C_BLUE"), ("cyan", "C_CYAN"), ("bold", "C_BOLD"), ("off", "C_OFF")):
            escaped = PALETTE[key].replace("\033", "\\033")
            assert f"{shell_name}=$'{escaped}'" in common, f"{key} disagrees with {shell_name}"


class TestTheHelpersUseIt:
    """A helper that hand-rolls an escape is one that cannot be turned off — the exact
    failure the shell-side palette gate prevents, arriving one print() at a time."""

    def test_no_script_declares_its_own_escape(self):
        offenders = []
        for path in sorted(SCRIPTS.glob("*.py")):
            if path.name == "cli_color.py":
                continue
            for n, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
                if line.lstrip().startswith("#"):
                    continue
                if "\\033[" in line or "\\x1b[" in line:
                    offenders.append(f"{path.name}:{n}")
        assert not offenders, f"raw ANSI outside cli_color.py: {offenders}"


class TestItTravelsWithTheHelpersThatImportIt:
    """A sibling import is only safe while the sibling ships. package.sh is exclude-list
    based, so cli_color.py is in the archive by default — but an exclude added later
    (`-xr!scripts/cli_*` is not a strange thing for someone to write) would take doctor.py
    down with it on every host, at exactly the moment it is being run to find out why
    something else is broken."""

    def test_no_package_exclude_can_drop_it(self):
        package = (REPO_ROOT / "scripts" / "package.sh").read_text(encoding="utf-8")
        excludes = re.findall(r"'-xr!([^']+)'", package)
        for pattern in excludes:
            assert not fnmatch.fnmatch("scripts/cli_color.py", pattern), f"package.sh excludes cli_color.py via {pattern!r}"
            assert not fnmatch.fnmatch("cli_color.py", pattern), f"package.sh excludes cli_color.py via {pattern!r}"

    def test_every_sibling_importer_lives_beside_it(self):
        """All in scripts/. An importer moved to a subdirectory keeps passing ruff and
        fails at run time, on a host."""
        for path in sorted(SCRIPTS.rglob("*.py")):
            if "from cli_color import" in path.read_text(encoding="utf-8"):
                assert path.parent == SCRIPTS, f"{path} imports cli_color as a sibling but is not one"


class TestDoctorRendersBothWays:
    """doctor.py is the largest block of operator-facing output in the tree.

    Report.render() directly rather than a subprocess: a real `python3 scripts/doctor.py`
    spends twenty seconds waiting out a Redis connect and a `docker info` before it prints
    anything, and none of that is what is under test here. The import is part of the test —
    doctor.py must reach cli_color as a sibling with no venv and no application on the path.
    """

    def _render(self, capsys, mode: str | None) -> str:
        import doctor

        report = doctor.Report()
        report.add("Configuration", doctor.PASS, ".env file", "present")
        report.add("Configuration", doctor.WARN, "production safety", "COOKIE_INSECURE=true", fix="set it to false")
        report.add("Services", doctor.FAIL, "Redis", "unreachable")
        report.add("Services", doctor.INFO, "Redis eviction", "could not read maxmemory-policy")
        env = os.environ.copy()
        try:
            if mode is None:
                os.environ.pop("LT_COLOR", None)
            else:
                os.environ["LT_COLOR"] = mode
            report.render()
        finally:
            os.environ.clear()
            os.environ.update(env)
        return capsys.readouterr().out

    def test_a_pipe_is_plain(self, capsys):
        out = self._render(capsys, "never")
        assert "\033[" not in out
        assert "    ✓ PASS  .env file — present" in out
        assert "           ↳ fix: set it to false" in out

    def test_lt_color_always_colours_a_pipe(self, capsys):
        """The redirection case, in the direction this process cannot detect on its own."""
        out = self._render(capsys, "always")
        assert "\033[32m✓ PASS\033[0m" in out
        assert "\033[33m! WARN\033[0m" in out
        assert "\033[31m✗ FAIL\033[0m" in out
        assert "\033[36m· INFO\033[0m" in out

    def test_every_verdict_level_has_a_tint(self, capsys):
        """A level with no entry in _TINTS raises a KeyError in the middle of a report —
        i.e. the preflight you run because nothing else works dies rendering itself."""
        import doctor

        assert set(doctor._TINTS) == set(doctor._SYMBOLS)
        for tint in doctor._TINTS.values():
            assert tint in PALETTE

    def test_the_plain_render_is_byte_identical_to_what_it_replaced(self, capsys):
        """One branch, not a coloured f-string beside a plain one — so switched off it must
        produce the plain output exactly."""
        out = self._render(capsys, "never")
        assert out.splitlines()[:3] == ["", "  Configuration", "    ✓ PASS  .env file — present"]
