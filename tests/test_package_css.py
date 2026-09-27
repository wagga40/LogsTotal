"""What `task package` says — and does — about the stylesheet it ships.

Behaviour tests for the CSS-mode block in `scripts/package.sh`. Real bash, an isolated
tmp_path cwd, a scrubbed environment, PATH shims for `7z` and `task` (the sibling style of
tests/test_deploy_check_scripts.py). package.sh resolves scripts/lib/common.sh relative to
its own location, so the repo's script runs against a throwaway tree.

The point under test is a message that was false for one whole branch: with no Tailwind
CLI, package.sh announced "this archive will ship DEVELOPMENT CSS" even when base.html
already loaded the compiled stylesheet, in which case the archive shipped exactly that.

The `task` shim is a recorder that also performs a MARKED flip of base.html, so a test can
tell prod mode from dev mode without re-implementing the Taskfile's perl substitution here
(that substitution has its own guard in tests/test_tailwind_palette_parity.py). What
package.sh owns is the orchestration: which mode it chooses, what it claims, and that the
tracked template goes back to dev mode on every exit — including a failing one.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
PACKAGE = REPO_ROOT / "scripts" / "package.sh"

pytestmark = pytest.mark.skipif(shutil.which("bash") is None, reason="bash not available")

DEV_BLOCK = """  <!-- TAILWIND:START -->
  <script src="/static/vendor/tailwind.js"></script>
  <!-- TAILWIND:END -->
"""
PROD_BLOCK = """  <!-- TAILWIND:START -->
  <link rel="stylesheet" href="/static/vendor/tailwind-built.css">
  <!-- TAILWIND:END -->
"""


def _tree(tmp_path: Path, *, mode: str = "dev", stylesheet: str | None = "/* built */\n", cli: bool = False) -> Path:
    """The smallest tree package.sh will run in: VERSION, requirements.txt, base.html."""
    (tmp_path / "VERSION").write_text("version: 9.9.9\n")
    (tmp_path / "requirements.txt").write_text("fastapi\n")
    tpl = tmp_path / "app" / "templates"
    tpl.mkdir(parents=True)
    (tpl / "base.html").write_text("<head>\n" + (PROD_BLOCK if mode == "prod" else DEV_BLOCK) + "</head>\n")
    vendor = tmp_path / "app" / "static" / "vendor"
    vendor.mkdir(parents=True)
    if stylesheet is not None:
        (vendor / "tailwind-built.css").write_text(stylesheet)
    if cli:
        cli_path = tmp_path / "tools" / "tailwind"
        cli_path.mkdir(parents=True)
        (cli_path / "tailwindcss").write_text("#!/bin/sh\nexit 0\n")
        (cli_path / "tailwindcss").chmod(0o755)
    return tmp_path


def _shims(tmp_path: Path, *, sevenzip_rc: int = 0) -> Path:
    """`7z` and `task` shims. Both record their argv; `task` also flips base.html."""
    binp = tmp_path / "bin"
    binp.mkdir()
    (binp / "7z").write_text(
        "#!/usr/bin/env bash\n"
        f'echo "7z $*" >> "{tmp_path}/calls.log"\n'
        # `7z a -flags ARCHIVE .` — the archive is the first argument ending in .7z.
        'for a in "$@"; do case "$a" in *.7z) : > "$a"; break ;; esac; done\n'
        f"exit {sevenzip_rc}\n"
    )
    (binp / "task").write_text(
        "#!/usr/bin/env bash\n"
        f'echo "task $*" >> "{tmp_path}/calls.log"\n'
        'case "$1" in\n'
        "  css:build|css:prod) printf '%s' '<head>\\n  <!-- TAILWIND:START -->\\n  <link rel=\"stylesheet\" href=\"/static/vendor/tailwind-built.css\">\\n  <!-- TAILWIND:END -->\\n</head>\\n' > app/templates/base.html ;;\n"
        "  css:dev) printf '%s' '<head>\\n  <!-- TAILWIND:START -->\\n  <script src=\"/static/vendor/tailwind.js\"></script>\\n  <!-- TAILWIND:END -->\\n</head>\\n' > app/templates/base.html ;;\n"
        "esac\n"
        "exit 0\n"
    )
    for f in binp.iterdir():
        f.chmod(0o755)
    return binp


def _run(tmp_path: Path, env_overrides: dict[str, str] | None = None, *, sevenzip_rc: int = 0) -> subprocess.CompletedProcess[str]:
    env = {**os.environ}
    for key in ("RELEASE_REPO_URL", "PACKAGE_USE_COMMITTED_CSS", "ARCHIVE"):
        env.pop(key, None)
    env["PATH"] = f"{_shims(tmp_path, sevenzip_rc=sevenzip_rc)}{os.pathsep}{env.get('PATH', '')}"
    # The go-task tarballs are a download with a pinned checksum; these tests are about CSS,
    # and tests/test_logstotal_wrapper.py covers the staging on its own.
    env["PACKAGE_SKIP_GO_TASK"] = "true"
    if env_overrides:
        env.update(env_overrides)
    return subprocess.run(["bash", str(PACKAGE)], cwd=tmp_path, env=env, capture_output=True, text=True, check=False)


def _calls(tmp_path: Path) -> list[str]:
    log = tmp_path / "calls.log"
    return log.read_text().splitlines() if log.exists() else []


def _mode(tmp_path: Path) -> str:
    text = (tmp_path / "app" / "templates" / "base.html").read_text()
    return "prod" if "tailwind-built.css" in text else "dev"


def test_a_tree_that_already_ships_compiled_css_is_not_called_development_css(tmp_path):
    """The false claim, stated as a test.

    No CLI, but base.html already loads the compiled stylesheet — the state a packaged tree
    is in, and the exact discriminator the Dockerfile's css stage uses. The archive really
    does contain that stylesheet, so announcing DEVELOPMENT CSS describes a different build.
    """
    _tree(tmp_path, mode="prod")
    r = _run(tmp_path)
    assert r.returncode == 0, r.stderr
    assert "DEVELOPMENT CSS" not in r.stdout, "package.sh calls a compiled-CSS archive a development-CSS one"
    assert "app/static/vendor/tailwind-built.css" in r.stdout, "the message never names the stylesheet the archive ships"
    assert _mode(tmp_path) == "prod", "package.sh moved a tree it was only supposed to read"
    assert not any(c.startswith("task css:") for c in _calls(tmp_path)), "no CSS task should run: nothing to build and nothing to restore"


def test_without_the_cli_the_default_is_the_play_cdn_and_the_message_names_both_ways_out(tmp_path):
    """The default is unchanged — correct-but-slow beats fast-and-silently-wrong — but the
    note has to say what the archive DOES contain and how to get the other thing."""
    _tree(tmp_path, mode="dev")
    r = _run(tmp_path)
    assert r.returncode == 0, r.stderr
    assert _mode(tmp_path) == "dev"
    assert "tailwind.js" in r.stdout, "the note never says what the archive actually serves"
    assert "./logstotal tailwind:install" in r.stdout
    assert "PACKAGE_USE_COMMITTED_CSS=true" in r.stdout, "the committed stylesheet is never offered"


def test_the_opt_in_ships_the_committed_stylesheet_and_says_what_that_risks(tmp_path):
    _tree(tmp_path, mode="dev")
    r = _run(tmp_path, {"PACKAGE_USE_COMMITTED_CSS": "true"})
    assert r.returncode == 0, r.stderr
    assert "task css:prod" in _calls(tmp_path), "the opt-in never pointed base.html at the stylesheet"
    assert "unstyled" in r.stdout, "the opt-in never says a stale stylesheet fails silently"
    assert _mode(tmp_path) == "dev", "the opt-in left the tracked template in production mode"


def test_the_opt_in_refuses_when_there_is_no_stylesheet_to_ship(tmp_path):
    _tree(tmp_path, mode="dev", stylesheet=None)
    r = _run(tmp_path, {"PACKAGE_USE_COMMITTED_CSS": "true"})
    assert r.returncode != 0
    assert "missing or empty" in r.stderr, "the refusal goes through common.sh::die, which writes to stderr"


def test_a_failed_archive_still_restores_dev_mode(tmp_path):
    """A restore block at the end of the script would let every non-zero exit between the
    CSS build and that block leave base.html — a TRACKED file — switched to production
    mode, with the compiled stylesheet rewritten beside it."""
    _tree(tmp_path, mode="dev", cli=True)
    r = _run(tmp_path, sevenzip_rc=1)
    assert r.returncode != 0, "a failing 7z must fail the package"
    assert _mode(tmp_path) == "dev", "a failed archive left the working tree in production mode"
    assert "task css:dev" in _calls(tmp_path)


def test_the_release_origin_stamp_is_removed_even_though_the_css_restore_also_traps(tmp_path):
    """Bash keeps only the LAST trap per signal. Two EXIT traps means one cleanup silently
    stops happening; this pins that both still do."""
    _tree(tmp_path, mode="dev", cli=True)
    r = _run(tmp_path, {"RELEASE_REPO_URL": "https://example.test/org/repo"})
    assert r.returncode == 0, r.stderr
    assert not (tmp_path / ".release-origin").exists(), ".release-origin was left in the working tree"
    assert _mode(tmp_path) == "dev", "base.html was left in production mode"


def test_package_never_writes_its_own_tailwind_swap():
    """One copy of the substitution, in taskfiles/dev.yml (css:prod). A fourth hand-written
    perl — Taskfile build, Taskfile dev, Dockerfile, and here — is how the dev/prod swap
    stops being reversible."""
    src = PACKAGE.read_text(encoding="utf-8")
    assert "TAILWIND:START" not in src, "package.sh grew its own copy of the base.html swap; call `task css:prod`"
