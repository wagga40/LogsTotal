#!/usr/bin/env python3
"""Cut a LogsTotal release: bump the declared versions, move the changelog, tag.

Stdlib only, like scripts/gen_secrets.py and scripts/backup_lifecycle.py — a release is cut
from a checkout that may not have a venv activated.

Two subcommands, and the split is deliberate:

  prepare   edits files and STOPS, so the changelog prose gets read by a human before it
            becomes an immutable tag and the published release notes.
  finish    commits, tags, and runs the gate — in that order, which is the whole reason it
            exists. The tag has to land ON the release commit (a manifest committed *into* a
            commit can never name that commit), and `./logstotal test` has to run WITH the tag in
            place because test_the_declared_version_has_a_git_tag cannot pass without it.

Neither pushes. `git push origin vX.Y.Z` fires .github/workflows/release.yml and publishes a
public GitHub Release; that is never a side effect a script should take unattended.
"""

from __future__ import annotations

import argparse
import datetime as _dt
import os
import re
import subprocess
import sys
from pathlib import Path

# The one colour decision — see scripts/cli_color.py. Sibling import, the
# scripts/deploy_fleet_env.py idiom: these helpers run through `run_py` on hosts with no
# venv, so nothing here may reach the application.
sys.path.insert(0, str(Path(__file__).resolve().parent))

from cli_color import colors

PROJECT_ROOT = Path(__file__).resolve().parent.parent

CONFIG_PY = PROJECT_ROOT / "app" / "config.py"
PYPROJECT = PROJECT_ROOT / "pyproject.toml"
VERSION_FILE = PROJECT_ROOT / "VERSION"
CHANGELOG = PROJECT_ROOT / "CHANGELOG.md"

SEMVER = re.compile(r"^\d+\.\d+\.\d+$")

#: A version-shaped token, with or without the `v`.
VERSION_TOKEN = re.compile(r"\bv?\d+\.\d+\.\d+\b")

#: Lines that name a version *on purpose* — "the default changed in 0.9.1" is a fact about
#: history, not a stale upgrade recipe, and rewriting it every release destroys the
#: information it carries. Checked BEFORE the marker below, so a historical line is exempt
#: even when it also looks like a recipe.
#:
#: tests/test_docs_in_sync.py imports this rather than re-declaring it: the sweep and the
#: guard that polices the sweep must agree about which lines are in scope, or a release
#: leaves behind exactly the sites the guard then fails on.
HISTORICAL_VERSION_MENTION = re.compile(
    r"\b(?:changed|dropped|added|removed|introduced|renamed|deprecated|replaced|split|landed|fixed)\s+in\b"
    r"|\b(?:since|as of|prior to|before|until|up to and including)\b"
    r"|\bin\s+0\.\d+\.\d+\s*,",
    re.I,
)

#: Lines that carry a version an operator will act on: upgrade recipes, archive names and
#: URLs, the /health sample body, the `# expect: version:` verification line, the directory
#: a source archive extracts to, and the ref an upgrade checks out.
VERSION_SITE_MARKER = re.compile(r"REF=|logstotal-|LogsTotal/(?:archive|releases)|task upgrade:|version\"?\s*:|LogsTotal-v|origin/v")

#: Swept for version strings. Mirrors _VERSION_SCAN_FILES in tests/test_docs_in_sync.py.
#: CHANGELOG.md is deliberately absent — its old sections are history, not recipes.
ROOT_MD_FILES = (
    "README.md",
    "CONTRIBUTING.md",
    "SECURITY.md",
    "CODE_OF_CONDUCT.md",
    "THIRD_PARTY_NOTICES.md",
)


def sweep_files() -> list[Path]:
    out = [PROJECT_ROOT / name for name in ROOT_MD_FILES]
    out += sorted((PROJECT_ROOT / "docs").rglob("*.md"))
    out += sorted((PROJECT_ROOT / "scripts").glob("*.sh"))
    return [p for p in out if p.exists()]


def die(message: str) -> None:
    c = colors(stream=sys.stderr)
    print(f"{c['bold']}{c['red']}ERROR:{c['off']} {message}", file=sys.stderr)
    raise SystemExit(1)


def git(*args: str, check: bool = True) -> str:
    result = subprocess.run(["git", *args], cwd=PROJECT_ROOT, capture_output=True, text=True, check=False)
    if check and result.returncode != 0:
        die(f"git {' '.join(args)} failed: {result.stderr.strip() or result.stdout.strip()}")
    return result.stdout.strip()


# ── Reading the three declarations ───────────────────────────────────────────


def declared_versions() -> dict[str, str]:
    """The three places a version lives, read the way each consumer reads it."""
    out: dict[str, str] = {}

    match = re.search(r'app_version: str = "([^"]+)"', CONFIG_PY.read_text(encoding="utf-8"))
    if match:
        out["app/config.py"] = match.group(1)

    match = re.search(r'^version = "([^"]+)"', PYPROJECT.read_text(encoding="utf-8"), re.M)
    if match:
        out["pyproject.toml"] = match.group(1)

    if VERSION_FILE.exists():
        for line in VERSION_FILE.read_text(encoding="utf-8").splitlines():
            key, _, value = line.partition(":")
            if key == "version" and value.strip():
                out["VERSION"] = value.strip()

    return out


def current_version() -> str:
    versions = declared_versions()
    if "app/config.py" not in versions:
        die('app/config.py has no `app_version: str = "..."` line')
    return versions["app/config.py"]


def as_tuple(version: str) -> tuple[int, ...]:
    return tuple(int(part) for part in version.split("."))


# ── prepare ──────────────────────────────────────────────────────────────────


def rewrite_declarations(new: str) -> list[str]:
    touched = []

    text = CONFIG_PY.read_text(encoding="utf-8")
    updated, count = re.subn(r'(app_version: str = ")[^"]+(")', rf"\g<1>{new}\g<2>", text, count=1)
    if count != 1:
        die("could not rewrite app_version in app/config.py")
    CONFIG_PY.write_text(updated, encoding="utf-8")
    touched.append("app/config.py")

    text = PYPROJECT.read_text(encoding="utf-8")
    updated, count = re.subn(r'^(version = ")[^"]+(")', rf"\g<1>{new}\g<2>", text, count=1, flags=re.M)
    if count != 1:
        die("could not rewrite version in pyproject.toml")
    PYPROJECT.write_text(updated, encoding="utf-8")
    touched.append("pyproject.toml")

    VERSION_FILE.write_text(f"version: {new}\n", encoding="utf-8")
    touched.append("VERSION")

    return touched


def sweep_docs(old: str, new: str) -> list[str]:
    """Rewrite version strings on the lines the docs guard polices, and only those."""
    pattern = re.compile(rf"\b(v?){re.escape(old)}\b")
    touched = []

    for path in sweep_files():
        text = path.read_text(encoding="utf-8")
        lines = text.splitlines(keepends=True)
        changed = False
        for i, line in enumerate(lines):
            if HISTORICAL_VERSION_MENTION.search(line):
                continue
            if not VERSION_SITE_MARKER.search(line):
                continue
            replaced = pattern.sub(rf"\g<1>{new}", line)
            if replaced != line:
                lines[i] = replaced
                changed = True
        if changed:
            path.write_text("".join(lines), encoding="utf-8")
            touched.append(str(path.relative_to(PROJECT_ROOT)))

    return touched


def _changelog_link_base(text: str) -> str:
    match = re.search(r"^\[Unreleased\]:\s*(\S+?)/compare/", text, re.M)
    if not match:
        die("CHANGELOG.md has no `[Unreleased]: <url>/compare/...` link definition to learn the repo URL from")
    return match.group(1)


def unreleased_body(text: str) -> str:
    match = re.search(r"^## \[Unreleased\]\s*\n(.*?)(?=^## \[)", text, re.M | re.S)
    return match.group(1).strip() if match else ""


def rewrite_changelog(new: str, previous: str, date: str) -> None:
    """`previous` is passed in, never re-read.

    current_version() reads app/config.py, which rewrite_declarations() has already bumped by
    now — the compare link would come out as `compare/vX...vX`, pointing a release's diff at
    itself.
    """
    text = CHANGELOG.read_text(encoding="utf-8")
    base = _changelog_link_base(text)

    body = unreleased_body(text)

    # Move the accumulated body under the new heading, leaving [Unreleased] empty. Every
    # replacement below is a callable, never a template string: in a template a backslash is
    # an escape, and release notes quote `DOMAIN\user` and Windows paths.
    text, count = re.subn(
        r"^## \[Unreleased\]\s*\n.*?(?=^## \[)",
        lambda _m: f"## [Unreleased]\n\n## [{new}] — {date}\n\n{body}\n\n",
        text,
        count=1,
        flags=re.M | re.S,
    )
    if count != 1:
        die("could not find the `## [Unreleased]` section in CHANGELOG.md")

    # [Unreleased] now compares against the new tag...
    text, count = re.subn(
        r"^\[Unreleased\]:\s*\S+$",
        lambda _m: f"[Unreleased]: {base}/compare/v{new}...HEAD",
        text,
        count=1,
        flags=re.M,
    )
    if count != 1:
        die("could not rewrite the [Unreleased] link definition in CHANGELOG.md")

    # ...and the new version gets its own compare link directly beneath it.
    text, count = re.subn(
        r"^(\[Unreleased\]: .*\n)",
        lambda m: f"{m.group(1)}[{new}]: {base}/compare/v{previous}...v{new}\n",
        text,
        count=1,
        flags=re.M,
    )
    if count != 1:
        die("could not insert the new link definition in CHANGELOG.md")

    CHANGELOG.write_text(text, encoding="utf-8")


def cmd_prepare(args: argparse.Namespace) -> int:
    new = args.version.lstrip("v")
    if not SEMVER.match(new):
        die(f"{args.version!r} is not X.Y.Z. Pre-release and build metadata are not supported.")

    git("rev-parse", "--git-dir")

    if not args.allow_dirty:
        dirty = changed_paths()
        if dirty:
            die("the working tree has uncommitted changes — commit or stash first, so the\n       release diff is only the release:\n         " + "\n         ".join(dirty))

    old = current_version()
    if as_tuple(new) <= as_tuple(old):
        die(f"{new} is not greater than the current version {old}.")

    tag = f"v{new}"
    if git("tag", "--list", tag):
        die(f"tag {tag} already exists locally. A published release is not re-cut; bump again.")
    remote_tags = git("ls-remote", "--tags", "origin", check=False)
    if f"refs/tags/{tag}" in remote_tags:
        die(f"tag {tag} already exists on origin. A published release is not re-cut; bump again.")

    # Every check before every write. This ordering is not cosmetic: inside
    # rewrite_changelog(), which is called *after* the three declarations are rewritten,
    # refusing an empty [Unreleased] would leave the tree half-bumped and the operator
    # holding a diff they did not ask for.
    if not unreleased_body(CHANGELOG.read_text(encoding="utf-8")):
        die(
            "CHANGELOG.md's `## [Unreleased]` section is empty.\n"
            "       release.yml publishes that section as the release notes and hard-fails on an\n"
            "       empty body — write the entry before cutting the release."
        )

    date = args.date or _dt.date.today().isoformat()

    touched = rewrite_declarations(new)
    rewrite_changelog(new, old, date)
    touched.append("CHANGELOG.md")
    touched += sweep_docs(old, new)

    c = colors()
    print(f"{c['bold']}{c['green']}✓{c['off']} prepared {c['bold']}{old}{c['off']} → {c['bold']}{new}{c['off']}.")
    print()
    for name in touched:
        print(f"  {c['dim']}updated{c['off']}  {name}")
    print()
    print(f"{c['bold']}Review the diff, then:{c['off']}")
    print()
    print("  git diff")
    print(f"  ./logstotal release:finish VERSION={new}")
    return 0


# ── finish ───────────────────────────────────────────────────────────────────

#: Paths a release commit may touch. Anything else means unrelated work is mixed in.
_ALLOWED_PREFIXES = ("docs/", "scripts/")
_ALLOWED_EXACT = {"app/config.py", "pyproject.toml", "VERSION", "CHANGELOG.md", *ROOT_MD_FILES}


def changed_paths() -> list[str]:
    """Every path with uncommitted work, as a bare path.

    Deliberately NOT `git status --porcelain`: that emits `XY path`, and the leading status
    column is a space for an unstaged modification — which the .strip() every other git()
    call wants would eat, turning ` M CHANGELOG.md` into `M CHANGELOG.md` and then, after
    slicing, `HANGELOG.md`. These two commands emit bare paths and need no slicing at all.
    """
    tracked = git("diff", "--name-only", "HEAD").splitlines()
    untracked = git("ls-files", "--others", "--exclude-standard").splitlines()
    return [p for p in (*tracked, *untracked) if p.strip()]


def _release_commit_files(new: str) -> list[str]:
    changed = changed_paths()
    if not changed:
        die(f"nothing to commit — did you run `./logstotal release:prepare VERSION={new}` first?")

    paths, unexpected = [], []
    for path in changed:
        if path in _ALLOWED_EXACT or any(path.startswith(p) for p in _ALLOWED_PREFIXES):
            paths.append(path)
        else:
            unexpected.append(path)

    if unexpected:
        die(
            "the working tree has changes that are not part of a release:\n         "
            + "\n         ".join(unexpected)
            + "\n       Commit or stash them separately — a release commit should be reviewable as one."
        )
    return paths


def verify_consistency(new: str) -> None:
    versions = declared_versions()
    if len(versions) != 3:
        die(f"expected three declared versions, found {sorted(versions)}")
    if set(versions.values()) != {new}:
        die(f"the declared versions disagree with {new}: {versions}")

    text = CHANGELOG.read_text(encoding="utf-8")
    if not re.search(rf"^## \[{re.escape(new)}\]", text, re.M):
        die(f"CHANGELOG.md has no `## [{new}]` section — release.yml publishes it as the release notes")
    if not re.search(rf"^\[{re.escape(new)}\]:\s*http", text, re.M):
        die(f"CHANGELOG.md has no `[{new}]:` link definition — the heading renders as literal brackets without it")
    if not re.search(rf"^\[Unreleased\]:\s*\S*compare/v{re.escape(new)}\.\.\.HEAD", text, re.M):
        die(f"CHANGELOG.md's [Unreleased] link still points at an earlier tag, so the 'unreleased' diff includes {new}")


def cmd_finish(args: argparse.Namespace) -> int:
    new = args.version.lstrip("v")
    if not SEMVER.match(new):
        die(f"{args.version!r} is not X.Y.Z.")

    git("rev-parse", "--git-dir")
    verify_consistency(new)
    paths = _release_commit_files(new)

    tag = f"v{new}"
    if git("tag", "--list", tag):
        die(f"tag {tag} already exists. Delete it (git tag -d {tag}) if you are redoing this.")

    c = colors()
    print(f"{c['bold']}{c['blue']}>>>{c['off']} git commit ({len(paths)} file(s))")
    git("add", "--", *paths)
    git("commit", "-m", f"chore: release {new}")

    # The tag AFTER the commit, always. A tag placed first names the parent commit.
    print(f"{c['bold']}{c['blue']}>>>{c['off']} git tag -a {tag}")
    git("tag", "-a", tag, "-m", f"LogsTotal {new}")

    # And the gate AFTER the tag: test_the_declared_version_has_a_git_tag cannot pass
    # without it, so running the suite first would fail for a reason that is not a problem.
    # Two direct calls rather than one `shell=True` string: nothing here needs a shell, and
    # the first non-zero stops the chain the same way `&&` would. Under ./logstotal the
    # go-task running this is a pinned copy that is not on PATH; Taskfile.yml hands its path
    # down as LOGSTOTAL_TASK_BIN, so the gate runs on the same binary as the release.
    task = os.environ.get("LOGSTOTAL_TASK_BIN") or "task"
    for gate_cmd in ([task, "check"], [task, "test"]):
        print(f"{c['bold']}{c['blue']}>>>{c['off']} {' '.join(gate_cmd)}")
        if subprocess.run(gate_cmd, cwd=PROJECT_ROOT, check=False).returncode != 0:
            e = colors(stream=sys.stderr)
            print(
                f"\n{e['bold']}{e['yellow']}WARN:{e['off']} gate failed — removing {tag} so the tree is not left half-released",
                file=sys.stderr,
            )
            git("tag", "-d", tag, check=False)
            die(f"`{' '.join(gate_cmd)}` failed. The commit is kept; fix, amend, and re-run.")

    branch = git("rev-parse", "--abbrev-ref", "HEAD")
    print()
    print(f"{c['bold']}{c['green']}✓{c['off']} released {c['bold']}{new}{c['off']} locally. Nothing has been pushed.")
    print()
    # One atomic push naming both refs: never `--tags`, which would publish every local tag.
    print(f"  {c['bold']}git push --atomic origin {branch} refs/tags/{tag}{c['off']}")
    print()
    print("Pushing the tag triggers .github/workflows/release.yml, which builds")
    print(f"logstotal-{new}.7z and publishes a PUBLIC GitHub Release.")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)

    prepare = sub.add_parser("prepare", help="bump the declared versions, move the changelog, sweep the docs")
    prepare.add_argument("--version", required=True, help="the new version, X.Y.Z")
    prepare.add_argument("--date", help="release date (YYYY-MM-DD); defaults to today")
    prepare.add_argument("--allow-dirty", action="store_true", help="skip the clean-worktree check")
    prepare.set_defaults(func=cmd_prepare)

    finish = sub.add_parser("finish", help="commit, tag, and run the gate")
    finish.add_argument("--version", required=True, help="the version prepared, X.Y.Z")
    finish.set_defaults(func=cmd_finish)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
