#!/usr/bin/env python3
"""
Diff `.env` against `.env.example`.

Surfaces two things an operator can otherwise miss silently:

  * New keys documented in `.env.example` that `.env` has never seen (commented
    or not) — added by an upgrade, invisible until you go looking.
  * Keys set in `.env` that `.env.example` doesn't document at all — usually a
    typo, since pydantic's `extra="ignore"` swallows unrecognized Settings
    fields without a warning.

Usage:
    python3 scripts/env_diff.py                 # diff ./.env against ./.env.example
    python3 scripts/env_diff.py --strict         # exit 1 if either report is non-empty (CI)
    python3 scripts/env_diff.py --env path/to/.env --example path/to/.env.example

Never prints a value from `.env` — only key names — since an "unknown" key
could be holding a real secret.

Stdlib-only on purpose — same constraint as scripts/gen_secrets.py: this may
run before a venv exists (e.g. right after `git checkout` in `./logstotal upgrade`).
"""

from __future__ import annotations

import argparse
import re
import sys
from dataclasses import dataclass
from pathlib import Path

# The one colour decision — see scripts/cli_color.py. Sibling import, the
# scripts/deploy_fleet_env.py idiom: these helpers run through `run_py` on hosts with no
# venv, so nothing here may reach the application.
sys.path.insert(0, str(Path(__file__).resolve().parent))

from cli_color import colors

PROJECT_ROOT = Path(__file__).resolve().parent.parent

# Matches a key line whether commented-out or live: "FOO=..." or "# FOO=...".
_KEY_RE = re.compile(r"^#?\s*([A-Z][A-Z0-9_]*)=")
# Matches only a live (uncommented) key line.
_SET_KEY_RE = re.compile(r"^([A-Z][A-Z0-9_]*)=")
# A non-indented declaration: "KEY=" or "# KEY=" with at most one space after the
# marker. .env.example's prose/example mentions are indented ("#   KEY=value"),
# so this separates the real default line from illustrative ones.
_DECLARATION_RE = re.compile(r"^#? ?([A-Z][A-Z0-9_]*)=")


@dataclass
class MissingKey:
    """A key documented in .env.example that the operator's .env has never seen."""

    key: str
    default_line: str  # the .env.example line verbatim (commented or not)
    section: str  # nearest preceding section-header comment, or "" if none


def parse_example_keys(text: str) -> dict[str, MissingKey]:
    """Return every key documented in .env.example, in file order.

    When a key appears more than once, the first non-indented declaration wins
    (see _DECLARATION_RE) — several keys are mentioned in indented "Examples:"
    prose lines *before* their real default (e.g. COMPOSE_PROFILES), and the
    report must show the real default, not an illustrative value. A key with
    only indented mentions falls back to its first occurrence.

    A key's "section" is the nearest preceding comment line that is itself not
    a key line and contains no '=' — .env.example uses banner comments like
    "# ── Redis / Queue ──" as section headers, and this also happens to pick
    up a closer explanatory comment when one immediately precedes the key,
    which is at least as useful as the section banner further up.
    """
    keys: dict[str, MissingKey] = {}
    declared: set[str] = set()  # keys whose stored line is a non-indented declaration
    section = ""
    for raw in text.splitlines():
        line = raw.strip()
        m = _KEY_RE.match(line)
        if m:
            key = m.group(1)
            is_declaration = _DECLARATION_RE.match(raw) is not None
            if key not in keys or (is_declaration and key not in declared):
                keys[key] = MissingKey(key=key, default_line=line, section=section)
                if is_declaration:
                    declared.add(key)
            continue
        if line.startswith("#") and "=" not in line:
            section = line
    return keys


def parse_seen_keys(env_text: str) -> set[str]:
    """Keys .env has ever mentioned, commented or not — commenting a key out still
    tells us the operator knows it exists and chose the default."""
    seen: set[str] = set()
    for raw in env_text.splitlines():
        m = _KEY_RE.match(raw.strip())
        if m:
            seen.add(m.group(1))
    return seen


def parse_set_keys(env_text: str) -> list[str]:
    """Keys actually active (uncommented) in .env, in file order."""
    out: list[str] = []
    for raw in env_text.splitlines():
        m = _SET_KEY_RE.match(raw.strip())
        if m:
            out.append(m.group(1))
    return out


def diff_env(example_text: str, env_text: str) -> tuple[list[MissingKey], list[str]]:
    """Return (missing, unknown).

    missing = keys .env.example documents that .env has never mentioned.
    unknown = keys .env sets that .env.example doesn't document at all (typo detector).
    """
    example_keys = parse_example_keys(example_text)
    seen = parse_seen_keys(env_text)
    missing = [item for key, item in example_keys.items() if key not in seen]

    set_keys = parse_set_keys(env_text)
    unknown = [key for key in set_keys if key not in example_keys]
    return missing, unknown


def render_report(missing: list[MissingKey], unknown: list[str]) -> None:
    c = colors()
    if not missing and not unknown:
        # `OK` with three trailing spaces, the verdict column common.sh prints: this report
        # is read directly under an upgrade's own check lines.
        print(f"  {c['green']}OK{c['off']}   .env covers all documented keys; no unknown keys.")
        return

    if missing:
        print(f"{c['bold']}New keys documented in .env.example, not yet in your .env ({len(missing)}):{c['off']}")
        for item in missing:
            print(f"\n  {c['bold']}{item.default_line}{c['off']}")
            if item.section:
                print(f"    {c['dim']}section: {item.section}{c['off']}")
            print(f"    {c['dim']}add to .env if you want to override the default{c['off']}")
        print()

    if unknown:
        print(f"{c['bold']}Keys set in your .env that .env.example doesn't document ({len(unknown)}):{c['off']}")
        for key in unknown:
            print(f"\n  {c['bold']}{key}{c['off']}")
            print(f"    {c['yellow']}not a recognized key — typo?{c['off']}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Diff .env against .env.example: new documented keys + unknown/typo'd keys")
    parser.add_argument("--env", default=str(PROJECT_ROOT / ".env"), help="path to .env (default: ./.env)")
    parser.add_argument("--example", default=str(PROJECT_ROOT / ".env.example"), help="path to .env.example (default: ./.env.example)")
    parser.add_argument("--strict", action="store_true", help="exit 1 if either report is non-empty (e.g. in CI)")
    parser.add_argument(
        "--optional",
        action="store_true",
        help="a missing .env is reported and tolerated rather than an error (callers for whom this file need not exist locally)",
    )
    args = parser.parse_args(argv)

    env_path = Path(args.env)
    example_path = Path(args.example)

    if not env_path.exists():
        # `--optional` exists for the multi-server upgrade, which runs from a workstation
        # that legitimately has no `.env` at all: the control plane's real one lives on the
        # control plane, and both `package.sh` and the deploy rsync exclude the local file
        # by name so it could never be the one that ships. The step is informational there —
        # `upgrade.sh` prints "review these against each host's env file" immediately above
        # it — and an informational step must not be able to abort an upgrade that has
        # already taken a backup and checked out new code: under `set -e` this `return 1`
        # would leave a half-staged tree at a detached HEAD.
        #
        # Not the default, because `task env:diff` typed by hand, and the single-host
        # upgrade paths, all run somewhere `.env` genuinely must exist — and "no .env"
        # is the most useful thing that command can tell you there.
        if args.optional:
            print("No local .env — nothing to diff against. Compare the new keys below against each host's env file.")
            print()
            example_keys = parse_example_keys(example_path.read_text(encoding="utf-8")) if example_path.exists() else {}
            print(f".env.example documents {len(example_keys)} keys.")
            return 0
        e = colors(stream=sys.stderr)
        print(f"{e['bold']}{e['red']}ERROR:{e['off']} .env not found (cp .env.example .env)", file=sys.stderr)
        return 1
    if not example_path.exists():
        e = colors(stream=sys.stderr)
        print(f"{e['bold']}{e['red']}ERROR:{e['off']} {example_path} not found", file=sys.stderr)
        return 1

    example_text = example_path.read_text(encoding="utf-8")
    env_text = env_path.read_text(encoding="utf-8")

    missing, unknown = diff_env(example_text, env_text)
    render_report(missing, unknown)

    if args.strict and (missing or unknown):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
