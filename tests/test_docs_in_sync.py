"""Guardrail: keep .env.example in sync with the Settings model.

This is the machine-checkable half of the "docs updated alongside the app" rule.
It fails the moment someone adds a config field to app/config.py without documenting
it in .env.example (or removes a field but leaves a stale .env.example entry), so the
reference config can't silently drift from the code.

If this test fails:
  * New Settings field?  → add a (commented) `# KEY=default` line to .env.example,
    and update the docs/configuration.md env table.
  * Removed a Settings field? → delete its line from .env.example.
  * The var is consumed outside pydantic (Docker/compose/entrypoint/init)? → add it to
    EXTERNAL_ENV_VARS below with a note.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

import yaml
from _taskfile import all_tasks, taskfile_paths

from app.config import Settings
from app.constants import CANCEL_MSG_DEAD_WORKER, CANCEL_MSG_USER, RECOVERY_MSG_ADMIN, RECOVERY_MSG_EXPIRED, RECOVERY_MSG_STARTUP
from app.models import SiteSettings

ENV_EXAMPLE = Path(__file__).resolve().parent.parent / ".env.example"

# Settings fields that are intentionally NOT documented in .env.example because an
# operator should never set them by hand.
INTERNAL_SETTINGS_FIELDS = {
    "app_name",  # branding constant
    "app_version",  # sourced from the VERSION file / code default
    "huey_task_timeout",  # deprecated alias for HUEY_QUEUE_EXPIRY
}

# Env vars that legitimately appear in .env.example but are read by Docker Compose,
# the entrypoints, Caddy, or init_db.py — not by pydantic Settings.
EXTERNAL_ENV_VARS = {
    "ADMIN_EMAIL",  # init_db.py bootstrap
    "ADMIN_PASSWORD",  # init_db.py bootstrap
    "HUEY_WORKERS",  # consumed by the huey_consumer CLI (Taskfile / compose)
    "COMPOSE_PROFILES",  # docker compose (also a Settings field, so harmless either way)
    "POSTGRES_PASSWORD",  # entrypoint builds DATABASE_URL from these
    "POSTGRES_USER",
    "POSTGRES_DB",
    "POSTGRES_HOST",
    "POSTGRES_PORT",
    "GARAGE_RPC_SECRET",  # garage-entrypoint.sh
    "GARAGE_ADMIN_TOKEN",  # garage-entrypoint.sh
    "DOMAIN",  # docker-caddy-entrypoint.sh
    "ACME_EMAIL",  # docker-caddy-entrypoint.sh
    "PROXY_TLS_CERT",  # docker-caddy-entrypoint.sh (PROXY_TLS=custom)
    "PROXY_TLS_KEY",  # docker-caddy-entrypoint.sh (PROXY_TLS=custom)
    "BASIC_AUTH_USER",  # docker-caddy-entrypoint.sh
    "BASIC_AUTH_HASH",  # docker-caddy-entrypoint.sh
    "WEB_PORT",  # docker compose port mapping
    "DOCKER_HOST_WORKDIR",  # worker → sibling tool containers
}


def _documented_keys() -> set[str]:
    """All env keys present in .env.example, including commented `# KEY=` lines."""
    text = ENV_EXAMPLE.read_text(encoding="utf-8")
    return set(re.findall(r"^#?\s*([A-Z][A-Z0-9_]+)=", text, flags=re.M))


def _settings_env_keys() -> set[str]:
    return {name.upper() for name in Settings.model_fields}


def test_every_setting_is_documented():
    """Every Settings field (minus internal ones) must appear in .env.example."""
    expected = {name for name in Settings.model_fields if name not in INTERNAL_SETTINGS_FIELDS}
    documented = _documented_keys()
    missing = sorted(name for name in expected if name.upper() not in documented)
    assert not missing, (
        "Settings fields missing from .env.example: "
        + ", ".join(missing)
        + ". Add a `# KEY=default` line to .env.example and update the docs/configuration.md env table "
        + "(or add the field to INTERNAL_SETTINGS_FIELDS if operators should never set it)."
    )


def test_no_stale_env_example_keys():
    """Every key in .env.example must be a real Settings field or a known external var."""
    documented = _documented_keys()
    known = _settings_env_keys() | EXTERNAL_ENV_VARS
    stale = sorted(key for key in documented if key not in known)
    assert not stale, (
        "Keys in .env.example that are neither a Settings field nor a known external var: "
        + ", ".join(stale)
        + ". Remove the stale line, or add it to EXTERNAL_ENV_VARS if it is consumed outside pydantic."
    )


def test_internal_fields_are_real():
    """Guard against the allow-list itself going stale."""
    for name in INTERNAL_SETTINGS_FIELDS:
        assert name in Settings.model_fields, f"INTERNAL_SETTINGS_FIELDS lists '{name}', which is no longer a Settings field"


# ── Task-name references in docs ─────────────────────────────────────────────

PROJECT_ROOT = Path(__file__).resolve().parent.parent

sys.path.insert(0, str(PROJECT_ROOT / "scripts"))
import release as _release  # noqa: E402

TASKFILE = PROJECT_ROOT / "Taskfile.yml"

# The admin/developer markdown doc set: the slim root README plus every page in
# docs/. Glob rather than name each page, so a new docs/*.md file is covered
# automatically instead of silently skipped.
DOCS_DIR = PROJECT_ROOT / "docs"
_DOCS_MD_FILES = sorted(str(p.relative_to(PROJECT_ROOT)) for p in DOCS_DIR.rglob("*.md"))
# The root-level project files sit outside every guard that exists to prevent exactly
# their kind of rot: they name tasks, link into docs/, and reference version tags, and
# nothing checked any of it. CODE_OF_CONDUCT.md is included so its SECURITY.md link stays
# live.
ROOT_MD_FILES = ["README.md", "CONTRIBUTING.md", "SECURITY.md", "CODE_OF_CONDUCT.md", "THIRD_PARTY_NOTICES.md"]
MD_DOC_FILES = [*ROOT_MD_FILES, *_DOCS_MD_FILES]
# Pages that specific content is pinned to (env table, backfill table, marker).
CONFIGURATION_DOC = DOCS_DIR / "configuration.md"
OPERATIONS_DOC = DOCS_DIR / "reference/admin-ui.md"
UPGRADING_DOC = DOCS_DIR / "runbooks/upgrading.md"
SECURITY_DOC = DOCS_DIR / "security.md"


def test_docs_dir_has_core_pages():
    """Guard the docs/*.md glob from silently going empty (e.g. after a rename):
    the core pages the pinning tests below rely on must all exist."""
    expected = {
        "docs/README.md",
        "docs/install/prerequisites.md",
        "docs/install/fleet.md",
        "docs/configuration.md",
        "docs/scaling.md",
        "docs/reference/admin-ui.md",
        "docs/runbooks/upgrading.md",
        "docs/security.md",
        "docs/contribute/development.md",
        "docs/reference/commands.md",
        "docs/troubleshooting.md",
    }
    missing = sorted(expected - set(_DOCS_MD_FILES))
    assert not missing, f"Expected docs pages missing from docs/: {missing}"


# Every shell script under scripts/ (including scripts/lib/) is scanned for
# `task <name>` references — glob rather than name each one, so a newly
# extracted script is covered automatically instead of silently skipped.
_SCRIPT_DOC_FILES = sorted(str(p.relative_to(PROJECT_ROOT)) for p in list((PROJECT_ROOT / "scripts").glob("*.sh")) + list((PROJECT_ROOT / "scripts" / "lib").glob("*.sh")))

# Everything else that prints, generates or documents a `task <name>`: Taskfile summaries,
# the env templates, the header written into every host's .env, and the Python that prints
# hints. A renamed task survives silently in any of these unless they are on this list.
#
# An optional local testkit/ (gitignored) is checked too when present, precisely because
# nothing else looks at it.
_OTHER_TASK_REF_FILES = sorted(
    str(path.relative_to(PROJECT_ROOT))
    for path in [
        PROJECT_ROOT / "Taskfile.yml",
        PROJECT_ROOT / "deploy.env.example",
        PROJECT_ROOT / ".env.example",
        PROJECT_ROOT / "docker-compose.yml",
        PROJECT_ROOT / "testkit" / "orbstack" / "Taskfile.yml",
        PROJECT_ROOT / "testkit" / "orbstack" / "README.md",
        *(PROJECT_ROOT / "taskfiles").glob("*.yml"),
        *(PROJECT_ROOT / "scripts").glob("*.py"),
        *(PROJECT_ROOT / "app").rglob("*.py"),
    ]
    if path.is_file()
)

DOC_FILES = [*MD_DOC_FILES, *_SCRIPT_DOC_FILES]

# CHANGELOG.md and tests/ are deliberately absent from both lists: they are records of
# behaviour as it was released, and rewriting history to please a linter is worse than the
# stale name it removes.

# A NAMESPACED task reference — `deploy:remove`, never bare `deploy`.
#
# The bare form cannot be scanned outside a code span. Measured over this tree, an
# unrestricted `task \s+([a-z][a-zA-Z0-9:_-]*)` produces ~40 prose hits — "task at",
# "task will", "task queue", "task runs" — so the guard would arrive pre-broken and be
# suppressed. Requiring at least one colon costs nothing real: the task names that get
# renamed are namespaced, and bare names inside markdown are already covered by
# `_referenced_tasks` below.
_NAMESPACED_TASK_REF = re.compile(r"(?<![\w:-])(?:task|\./logstotal)\s+([a-z][a-z0-9-]*(?::[a-z0-9][a-z0-9-]*)+)")


def _defined_tasks() -> set[str]:
    """Every task name across Taskfile.yml and the files it includes.

    Parsed as YAML, not scanned as text. A regex matches any 2-space-indented bare
    key *anywhere* in the file, so a key under `vars:` or under the shared
    `x-preconditions:` anchor block would register as a phantom task — which would
    then need a `desc:` and a docs mention or three tests fail. Reading `tasks:`
    says what it means, and PyYAML resolves the
    precondition anchors on the way past.
    """
    names = set(all_tasks())
    assert len(names) > 20, "Taskfile parsing looks broken — too few tasks found"
    return names


#: Either spelling: the docs write `./logstotal <name>`, and anyone with go-task installed may
#: write `task <name>`. A guard that knew only one would pass on the other by matching nothing.
_TASK_REF = r"(?:[A-Z_]+=\S+\s+)*(?:task|\./logstotal)\s+([a-z][a-zA-Z0-9:_-]*)"


def _referenced_tasks(text: str) -> set[str]:
    """`task <name>` references inside inline code spans and fenced code blocks.

    Restricting to code contexts avoids prose false-positives ("task runner",
    "task will", ...).
    """
    refs: set[str] = set()
    for span in re.findall(r"`([^`\n]+)`", text):
        refs.update(re.findall(_TASK_REF, span))
    for block in re.findall(r"```(?:bash|sh|console|shell)?\n(.*?)```", text, flags=re.S):
        for line in block.splitlines():
            refs.update(re.findall(rf"(?:^|&&|\|\||;)\s*{_TASK_REF}", line.strip()))
    return refs


def _testkit_tasks() -> set[str]:
    """Task names defined by an optional local testkit's own Taskfile, or an empty set.

    The testkit is gitignored, so it is normally absent — in a fresh clone, in CI, in a
    release archive. Missing means "nothing extra is defined", never a failure.
    """
    path = PROJECT_ROOT / "testkit" / "orbstack" / "Taskfile.yml"
    if not path.is_file():
        return set()
    return set(yaml.safe_load(path.read_text(encoding="utf-8")).get("tasks") or {})


def test_the_task_reference_scan_still_sees_the_docs():
    """A floor under the guard below, which can only ever report what it matches.

    The docs were respelled from `task <name>` to `./logstotal <name>` once already; a regex
    that stopped matching would have left every check here green over zero references.
    """
    seen = set().union(*(_referenced_tasks((PROJECT_ROOT / doc).read_text(encoding="utf-8")) for doc in MD_DOC_FILES))
    assert len(seen) >= 40, f"only {len(seen)} distinct task references found in the docs — has the command spelling changed?"
    assert {"quickstart", "backup", "upgrade", "doctor:docker"} <= seen


def test_documented_task_names_exist():
    """Every `task <name>` referenced in the admin docs must exist in Taskfile.yml."""
    defined = _defined_tasks()
    problems: list[str] = []
    for doc in DOC_FILES:
        path = PROJECT_ROOT / doc
        text = path.read_text(encoding="utf-8")
        refs = _referenced_tasks(text)
        if doc.endswith(".sh"):
            # Shell scripts print their hints; a name inside an echo is the whole point, so
            # a bare `echo "  task deploy:x"` counts without a run/use/with before `task`.
            refs |= set(_NAMESPACED_TASK_REF.findall(text))
        for name in sorted(refs - defined):
            problems.append(f"{doc}: references `task {name}` which is not defined in Taskfile.yml")

    # A local testkit has its own Taskfile and namespace, and its tasks legitimately call
    # both. Resolve its references against the union, or the guard reports its own tasks as
    # missing.
    testkit_defined = defined | _testkit_tasks()
    for doc in _OTHER_TASK_REF_FILES:
        text = (PROJECT_ROOT / doc).read_text(encoding="utf-8")
        known = testkit_defined if doc.startswith("testkit/") else defined
        for name in sorted(set(_NAMESPACED_TASK_REF.findall(text)) - known):
            problems.append(f"{doc}: references `task {name}` which is not defined in Taskfile.yml")

    assert not problems, "\n".join(problems)


# ── docs/reference/admin-ui.md backfill docs ↔ admin router routes ───────────────────


def test_operations_backfills_match_admin_routes():
    """The backfill table in docs/reference/admin-ui.md must list exactly the POST /admin/backfill-*
    routes that exist (both directions — no stale docs, no undocumented backfills)."""
    admin_src = (PROJECT_ROOT / "app" / "routers" / "admin.py").read_text(encoding="utf-8")
    routes = set(re.findall(r'@router\.post\("(/backfill-[a-z-]+)"\)', admin_src))
    assert routes, "No backfill routes found in admin.py — parsing broken?"

    operations = OPERATIONS_DOC.read_text(encoding="utf-8")
    documented = set(re.findall(r"/admin(/backfill-[a-z-]+)", operations))

    undocumented = sorted(routes - documented)
    stale = sorted(documented - routes)
    assert not undocumented, f"Backfill routes missing from docs/reference/admin-ui.md: {undocumented}"
    assert not stale, f"docs/reference/admin-ui.md documents backfill routes that no longer exist: {stale}"


# ── docs/configuration.md env table coverage ─────────────────────────────────

# Settings fields documented in .env.example but intentionally absent from the
# docs/configuration.md tables (niche/internal knobs). Keep this list short.
CONFIG_ENV_SKIP: set[str] = set()


def test_configuration_doc_documents_every_setting():
    """Every operator-facing Settings field must appear as `KEY` in docs/configuration.md."""
    config_doc = CONFIGURATION_DOC.read_text(encoding="utf-8")
    expected = {name.upper() for name in Settings.model_fields if name not in INTERNAL_SETTINGS_FIELDS} - CONFIG_ENV_SKIP
    missing = sorted(key for key in expected if f"`{key}`" not in config_doc)
    assert not missing, (
        "Settings fields missing from docs/configuration.md: "
        + ", ".join(missing)
        + ". Add a row to the docs/configuration.md env table (or add to CONFIG_ENV_SKIP with a reason)."
    )


# ── Stale-job recovery message strings ───────────────────────────────────────

RECOVERY_DOC_FILES = MD_DOC_FILES


def test_recovery_messages_match_constants():
    """Docs that quote a stale-job recovery or cancellation `error_message` must
    quote one of the shared constants verbatim, and the old wording must be gone."""
    for doc in RECOVERY_DOC_FILES:
        text = (PROJECT_ROOT / doc).read_text(encoding="utf-8")
        assert "Worker died mid-job" not in text, f"{doc} still quotes the stale 'Worker died mid-job' recovery message"
        for msg in re.findall(r'error_message="([^"]*)"', text):
            assert msg in (RECOVERY_MSG_STARTUP, RECOVERY_MSG_ADMIN, RECOVERY_MSG_EXPIRED, CANCEL_MSG_USER, CANCEL_MSG_DEAD_WORKER), (
                f"{doc} quotes recovery message {msg!r}, which is not a RECOVERY_MSG_* / CANCEL_MSG_* constant"
            )


# ── Shipped workflows always cap CPU-bound tool threads ──────────────────────


def test_hayabusa_chainsaw_tasks_set_integer_threads():
    """Every hayabusa/chainsaw task in workflows/*.yml must set an integer `threads:`
    so the tool never falls back to grabbing all logical cores."""
    for wf in sorted((PROJECT_ROOT / "workflows").glob("*.yml")):
        data = yaml.safe_load(wf.read_text(encoding="utf-8")) or {}
        for task in data.get("tasks", []):
            if task.get("tool") in ("hayabusa", "chainsaw"):
                threads = task.get("threads")
                assert isinstance(threads, int) and not isinstance(threads, bool), f"{wf.name}: {task.get('tool')} task must set an integer `threads:` (got {threads!r})"


# ── Cross-file links & in-page anchors resolve ───────────────────────────────

LINK_DOC_FILES = MD_DOC_FILES

_MD_LINK = re.compile(r"\[([^\]]+)\]\(([^)]+)\)")


def _strip_fenced_code(text: str) -> str:
    """Drop ```-fenced code blocks so links/headings inside samples are ignored."""
    return re.sub(r"```.*?```", "", text, flags=re.S)


def _github_slug(heading: str) -> str:
    """Reproduce GitHub's heading-anchor slug for a heading's text.

    Strip markdown (links → link text, backticks, bold/strikethrough markers),
    lowercase, drop everything that is not a Unicode alphanumeric / underscore /
    space / hyphen, then turn spaces into hyphens. Consecutive hyphens are
    preserved (GitHub keeps them, e.g. "Scaling & Capacity Planning" →
    "scaling--capacity-planning"). Underscores are kept as literals (GitHub keeps
    them: "### JOB_OUTPUT_RETENTION_DAYS" → "job_output_retention_days"); this
    repo's docs never use `_foo_` emphasis in headings.
    """
    text = re.sub(r"\[([^\]]*)\]\([^)]*\)", r"\1", heading)  # [text](url) → text
    text = text.replace("`", "")
    text = re.sub(r"[*~]", "", text)  # bold/italic/strikethrough markers (not `_` — see above)
    text = text.lower()
    kept = [ch if (ch.isalnum() or ch in "-_") else (" " if ch == " " else "") for ch in text]
    return "".join(kept).replace(" ", "-")


def _iter_headings(path: Path):
    for line in _strip_fenced_code(path.read_text(encoding="utf-8")).splitlines():
        m = re.match(r"^#{1,6}\s+(.*?)\s*$", line)
        if m:
            yield m.group(1)


# NOTE: the three link docs currently contain NO duplicate heading slugs, so the
# GitHub `-1` / `-2` disambiguation suffixes are intentionally not implemented.
# test_link_docs_have_no_duplicate_heading_slugs guards that assumption.
def _heading_slugs(path: Path) -> set[str]:
    return {_github_slug(h) for h in _iter_headings(path)} | set(re.findall(r'<a id="([^"]+)"', path.read_text(encoding="utf-8")))


def _local_links(text: str):
    """Yield (label, filepart, anchor) for each relative markdown link.

    External (http/https/mailto/tel) links and links inside fenced code are skipped.
    """
    for m in _MD_LINK.finditer(_strip_fenced_code(text)):
        target = m.group(2).strip()
        if target.startswith(("http://", "https://", "mailto:", "tel:")):
            continue
        filepart, _, anchor = target.partition("#")
        yield m.group(1), filepart, (anchor or None)


def test_doc_links_and_anchors_resolve():
    """Every relative markdown link in the README + docs/*.md set must point at a
    file that exists, and every `#anchor` must match a heading (by GitHub slug) in
    the target file. Relative links resolve against the containing file's directory
    (so docs/*.md sibling links work). Reports all broken links, not just the first."""
    slug_cache: dict[Path, set[str]] = {}
    problems: list[str] = []
    for doc in LINK_DOC_FILES:
        doc_path = PROJECT_ROOT / doc
        for label, filepart, anchor in _local_links(doc_path.read_text(encoding="utf-8")):
            target_path = doc_path if filepart == "" else (doc_path.parent / filepart).resolve()
            shown = f"[{label}]({filepart}{'#' + anchor if anchor else ''})"
            if filepart and not target_path.exists():
                problems.append(f"{doc}: {shown} → missing file {filepart!r}")
                continue
            if anchor is None:
                continue
            if target_path.suffix.lower() != ".md":
                problems.append(f"{doc}: {shown} → anchor on non-markdown target {filepart!r}")
                continue
            if target_path not in slug_cache:
                slug_cache[target_path] = _heading_slugs(target_path)
            if anchor not in slug_cache[target_path]:
                problems.append(f"{doc}: {shown} → no heading in {target_path.name} slugs to '{anchor}'")
    assert not problems, "Broken doc links/anchors:\n" + "\n".join(problems)


def test_link_docs_have_no_duplicate_heading_slugs():
    """The anchor checker assumes unique heading slugs per file (no `-N` suffixing).
    Guard that assumption so a future duplicate heading is caught here first."""
    problems: list[str] = []
    for doc in LINK_DOC_FILES:
        seen: set[str] = set()
        dupes: set[str] = set()
        for heading in _iter_headings(PROJECT_ROOT / doc):
            slug = _github_slug(heading)
            (dupes if slug in seen else seen).add(slug)
        for dup in sorted(dupes):
            problems.append(f"{doc}: duplicate heading slug '{dup}' — teach _heading_slugs the -N suffix rule")
    assert not problems, "\n".join(problems)


# ── HUEY_WORKERS compose defaults ⇄ docs ─────────────────────────────────────


def _compose_huey_default(compose_file: str) -> str:
    """The N in `${HUEY_WORKERS:-N}` from a compose file (exactly one expected)."""
    text = (PROJECT_ROOT / compose_file).read_text(encoding="utf-8")
    matches = re.findall(r"\$\{HUEY_WORKERS:-(\d+)\}", text)
    assert len(matches) == 1, f"{compose_file}: expected exactly one ${{HUEY_WORKERS:-N}} default, found {matches}"
    return matches[0]


def test_huey_workers_defaults_documented():
    """The two HUEY_WORKERS defaults — the main compose (2) vs the dedicated-worker
    compose (4) — must be stated in the docs next to the compose file they come from.
    The numbers are read FROM the compose files, so a future bump forces a doc edit."""
    main_default = _compose_huey_default("docker-compose.yml")
    worker_default = _compose_huey_default("docker-compose.worker.yml")

    env_lines = ENV_EXAMPLE.read_text(encoding="utf-8").splitlines()
    doc_lines = [ln for doc in MD_DOC_FILES for ln in (PROJECT_ROOT / doc).read_text(encoding="utf-8").splitlines()]

    problems: list[str] = []
    # Main default: stated next to the main compose file in .env.example.
    # (".env.example" mentions docker-compose.worker.yml too, but that longer name
    # does not contain the substring "docker-compose.yml", so the checks don't cross.)
    if not any("docker-compose.yml" in ln and main_default in ln for ln in env_lines):
        problems.append(f".env.example: no line ties docker-compose.yml to its HUEY_WORKERS default {main_default!r}")
    # Dedicated-worker default: stated next to docker-compose.worker.yml in the docs or .env.example.
    if not any("docker-compose.worker.yml" in ln and worker_default in ln for ln in env_lines + doc_lines):
        problems.append(f"docs/.env.example: no line ties docker-compose.worker.yml to its HUEY_WORKERS default {worker_default!r}")
    assert not problems, "HUEY_WORKERS default drift:\n" + "\n".join(problems)


# ── Destructive migrations ⇄ docs/runbooks/upgrading.md ───────────────────────────────

ALEMBIC_VERSIONS = PROJECT_ROOT / "alembic" / "versions"
DESTRUCTIVE_MARKER = "<!-- destructive-migrations -->"


def _destructive_revisions() -> set[str]:
    """Revision IDs whose `upgrade()` body drops a table or column (rollback-unsafe)."""
    destructive: set[str] = set()
    for path in ALEMBIC_VERSIONS.glob("*.py"):
        src = path.read_text(encoding="utf-8")
        rev_m = re.search(r"""^revision[^=\n]*=\s*["']([0-9a-f]+)["']""", src, flags=re.M)
        up_m = re.search(r"def upgrade\b", src)
        if not rev_m or not up_m:
            continue
        down_m = re.search(r"def downgrade\b", src)
        body = src[up_m.end() : (down_m.start() if down_m else len(src))]
        if re.search(r"\b(?:drop_table|drop_column)\b", body):
            destructive.add(rev_m.group(1))
    return destructive


def _documented_destructive_revisions() -> set[str]:
    """12-hex revision IDs backticked in docs/runbooks/upgrading.md's marked rollback-unsafe paragraph."""
    lines = UPGRADING_DOC.read_text(encoding="utf-8").splitlines()
    idx = next((i for i, ln in enumerate(lines) if DESTRUCTIVE_MARKER in ln), None)
    assert idx is not None, f"docs/runbooks/upgrading.md is missing the {DESTRUCTIVE_MARKER} marker above the rollback-unsafe paragraph"
    paragraph: list[str] = []
    for ln in lines[idx + 1 :]:
        if not ln.strip():
            break
        paragraph.append(ln)
    text = " ".join(paragraph)
    return {tok for tok in re.findall(r"`([^`]+)`", text) if re.fullmatch(r"[0-9a-f]{12}", tok)}


def test_destructive_migrations_documented():
    """docs/runbooks/upgrading.md's rollback-unsafe paragraph must name exactly the revisions whose
    `upgrade()` drops a table/column — both directions (no stale IDs, no missing ones)."""
    code = _destructive_revisions()
    assert code, "No destructive revisions detected — the alembic scan is broken"
    documented = _documented_destructive_revisions()
    problems: list[str] = []
    missing = sorted(code - documented)
    stale = sorted(documented - code)
    if missing:
        problems.append(f"Destructive revisions not named in docs/runbooks/upgrading.md's rollback-unsafe paragraph: {missing}")
    if stale:
        problems.append(f"docs/runbooks/upgrading.md's rollback-unsafe paragraph names revisions that are not destructive: {stale}")
    assert not problems, "\n".join(problems)


# ── Every defined task is documented (inverse of test_documented_task_names_exist) ──

# Tasks defined in Taskfile.yml that are intentionally NOT referenced as `task <name>`
# in the README + docs/*.md set because an operator never invokes them by name.
# Keep this short, with a reason per entry.
UNDOCUMENTED_TASKS_OK: set[str] = {
    "default",  # meta task: `task default` just runs `task --list`; never invoked by name
    "upgrade:stage-code",  # internal helper for `task upgrade`; not invoked by operators
}

TASK_DOC_FILES = MD_DOC_FILES


def test_every_task_is_documented():
    """Every task in Taskfile.yml must be referenced as `task <name>` in the admin docs,
    or be listed in UNDOCUMENTED_TASKS_OK with a reason. Inverse of the existing
    test_documented_task_names_exist (which guards the other direction)."""
    defined = _defined_tasks()
    referenced: set[str] = set()
    for doc in TASK_DOC_FILES:
        referenced |= _referenced_tasks((PROJECT_ROOT / doc).read_text(encoding="utf-8"))
    undocumented = sorted(defined - referenced - UNDOCUMENTED_TASKS_OK)
    assert not undocumented, (
        "Tasks defined in Taskfile.yml but never documented as `task <name>` in "
        + ", ".join(TASK_DOC_FILES)
        + ": "
        + ", ".join(undocumented)
        + ". Add a `task <name>` mention to the docs, or add the task to UNDOCUMENTED_TASKS_OK with a reason."
    )


def test_undocumented_tasks_ok_are_real():
    """Guard the allow-list itself from going stale."""
    defined = _defined_tasks()
    stale = sorted(name for name in UNDOCUMENTED_TASKS_OK if name not in defined)
    assert not stale, f"UNDOCUMENTED_TASKS_OK lists tasks that no longer exist in Taskfile.yml: {stale}"


# ── SiteSettings ⇄ docs/reference/admin-ui.md reference ──────────────────────────────


def _sitesettings_columns() -> set[str]:
    """SiteSettings column names, minus the surrogate `id`."""
    return {c.name for c in SiteSettings.__table__.columns if c.name != "id"}


def _operations_sitesettings_section() -> str:
    """The body of the `## SiteSettings reference` section (up to the next `## `)."""
    text = OPERATIONS_DOC.read_text(encoding="utf-8")
    m = re.search(r"^##\s+SiteSettings reference\s*$(.*?)(?=^##\s)", text, flags=re.M | re.S)
    assert m, "docs/reference/admin-ui.md is missing the '## SiteSettings reference' section"
    return m.group(1)


# ── In-app "For administrators" docs section ⇄ tasks + admin routes ─────────
#
# app/templates/docs/index.html is HTML, not markdown, so it can't reuse
# _referenced_tasks()/_MD_LINK as-is (no backtick fences, and its `/admin/...`
# mentions are plain path strings in <a href> / <code>, not markdown links).
# This guard is scoped to just the new <section id="admins"> — the rest of the
# page is end-user content with no task/admin-route references to pin.

DOCS_INDEX = PROJECT_ROOT / "app" / "templates" / "docs" / "index.html"
# Every router mounted under /admin. `ai_admin.py` was missing from this list, which meant
# an `/admin/ai/...` path in the in-app docs would have been reported as unregistered.
ADMIN_ROUTER_FILES = [
    "app/routers/admin.py",
    "app/routers/enrichment_admin.py",
    "app/routers/api_tokens_admin.py",
    "app/routers/ai_admin.py",
    "app/routers/activity_admin.py",
    "app/routers/storage_admin.py",
]

_HTML_CODE_SPAN = re.compile(r"<code[^>]*>(.*?)</code>", re.S)

# A `/admin...` path literal: must start at a non-identifier boundary (so it never
# matches mid-word, e.g. inside "/administration") and must not be followed by more
# identifier characters (so "/admin" alone doesn't swallow a longer unrelated word).
_ADMIN_PATH_RE = re.compile(r"(?<![\w.-])(/admin(?:/[a-zA-Z0-9_-]+)*)(?![a-zA-Z0-9_-])")


def _admins_section_html() -> str:
    text = DOCS_INDEX.read_text(encoding="utf-8")
    m = re.search(r'<section id="admins".*?</section>', text, flags=re.S)
    assert m, 'app/templates/docs/index.html is missing <section id="admins">'
    return m.group(0)


def _html_task_refs(html: str) -> set[str]:
    """`task <name>` references inside <code>...</code> spans."""
    refs: set[str] = set()
    for span in _HTML_CODE_SPAN.findall(html):
        refs.update(re.findall(_TASK_REF, span))
    return refs


def _html_admin_path_refs(html: str) -> set[str]:
    return set(_ADMIN_PATH_RE.findall(html))


def _admin_route_paths() -> set[str]:
    """Full concrete paths (mount prefix + route suffix) for every @router.get/post
    across the three admin routers — mirrors the docs/reference/admin-ui.md backfill-route
    extraction above (regex the router source, don't import the app)."""
    paths: set[str] = set()
    for rel in ADMIN_ROUTER_FILES:
        src = (PROJECT_ROOT / rel).read_text(encoding="utf-8")
        prefix_m = re.search(r'APIRouter\(prefix="([^"]*)"\)', src)
        assert prefix_m, f"{rel}: could not find APIRouter(prefix=...) — parsing broken?"
        prefix = prefix_m.group(1)
        for _method, suffix in re.findall(r'@router\.(get|post)\("([^"]*)"\)', src):
            paths.add(prefix + suffix)
    assert len(paths) > 15, "Admin route parsing looks broken — too few routes found"
    return paths


def _admin_path_is_registered(literal: str, registered: set[str]) -> bool:
    """`literal` resolves if it's an exact registered path, or a path-segment prefix
    of one (e.g. docs mentioning the bare `/admin/enrichment` mount).

    Direction matters: this checks whether `literal` is a prefix of some `registered`
    entry (at a `/` boundary), never the reverse. Checking the reverse — whether some
    registered mount prefix (like `/admin`) is a prefix of `literal` — is the false-pass
    bug this guard exists to avoid: it would let a bogus `/admin/no-such-route` pass
    just because `/admin` itself is a valid mount.
    """
    if literal in registered:
        return True
    return any(reg.startswith(literal + "/") for reg in registered)


def test_admin_docs_section_task_and_route_refs_are_valid():
    """The in-app docs' "For administrators" section references `task <name>`
    commands and `/admin/...` routes for operators — pin both so a rename doesn't
    silently rot in a page the markdown doc-sync guards above don't cover."""
    html = _admins_section_html()

    tasks = _html_task_refs(html)
    assert len(tasks) >= 2, "docs #admins section should reference at least 2 task commands — extraction looks broken"
    defined = _defined_tasks()
    unknown_tasks = sorted(tasks - defined)
    assert not unknown_tasks, f"docs/index.html #admins references unknown task(s) not in Taskfile.yml: {unknown_tasks}"

    admin_paths = _html_admin_path_refs(html)
    assert len(admin_paths) >= 3, "docs #admins section should reference at least 3 /admin routes — extraction looks broken"
    registered = _admin_route_paths()
    unknown_paths = sorted(p for p in admin_paths if not _admin_path_is_registered(p, registered))
    assert not unknown_paths, f"docs/index.html #admins references unknown admin route(s): {unknown_paths}"


def test_sitesettings_columns_documented():
    """Forward: every SiteSettings column is backticked in docs/reference/admin-ui.md. Reverse: the
    SiteSettings section's table lists no snake_case column-looking token that is not a
    real column (catches a renamed/removed setting left stale in the docs)."""
    columns = _sitesettings_columns()
    operations = OPERATIONS_DOC.read_text(encoding="utf-8")
    missing = sorted(c for c in columns if f"`{c}`" not in operations)

    # Reverse: scope to the SiteSettings section's table rows only. A settings column
    # looks like a lowercase snake_case token (has an underscore), which excludes the
    # `true`/`false`/`10` cell values and the uppercase `TOOL_MAX_WORKERS` env var.
    section = _operations_sitesettings_section()
    row_text = "\n".join(ln for ln in section.splitlines() if ln.lstrip().startswith("|"))
    tokens = {t for t in re.findall(r"`([a-z][a-z0-9_]+)`", row_text) if "_" in t}
    stale = sorted(t for t in tokens if t not in columns)

    problems: list[str] = []
    if missing:
        problems.append(f"SiteSettings columns missing (not backticked) from docs/reference/admin-ui.md: {missing}")
    if stale:
        problems.append(f"docs/reference/admin-ui.md SiteSettings section lists tokens that are not SiteSettings columns: {stale}")
    assert not problems, "\n".join(problems)


# ── Maintenance actions ↔ real POST routes ───────────────────────────────────


def test_maintenance_actions_have_real_post_routes():
    """Every Maintenance-tab action must POST to a route that actually exists,
    and the two non-backfill actions stay documented in docs/reference/admin-ui.md (the
    backfill table has its own bidirectional guard above)."""
    from app.routers import admin as admin_module

    post_paths = {route.path for route in admin_module.router.routes if "POST" in (getattr(route, "methods", None) or set())}
    for action in admin_module.MAINTENANCE_ACTIONS:
        assert action["url"] in post_paths, f"MAINTENANCE_ACTIONS url has no POST route: {action['url']}"

    operations = OPERATIONS_DOC.read_text(encoding="utf-8")
    operations += (DOCS_DIR / "runbooks/storage.md").read_text()
    operations += (DOCS_DIR / "runbooks/workers.md").read_text()
    for path in ("/admin/cleanup-outputs", "/admin/recover-stuck-jobs"):
        assert path in post_paths, f"expected POST route missing: {path}"
        assert path in operations, f"docs/reference/admin-ui.md no longer documents {path}"


# ── Compose profile names ↔ docs ─────────────────────────────────────────────


def _compose_profiles() -> set[str]:
    data = yaml.safe_load((PROJECT_ROOT / "docker-compose.yml").read_text(encoding="utf-8"))
    profiles: set[str] = set()
    for svc in (data.get("services") or {}).values():
        profiles.update(svc.get("profiles") or [])
    return profiles


def test_compose_profiles_documented_and_no_stale_profile_examples():
    """Every compose profile is shown in a COMPOSE_PROFILES= example in
    docs/configuration.md + .env.example, and every profile named in a
    COMPOSE_PROFILES= example anywhere in the doc set is a real compose profile
    (catches renames/typos)."""
    profiles = _compose_profiles()
    assert profiles, "no profiles found in docker-compose.yml — parser broke?"

    def _profiles_in_examples(text: str) -> set[str]:
        used: set[str] = set()
        for match in re.findall(r"COMPOSE_PROFILES=([a-z0-9_,\-]+)", text):
            used.update(p for p in match.split(",") if p)
        return used

    # Forward: the canonical profile references must show every profile.
    for source_name in ("docs/configuration.md", ".env.example"):
        used = _profiles_in_examples((PROJECT_ROOT / source_name).read_text(encoding="utf-8"))
        missing = profiles - used
        assert not missing, f"{source_name}: no COMPOSE_PROFILES= example mentions profile(s) {missing}"

    # Reverse: no example anywhere in the doc set names a profile that doesn't exist.
    for source_name in [*MD_DOC_FILES, ".env.example"]:
        used = _profiles_in_examples((PROJECT_ROOT / source_name).read_text(encoding="utf-8"))
        stale = used - profiles
        assert not stale, f"{source_name}: COMPOSE_PROFILES= example names unknown profile(s) {stale}"


# ── Deploy script env vars are self-documented ───────────────────────────────


def test_deploy_script_env_vars_are_self_documented():
    """Every DEPLOY_* knob the deploy script reads must be documented in its own
    header comment block — the header is what README points operators at."""
    # Every deploy script, not just the orchestrator: they all read DEPLOY_* knobs and
    # their headers are what the docs point operators at.
    scripts = sorted((PROJECT_ROOT / "scripts").glob("deploy*.sh"))
    assert scripts, "no deploy scripts found"
    internal = {"DEPLOY_DRY_RUN_HEALTH", "DEPLOY_DRY_RUN_OS_RELEASE"}  # test hooks, not operator knobs
    problems = []
    for script_path in scripts:
        script = script_path.read_text(encoding="utf-8")
        # Both shell-option preludes in use across these scripts.
        for sentinel in ("set -euo pipefail", "set -eu", "set -e"):
            if sentinel in script:
                header, _, body = script.partition(sentinel)
                break
        else:
            continue
        # Lines that only *print* a variable name are documentation, not a read: the
        # scaffold's "next steps" block and preflight's warnings both name knobs
        # belonging to other scripts.
        read_lines = [line for line in body.splitlines() if not re.match(r"\s*(echo|printf|info|warn|step|header|die)\b", line)]
        used = set(re.findall(r"\bDEPLOY_[A-Z_]+\b", "\n".join(read_lines)))
        documented = set(re.findall(r"\bDEPLOY_[A-Z_]+\b", header))
        missing = used - documented - internal
        if missing:
            problems.append(f"{script_path.name}: {sorted(missing)}")
    assert not problems, f"deploy scripts use undocumented env vars: {problems}"


# ── Every DEPLOY_* is documented where an operator will look ─────────────────
#
# The guard above checks each script's own header, which is necessary and was never
# sufficient: it globs `scripts/deploy*.sh`, so it has never seen upgrade.sh (which reads
# eleven of these), quickstart.sh, either .py helper or lib/common.sh — and it never looks
# at docs/ or deploy.env.example at all. That is exactly why 23 variables reached operators
# undocumented while this test passed.

#: Where the tooling reads DEPLOY_* from. Deliberately wider than `scripts/deploy*.sh`.
_DEPLOY_VAR_SOURCES = (
    *sorted((PROJECT_ROOT / "scripts").glob("*.sh")),
    *sorted((PROJECT_ROOT / "scripts" / "lib").glob("*.sh")),
    *sorted((PROJECT_ROOT / "scripts").glob("*.py")),
    *taskfile_paths(),
)

#: Set BY a script for another script, or a test hook. Documented in
#: docs/contribute/development.md's "Deploy tooling internals" table (or, for the per-run and
#: FLEET_FROM knobs, in the fleet reference), and deliberately absent from
#: deploy.env.example: putting them there would invite an operator to set them.
_DEPLOY_VARS_NOT_SETTINGS = {
    "DEPLOY_ACTION",
    "DEPLOY_PLAN_ONLY",
    "DEPLOY_SMOKE_STRICT",
    "DEPLOY_HEALTH_CONFIRMED",
    "DEPLOY_VPN_DEFAULT",
    "DEPLOY_DRY_RUN_HEALTH",
    "DEPLOY_DRY_RUN_OS_RELEASE",
    # Per-invocation, or a confirmation. A confirmation you wrote down once is not one.
    "DEPLOY_ENV_FILE",
    "DEPLOY_HOST",
    "DEPLOY_CMD",
    "DEPLOY_REMOVE_CONFIRM",
    "DEPLOY_CLEAN_CONFIRM",
    # Set by a script for its own use, never by an operator.
    "FLEET_MANIFEST",
    "FLEET_ADOPTED",
    "FLEET_WORK",
    "FLEET_VERIFIED",
    "FLEET_HOSTS_SOURCE",
    # Names WHICH fleet this command is about, so it cannot live in the file describing
    # this one — deploy.env would then be naming a different fleet than itself.
    "FLEET_FROM",
    "FLEET_REFRESH",
    "FLEET_CACHE_TTL",
}


#: FLEET_* joins DEPLOY_* here. FLEET_FROM, FLEET_REFRESH and FLEET_CACHE_TTL are operator
#: knobs by any reasonable definition, and without this they reach operators undocumented —
#: which is the situation these guards were written for, arriving under a new prefix.
#:
#: They are NOT named DEPLOY_*, deliberately. A value saying WHICH fleet a command is about
#: must not live in the file describing THIS fleet, and a DEPLOY_ name would earn a row in
#: deploy.env.example's fleet section, implying exactly that.
_DEPLOY_VAR_PATTERN = r"\b(?:DEPLOY|FLEET)_[A-Z_]+\b"
_DEPLOY_VAR_PATTERN_BACKTICKED = r"`((?:DEPLOY|FLEET)_[A-Z_]+)`"


def _deploy_vars_used() -> set[str]:
    used: set[str] = set()
    for path in _DEPLOY_VAR_SOURCES:
        used |= set(re.findall(_DEPLOY_VAR_PATTERN, path.read_text(encoding="utf-8")))
    return used


#: The DEPLOY_*/FLEET_* reference is split by audience: docs/reference/fleet.md holds every
#: operator-facing variable (its "`DEPLOY_*` reference" section plus FLEET_FROM),
#: docs/contribute/development.md the ones scripts set for each other, and
#: docs/configuration.md keeps a pointer to both. Together they must be complete.
FLEET_REFERENCE_DOC = DOCS_DIR / "reference/fleet.md"
DEPLOY_REFERENCE_DOCS = (CONFIGURATION_DOC, FLEET_REFERENCE_DOC, DOCS_DIR / "contribute/development.md")


def _deploy_vars_documented() -> set[str]:
    return set(re.findall(_DEPLOY_VAR_PATTERN_BACKTICKED, "\n".join(p.read_text(encoding="utf-8") for p in DEPLOY_REFERENCE_DOCS)))


def test_every_deploy_var_is_in_the_reference_table():
    """The reference is where an operator looks up a knob, so it has to be complete rather
    than representative."""
    assert "## `DEPLOY_*` reference" in FLEET_REFERENCE_DOC.read_text(encoding="utf-8"), "the reference section is gone or renamed"
    assert "## `DEPLOY_*` reference" in CONFIGURATION_DOC.read_text(encoding="utf-8"), "docs/configuration.md lost its pointer to the reference"
    missing = _deploy_vars_used() - _deploy_vars_documented()
    assert not missing, f"DEPLOY_* variables the tooling reads but no reference page mentions: {sorted(missing)}"


def test_the_reference_table_has_no_variables_that_do_not_exist():
    """The other direction: a knob removed from the scripts and left in the docs sends an
    operator to set something nothing reads."""
    stale = _deploy_vars_documented() - _deploy_vars_used()
    assert not stale, f"documented but read by nothing: {sorted(stale)}"


def test_every_operator_facing_deploy_var_is_in_deploy_env_example():
    """docs/install/fleet.md called deploy.env.example the file that "lists every knob",
    and it missed 23 of them.

    Anything an operator is meant to SET belongs there — that file is both the template
    they copy and the only place several of these are discoverable. The exceptions are
    listed in _DEPLOY_VARS_NOT_SETTINGS with a reason each, and are covered by the
    reference table instead."""
    example = (PROJECT_ROOT / "deploy.env.example").read_text(encoding="utf-8")
    present = set(re.findall(r"^#?\s*(DEPLOY_[A-Z_]+)=", example, re.M))
    # Named in prose counts too: several are documented as a group.
    present |= set(re.findall(r"\b(DEPLOY_[A-Z_]+)\b", example))
    missing = _deploy_vars_used() - present - _DEPLOY_VARS_NOT_SETTINGS
    assert not missing, f"operator-facing DEPLOY_* absent from deploy.env.example: {sorted(missing)}"


def test_the_not_settings_list_has_no_stale_entries():
    """A ratchet, the UNDOCUMENTED_TASKS_OK shape: an exemption for a variable that no
    longer exists hides the next one that should not have been exempted."""
    stale = _DEPLOY_VARS_NOT_SETTINGS - _deploy_vars_used()
    assert not stale, f"exempted but read by nothing: {sorted(stale)}"


# ── Upgrade recipes must use the composed upgrade tasks ──────────────────────


def test_upgrade_recipes_use_upgrade_tasks():
    """Upgrading with bare deploy:multiserver skips the verified backup,
    migrations, and doctor/health gates. The docs must never show that recipe
    (DEPLOY_KEEPENV=true + deploy:multiserver on one line marks an
    existing-deployment push), and must document task upgrade."""
    for doc in MD_DOC_FILES:
        text = (PROJECT_ROOT / doc).read_text(encoding="utf-8")
        for line_number, line in enumerate(text.splitlines(), start=1):
            deploys = "task deploy" in line or "./logstotal deploy" in line
            assert not ("DEPLOY_KEEPENV=true" in line and deploys), f"{doc}:{line_number} shows a bare deploy:multiserver upgrade recipe — use ./logstotal upgrade"
    assert "./logstotal upgrade" in UPGRADING_DOC.read_text(encoding="utf-8")
    assert "./logstotal upgrade" in (DOCS_DIR / "install/fleet.md").read_text(encoding="utf-8")


def test_upgrading_checklist_pins_verified_backup():
    """The pre-upgrade checklist must keep the verified-backup requirement:
    the canonical task backup, its verify step, and the receipt artifact."""
    text = UPGRADING_DOC.read_text(encoding="utf-8")
    for token in ("./logstotal backup", "backup:verify", "last-verified.json"):
        assert token in text, f"docs/runbooks/upgrading.md lost the '{token}' reference from the verified-backup checklist"


# ── the rollback consumes its snapshot ───────────────────────────────────────


def test_rollback_snapshot_consumption_is_documented():
    """Both README.md and docs/runbooks/upgrading.md must clarify that `task upgrade:rollback`
    consumes (deletes) its snapshot — otherwise operators expect a git-reflog-style
    idempotent restore and are surprised when a second rollback jumps back two
    releases."""
    readme = (PROJECT_ROOT / "README.md").read_text(encoding="utf-8")
    upgrading = UPGRADING_DOC.read_text(encoding="utf-8")
    for label, text in (("README.md", readme), ("docs/runbooks/upgrading.md", upgrading)):
        assert "./logstotal upgrade:rollback" in text, f"{label} must mention `./logstotal upgrade:rollback` when documenting rollback semantics"
        assert "consumes" in text.lower() or "consume" in text.lower(), f"{label} must say the snapshot is consumed by the rollback"
        assert "snapshot" in text.lower(), f"{label} must name the snapshot in the rollback-consumption note"


# ── "On this page:" navigation anchors resolve ──────────────────────────────


# ── COMPOSE_PROFILES activation tokens are documented ──────────────────────


def test_compose_profile_gates_documented():
    """Every COMPOSE_PROFILES profile that enables a service must be documented
    with its activation prerequisite/token (ENV var, file, or gate logic)."""
    profiles = _compose_profiles()
    # Profiles that require documentation (skip meta ones like 'default')
    checkable = profiles - {"default"}

    config_doc = CONFIGURATION_DOC.read_text(encoding="utf-8")
    env_example = ENV_EXAMPLE.read_text(encoding="utf-8")

    # Profiles checked: postgres, proxy, s3. Each must appear in an activation
    # section of docs/configuration.md or .env.example (e.g. "POSTGRES_PASSWORD=",
    # "DOMAIN=", "S3_ENDPOINT=").
    profile_gates = {
        "postgres": ("POSTGRES_PASSWORD", "POSTGRES_HOST", "POSTGRES_USER"),
        "proxy": ("DOMAIN", "ACME_EMAIL"),
        "s3": ("S3_ENDPOINT", "S3_BUCKET"),
        "workers": ("REDIS_EXPOSE",),  # multi-server: exposes Redis to the network for remote workers
    }

    problems: list[str] = []
    # All non-default profiles must have documented gates
    unmapped = checkable - set(profile_gates.keys())
    if unmapped:
        problems.append(f"Profiles without documented gates (add to profile_gates dict): {sorted(unmapped)}")

    for profile in sorted(checkable):
        if profile not in profile_gates:
            continue  # Skip unknown profiles
        gates = profile_gates[profile]
        found = any(gate in config_doc or gate in env_example for gate in gates)
        if not found:
            problems.append(f"COMPOSE_PROFILES profile '{profile}' not documented with any of its gates: {gates}")

    # Note: We check that gate strings appear in configuration.md,
    # but don't verify they are in the profile's activation section.
    # A visual inspection of docs/configuration.md is recommended to ensure
    # each profile's activation is clearly explained.
    assert not problems, "Undocumented profile activation gates:\n" + "\n".join(problems)


# ── Alembic revisions form a single chain (DAG integrity) ──────────────────


def test_alembic_revisions_form_single_chain():
    """Every alembic revision must have a unique downrevision (except head),
    forming a single unambiguous chain. Branches = future conflict."""
    if not ALEMBIC_VERSIONS.exists():
        return  # No revisions yet

    revisions: dict[str, tuple[str | None, str]] = {}  # rev_id -> (down_rev, filename)
    for path in sorted(ALEMBIC_VERSIONS.glob("*.py")):
        if path.name.startswith("__"):
            continue
        src = path.read_text(encoding="utf-8")
        rev_m = re.search(r"""revision[^=\n]*=\s*["']([0-9a-f]+)["']""", src, flags=re.M)
        down_m = re.search(r"""down_revision[^=\n]*=\s*["']([0-9a-f]+)["']""", src, flags=re.M)
        if not rev_m:
            continue
        rev_id = rev_m.group(1)
        down_rev = down_m.group(1) if down_m else None
        revisions[rev_id] = (down_rev, path.name)

    problems: list[str] = []
    # Build a mapping: down_rev -> list of children
    children: dict[str | None, list[str]] = {}
    for rev_id, (down_rev, _) in revisions.items():
        if down_rev not in children:
            children[down_rev] = []
        children[down_rev].append(rev_id)

    # Check: every down_rev (except None) exists as a revision
    for rev_id, (down_rev, filename) in revisions.items():
        if down_rev is not None and down_rev not in revisions:
            problems.append(f"{filename} (rev {rev_id}): down_revision {down_rev!r} does not exist")

    # Check: no downrev has more than one child (single chain, not branched)
    for down_rev, child_list in children.items():
        if len(child_list) > 1:
            problems.append(f"Branch detected: down_revision {down_rev!r} has multiple children: {child_list}")

    assert not problems, "Alembic revision chain is broken:\n" + "\n".join(problems)


# ── Every task has a description ────────────────────────────────────────────


def test_every_task_has_a_desc():
    """Every task in Taskfile.yml must have a `desc:` field (or be in an allow-list
    of intentional exceptions). Descriptions are how `task --list` and operators
    discover available commands."""
    with open(TASKFILE) as f:
        tf = yaml.safe_load(f)

    # Tasks that intentionally have no desc (internal helpers, aliases)
    no_desc_allowed = {
        "upgrade:stage-code",  # internal helper for `task upgrade`
    }

    tasks = tf.get("tasks", {})
    problems: list[str] = []
    for task_name in sorted(tasks.keys()):
        task_def = tasks[task_name]
        # Skip internal tasks (those with internal: true)
        if isinstance(task_def, dict) and task_def.get("internal", False):
            continue
        # Skip explicitly allowed tasks
        if task_name in no_desc_allowed:
            continue
        # Check for desc field
        if not (isinstance(task_def, dict) and task_def.get("desc")):
            problems.append(f"{task_name}: missing `desc:` field (add one, or add to no_desc_allowed if internal)")

    assert not problems, "Tasks without descriptions:\n" + "\n".join(problems)


# ── SiteSettings reference table strictness ────────────────────────────────


def test_sitesettings_reference_table_rows_have_default_and_effect():
    """Every row in docs/reference/admin-ui.md's SiteSettings table must have a
    | Setting | Default | Effect | structure with no empty cells — incomplete
    rows are confusing for operators."""
    section = _operations_sitesettings_section()
    lines = section.splitlines()

    # Find table start and filter out header/separator rows
    rows: list[str] = []
    is_header = True
    for ln in lines:
        if not ln.lstrip().startswith("|"):
            break
        # Skip header row (first row)
        if is_header:
            is_header = False
            continue
        # Skip separator rows (|---|---|---|...) using regex
        if re.match(r"^\s*\|[\s\-|:]+\|\s*$", ln):
            continue
        rows.append(ln)

    problems: list[str] = []
    for i, row in enumerate(rows, start=1):
        # Simple check: 4 pipe chars = 4 columns (Setting | Default | Effect | empty)
        pipes = row.count("|")
        if pipes < 4:
            problems.append(f"Row {i} has fewer than 3 columns: {row.strip()[:60]}...")
        # Check for empty cells (||): each column should have content
        cells = [cell.strip() for cell in row.split("|")[1:-1]]  # Skip outer pipes
        for j, cell in enumerate(cells):
            if not cell:
                col_names = ["Setting", "Default", "Effect"]
                col = col_names[j] if j < len(col_names) else f"column {j}"
                problems.append(f"Row {i} has empty {col} cell: {row.strip()[:60]}...")

    assert not problems, "SiteSettings table has incomplete rows:\n" + "\n".join(problems)


# ── Rate limiting is Redis-backed, and the docs must not claim otherwise ─────


def test_docs_do_not_claim_rate_limits_are_per_process():
    """docs/security.md must not state the opposite of the implementation.

    Saying limits are "in-memory counters (not Redis)" and that N web processes multiply
    the limit is advice that would lead an operator to divide their intended limit by the
    replica count. Both middlewares are Redis-backed (`logstotal:ratelimit:*`)
    with an in-memory fallback only when Redis is unreachable.
    """
    middleware = (PROJECT_ROOT / "app" / "middleware" / "production.py").read_text(encoding="utf-8")
    assert "logstotal:ratelimit:" in middleware, "rate limiting no longer uses the Redis key this test assumes"

    security = SECURITY_DOC.read_text(encoding="utf-8")
    assert "in-memory counters (not Redis)" not in security
    assert "Redis" in security.split("## Rate limit semantics", 1)[1].split("##", 1)[0], "the rate-limit section must say the counters are shared via Redis"


def test_csrf_protection_is_documented():
    """`CsrfMiddleware` rejects cookie-authed writes whose Origin/Referer mismatches Host.

    It is enforced with no config knob, so it went undocumented — but it fails *closed*
    with a 403, and a proxy that rewrites Host without Origin trips it. Operators need it
    written down to debug that.
    """
    assert "CsrfMiddleware" in (PROJECT_ROOT / "app" / "middleware" / "production.py").read_text(encoding="utf-8")
    security = SECURITY_DOC.read_text(encoding="utf-8")
    assert "CSRF" in security, "docs/security.md must document the CSRF/Origin requirement"
    for token in ("Origin", "Referer", "403"):
        assert token in security, f"the CSRF section should mention {token}"


# ── The backup receipt must be readable from the web container ───────────────


def test_web_container_can_read_the_backup_receipt():
    """`check_backup_receipt` reads backups/last-verified.json to drive the System-checks
    card and the getting-started checklist. Without a mount it reported "no verified
    backup" on every Docker deployment however faithfully backups were taken — a check
    that can only ever fail is worse than no check."""
    data = yaml.safe_load((PROJECT_ROOT / "docker-compose.yml").read_text(encoding="utf-8"))
    web_volumes = data["services"]["web"].get("volumes") or []
    mounts = [v for v in web_volumes if isinstance(v, str) and "/backups" in v]
    assert mounts, "web has no backups mount — check_backup_receipt cannot see the receipt"
    assert any(m.endswith(":ro") for m in mounts), "the backups mount must be read-only"


def test_worker_does_not_mount_backups():
    """Nothing in the worker reads the receipt; mounting it there would only widen the
    write surface around backups/."""
    data = yaml.safe_load((PROJECT_ROOT / "docker-compose.yml").read_text(encoding="utf-8"))
    worker_volumes = data["services"]["worker"].get("volumes") or []
    assert not [v for v in worker_volumes if isinstance(v, str) and "/backups" in v]


# ── Release metadata ─────────────────────────────────────────────────────────


def _declared_versions() -> dict[str, str]:
    """The three places a version number lives, read the way each consumer reads it."""
    import re

    config_src = (PROJECT_ROOT / "app" / "config.py").read_text(encoding="utf-8")
    config_version = re.search(r'app_version: str = "([^"]+)"', config_src).group(1)

    pyproject_src = (PROJECT_ROOT / "pyproject.toml").read_text(encoding="utf-8")
    pyproject_version = re.search(r'^version = "([^"]+)"', pyproject_src, re.M).group(1)

    out = {"app/config.py": config_version, "pyproject.toml": pyproject_version}

    version_file = PROJECT_ROOT / "VERSION"
    if version_file.exists():
        for line in version_file.read_text(encoding="utf-8").splitlines():
            key, _, value = line.partition(":")
            if key == "version" and value.strip():
                out["VERSION"] = value.strip()
    return out


def test_the_version_is_the_same_everywhere():
    """`app/config.py`, `pyproject.toml` and `VERSION` must agree.

    Three independent declarations with no check between them drift the obvious way.

    `task release:prepare` is what keeps them in step — this test is the guard that the
    tool did its job, which is why all three declarations survive rather than collapsing
    into one.
    """
    versions = _declared_versions()
    assert len(set(versions.values())) == 1, f"version mismatch: {versions}. Run `task release:prepare VERSION=X.Y.Z` rather than editing any of the three by hand."


def test_release_metadata_files_exist():
    """The files a public release is expected to carry.

    `pyproject.toml` declares MIT, but without a LICENSE file at the root GitHub reports
    "no license" and the code is all-rights-reserved to anyone downstream.
    """
    for name in ("LICENSE", "CHANGELOG.md", "CONTRIBUTING.md", "SECURITY.md"):
        assert (PROJECT_ROOT / name).exists(), f"{name} is missing from the repository root"


#: Files scanned for stale version references. Wider than the docs set on purpose: the two
#: surviving `0.2.0` strings hid in `scripts/upgrade.sh` and in a *verification*
#: instruction telling the operator what output proves the upgrade worked — seven minor
#: versions wrong, in the one place a wrong number is read as confirmation.
_VERSION_SCAN_FILES = [
    *(PROJECT_ROOT / f for f in ROOT_MD_FILES),
    *sorted((PROJECT_ROOT / "docs").rglob("*.md")),
    *sorted((PROJECT_ROOT / "scripts").glob("*.sh")),
]

#: Imported, never re-declared. `scripts/release.py` rewrites exactly the lines this test
#: then polices, so a second copy of either regex means a release can leave behind precisely
#: the sites the guard fails on — with the two definitions looking identical in review.
#:
#: _HISTORICAL_VERSION_MENTION exempts prose that names an old version *on purpose* ("the
#: default changed in 0.9.1"): a fact about history, not a stale upgrade recipe. It is
#: checked before the marker set, so a historical line stays exempt even when it also looks
#: like a recipe.
_HISTORICAL_VERSION_MENTION = _release.HISTORICAL_VERSION_MENTION
_VERSION_SITE_MARKER = _release.VERSION_SITE_MARKER


def test_docs_do_not_reference_unreleased_version_tags():
    """Upgrade recipes must not name a version that does not exist.

    Every `task upgrade:* REF=vX.Y.Z` in the docs is something an operator will paste. The
    docs shipped `v0.2.0` throughout — including a GitHub archive URL — while no tag had
    ever been cut, so each one 404s. Placeholders are fine; specific dead versions are not.

    Matches with **or without** the `v` prefix. The `v`-only regex is why two `0.2.0`
    strings survived the sweep that introduced this test.
    """
    import re

    current = _declared_versions()["app/config.py"]
    allowed = {current, f"v{current}"}
    offenders = []
    for path in _VERSION_SCAN_FILES:
        text = path.read_text(encoding="utf-8")
        for match in re.finditer(r"\bv?\d+\.\d+\.\d+\b", text):
            token = match.group(0)
            if token in allowed:
                continue
            # Third-party versions are pinned all over these files (Task, Tailwind, tool
            # releases). Only flag a token that looks like *our* release: on a line that
            # also mentions the project, a REF=, or an upgrade/archive recipe.
            line = text[text.rfind("\n", 0, match.start()) + 1 : text.find("\n", match.end())]
            # A version the *application reports about itself* is the same class of stale
            # claim as an upgrade recipe, and four of them were invisible to the original
            # marker set: the `/health` example body, the `# expect: version:` line an
            # operator reads as proof the upgrade landed, the `LogsTotal-vX.Y.Z/` directory
            # an archive extracts to, and the `origin/vX.Y.Z` ref the upgrade prefers.
            if _HISTORICAL_VERSION_MENTION.search(line):
                continue
            if _VERSION_SITE_MARKER.search(line):
                offenders.append(f"{path.relative_to(PROJECT_ROOT)}: {token}")
    assert not offenders, f"docs name versions of LogsTotal that do not exist: {sorted(set(offenders))}. Use <version> as a placeholder, or the current release."


def test_the_declared_version_has_a_git_tag():
    """The version in the code must correspond to a tag that exists.

    `CHANGELOG.md` links to `releases/tag/vX.Y.Z` and the upgrade recipes tell operators to
    check out `REF=vX.Y.Z`. Without a check connecting the declared version to git, a
    repository with no matching tag leaves every documented upgrade path 404ing, unnoticed.

    Skipped outside a git checkout (a release archive, a Docker build context).
    """
    import subprocess

    import pytest

    if not (PROJECT_ROOT / ".git").exists():
        pytest.skip("not a git checkout")
    current = _declared_versions()["app/config.py"]
    try:
        out = subprocess.run(["git", "tag", "--list", f"v{current}"], cwd=PROJECT_ROOT, capture_output=True, text=True, timeout=10, check=False)
    except Exception:  # pragma: no cover - git missing
        pytest.skip("git unavailable")
    assert out.stdout.strip(), (
        f"app/config.py declares {current} but no `v{current}` tag exists. Cut the tag before release, or the CHANGELOG link and every documented `REF=v{{current}}` upgrade 404s."
    )


def test_the_declared_version_has_a_changelog_entry():
    """The declared version needs a CHANGELOG section *and* its two link definitions.

    Step 3 of the release ritual in `docs/runbooks/upgrading.md` was guarded only by prose, while
    steps 1, 2 and 6 each had a test. A release whose changelog entry was forgotten still
    tags, still builds, still publishes — and `release.yml` points `body_path` at this file,
    so the published notes would be the *previous* version's.

    Three things are checked, because they fail independently:

    - `## [X.Y.Z]` — the section itself.
    - `[X.Y.Z]: …compare/…` — the link the section heading resolves through. Without it the
      heading renders as literal brackets.
    - `[Unreleased]: …compare/vX.Y.Z...HEAD` — the moved forward-link. Forgetting this one
      is invisible in rendered output and silently keeps pointing at the release before.
    """
    current = _declared_versions()["app/config.py"]
    changelog = (PROJECT_ROOT / "CHANGELOG.md").read_text(encoding="utf-8")

    assert re.search(rf"^## \[{re.escape(current)}\]", changelog, re.M), (
        f"CHANGELOG.md has no `## [{current}]` section. Step 3 of the release ritual in docs/runbooks/upgrading.md — release.yml publishes this file as the release notes, so without it the notes describe the previous version."
    )
    assert re.search(rf"^\[{re.escape(current)}\]:\s*http", changelog, re.M), (
        f"CHANGELOG.md has no `[{current}]:` link definition at the bottom. The `## [{current}]` heading renders as literal brackets without it."
    )
    assert re.search(rf"^\[Unreleased\]:\s*\S*compare/v{re.escape(current)}\.\.\.HEAD", changelog, re.M), (
        f"CHANGELOG.md's `[Unreleased]:` link must compare from `v{current}`. It still points at an earlier tag, so the 'unreleased' diff silently includes {current}'s own changes."
    )


def test_deploy_plan_verdicts_agree_with_the_script():
    """`task deploy:plan`'s whole job is a per-host verdict, so the words it prints and the
    words the table in docs/install/fleet.md explains have to be the same words.

    This pins the VOCABULARY — that every verdict the script prints is explained, and that
    the table promises none the script cannot produce. It does not compare formats, which
    interpolate runtime values.

    What it catches is a verdict being renamed, added or removed, which is how the table
    goes stale.
    """
    script = (PROJECT_ROOT / "scripts" / "deploy-preflight.sh").read_text()
    doc = (DOCS_DIR / "install/fleet.md").read_text()

    emitted = set(re.findall(r"VERDICT: ([A-Z][A-Z ]*[A-Z])", script))
    assert emitted, "no VERDICT lines found — has the plan output been restructured?"

    for verdict in emitted:
        assert f"`{verdict}" in doc, f"deploy:plan prints VERDICT: {verdict}, and docs/install/fleet.md never explains it"

    # And nothing the table promises may be absent from the script. Scoped to the plan
    # section — the file holds several tables, and an unscoped scan reads the first word of
    # every `DEPLOY_*` row in the options table as a verdict.
    section = doc.split("### Before you deploy")[1].split("\n### ")[0]
    table = re.findall(r"^\| `([A-Z][A-Z ]*[A-Z])", section, re.MULTILINE)
    assert table, "the verdict table is gone or its heading changed"
    for verdict in table:
        assert verdict in emitted, f"docs/install/fleet.md documents a `{verdict}` verdict that deploy-preflight.sh never prints"


def test_no_task_is_listed_twice_in_the_same_section_of_tasks_md():
    """Renaming several tasks onto one name left their bullets behind as duplicates.

    docs/reference/commands.md carried three `task deploy` entries with three different descriptions,
    two `task deploy:env`, two `task upgrade` and two `task upgrade:rollback` — the reader
    cannot tell which is true, and one of them was literally the retired task's text.

    Per SECTION, because a task legitimately appears in "Most-used commands" and again in
    its own section.
    """
    text = (DOCS_DIR / "reference/commands.md").read_text(encoding="utf-8")
    section = "(top)"
    seen: dict[str, set[str]] = {}
    offenders = []
    for line in text.splitlines():
        if line.startswith("## "):
            section = line[3:].strip()
            continue
        m = re.match(r"^- `(?:task|\./logstotal) ([a-z:._-]+)`", line)
        if not m:
            continue
        name = m.group(1)
        bucket = seen.setdefault(section, set())
        if name in bucket:
            offenders.append(f"{section}: task {name}")
        bucket.add(name)
    assert not offenders, f"duplicate task bullets within one section: {offenders}"
