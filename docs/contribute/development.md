# Development

How to work on LogsTotal itself: dependencies, tool adapters, tests, CI and code quality. Releasing and packaging have [their own page](releasing.md).

Set up a development environment with [Path A: Local Development](local-development.md#path-a-local-development). For conventions, project layout, and data models, see the codebase itself — `app/models.py` (ORM models), `app/tools/base.py` (the tool-adapter contract), and the per-module docstrings under `app/`.

## Production CSS (Tailwind)

Development compiles Tailwind in the browser with `app/static/vendor/tailwind.js` (Tailwind's browser build, committed to the repo and refreshed by `./logstotal vendor:update` — no Node build). For production, serve compiled CSS instead: run `./logstotal tailwind:install` once per machine (the CLI is gitignored), then `./logstotal css:build` before starting the server. That switches `base.html` to `tailwind-built.css`. Skip it and the app still works, compiling in the browser. Restore dev mode with `./logstotal css:dev`.

Both builds compile one file, `app/templates/partials/_tailwind.css`: the theme (gray mapped onto the `--ui-gray-*` variables in `app/static/themes.css`, Tailwind 3's palette and line heights pinned) and the cascade layers. Change the theme there, never in `base.html`. `app/static/tailwind-input.css` adds only what the production build needs on top: which files to scan for class names, and the entity-chip safelist.

`app/static/vendor/tailwind-built.css` is **tracked**, so every checkout has one — but it is only as current as the last `./logstotal css:build`. Tailwind scans the templates to decide which classes to emit, so a class added to a template after that build is simply absent from the stylesheet, and the elements using it render unstyled with no error anywhere. That is why every consumer keys off `base.html`'s own mode rather than the file merely existing, and why nothing switches you to that stylesheet on your behalf.

- **Docker image (Path B):** run both commands on the host before `docker compose build` / `./logstotal docker:up` so the image bakes in `tailwind-built.css`. A tree that is already in production mode (an extracted release archive) is used as-is instead — that is what makes an air-gapped image build possible.
- **Packaging:** `./logstotal package` re-runs `./logstotal css:build` automatically when the CLI is present, so the archive ships production CSS. Without the CLI it leaves `base.html` alone and the archive serves Tailwind's browser build: correct, but a ~75 KB gzipped compiler runs in the browser on every page load. To ship the committed stylesheet instead — an air-gapped build, or a checkout you know matches it — run `PACKAGE_USE_COMMITTED_CSS=true ./logstotal package`. It is opt-in because nothing without the CLI can check that the stylesheet matches the templates.
- **Pointing without compiling:** `./logstotal css:prod` is the swap on its own, and `./logstotal css:dev` reverses either one.

## Front-end assets

There is no Node build step and no `package.json`. Every third-party file is a pinned,
committed bundle in `app/static/vendor/`, downloaded by `./logstotal vendor:update` (versions live
at the top of `Taskfile.yml`, which is also where the shared preconditions and the
`includes:` for `taskfiles/dev.yml` and `taskfiles/ops.yml` live):

| File | What uses it |
|---|---|
| `htmx.min.js`, `hx-alpine-compat.js` | every page |
| `alpine.min.js` | every page |
| `tailwind.js` / `tailwind-built.css` | dev / production CSS (see above) |
| `prism*.js`, `prism-tomorrow.min.css` | syntax highlighting |
| `mermaid.min.js` | `/docs` diagrams, and diagrams in analyst prose (comments, notes, AI analyses) — fetched lazily, only on a page that has one |
| `graphology.umd.min.js`, `graphology-library.min.js`, `sigma.min.js` | the relationship graph, loaded only on `/intel/entities/…` and `/intel/cases/…` |

**Our own scripts must be listed before `alpine.min.js` in `base.html`.** Alpine evaluates
every `x-data` in the microtask right after its own script runs, so a factory defined in a
later deferred script is undefined when it is needed. The relationship-graph block is one
contiguous list — the three vendor bundles, then `graph-view.js`, `graph-algo.js`,
`graph-render.js`, `graph.js` — and `tests/test_graph_client_contract.py` pins that order.

The graph client has a small Node test suite (`./logstotal test:js`) covering its pure logic: the
emphasis precedence table, the query engine, the payload merge. It uses `node --test` with
no `package.json` and skips when node is absent.

## PostgreSQL SQL compatibility

The suite runs on SQLite, which is permissive exactly where PostgreSQL is strict.
`./logstotal test:pg` (`tests/test_postgres_sql_compat.py`) executes the app's own statements
against a real server.

Add a case there whenever you write SQL that depends on a column's *type* rather than its
text: enum comparisons, JSON operators, casts, a `CASE` over a non-text column.

> [!IMPORTANT]
> The test must **execute**, not compile, and must go through **asyncpg**. A compile-only
> assertion passes with the bug present, because both dialects render identical SQL text and
> the difference is the bind parameter's type; psycopg2 passes too, because it interpolates
> an untyped literal that PostgreSQL coerces by context. The web tier is asyncpg.

## Adding a dependency

PDM (`pyproject.toml` + `pdm.lock`) is the source of truth. `requirements.txt` is generated for the Docker image and must be kept in sync.

```bash
pdm add <package>               # or: pdm add -dG dev <package> for dev-only
./logstotal lock                       # regenerates pdm.lock and requirements.txt
./logstotal test && ./logstotal check         # confirm nothing broke
git add pyproject.toml pdm.lock requirements.txt
git commit -m "deps: add <package>"
```

Never hand-edit `requirements.txt` — any edit you make will be overwritten the next time someone runs `./logstotal lock`.

## Adding a tool adapter

The integration contract has three parts: a `ToolSpec` in `app/tools/catalog.py`, a
`ToolAdapter` subclass, and a typed `OutputMapping` declared beside the adapter. The catalog
is standard-library-only so the updater, diagnostics and offline tooling can use it before
the application environment exists.

### Responsibilities

| Component | Owns |
|---|---|
| Catalog | Tool identity, capabilities, release assets, required files and named runtime profiles |
| Workflow | Tools to run, accepted input types, profile selection and per-task overrides |
| Adapter | CLI arguments, input preparation, Sigma evaluation mappings and completion checks |
| Output mapping | Native record layout, rule metadata, grouping, counts, evidence and field projections |
| Shared result consumers | Finding persistence, timelines, entities, relationships and process trees |

Input mappings and output mappings have different jobs. RSigma's Windows pipeline and
Zircolite's journald configuration affect **which rules match**. `OutputMapping` describes
**the output already produced**. Do not change both layers during an extraction refactor.

### Minimal output mapping

For a JSONL engine emitting a `rule` object and top-level event fields such as `Timestamp`,
`Computer`, `EventID` and `Image`, the declaration is:

```python
from app.tools.base import ToolAdapter
from app.tools.mapping import MetadataMapping, OutputMapping, Selector


class ExampleAdapter(ToolAdapter):
    name = "example"
    output_mapping = OutputMapping(
        format="jsonl",
        grouping="identity",
        finding=MetadataMapping(
            rule_name=Selector((("rule", "title"),), default="Unknown Rule"),
            rule_id=Selector((("rule", "id"),), default=""),
            severity=Selector((("rule", "level"),)),
            tags=Selector((("rule", "tags"),), default=[]),
        ),
    )

    # Implement _build_local_cmd() for this engine's CLI.
    # The catalog supplies capabilities and the raw-output filename suffix.
```

The base adapter uses this same declaration for execution-time loading, `normalize()`
and `iter_raw_matches()`. `format="json"` expects an array of records;
`format="jsonl"` streams one record per line. `strict=True` rejects malformed records
instead of skipping them; a named `validate` callback can check engine-specific requirements.
A path tuple names literal dictionary keys: `("event", "code")` is nested, while
`("event.code",)` is a single dotted key. Multiple paths are ordered fallbacks. The default
fallback skips falsey values; `fallback="missing"` preserves an explicitly present `None`,
zero or empty string. Named Python transforms handle exceptional native shapes.

Use `events` to select a list of matched events from a rule block and `reported_count` for
its independent count. `grouping="blocks"` retains separate blocks, including blocks with
no evidence; `grouping="name"` groups by title; `grouping="identity"` groups by ID with a
title fallback. Capping stored details never reduces a finding's reported count.

For differently named event fields, declare their native paths once:

```python
from app.tools.event_fields import EventField, EventProjection, EventRecord, EventSource

EVENT_FIELDS = EventProjection.canonical(
    EventSource(
        ("payload",),
        fields=(
            EventField("Timestamp", (("when",),)),
            EventField("Computer", (("host",),)),
            EventField("Image", (("executable",),)),
            EventField("User", (("account",),)),
        ),
    )
)


def project_event(event):
    return EventRecord(event, projection=EVENT_FIELDS)


# Set event_projection=project_event on the OutputMapping.
```

The timestamp and host aliases then serve both timeline metadata and entity extraction.
`EventField` falls through missing or null values by default, preserving zero and `False`.
Use `fallback="missing"` to preserve explicit nulls too, or `fallback="truthy"` when the
source contract requires empty or zero values to fall through.
`EventRecord` serializes as the original native event; its projection is transient and is
reattached when raw output is read again. Use `detail_projection` separately if saved
finding samples need canonical aliases for consumers that read details from the database.

### Adding an engine

1. Declare the adapter import path, supported log types and execution modes, unique output
   suffix, thread capability, upstream repositories, assets and required files in the
   catalog. Add named runtime profiles for reusable rules and execution settings. Binary
   paths derive from release assets; workflow tasks can override them.
2. Implement command construction and any required input preparation. Reuse the base
   timeout, cancellation and process-group cleanup. For detections emitted on stdout,
   `_exec(stdout_path=...)` writes to disk. Keep engine-specific completion checks in the
   adapter: Rsigma validates its summary before publishing a final output file.
3. Declare the output mapping. Use `detail_projection` for the saved finding sample and
   `event_projection` for an analytics view that preserves native evidence. Rule YAML
   lookup is shared; use a named metadata resolver when severity comes from rule content,
   as it does for ChopChopGo. JSONL readers stream records.
4. Add a staging recipe to `scripts/detection_tools.py` if the upstream rule layout needs
   one. Stage binaries, rules and input mappings together, preserve licenses, and record
   checksums and provenance in `tools/<tool>/upstream.json`. Keep upstream packaging
   details out of the analytics layer.
5. Add a workflow task selecting the profile, update the tool runbook and
   `THIRD_PARTY_NOTICES.md`, and test real samples. Verify findings, matched events, caps,
   storage replay, attribution, cancellation and incomplete evaluation. The shared mapping
   and event-view tests include a synthetic engine that reaches analytics without vendor
   branches in the consumers.

### Preserving existing results

Existing mappings have explicit legacy policies. Hayabusa groups by title and stores a
reduced sample; Rsigma groups by identity and retains aliases; Zircolite counts rule blocks
independently of available events. Some raw metadata fallbacks also differ from finding
metadata. `raw_overrides` records these differences without duplicating the parser.

`EventView` centralizes the field sources used by analytics, relationships, process trees
and marker metadata. Those consumers do not all use the same precedence: entities may see
multiple sources, while a process field needs one value. Preserve both the native evidence
and the consumer-specific view when introducing aliases. In particular, process-only
fields must not silently expand entity extraction.

`tests/test_output_parity.py` compares against frozen pre-refactor results for all five
engines, including persistence and JSON exports. Do not regenerate those expectations to
make a migration pass. Fixing an existing omission is a separate change with explicit
before/after results. Preserve the source-hour histogram and UTC alert-marker time handling,
malformed-record policies, sample limits and event-processing caps.

Run `./logstotal check`, `./logstotal test`, and the affected sample workflows. For vendored
tools, run `./logstotal ci:artifacts` to exercise both release formats. No plugin framework,
database field or consumer-specific tool branch is needed for an engine fitting this contract.

## Deleting rows in the async path

`AsyncSession.delete()` loads and fires ORM cascades, so a `relationship(..., cascade="all, delete-orphan")` is enough for anything deleted that way (a case, a job). Core `delete()` statements do **not** — `app/intel/entities.py::remove_entity_links_for_job_async` removes orphaned entities with a Core delete, so every child table of `Entity` must be deleted explicitly there or PostgreSQL raises a foreign-key error on job deletion. If you add a table that references `Entity`, add it to that function too.

The `comment` table uses three nullable FKs (`case_id` / `entity_id` / `job_id`) with a `ck_comment_single_target` CHECK, so its cascades work the same way.

## Running tests

```bash
./logstotal test                       # full suite, in parallel
./logstotal test -- -n0 tests/test_x.py -k name   # one file, serial, live output
./logstotal test:cov                   # with coverage report
```

Tests are split into three tiers (pure functions, unit with mocks, integration). See `tests/` for structure.

The suite runs under `pytest-xdist` with `--dist loadfile`, which keeps every test in a
file on one worker — two files carry module-level generators whose values depend on call
order within the file, and `deploy-env-push`'s staging path is process-global.

It needs no Redis. `tests/conftest.py` points `app.redis_client` at `fakeredis` and Huey's
own queue at `MemoryStorage`, so "Redis is down" is never an explanation for a failure.

Two fixtures in `tests/conftest.py` are there purely for speed, and both are pinned by
tests of their own so they cannot quietly become something else:

- `_fast_password_hashing` swaps fastapi-users' Argon2 parameters for cheap ones.
  `tests/test_password_hashing.py` asserts production still gets the real parameters.
- `async_db` replays a cached DDL script instead of calling `Base.metadata.create_all`.
  `tests/helpers.py` owns the cache.

## Continuous integration

There are two copies of the CI workflow. `.github/workflows/ci.yml` runs on GitHub;
`.forgejo/workflows/ci.yml` is a mirror of it for a self-hosted Forgejo runner. Both call
the **same four tasks**: a workflow file describes how to provision a runner, never what to
check. `tests/test_ci_workflows.py` enforces that split. The release workflows are paired
the same way (`release.yml` in each directory).

```bash
./logstotal ci:test                    # the suite + the graph JS tests
./logstotal ci:artifacts               # compose parses, image builds, archive builds, no secrets
./logstotal ci:deploy                  # the stack really boots, and really analyses a log
./logstotal ci:dry-run                 # shellcheck + the 8-step deploy chain against no hosts
```

Any red CI job reproduces locally by running its task. `./logstotal ci:deploy` is the only one
that starts a deployment rather than reasoning about it.

Set `POSTGRES_TEST_URL` for `./logstotal ci:test` to include `tests/test_postgres_sql_compat.py`.
Under `CI=true` those tests **fail** rather than skip when the URL is missing: they are
the only tests that see PostgreSQL, so a silent skip restores the blind spot they exist to
remove.

`scripts/ci-provision.sh` installs the host tools a runner lacks (shellcheck, sqlite3, 7z,
jq, tailwind, pdm) into `~/.local/bin`, which persists between runs on the self-hosted
Forgejo runner's host executor.
`bash scripts/ci-provision.sh --report` prints the runner's CPU and memory.

## Documentation website

`docs/` is published as the website at <https://wagga40.github.io/LogsTotal/> by
`.github/workflows/docs.yml`: built on every pull request that touches it, deployed on a
release tag. It is built with [Zensical](https://zensical.org) from `mkdocs.yml`, a format
Material for MkDocs also reads.

```bash
pdm install -G docs
./logstotal docs:serve      # http://localhost:8001, rebuilds on save
./logstotal docs:build      # what CI runs: strict, so a broken link or anchor fails
```

- A new page must be added to `nav` in `mkdocs.yml`, or it is built but unreachable
  (`tests/test_docs_site.py` checks it).
- Pages must also read correctly on GitHub: callouts use GitHub's `> [!NOTE]` syntax, and
  heading anchors follow GitHub's rules.
- Links to repository files outside `docs/` are absolute GitHub URLs; links between pages
  are relative.
- The application links to the site through `app/docs_site.py::docs_url()`, never with a
  repository path.

## Code quality

```bash
./logstotal fmt                        # auto-format
./logstotal check                      # lint + fmt-check + shellcheck — run before every commit
```

**Two host tools the gates assume**, neither installed by `./logstotal setup`:

| Tool | Needed by | Install |
|------|-----------|---------|
| `shellcheck` | `./logstotal check` (the `lint:shell` step, which hard-errors without it) | `brew install shellcheck` / `apt install shellcheck` |
| `sqlite3` | `./logstotal test` — `tests/test_backup_scripts.py` shells out to `scripts/backup.sh` | `brew install sqlite` / `apt install sqlite3` |

In CI, `scripts/ci-provision.sh` installs whichever of them a runner lacks into
`~/.local/bin` rather than skipping the checks.

## Deploy tooling internals

The deploy scripts pass a few variables to each other, and the tests use two hooks. None of
them is an operator setting — setting one by hand generally makes things worse — and they
are deliberately absent from `deploy.env.example`. The operator-facing variables are in the
[`DEPLOY_*` reference](../reference/fleet.md#deploy_-reference).

| Variable | Effect |
|----------|--------|
| `DEPLOY_ACTION` | Which action `deploy-multiserver.sh` performs. Every task names its own |
| `DEPLOY_PLAN_ONLY` | Turns the preflight into `./logstotal deploy:plan` — read-only, always exit 0 |
| `DEPLOY_SMOKE_STRICT` | Asks the smoke check for a distinguishable exit code, so a caller can tell "failed" from "could not measure" |
| `DEPLOY_HEALTH_CONFIRMED` | Tells the smoke check that the control plane already reported healthy from **inside** its own network, so an endpoint unreachable from here is a routing fact rather than an outage |
| `DEPLOY_VPN_DEFAULT` | What `DEPLOY_VPN` defaults to (`wireconf`). Exists so the default itself can be moved in one place |
| `DEPLOY_DRY_RUN_HEALTH` | Test hook: the `/health` verdict a dry run reports |
| `DEPLOY_DRY_RUN_OS_RELEASE` | Test hook: the `/etc/os-release` a dry run reads |
| `FLEET_MANIFEST` | Overrides where the fleet record is read from. Set by `FLEET_FROM` adoption to point at the cached copy |
| `FLEET_ADOPTED` | Set when this run is acting on a record fetched from elsewhere, so the env steps can refuse |
| `FLEET_HOSTS_SOURCE` | Which source answered for the host list, so a command can say where its target came from |
| `FLEET_WORK` | Scratch directory holding the record a deploy is updating |
| `FLEET_VERIFIED` | Whether the deploy confirmed the fleet, deciding the closing banner's wording |

`tests/test_docs_in_sync.py` checks that every `DEPLOY_*` and `FLEET_*` variable the tooling
reads appears either here or in the fleet reference.

## Script output

Every `scripts/*.sh` prints through `scripts/lib/common.sh`, and every `scripts/*.py`
through `scripts/cli_color.py`. Don't hand-roll a label or an escape sequence — two tests
fail on either.

| | Use | Renders |
|---|---|---|
| a phase | `header "Step 3/8: bootstrap"` | `========== … ==========` |
| a sub-step | `step "hashing the password"` | `--- … ---` |
| doing something | `info "docker compose build"` | `>>> …` |
| it worked | `ok "Docker ready"` | `✓ …` |
| an advisory, nothing to act on | `note "msg" "detail…"` | `NOTE: …` |
| something to act on | `warn "…"` | `WARN: …` on **stderr** |
| stopping | `die "…"` | `ERROR: …` on **stderr**, exit 1 |
| a value worth finding on screen | `value "$host"` | bold |
| a closing block | `banner_open` / `kv Label value` / `banner_close` | a `════` rule |

A script that *checks* things uses `scripts/lib/verdict.sh` instead — `v_pass` / `v_fail` /
`v_warn` / `v_unknown` / `v_tally`. **Keep your own exit code**: `v_status` returns 0 when
some checks passed and others were merely unmeasured, which is right for a preflight that
lists what it could not measure and continues, and wrong for `health-remote.sh` (an
upgrade gates on it) and `backup.sh verify` (a backup's verified-receipt gates on it).

**Colour is resolved once**, in `common.sh`, behind a TTY / no-`NO_COLOR` / `TERM` != `dumb`
gate, and exported as `LT_COLOR` so a Python helper reads that answer instead of asking
`isatty()` from inside a subprocess that cannot see the caller's redirection. So piped
output is byte-plain, `NO_COLOR=1` turns it off everywhere, and `LT_COLOR=always` keeps it
through a pipe (`./logstotal doctor | less -R`).

**The one exemption**: a heredoc piped to a remote host — `host_exec "$h" bash -s <<'EOS'` —
runs under a bare `bash` that never sourced the library, so those bodies use plain `echo`.
`warn` there is `command not found`, and several of those sites are `|| warn …` trailers
where the `||` would swallow it and the step would report success.

---

**Related:** [Local development](local-development.md) · [Releasing](releasing.md) · [Command reference](../reference/commands.md)
