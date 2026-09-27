# Contributing to LogsTotal

Thanks for taking the time. This page covers **process** — how to propose a change and get
it merged. The technical guide (dev environment, adding a tool adapter, front-end assets,
packaging) lives in [docs/development.md](docs/contribute/development.md).

Security problems go through [SECURITY.md](SECURITY.md), never a public issue or PR.

## Reporting a bug

Open an issue at <https://github.com/wagga40/LogsTotal/issues>. Four things turn a report
into something reproducible, and all four are one command or one glance:

1. **Version** — `./logstotal version`, or the footer of any page. If you are running an
   unreleased build (`ALLOW_UNRELEASED=true`), say so and include
   `git rev-parse --short HEAD`: nothing on the host records which commit it is.
2. **Deployment path** — A (local dev), B (Docker, single host) or C (multi-server), from
   [docs/installation.md](docs/install/prerequisites.md). Several classes of bug exist only on one of
   them.
3. **`./logstotal doctor` output** — `./logstotal doctor:docker` on the Docker paths. It is a preflight,
   so it often names the cause outright; when it does not, its output still says which
   subsystems were healthy at the time.
4. **What you expected, and what happened** — with the exact log type and workflow if the
   problem involves an analysis. `./logstotal docker:logs:worker` (or the worker's own output) is
   where an analysis failure explains itself.

Security problems do **not** go here — see [SECURITY.md](SECURITY.md).

## Before you write code

Open an issue first for anything beyond a bug fix or a typo. LogsTotal has opinions —
several things that look like omissions are deliberate, and documented as such — so a
short conversation up front is cheaper than a rejected pull request. Worth knowing:

- **No Node, no build step.** Front-end dependencies are pinned, committed files in
  `app/static/vendor/`. The one exception is `tests/js/`, which runs under `node --test`
  and is skipped when node is absent.
- **HTMX and Alpine, not a SPA.** Server-rendered Jinja templates with progressive
  enhancement.
- **Async in FastAPI routes, sync in Huey tasks.** The two never mix; the engines are
  separate.
- **Tool adapters import neither FastAPI nor Huey.** They are plain Python.

`CLAUDE.md` is not in the repository, but `docs/development.md` and the module
docstrings carry the same conventions. When a design decision is non-obvious, the code
usually explains itself — please keep that up in anything you add.

## Making a change

```bash
./logstotal setup          # deps, .env with generated secrets, database
./logstotal dev            # http://localhost:8000
./logstotal worker:watch   # in a second terminal (needs Redis: ./logstotal redis:bg)
```

Then, before you push:

```bash
./logstotal fmt            # auto-fix formatting
./logstotal check          # ruff + format check + shellcheck — must pass
./logstotal test           # full suite — must pass
./logstotal test:js        # only if you touched the relationship graph's client code
```

Branch off `main`. Keep a pull request to one concern; two unrelated fixes are two pull
requests.

## What a good change looks like

- **Tests come with it.** Pure functions get a unit test (see the tiers in
  `docs/development.md`); a bug fix gets a test that fails without it — please check that
  it does, rather than assuming.
- **Documentation is part of the change, not a follow-up.** A new `Settings` field needs a
  commented line in `.env.example` and a row in `docs/configuration.md`; a new task needs a
  mention in `docs/tasks.md`; a user-visible feature needs its section in
  `app/templates/docs/index.html`. `tests/test_docs_in_sync.py` enforces a good deal of
  this and will tell you what it wants.
- **A model change needs an Alembic revision.** `./logstotal db:revision -- "description"`, then check
  the generated file — autogenerate misses things. A parity test fails if the migrations
  and the models disagree.
- **Comments explain *why*.** What the code does is already there in the code.

## Commit messages

Conventional-commit prefixes (`feat:`, `fix:`, `docs:`, `refactor:`, `test:`, `chore:`),
an imperative subject, and a body explaining the reasoning when the change is not obvious.
The body says what was wrong and why the fix is the right shape, not what the diff already
shows.

Please do not add tool-attribution trailers (`Co-Authored-By: <an AI>`,
`Generated with ...`) to commits.

## Reviews

Expect questions about *why* more often than about *what*. If a review comment seems
wrong, say so with your reasoning — that is more useful than a silent change.

Every pull request runs `./logstotal check` and `./logstotal test` in CI. A red build blocks merge.
