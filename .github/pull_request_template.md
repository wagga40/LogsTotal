<!--
Read CONTRIBUTING.md first if you have not. The short version: open an issue before
anything beyond a bug fix or a typo, and keep `task check && task test` green.
-->

## What this changes

<!-- One or two sentences. What was wrong, or what is now possible. -->

## Why

<!-- Link the issue. If the change is not obviously correct, say what convinced you. -->

## Checks

- [ ] `task check` passes (ruff lint + format + shellcheck)
- [ ] `task test` passes
- [ ] Docs updated — `docs/*.md` for operator-facing behaviour, `.env.example` **and**
      `docs/configuration.md` for any new `Settings` field (a test enforces both)
- [ ] An Alembic revision accompanies any model change (a test enforces this too)
- [ ] Tests added for the behaviour, not just the line
