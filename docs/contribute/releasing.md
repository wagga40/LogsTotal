# Releasing

How a version is cut, tagged and published, and how a release archive is built.

## Cutting a release

Write the `## [Unreleased]` entry in `CHANGELOG.md` as you go — the release workflow
publishes that section verbatim as the release notes, and refuses an empty one. Then:

```bash
./logstotal release:prepare VERSION=X.Y.Z    # 1. edit
git diff                              # 2. read what it wrote
./logstotal release:finish VERSION=X.Y.Z     # 3. commit, tag, gate
git push --atomic origin <branch> refs/tags/vX.Y.Z
```

`release:prepare` rewrites `app/config.py`, `pyproject.toml` and `VERSION` together, moves
the changelog section and both of its link definitions, and sweeps the version strings out
of the docs — `REF=v…` commands, archive URLs, the `/health` example body, the
`# expect: version:` line. Prose that names a specific older version on purpose is left
alone. It refuses a dirty tree, a non-increase, an existing tag, and an empty
`## [Unreleased]`, and it checks all of those *before* it writes anything — a refusal
never leaves the tree half-bumped.

Pushing the tag is what publishes the release: `.github/workflows/release.yml` builds and
uploads `logstotal-X.Y.Z.7z` when the tag reaches GitHub, and its mirror,
`.forgejo/workflows/release.yml`, does the same on a self-hosted Forgejo runner. Both
re-verify the tag against all three declared versions before building, and both can be
re-run by hand against an existing tag.

`release:finish` commits, then tags, then runs `./logstotal check && ./logstotal test`. That order is the
point of the command. The tag has to land **on** the release commit, and the suite has to
run **with** the tag in place, because `test_the_declared_version_has_a_git_tag` cannot pass
without it. A failed gate deletes the tag and keeps the commit, so you fix and amend.

Neither command pushes.

> [!IMPORTANT]
> **Push the tag, by name, with the branch.** CI's version check needs the release tag on
> the remote, not just in your clone. Push both refs in one atomic push, as above; never
> `git push --tags`, which publishes every local tag at once.

`VERSION` holds one line — `version: X.Y.Z` — and `./logstotal release:prepare` is the only thing
that writes it. No build, package or upgrade touches it (`tests/test_version_file.py`
enforces that), so it changes in release commits and nowhere else. It is committed rather
than generated-and-ignored so a fresh clone reports its real version.

## Packaging

```bash
./logstotal lock      # ensure requirements.txt is up to date
./logstotal package   # creates logstotal-<version>.7z
```

**Tailwind:** for a production archive that serves compiled CSS see [Production CSS (Tailwind)](development.md#production-css-tailwind) — `./logstotal package` re-runs `./logstotal css:build` automatically when the CLI is present, so the archive ships `tailwind-built.css`; without the CLI it ships the vendor Tailwind JS bundle and the app still works, or `PACKAGE_USE_COMMITTED_CSS=true ./logstotal package` ships the committed stylesheet as it stands. `./logstotal package` restores dev mode from an EXIT trap, so a failed build leaves `base.html` where it found it.

To install from the archive, follow [Prerequisites](../install/prerequisites.md).

---

**Related:** [Development](development.md) · [Upgrade and roll back](../runbooks/upgrading.md) · [Command reference](../reference/commands.md)
