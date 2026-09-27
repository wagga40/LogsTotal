"""Release resolution — `scripts/lib/common.sh`'s release_* helpers.

An upgrade installs a published release, never whatever a branch happens to hold: a `REF`
defaulting to `origin/main` would make the documented command for upgrading a production
fleet track a branch, with nothing comparing what is installed against what was released.
These tests pin the policy, and the one rule that matters most: **it never falls back to a
branch.**

Driven through real bash, the `tests/test_common_sh.py` way — the functions are shell, and
a Python reimplementation of them would pin the reimplementation.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
COMMON_SH = REPO_ROOT / "scripts" / "lib" / "common.sh"

pytestmark = pytest.mark.skipif(shutil.which("bash") is None, reason="bash not available")


#: Every var release_resolve_ref reads. Scrubbed unless the test sets it, because an
#: ambient value silently changes the branch under test.
#:
#: This is not hypothetical: `task release:finish` exports VERSION=X.Y.Z (the Taskfile
#: bridges it) and then runs `task test`, so pytest inherited VERSION and every REF-handling
#: assertion here took the pin branch instead. The suite was green everywhere except inside
#: the one command that cuts a release. tests/test_upgrade_script.py carries the same
#: defence for the same reason.
_SCRUBBED = (
    "REF",
    "VERSION",
    "ALLOW_UNRELEASED",
    "RELEASE_REPO_URL",
    "RELEASE_API_URL",
    "SKIP_IF_CURRENT",
    "ARCHIVE",
    "DEPLOY_ENV_FILE",
)


def _sh(
    body: str,
    env: dict[str, str] | None = None,
    tags: str | None = None,
    cwd: Path | None = None,
    artifact: int | None = None,
) -> subprocess.CompletedProcess:
    """Source common.sh and run `body`, optionally stubbing the published tag list.

    `cwd` matters for release_repo_url: its git-origin and `.release-origin` arms are both
    read relative to the working directory, so a test for either has to leave REPO_ROOT.

    `artifact` stubs release_artifact_exists' exit code (0 present, 1 absent, 2 could not
    measure). Any test whose subject is a PIN must set it: the real probe reaches the
    network, so without it the assertion is answered by whether this machine can see the
    release server rather than by the policy under test.
    """
    stub = f"release_tags() {{ printf '{tags}'; }}\n" if tags is not None else ""
    if artifact is not None:
        stub += f"release_artifact_exists() {{ return {artifact}; }}\n"
    script = f". {COMMON_SH}\n{stub}{body}\n"

    clean = {**os.environ}
    for var in _SCRUBBED:
        if var not in (env or {}):
            clean.pop(var, None)

    return subprocess.run(
        ["bash", "-c", script],
        capture_output=True,
        text=True,
        check=False,
        cwd=cwd or REPO_ROOT,
        env={**clean, **(env or {})},
    )


class TestRepoUrl:
    """The lookup must work on a server with no SSH key, so ssh remotes become https."""

    @pytest.mark.parametrize(
        ("configured", "expected"),
        [
            ("git@github.com:wagga40/LogsTotal.git", "https://github.com/wagga40/LogsTotal"),
            ("https://github.com/wagga40/LogsTotal.git", "https://github.com/wagga40/LogsTotal"),
            ("ssh://git@forge.example.com/you/LogsTotal.git", "https://forge.example.com/you/LogsTotal"),
            ("https://forge.example.com/you/LogsTotal", "https://forge.example.com/you/LogsTotal"),
        ],
    )
    def test_normalises_to_anonymous_https(self, configured: str, expected: str):
        """`git ls-remote git@github.com:…` needs a key a production host does not have.

        The scp-style case is the subtle one: substituting the first colon in the whole
        string rewrites the one in `https://`, producing `https///github.com:owner/repo`.
        """
        res = _sh("release_repo_url", {"RELEASE_REPO_URL": configured})
        assert res.stdout == expected

    def test_an_install_with_no_git_origin_falls_back_to_the_project(self, tmp_path):
        """The primary install path has no origin at all.

        A release archive ships without `.git` — that is the documented way to install, and
        the way upgrades then fetch. With nothing configured and no origin to read, the
        lookup has to land somewhere, and the somewhere is where the releases are.
        """
        res = subprocess.run(
            ["bash", "-c", f". {COMMON_SH}\nrelease_repo_url\n"],
            capture_output=True,
            text=True,
            check=False,
            cwd=tmp_path,  # no .git anywhere above it
            env={"PATH": os.environ["PATH"], "HOME": str(tmp_path)},
        )
        assert res.stdout == "https://github.com/wagga40/LogsTotal"

    def test_a_release_archive_carries_the_server_it_came_from(self, tmp_path):
        """`.release-origin` answers where nothing else can.

        An archive install has no `.git`, and an SSH origin normalises to a URL with no
        port — `ssh://git@forge.example.com/you/LogsTotal.git` becomes
        `https://forge.example.com/...` while the asset really lives on `:3000`. Neither is
        derivable, so scripts/package.sh records it at build time from CI's own
        `github.server_url`.
        """
        (tmp_path / ".release-origin").write_text("url: http://forge.example.com:3000/you/LogsTotal\n")
        res = _sh("release_repo_url; printf '|'; release_repo_url_source", cwd=tmp_path)
        assert res.stdout == "http://forge.example.com:3000/you/LogsTotal|.release-origin"

    def test_deploy_env_answers_when_there_is_no_stamp(self, tmp_path):
        """The manual override for an install that predates the stamp, or a mirrored one.

        Read with `$(deploy_env_default …)`, never `deploy_env_load`: the go-task `env:`
        bridge exports a key set-but-empty and deploy_env_load skips a key that is merely
        set.
        """
        env_file = tmp_path / "deploy.env"
        env_file.write_text("DEPLOY_HOSTS=cp\nRELEASE_REPO_URL=http://forge.example.com:3000/you/LogsTotal\n")
        res = _sh("release_repo_url", {"DEPLOY_ENV_FILE": str(env_file)}, cwd=tmp_path)
        assert res.stdout == "http://forge.example.com:3000/you/LogsTotal"

    def test_the_environment_beats_every_recorded_source(self, tmp_path):
        """A caller who names the server outranks anything on disk."""
        (tmp_path / ".release-origin").write_text("url: http://stamped.example.com:3000/o/r\n")
        res = _sh("release_repo_url", {"RELEASE_REPO_URL": "https://asked.example.com/o/r"}, cwd=tmp_path)
        assert res.stdout == "https://asked.example.com/o/r"

    def test_a_trailing_slash_never_reaches_the_asset_url(self, tmp_path):
        """Otherwise every derived URL carries a `//` — cosmetic on GitHub, a 404 elsewhere."""
        res = _sh("release_repo_url", {"RELEASE_REPO_URL": "https://git.example.com/o/r/"}, cwd=tmp_path)
        assert res.stdout == "https://git.example.com/o/r"


class TestApiUrl:
    def test_github(self):
        res = _sh("release_api_url", {"RELEASE_REPO_URL": "https://github.com/o/r"})
        assert res.stdout == "https://api.github.com/repos/o/r/releases/latest"

    def test_forgejo_uses_the_gitea_shape(self):
        res = _sh("release_api_url", {"RELEASE_REPO_URL": "https://git.example.com/o/r"})
        assert res.stdout == "https://git.example.com/api/v1/repos/o/r/releases/latest"

    def test_a_plaintext_forge_keeps_its_scheme(self):
        """Forcing `https://` here would send every API call for an http instance to a
        plaintext port over TLS: `tlsv1 alert protocol version`, an error naming nothing an
        operator can act on.
        """
        res = _sh("release_api_url", {"RELEASE_REPO_URL": "http://forge.example.com:3000/you/LogsTotal"})
        assert res.stdout == "http://forge.example.com:3000/api/v1/repos/you/LogsTotal/releases/latest"

    def test_github_is_always_https_whatever_the_repo_url_says(self):
        res = _sh("release_api_url", {"RELEASE_REPO_URL": "http://github.com/o/r"})
        assert res.stdout == "https://api.github.com/repos/o/r/releases/latest"


class TestLatestTag:
    def test_the_newest_release_wins_a_numeric_sort(self):
        """A lexical sort puts v0.9.10 before v0.9.2 — the whole reason for the field sort."""
        res = _sh("release_latest_tag", tags="v0.9.2\\nv0.9.10\\nv0.10.0\\nv0.9.3\\n")
        assert res.stdout == "v0.10.0"

    def test_nothing_published_is_empty_not_an_error(self):
        res = _sh("release_latest_tag", tags="")
        assert res.stdout == ""
        assert res.returncode == 0


class TestIsReleaseTag:
    @pytest.mark.parametrize("ref", ["v1.2.3", "v0.0.1", "v10.20.30"])
    def test_accepts(self, ref: str):
        assert _sh(f'is_release_tag "{ref}"', tags="").returncode == 0

    @pytest.mark.parametrize("ref", ["1.2.3", "main", "v1.2", "v1.2.3-rc1", "origin/main", ""])
    def test_rejects(self, ref: str):
        assert _sh(f'is_release_tag "{ref}"', tags="").returncode != 0


class TestPolicy:
    TAGS = "v0.9.2\\nv0.9.3\\nv0.9.4\\n"

    def test_nothing_set_resolves_the_latest(self):
        res = _sh("release_resolve_ref", tags=self.TAGS)
        assert res.stdout == "v0.9.4"

    def test_a_pin_is_honoured(self):
        res = _sh("release_resolve_ref", {"VERSION": "0.9.3"}, tags=self.TAGS)
        assert res.stdout == "v0.9.3"

    def test_a_pin_normalises_a_leading_v(self):
        res = _sh("release_resolve_ref", {"VERSION": "v0.9.3"}, tags=self.TAGS)
        assert res.stdout == "v0.9.3"

    def test_a_pin_that_was_never_released_is_refused(self):
        res = _sh("release_resolve_ref", {"VERSION": "9.9.9"}, tags=self.TAGS, artifact=1)
        assert res.returncode != 0
        assert "no release v9.9.9" in res.stderr
        assert "v0.9.4" in res.stderr, "it must list what IS published"

    def test_an_unreachable_server_warns_rather_than_refusing_a_pin(self):
        """ "No such release" and "could not ask" are different answers.

        Refusing on an empty tag list would make every offline pinned upgrade impossible,
        including on the air-gapped hosts this tooling explicitly supports.
        """
        res = _sh("release_resolve_ref", {"VERSION": "0.9.4"}, tags="", artifact=2)
        assert res.returncode == 0
        assert res.stdout == "v0.9.4"
        assert "could not reach" in res.stderr

    def test_a_branch_is_refused(self):
        res = _sh("release_resolve_ref", {"REF": "main"}, tags=self.TAGS)
        assert res.returncode != 0
        assert "not a published release" in res.stderr
        assert "ALLOW_UNRELEASED=true" in res.stderr, "the refusal must name the escape hatch"

    def test_a_branch_is_allowed_behind_the_escape_hatch(self):
        res = _sh("release_resolve_ref", {"REF": "main", "ALLOW_UNRELEASED": "true"}, tags=self.TAGS)
        assert res.returncode == 0
        assert res.stdout == "main"
        assert "UNRELEASED" in res.stderr, "it must say the build is unsupported"

    def test_a_release_tag_ref_needs_no_escape_hatch(self):
        res = _sh("release_resolve_ref", {"REF": "v0.9.3"}, tags=self.TAGS)
        assert res.stdout == "v0.9.3"

    def test_an_archive_short_circuits_resolution(self):
        res = _sh("release_resolve_ref", {"ARCHIVE": "/tmp/x.7z"}, tags=self.TAGS)
        assert res.returncode == 0
        assert res.stdout == ""

    def test_it_never_falls_back_to_a_branch(self):
        """The rule this policy exists for.

        With nothing published and nothing reachable it must refuse, and the word `main`
        must not appear anywhere in the output — a branch is not a safe fallback.
        """
        res = _sh("release_resolve_ref", tags="")
        assert res.returncode != 0
        assert "could not resolve the latest release" in res.stderr
        assert "main" not in (res.stdout + res.stderr)


def _fake_curl(tmp_path: Path, script: str) -> Path:
    """A PATH dir whose `curl` behaves as `script` says. Everything else stays real.

    `path_without("curl")` is not usable here: it strips whole PATH entries, so removing
    /usr/bin takes sed, grep and cut with it and the function under test never runs.
    """
    d = tmp_path / "bin"
    d.mkdir(exist_ok=True)
    (d / "curl").write_text(f"#!/bin/sh\n{script}\n")
    (d / "curl").chmod(0o755)
    return d


def _sh_with_curl(body: str, tmp_path: Path, curl: str, env: dict[str, str] | None = None):
    """Run `body` with a stubbed curl and no git, from a dir with no repo above it."""
    bindir = _fake_curl(tmp_path, curl)
    # `git` must be absent too, or release_tags answers from its ls-remote arm and the
    # curl arm under test is never reached.
    (bindir / "git").write_text("#!/bin/sh\nexit 1\n")
    (bindir / "git").chmod(0o755)
    clean = {**os.environ}
    for var in _SCRUBBED:
        if var not in (env or {}):
            clean.pop(var, None)
    clean["PATH"] = f"{bindir}{os.pathsep}{os.environ['PATH']}"
    return subprocess.run(
        ["bash", "-c", f". {COMMON_SH}\n{body}\n"],
        capture_output=True,
        text=True,
        check=False,
        cwd=tmp_path,
        env={**clean, **(env or {})},
    )


#: One release page, in the shape both GitHub and Gitea/Forgejo return.
def _page(*tags: str) -> str:
    items = ",".join(f'{{"tag_name": "{t}", "draft": false}}' for t in tags)
    return f"[{items}]"


class TestTagsFromTheApi:
    """The arm that runs on every deployed host.

    scripts/deploy-bootstrap.sh installs docker, 7z, rsync, curl and go-task — not git — so
    with no git binary this is the ONLY source of tags there.
    """

    def test_it_returns_every_release_not_just_the_newest(self, tmp_path):
        """Reading /releases/latest and `head -1` would return exactly one tag, and pinning
        any older release would be refused as unpublished."""
        page = _page("v0.9.14", "v0.9.13", "v0.9.11", "v0.9.3")
        res = _sh_with_curl("release_tags_api", tmp_path, f"cat <<'EOF'\n{page}\nEOF")
        assert res.stdout.split() == ["v0.9.14", "v0.9.13", "v0.9.11", "v0.9.3"]

    def test_it_asks_for_both_page_size_keys(self, tmp_path):
        """GitHub reads per_page, Forgejo reads limit, and each ignores the other's."""
        res = _sh_with_curl(
            "release_tags_list_url 1",
            tmp_path,
            "exit 1",
            {"RELEASE_REPO_URL": "https://git.example.com/o/r"},
        )
        assert "per_page=100" in res.stdout and "limit=100" in res.stdout
        assert "/releases?" in res.stdout and "/latest" not in res.stdout

    def test_a_non_release_tag_is_filtered_out(self, tmp_path):
        page = _page("v1.0.0-rc1", "nightly", "v0.9.3")
        res = _sh_with_curl("release_tags_api", tmp_path, f"cat <<'EOF'\n{page}\nEOF")
        assert res.stdout.split() == ["v0.9.3"]

    def test_html_or_a_404_degrades_to_nothing_rather_than_crashing(self, tmp_path):
        for body in ("<!DOCTYPE html><html>not an api</html>", ""):
            res = _sh_with_curl("release_tags_api", tmp_path, f"printf '%s' '{body}'")
            assert res.returncode == 0, res.stderr
            assert res.stdout.strip() == ""

    def test_it_stops_at_the_page_cap_instead_of_paging_forever(self, tmp_path):
        """A server that answers every page identically must not spin.

        Nothing branches on having been capped — see the note in release_tags_api: a flag
        set inside `tags=$(release_tags)` dies with the subshell, so the artifact probe is
        the authority instead.
        """
        full = _page(*[f"v0.9.{i}" for i in range(100)])
        res = _sh_with_curl(
            "release_tags_api | grep -c .",
            tmp_path,
            f"cat <<'EOF'\n{full}\nEOF",
            {"RELEASE_API_MAX_PAGES": "2"},
        )
        assert res.stdout.strip() == "200", "two pages of 100, then it stops"


class TestArtifactProbe:
    """`release_artifact_exists` — the authority on whether a package can be fetched.

    A TAG IS NOT A RELEASE: a tag can exist with no published asset. Under git mode that
    merely checks out the tag; under package mode it 404s at download, after the backup has
    been taken.
    """

    def test_present(self, tmp_path):
        res = _sh_with_curl("release_artifact_exists v0.9.3; echo rc=$?", tmp_path, "exit 0")
        assert res.stdout.strip() == "rc=0"

    def test_absent_when_the_server_answers_but_the_asset_does_not(self, tmp_path):
        # First call (the asset) fails; second (the repo root) succeeds → definitively absent.
        curl = 'case "$*" in *releases/download*) exit 22 ;; *) exit 0 ;; esac'
        res = _sh_with_curl("release_artifact_exists v9.9.9; echo rc=$?", tmp_path, curl)
        assert res.stdout.strip() == "rc=1"

    def test_unreachable_is_not_the_same_as_absent(self, tmp_path):
        """An offline host must not report every release as missing — rc 2 means
        'could not measure', and callers are required not to refuse on it."""
        res = _sh_with_curl("release_artifact_exists v0.9.3; echo rc=$?", tmp_path, "exit 7")
        assert res.stdout.strip() == "rc=2"


class TestPinResolutionUsesTheArtifact:
    def test_a_pin_missing_from_the_list_is_accepted_when_its_package_exists(self, tmp_path):
        """The list can be incomplete — capped, or a server that lists releases its own
        way. The package answers the question the caller actually has."""
        res = _sh_with_curl(
            "release_resolve_ref",
            tmp_path,
            f"case \"$*\" in *releases/download*) exit 0 ;; *) cat <<'EOF'\n{_page('v0.9.14')}\nEOF\n;; esac",
            {"VERSION": "0.9.3"},
        )
        assert res.returncode == 0, res.stderr
        assert res.stdout == "v0.9.3"

    def test_the_refusal_names_the_page_cap_as_a_possible_cause(self, tmp_path):
        """A forge with more than RELEASE_API_MAX_PAGES x 100 releases can hide a real one
        from the list. The artifact probe is what actually decides, so the refusal is still
        correct — but it has to name the cap, or the operator has no way to reach the
        release they can see in their own browser."""
        curl = f"case \"$*\" in *releases/download*) exit 22 ;; *releases?*) cat <<'EOF'\n{_page('v0.9.14')}\nEOF\n;; *) exit 0 ;; esac"
        res = _sh_with_curl("release_resolve_ref", tmp_path, curl, {"VERSION": "0.5.0"})
        assert res.returncode != 0
        assert "RELEASE_API_MAX_PAGES" in res.stderr

    def test_a_complete_list_without_the_pin_still_refuses(self, tmp_path):
        """The guard must not become a blanket 'always continue'."""
        curl = f"case \"$*\" in *releases/download*) exit 22 ;; *releases?*) cat <<'EOF'\n{_page('v0.9.14')}\nEOF\n;; *) exit 0 ;; esac"
        res = _sh_with_curl("release_resolve_ref", tmp_path, curl, {"VERSION": "9.9.9"})
        assert res.returncode != 0
        assert "no release v9.9.9" in res.stderr


# ── The fleet record as a release source ─────────────────────────────────────


def _control_plane(tmp_path: Path, server: str) -> Path:
    """A directory shaped like an archive install: a fleet record, no .git, no deploy.env.

    That combination is the whole point. deploy.env belongs to whoever ran the deploy and
    package.sh keeps it out of the archive, so on the machine the fleet is *run* from,
    neither of release_repo_url's explicit sources exists.
    """
    install = tmp_path / "opt" / "logstotal"
    (install / "fleet").mkdir(parents=True)
    subprocess.run(
        [
            sys.executable,
            str(REPO_ROOT / "scripts" / "fleet_manifest.py"),
            "--file",
            str(install / "fleet" / "manifest.json"),
            "intent",
            "--hosts",
            "local,w1.example.com",
            "--install-dir",
            str(install),
            "--written-by",
            "0.10.4",
            "--written-at",
            "2026-01-01T00:00:00Z",
            "--option",
            f"remote_dir={install}",
            "--release",
            f"server={server}",
        ],
        check=True,
        capture_output=True,
    )
    return install


class TestTheFleetRecordNamesTheReleaseServer:
    """Where releases come from is recorded, not derived — and the record was write-only.

    An ssh origin carries no web scheme or port: `ssh://git@host/o/r.git` normalises to
    `https://host/o/r`, which is wrong for any self-hosted forge not on 443. This repo is
    its own example. Every deploy has recorded the right URL since the fleet record landed,
    and nothing could read it back: fleet_manifest.py's `get` reads options{}, while the
    server lives under release{}.
    """

    SERVER = "https://git.example.com:3000/you/LogsTotal"

    def test_a_control_plane_answers_from_its_own_record(self, tmp_path: Path):
        install = _control_plane(tmp_path, self.SERVER)
        out = _sh('echo "$(release_repo_url)|$(release_repo_url_source)"', env={"DEPLOY_REMOTE_DIR": str(install)}, cwd=install)
        url, source = out.stdout.strip().split("|")
        assert url == self.SERVER, "the record's server did not reach release_repo_url"
        assert source == "this fleet record"

    def test_the_port_survives(self, tmp_path: Path):
        """The reason the arm exists. A derived origin loses `:3000` and there is nothing
        to recompute it from, so the upgrade quietly asks the wrong host."""
        install = _control_plane(tmp_path, self.SERVER)
        out = _sh("release_repo_url", env={"DEPLOY_REMOTE_DIR": str(install)}, cwd=install)
        assert ":3000" in out.stdout

    def test_an_explicit_url_still_wins(self, tmp_path: Path):
        install = _control_plane(tmp_path, self.SERVER)
        out = _sh(
            'echo "$(release_repo_url)|$(release_repo_url_source)"',
            env={"DEPLOY_REMOTE_DIR": str(install), "RELEASE_REPO_URL": "https://explicit.example/o/r"},
            cwd=install,
        )
        url, source = out.stdout.strip().split("|")
        assert url == "https://explicit.example/o/r"
        assert source == "RELEASE_REPO_URL", "a record must fill a gap, never override a choice"

    def test_deploy_env_still_wins(self, tmp_path: Path):
        install = _control_plane(tmp_path, self.SERVER)
        (install / "deploy.env").write_text("RELEASE_REPO_URL=https://from-deploy-env.example/o/r\n")
        out = _sh(
            'echo "$(release_repo_url)|$(release_repo_url_source)"',
            env={"DEPLOY_REMOTE_DIR": str(install), "DEPLOY_ENV_FILE": str(install / "deploy.env")},
            cwd=install,
        )
        url, source = out.stdout.strip().split("|")
        assert url == "https://from-deploy-env.example/o/r"
        assert source.endswith("deploy.env")

    def test_no_record_is_not_an_error(self, tmp_path: Path):
        """Everything about the record degrades to 'I know nothing'. A cosmetic file must
        never become a hard dependency of the tool that reads it."""
        empty = tmp_path / "empty"
        empty.mkdir()
        out = _sh("release_repo_url", env={"DEPLOY_REMOTE_DIR": str(empty)}, cwd=empty)
        assert out.returncode == 0
        assert out.stdout.strip(), "release_repo_url must always name some server"

    def test_the_two_functions_cannot_disagree(self):
        """release_repo_url_source exists so an operator can see WHICH arm answered.
        Its own comment says the two are kept side by side so they cannot describe
        different arms — which only holds if every arm is added to both."""
        src = COMMON_SH.read_text(encoding="utf-8")

        def arms(name: str) -> int:
            body = src[src.index(f"{name}() {{") :]
            return body[: body.index("\n}\n")].count("fleet_release server")

        assert arms("release_repo_url") == 1
        assert arms("release_repo_url_source") == 1
