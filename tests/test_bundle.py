"""A bundle is what makes a closed-network install possible.

`ARCHIVE=` already gets the application across without a network — the archive is copied
from the machine running the deploy, so hosts never reach the release server. What it does
not solve is the images: every host still runs `docker compose build`, pulling
python:3.14-slim, Debian packages, PyPI wheels and a ~46 MB Tailwind CLI, and Compose then
pulls Redis, PostgreSQL, Caddy and socat.

And Zircolite is pulled **lazily inside the first Windows job**, which is the one that
matters: without it a closed install passes every check, reports healthy, and fails hours
later when someone uploads an EVTX file. Five of the six shipped workflows use it.
"""

from __future__ import annotations

import json
import os
import re
import shlex
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
BUNDLE_SH = REPO_ROOT / "scripts" / "bundle.sh"

pytestmark = pytest.mark.skipif(shutil.which("bash") is None, reason="bash not available")


def _docker_stub(tmp_path: Path) -> Path:
    """A `docker` that builds and saves nothing, so these test the bundle's mechanics
    rather than spending twenty minutes on a real image build."""
    d = tmp_path / "shim"
    d.mkdir(exist_ok=True)
    (d / "docker").write_text(
        f"#!{sys.executable}\n"
        + r"""import io, json, pathlib, sys, tarfile
args = sys.argv[1:]
state = pathlib.Path(__file__).parent
if args[0] == "build":
    tag = args[args.index("-t") + 1]
    labels = dict(args[i+1].split("=", 1) for i,a in enumerate(args) if a == "--label")
    (state / tag).write_text(json.dumps(labels))
    with (state / "build-contexts").open("a") as f:
        f.write(pathlib.Path("VERSION").read_text())
elif args[0] == "save":
    tag = args[1]
    labels = json.loads((state / tag).read_text()) if (state / tag).exists() else {}
    with tarfile.open(args[args.index("-o") + 1], "w") as tar:
        for name, body in {"manifest.json": [{"Config": "config.json", "RepoTags": [tag]}], "config.json": {"config": {"Labels": labels}}}.items():
            data = json.dumps(body).encode()
            info = tarfile.TarInfo(name); info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
"""
    )
    (d / "docker").chmod(0o755)
    return d


def _archive(tmp_path: Path, version: str = "1.2.3") -> Path:
    src = tmp_path / "src"
    src.mkdir(exist_ok=True)
    for name in ("Taskfile.yml", "Dockerfile", "Dockerfile.garage", "docker-compose.yml", "docker-compose.worker.yml"):
        shutil.copy(REPO_ROOT / name, src / name)
    shutil.copytree(REPO_ROOT / "workflows", src / "workflows", dirs_exist_ok=True)
    (src / "VERSION").write_text(f"version: {version}\n", encoding="utf-8")
    out = tmp_path / f"logstotal-{version}.7z"
    subprocess.run(["7z", "a", "-mf=off", str(out), "."], cwd=src, capture_output=True, check=True)
    return out


def _build(tmp_path: Path, cwd: Path | None = None) -> subprocess.CompletedProcess[str]:
    shim = _docker_stub(tmp_path)
    env = {**os.environ, "PATH": f"{shim}{os.pathsep}{os.environ['PATH']}"}
    env.update(
        {
            "VERSION": "1.2.3",
            "ARCHIVE": str(_archive(tmp_path)),
            "BUNDLE_OUT": str(tmp_path / "bundle.7z"),
        }
    )
    return subprocess.run(
        ["bash", str(BUNDLE_SH), "build"],
        cwd=cwd or REPO_ROOT,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )


# ── What must be in it ───────────────────────────────────────────────────────


def test_the_image_list_is_read_from_the_files_that_declare_it():
    """Not restated in the script. A hand-maintained list of images goes stale silently,
    and the failure mode is an install that looks healthy until the one job that needs the
    image nobody remembered."""
    listed = subprocess.run(
        ["bash", "-c", f'. "{BUNDLE_SH.parent}/lib/common.sh"; ' + _bundle_images_body()],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=True,
    ).stdout.split()

    compose = (REPO_ROOT / "docker-compose.yml").read_text(encoding="utf-8")
    for image in re.findall(r"^\s+image: ([a-z0-9./:-]+)$", compose, re.M):
        if image.startswith("logstotal"):
            continue
        assert image in listed, f"{image} is in compose and would not be bundled"


def _bundle_images_body() -> str:
    src = BUNDLE_SH.read_text(encoding="utf-8")
    body = re.search(r"bundle_images\(\) \{.*?\n\}", src, re.S)
    assert body, "bundle_images is gone or renamed"
    return body.group(0) + "\nbundle_images | sort -u"


def test_zircolite_is_bundled():
    """The one that decides whether a closed install can analyse Windows logs at all — and
    the only image pulled lazily, inside a job, hours after the deploy reported success."""
    listed = subprocess.run(
        ["bash", "-c", f'. "{BUNDLE_SH.parent}/lib/common.sh"; ' + _bundle_images_body()],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    assert "zircolite" in listed
    assert "@sha256:" in listed, "it must be bundled by DIGEST: a tag can move, and an air-gapped host cannot check"


def test_every_workflow_image_would_be_bundled():
    """Parses workflows/ directly, so adding a tool that runs in a container cannot quietly
    produce bundles that do not carry it."""
    listed = subprocess.run(
        ["bash", "-c", f'. "{BUNDLE_SH.parent}/lib/common.sh"; ' + _bundle_images_body()],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    declared = set()
    for wf in (REPO_ROOT / "workflows").glob("*.yml"):
        declared |= set(re.findall(r"docker_image:\s*(\S+)", wf.read_text(encoding="utf-8")))
    for image in declared:
        assert image in listed, f"{image} is used by a workflow and would not be bundled"


# ── Building one ─────────────────────────────────────────────────────────────


@pytest.mark.skipif(shutil.which("7z") is None, reason="7z not available")
def test_a_bundle_carries_the_archive_the_app_image_and_the_rest(tmp_path: Path):
    result = _build(tmp_path)
    assert result.returncode == 0, result.stdout + result.stderr
    bundle = tmp_path / "bundle.7z"
    assert bundle.exists()

    # Read through 7z, since that is what a bundle is. `-slt` and the `Path = ` prefix
    # rather than the column listing, for the reason do_verify documents: a name is the last
    # field there, so a path with a space would be truncated.
    listing = subprocess.run(["7z", "l", "-ba", "-slt", str(bundle)], capture_output=True, text=True, check=True).stdout
    names = [ln[len("Path = ") :] for ln in listing.splitlines() if ln.startswith("Path = ")]
    out = tmp_path / "unpacked"
    subprocess.run(
        ["7z", "x", "-y", f"-o{out}", str(bundle), "bundle-manifest.json"],
        capture_output=True,
        check=True,
    )
    manifest = json.loads((out / "bundle-manifest.json").read_text())

    assert any(n.endswith("logstotal-1.2.3.7z") for n in names)
    assert any(n.endswith("images/logstotal.tar") for n in names)
    # Exactly as many as the manifest names — no more. When the bundle was a tar, one built
    # on macOS carried an AppleDouble `._` sidecar beside every image: junk on a Linux host,
    # and twice the entries a consumer counting them would expect. 7z does not produce them;
    # the assertion stays because the property is what matters, not the tool.
    saved = [n for n in names if "images/third-party-" in n]
    assert len(saved) == len(manifest["images"]), names
    assert not [n for n in names if "/._" in n], f"AppleDouble sidecars in the bundle: {names}"
    assert manifest["version"] == "1.2.3"
    assert manifest["architecture"], "a bundle is single-architecture and must say which"
    assert manifest["archive_sha256"]


@pytest.mark.skipif(shutil.which("7z") is None, reason="7z not available")
def test_a_bundle_uses_archive_sources_even_outside_a_checkout(tmp_path: Path):
    """Build context and runtime image discovery both come from the chosen archive."""
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    result = _build(tmp_path, cwd=elsewhere)
    assert result.returncode == 0, result.stdout + result.stderr
    assert (tmp_path / "bundle.7z").exists()
    assert (tmp_path / "shim/build-contexts").read_text().splitlines() == ["version: 1.2.3"] * 2


@pytest.mark.skipif(shutil.which("7z") is None, reason="7z not available")
def test_building_one_prints_no_shell_errors(tmp_path: Path):
    """The EXIT trap fires after the function that made the temp directory has returned, so
    a `local` is out of scope by then — `work: unbound variable` printed on top of the
    summary. deploy-multiserver.sh carries the same note about STAGE_TMPDIR; this hit the
    identical trap and was found the same way, by running it."""
    result = _build(tmp_path)
    assert "unbound variable" not in result.stderr, result.stderr
    assert "unbound variable" not in result.stdout, result.stdout


# ── Checking one ─────────────────────────────────────────────────────────────


@pytest.mark.skipif(shutil.which("7z") is None, reason="7z not available")
def test_verify_needs_no_docker(tmp_path: Path):
    """An operator has to be able to check a bundle BEFORE carrying it through an airlock,
    and the machine they check it on is not necessarily one that runs containers."""
    assert _build(tmp_path).returncode == 0
    # A PATH with no docker on it at all.
    clean = tmp_path / "cleanbin"
    clean.mkdir()
    # `7z` rather than `tar`: a bundle is a .7z, so reading one needs p7zip. That is
    # still not Docker, which is what this test is about — an operator checking a bundle
    # before it goes through an airlock needs an archiver, not a container runtime.
    for tool in ("bash", "7z", "cut", "basename", "dirname", "grep", "sed", "mktemp", "rm", "cd", "shasum", "sha256sum", "python3", "uname", "head", "sort", "printf"):
        found = shutil.which(tool)
        if found and not (clean / tool).exists():
            (clean / tool).symlink_to(found)
    assert not (clean / "docker").exists()

    result = subprocess.run(
        ["bash", str(BUNDLE_SH), "verify", str(tmp_path / "bundle.7z")],
        cwd=REPO_ROOT,
        env={"PATH": str(clean), "HOME": str(tmp_path)},
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "0 failed" in result.stdout


@pytest.mark.skipif(shutil.which("7z") is None, reason="7z not available")
def test_verify_catches_a_bundle_that_changed_in_transit(tmp_path: Path):
    assert _build(tmp_path).returncode == 0
    bundle = tmp_path / "bundle.7z"
    with bundle.open("ab") as fh:
        fh.write(b"tampered")

    result = subprocess.run(
        ["bash", str(BUNDLE_SH), "verify", str(bundle)],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode != 0
    assert "MISMATCH" in result.stdout


@pytest.mark.skipif(shutil.which("7z") is None, reason="7z not available")
def test_a_bundle_with_no_checksum_beside_it_is_unknown_not_failed(tmp_path: Path):
    """A checksum file is only as trustworthy as the channel it arrived on, so its absence
    is something not measured rather than something wrong. The verdict vocabulary has a
    word for that, and using FAIL here would teach operators to ignore it."""
    assert _build(tmp_path).returncode == 0
    (tmp_path / "bundle.7z.sha256").unlink()
    result = subprocess.run(
        ["bash", str(BUNDLE_SH), "verify", str(tmp_path / "bundle.7z")],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert "UNKNOWN" in result.stdout
    assert "1 not measured" in result.stdout
    assert result.returncode == 0, "an unmeasured checksum must not fail the check"


# ── The other answer for a closed network: a mirror ──────────────────────────


def test_a_workflow_image_can_be_served_from_a_mirror(monkeypatch):
    """The tool images are named in workflow YAML and pulled by the worker, so the compose
    prefix cannot reach them. This is the site that can."""
    from app.tools.base import apply_registry_prefix

    monkeypatch.setenv("REGISTRY_PREFIX", "registry.internal")
    zircolite = "wagga40/zircolite:3.8.1@sha256:41b0683343c591069b94b17ed6c16a3edced15f905c7dce73a41cfa715e0f39b"
    assert apply_registry_prefix(zircolite) == f"registry.internal/{zircolite}"


def test_the_digest_survives_the_prefix(monkeypatch):
    """A mirror serving different content under the same digest is not a mirror. Keeping it
    means a pull through one is verified exactly as a pull from the origin would be."""
    from app.tools.base import apply_registry_prefix

    monkeypatch.setenv("REGISTRY_PREFIX", "registry.internal")
    out = apply_registry_prefix("wagga40/zircolite:3.8.1@sha256:abc123")
    assert out.endswith("@sha256:abc123")


def test_a_library_image_is_prefixed(monkeypatch):
    """`redis:7-alpine` is a NAME and a TAG, not a host and a port. Reading its colon as a
    registry left every single-part image unprefixed while the multi-part ones worked —
    which on a mirrored network is most of the stack silently still pointing at Docker Hub."""
    from app.tools.base import apply_registry_prefix

    monkeypatch.setenv("REGISTRY_PREFIX", "registry.internal")
    assert apply_registry_prefix("redis:7-alpine") == "registry.internal/redis:7-alpine"


@pytest.mark.parametrize("image", ["ghcr.io/owner/tool:1", "localhost:5000/tool:1", "registry.example.com:5000/a/b"])
def test_an_image_that_already_names_a_registry_is_left_alone(monkeypatch, image: str):
    """It has been told where to come from."""
    from app.tools.base import apply_registry_prefix

    monkeypatch.setenv("REGISTRY_PREFIX", "registry.internal")
    assert apply_registry_prefix(image) == image


def test_no_prefix_means_no_change(monkeypatch):
    """Empty by default — which is exactly the behaviour before any of this existed."""
    from app.tools.base import apply_registry_prefix

    monkeypatch.delenv("REGISTRY_PREFIX", raising=False)
    assert apply_registry_prefix("redis:7-alpine") == "redis:7-alpine"


# ── What a bundle has to carry to actually start a fleet ─────────────────────


class TestABundleCarriesEveryImageItStarts:
    """Both of these pass every other check and then fail the deploy.

    An air-gapped deploy runs to its last step and dies with
    `Error response from daemon: No such image: logstotal-garage:latest` — a bundle that
    `task bundle:verify` reports as complete, on hosts whose images are all present under a
    name nothing asks for.
    """

    def test_the_garage_image_is_built_and_saved(self):
        """`garage` is built from Dockerfile.garage exactly as the app is from Dockerfile,
        and it is in the `s3` profile every multi-server install turns on."""
        script = (REPO_ROOT / "scripts" / "bundle.sh").read_text()
        assert "Dockerfile.garage" in script, "the bundle never builds the garage image"
        assert "images/logstotal-garage.tar" in script, "the bundle never saves it"

    def test_verify_checks_for_it(self):
        """Otherwise verify reports a bundle that cannot start a control plane as complete."""
        script = (REPO_ROOT / "scripts" / "bundle.sh").read_text()
        verify = script.split("do_verify()")[1]
        assert "logstotal-garage.tar" in verify

    def test_the_manifest_records_the_tag_the_images_were_saved_under(self):
        """The images are tagged with the RELEASE so a host can hold two. compose asks for
        `${LOGSTOTAL_IMAGE_TAG:-latest}`, so the deploy has to be told which tag to ask
        for — it is not derivable from anything else on the host."""
        script = (REPO_ROOT / "scripts" / "bundle.sh").read_text()
        assert '"image_tag"' in script

    def test_the_deploy_asks_for_that_tag(self):
        """Nothing set LOGSTOTAL_IMAGE_TAG, so every bundle deploy went looking for
        `:latest`, found nothing under `--pull never`, and died — with the right images on
        the host the whole time, unreferenced."""
        deploy = (REPO_ROOT / "scripts" / "deploy-multiserver.sh").read_text()
        assert "image_tag" in deploy, "the deploy never reads the tag out of the manifest"
        assert "export LOGSTOTAL_IMAGE_TAG=" in deploy
        # And it must reach the REMOTE compose, not just this shell.
        start = deploy.split("remote_start()")[1].split("\n}")[0]
        assert "LOGSTOTAL_IMAGE_TAG" in start, "the tag never reaches the host running compose"


class TestADigestCannotSurviveDockerSave:
    """Measured, not assumed: the tarball for a digest-pinned reference records
    `RepoTags:null`, because a digest is not a tag and the save format has nowhere to put
    it. `docker load` on the far side yields `<none>:<none>` with RepoTags=[] AND
    RepoDigests=[], and a real `docker run` of the workflow's reference then goes to the
    network for a manifest an air-gapped host cannot reach.

    So the TAG travels and the pin is enforced once, earlier: the pull happens on a machine
    with a registry, and the bundle carries its own sha256 from there.
    """

    def test_the_digest_is_dropped_for_the_save(self):
        script = (REPO_ROOT / "scripts" / "bundle.sh").read_text()
        assert "save_ref_for" in script
        assert "docker tag" in script, "the pulled image has to be given the tag it is saved under"

    def test_a_plain_reference_is_untouched(self):
        """Only digest-pinned references change; redis:7-alpine already saves correctly."""
        fn = _bash_function("save_ref_for")
        assert fn("redis:7-alpine") == "redis:7-alpine"
        assert fn("wagga40/zircolite:3.8.1@sha256:41b0abc") == "wagga40/zircolite:3.8.1"


def _bash_function(name: str):
    """Run one function out of bundle.sh, so the shell is the thing under test."""
    script = (REPO_ROOT / "scripts" / "bundle.sh").read_text()
    start = script.index(f"{name}()")
    body = script[start : script.index("\n}", start) + 2]

    def call(arg: str) -> str:
        return subprocess.run(
            ["bash", "-c", f"{body}\n{name} {shlex.quote(arg)}"],
            capture_output=True,
            text=True,
            check=False,
        ).stdout

    return call


class TestTheImageUsesTheStylesheetThatShipped:
    """A release archive already CONTAINS the compiled stylesheet — `task package` runs
    `css:build` before packing — so the image must not rebuild it, downloading a 46 MB CLI
    from GitHub to reproduce a file already in the tree.

    That would make `task deploy ARCHIVE=…` require the internet on every host, which is
    the one thing a closed network cannot give it.
    """

    def test_a_packaged_tree_reuses_it_instead_of_downloading(self):
        stage = _css_stage()
        assert "app/static/vendor/tailwind-built.css" in stage, "the image never looks for a shipped stylesheet"
        assert "cp app/static/vendor/tailwind-built.css" in stage

    def test_the_discriminator_is_base_htmls_mode_not_the_file_existing(self):
        """`tailwind-built.css` is TRACKED, so every checkout has one and it is routinely
        stale — Tailwind scans templates to decide which classes to emit, so a class added
        to a template today is missing from a stylesheet compiled last week.

        `task package` flips base.html to the compiled sheet and writes it in the same step,
        so "base.html already points at the compiled sheet" means exactly "this tree was
        packaged". Keying off the file alone would bake a stale stylesheet into every
        developer build.
        """
        stage = _css_stage()
        condition = stage.split("if ", 1)[1].split("; then", 1)[0]
        assert "base.html" in condition, f"the reuse branch does not check base.html's mode: {condition.strip()!r}"

    def test_a_working_tree_still_compiles(self):
        stage = _css_stage()
        assert "tailwindcss -i app/static/tailwind-input.css" in stage, "a checkout must still build"
        assert "else" in stage


def _css_stage() -> str:
    """The Dockerfile's css stage, which is where the decision lives."""
    text = (REPO_ROOT / "Dockerfile").read_text(encoding="utf-8")
    return text.split("FROM deps AS css", 1)[1].split("\nFROM ", 1)[0]


class TestABundleIsA7z:
    """Same format as the release archive it contains, and the same flags.

    `7z` is already a hard prerequisite on every host — deploy:bootstrap installs it and
    extracting the release needs it — so this asks for nothing new, and it leaves one
    archive format to reason about instead of two.
    """

    def test_the_default_name_says_so(self):
        src = (REPO_ROOT / "scripts" / "bundle.sh").read_text(encoding="utf-8")
        assert "logstotal-bundle-${version}-${arch}.7z" in src

    def test_the_executable_filter_is_off(self):
        """-mf=off IS LOAD-BEARING. 7-Zip 21+ applies an ARM64 BCJ filter (method 0A) that
        p7zip cannot decode: it exits 2 having extracted everything EXCEPT the executables.
        That shipped once already, in the release archive, and made every published archive
        unextractable on the hosts it was built for. A bundle carries image tarballs full of
        binaries, so it is exposed to exactly the same thing."""
        src = (REPO_ROOT / "scripts" / "bundle.sh").read_text(encoding="utf-8")
        create = next(ln for ln in src.splitlines() if "7z a " in ln)
        assert "-mf=off" in create, f"the bundle may not be extractable on a host: {create.strip()!r}"

    def test_the_output_path_is_absolute_before_the_archive_is_written(self):
        """7z takes its file list relative to the CWD, so assembly cds into the staging
        directory. A relative output path would be written THERE and deleted by the EXIT
        trap — a build that reports success and leaves nothing behind."""
        src = (REPO_ROOT / "scripts" / "bundle.sh").read_text(encoding="utf-8")
        before = src.split("7z a ", 1)[0]
        assert 'out="$(pwd)/${out}"' in before

    def test_the_deploy_gate_opens_a_7z(self):
        gate = (REPO_ROOT / "scripts" / "deploy-package-gate.sh").read_text(encoding="utf-8")
        assert "7z x" in gate and "tar -xf" not in gate


@pytest.mark.skipif(shutil.which("7z") is None or shutil.which("rsync") is None, reason="7z and rsync required")
def test_single_host_bundle_upgrade_stages_and_starts_without_network(tmp_path):
    from test_upgrade_script import _make_stub_dir

    built = _build(tmp_path)
    assert built.returncode == 0, built.stderr
    shim = _make_stub_dir(tmp_path)
    for name in ("curl", "git"):
        file = shim / name
        file.write_text(f'#!/bin/sh\necho "UNEXPECTED NETWORK: {name}" >&2\nexit 91\n')
        file.chmod(0o755)
    install = tmp_path / "installed"
    install.mkdir()
    (install / ".env").write_text("SECRET_KEY=test-only\n")
    (install / "VERSION").write_text("version: 0.0.1\n")
    env = {
        "PATH": f"{shim}:{os.environ['PATH']}",
        "HOME": str(tmp_path),
        "BUNDLE": str(tmp_path / "bundle.7z"),
        "SKIP_SNAPSHOT": "true",
        "NO_COLOR": "1",
    }
    result = subprocess.run(["bash", str(REPO_ROOT / "scripts/upgrade.sh"), "docker"], cwd=install, env=env, capture_output=True, text=True, timeout=40)
    output = result.stdout + result.stderr
    assert result.returncode == 0, output
    assert "UNEXPECTED NETWORK" not in output
    assert (install / "VERSION").read_text() == "version: 1.2.3\n"
    assert (install / "data/.bundle-images").read_text() == "tag=1.2.3\n"
    assert "STUB docker load -i" in output
    assert "STUB docker compose build" not in output
    assert "STUB docker compose up -d --no-build --pull never" in output


@pytest.mark.skipif(shutil.which("7z") is None, reason="7z required")
def test_fleet_bundle_upgrade_uses_local_archive_and_images(tmp_path):
    from test_upgrade_script import _healthy_curl, _make_stub_dir

    built = _build(tmp_path)
    assert built.returncode == 0, built.stderr
    shim = _make_stub_dir(tmp_path)
    _healthy_curl(shim)  # The application health probe, not a release lookup.
    (shim / "git").write_text('#!/bin/sh\necho "UNEXPECTED RELEASE LOOKUP" >&2\nexit 91\n')
    install = tmp_path / "controller"
    install.mkdir()
    (install / "VERSION").write_text("version: 0.0.1\n")
    env = {
        "PATH": f"{shim}:{os.environ['PATH']}",
        "HOME": str(tmp_path),
        "BUNDLE": str(tmp_path / "bundle.7z"),
        "DEPLOY_HOSTS": "cp.example.com w1.example.com",
        "DEPLOY_DRY_RUN": "true",
        "SKIP_BACKUP": "true",
        "NO_COLOR": "1",
    }
    result = subprocess.run(["bash", str(REPO_ROOT / "scripts/upgrade.sh"), "multiserver"], cwd=install, env=env, capture_output=True, text=True, timeout=40)
    output = result.stdout + result.stderr
    assert result.returncode == 0, output
    assert "UNEXPECTED RELEASE LOOKUP" not in output
    assert "upgrade complete (fleet)" in output
    assert "load images from the bundle" in output
    assert "logstotal-1.2.3.7z" in output
    assert "STUB task package" not in output
    assert (install / "VERSION").read_text() == "version: 0.0.1\n"
