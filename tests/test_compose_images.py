"""Every service that builds an image must also name it.

Without an `image:` key, Compose names a built image after the project directory — and
there is nothing a `docker load` can satisfy. So a host with no network cannot be GIVEN an
image, only told to build one, and building pulls python:3.14-slim, Debian packages, PyPI
wheels and a 46 MB Tailwind CLI from GitHub.

Naming them is what makes `docker save` on a connected machine and `docker load` on a
closed one possible at all. It costs one line per service and is impossible to notice
missing until the day it matters.
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parents[1]
COMPOSE_FILES = ("docker-compose.yml", "docker-compose.worker.yml")


def _services(name: str) -> dict:
    return yaml.safe_load((REPO_ROOT / name).read_text(encoding="utf-8")).get("services", {})


@pytest.mark.parametrize("compose_file", COMPOSE_FILES)
def test_every_built_service_names_its_image(compose_file: str):
    unnamed = [name for name, svc in _services(compose_file).items() if isinstance(svc, dict) and "build" in svc and not svc.get("image")]
    assert not unnamed, f"{compose_file}: these build an image nothing can `docker load` into place: {unnamed}"


def test_the_two_compose_files_agree_on_the_application_image():
    """docker-compose.worker.yml has always used `logstotal:latest` and the main file built
    an unnamed one. A remote worker therefore ran whatever `docker build -t logstotal:latest`
    last produced on that host, which is not necessarily what the control plane runs."""
    main = _services("docker-compose.yml")
    worker = _services("docker-compose.worker.yml")
    main_image = main["worker"]["image"]
    remote_image = worker["worker"]["image"]
    assert main_image.startswith("logstotal:")
    assert remote_image.startswith("logstotal:")
    assert main["web"]["image"] == main_image, "web and worker must run the same image"
    # The whole reference, not its prefix. Both files can say `logstotal:` and mean
    # different tags — ${LOGSTOTAL_IMAGE_TAG:-latest} in one, a hardcoded `latest` in the
    # other — and an air-gapped install would start its control plane on
    # logstotal:<version> and fail every worker with `No such image: logstotal:latest`,
    # with the right image sitting on each host under the right name.
    assert remote_image == main_image, f"the two compose files name different images: {main_image!r} vs {remote_image!r}"


def test_the_image_tag_is_overridable():
    """A bundle carries an image tagged with the release it holds, so the tag has to be a
    variable — otherwise two releases on one host are the same `latest`."""
    # BOTH files. Checking only the main one is how the worker kept its hardcoded tag.
    for name in ("docker-compose.yml", "docker-compose.worker.yml"):
        text = (REPO_ROOT / name).read_text(encoding="utf-8")
        assert "LOGSTOTAL_IMAGE_TAG" in text, f"{name} pins the tag"
        assert "${LOGSTOTAL_IMAGE_TAG:-latest}" in text, f"{name} must default to the tag already in use"


# ── Pulling from a mirror instead of Docker Hub ──────────────────────────────


def test_every_image_not_built_here_can_come_from_a_mirror():
    """A network with no route to Docker Hub but a registry of its own sets
    REGISTRY_PREFIX, and every pull goes there instead. An image that misses the prefix is
    the one that fails on that network, at the moment it is first needed."""
    text = (REPO_ROOT / "docker-compose.yml").read_text(encoding="utf-8")
    unprefixed = [line.strip() for line in text.splitlines() if line.strip().startswith("image:") and "REGISTRY_PREFIX" not in line and "logstotal" not in line]
    assert not unprefixed, f"these cannot be served from a mirror: {unprefixed}"


def test_the_images_we_build_here_are_not_prefixed():
    """They are built locally — a registry prefix would point at something that does not
    exist there — and on a bundle install they arrive by `docker load`."""
    text = (REPO_ROOT / "docker-compose.yml").read_text(encoding="utf-8")
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("image:") and "logstotal" in stripped:
            assert "REGISTRY_PREFIX" not in stripped, stripped


# ── Images that came from a bundle ───────────────────────────────────────────


def test_the_adapter_only_drops_a_digest_when_told_to(monkeypatch):
    """The pin is moved, not discarded: LOGSTOTAL_BUNDLED_IMAGES is set by the deploy on
    hosts loaded from a bundle and nowhere else, so an ordinary install pulls exactly as
    before. Getting this backwards would silently unpin every deployment."""
    from app.tools.base import apply_bundled_images

    pinned = "wagga40/zircolite:3.8.1@sha256:41b0abc"
    monkeypatch.delenv("LOGSTOTAL_BUNDLED_IMAGES", raising=False)
    assert apply_bundled_images(pinned) == pinned

    monkeypatch.setenv("LOGSTOTAL_BUNDLED_IMAGES", "true")
    assert apply_bundled_images(pinned) == "wagga40/zircolite:3.8.1"
    assert apply_bundled_images("redis:7-alpine") == "redis:7-alpine"


def test_a_host_remembers_how_it_got_its_images():
    """`task deploy:start` and every restart go through remote_start with no bundle in
    sight, default to building, and on a closed network died pulling python:3.12-slim —
    day 2 broken on a fleet day 1 had installed fine.

    The marker lives under data/, which the overlay never deletes, and carries the tag so a
    restart asks for the images that are actually on the host.
    """
    deploy = (REPO_ROOT / "scripts" / "deploy-multiserver.sh").read_text()
    assert "data/.bundle-images" in deploy
    start = deploy.split("remote_start()")[1].split("\n}")[0]
    assert ".bundle-images" in start, "a plain start never consults the marker"
    assert "LOGSTOTAL_NO_BUILD=true" in start

    # And the worker CONTAINER has to be told, which only .env can do — the tool adapter
    # runs inside it. It must be written at START time: both the KEEPENV restore and the env
    # push land after the image-load step, and either one puts a file back without the line.
    # Written any earlier, the marker survives and the .env line does not, which is the half
    # the container actually reads.
    assert "LOGSTOTAL_BUNDLED_IMAGES=true" in start, "the env line is written somewhere a later .env restore can clobber"
