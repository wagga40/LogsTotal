"""The bundled Garage service is configured only through what docker-compose.yml hands it.

It has no `env_file:`, so garage-entrypoint.sh sees exactly the keys listed under the
service's `environment:` and nothing from .env. GARAGE_RPC_SECRET and GARAGE_ADMIN_TOKEN
were missing from that list: `./logstotal gen-secrets` and the fleet env generator wrote
both, and every deployment ran on the built-in defaults anyway, behind a warning in a log
nobody reads.
"""

from __future__ import annotations

import re
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parents[1]


def _garage_service() -> dict:
    return yaml.safe_load((REPO_ROOT / "docker-compose.yml").read_text(encoding="utf-8"))["services"]["garage"]


def test_garage_has_no_env_file_so_its_environment_is_the_whole_contract():
    """If this ever changes, the test below is answering the wrong question."""
    assert "env_file" not in _garage_service()


def test_every_variable_the_entrypoint_reads_is_passed_in():
    lines = (REPO_ROOT / "garage-entrypoint.sh").read_text(encoding="utf-8").splitlines()
    code = "\n".join(line for line in lines if not line.lstrip().startswith("#"))
    assigned = set(re.findall(r"^([A-Z][A-Z0-9_]*)=", code, flags=re.M))
    # The by-hand fallbacks for `docker run` without compose; compose must NOT pass these
    # (see the test below), so they are the one deliberate gap.
    by_hand = {"GARAGE_RPC_SECRET", "GARAGE_ADMIN_TOKEN"}
    read = set(re.findall(r"\$\{([A-Z][A-Z0-9_]*)", code)) - assigned - by_hand
    assert {"LT_GARAGE_RPC_SECRET", "S3_REGION"} <= read, "the scan no longer sees the entrypoint's variables"
    passed = set(_garage_service().get("environment") or {})
    missing = sorted(read - passed)
    assert not missing, f"garage-entrypoint.sh reads {missing}, which docker-compose.yml never passes to the garage service"


def test_the_secrets_come_from_env_under_names_garage_does_not_read():
    """From .env, and renamed: Garage reads GARAGE_RPC_SECRET/GARAGE_ADMIN_TOKEN from its own
    environment as config overrides, so passing an empty one under that name replaced the
    entrypoint's default with "" and the node refused to start ("Invalid RPC secret key")."""
    env = _garage_service()["environment"]
    for key in ("GARAGE_RPC_SECRET", "GARAGE_ADMIN_TOKEN"):
        assert key not in env, f"{key} is read by Garage itself; an empty value stops the node"
        assert env[f"LT_{key}"] == f"${{{key}:-}}", f"LT_{key} must be interpolated from .env's {key}"
