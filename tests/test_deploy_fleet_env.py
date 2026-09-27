"""Tests for scripts/deploy_fleet_env.py — one .env per fleet host.

The two properties worth pinning hardest are non-rotation and determinism. A
generator that quietly rotates SECRET_KEY logs every session out, and one that
rotates POSTGRES_PASSWORD leaves every worker authenticating against the old
credentials — which surfaces as jobs stuck in `pending`, the least diagnosable
failure this deployment has. Both are silent, and both would be discovered in
production rather than here.
"""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]

sys.path.insert(0, str(REPO_ROOT / "scripts"))
_spec = importlib.util.spec_from_file_location("deploy_fleet_env", REPO_ROOT / "scripts" / "deploy_fleet_env.py")
assert _spec and _spec.loader
dfe = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(dfe)


def _run(tmp_path: Path, *extra: str, hosts: str = "cp.example.com,w1.example.com") -> int:
    return dfe.main(
        [
            "--hosts",
            hosts,
            "--out-dir",
            str(tmp_path / "deploy-envs"),
            "--state",
            str(tmp_path / "deploy-envs" / "secrets.json"),
            "--addresses",
            str(tmp_path / "deploy-envs" / "vpn.json"),
            "--seed-from",
            str(tmp_path / "nonexistent.env"),
            *extra,
        ]
    )


def _env(tmp_path: Path, slug: str) -> str:
    return (tmp_path / "deploy-envs" / f"{slug}.env").read_text(encoding="utf-8")


def _value(text: str, key: str) -> str:
    for line in text.splitlines():
        if line.startswith(f"{key}="):
            return line.split("=", 1)[1]
    raise AssertionError(f"{key} not found in:\n{text}")


# ── One file per host ────────────────────────────────────────────────────────


def test_every_host_gets_its_own_file(tmp_path: Path):
    assert _run(tmp_path, hosts="cp.example.com,w1.example.com,w2.example.com") == 0
    out = tmp_path / "deploy-envs"
    assert {p.name for p in out.glob("*.env")} == {
        "cp.example.com.env",
        "w1.example.com.env",
        "w2.example.com.env",
    }


def test_each_worker_gets_a_distinct_name_and_address(tmp_path: Path):
    """One template for N workers is what made the operator hand-edit WORKER_NAME per
    machine; two workers sharing a name make /admin/workers unreadable."""
    _run(tmp_path, hosts="cp.example.com,w1.example.com,w2.example.com")
    assert _value(_env(tmp_path, "w1.example.com"), "WORKER_NAME") == "w1"
    assert _value(_env(tmp_path, "w2.example.com"), "WORKER_NAME") == "w2"
    assert _value(_env(tmp_path, "w1.example.com"), "WORKER_IP") == "w1.example.com"


def test_a_bare_ip_worker_falls_back_to_a_positional_name(tmp_path: Path):
    _run(tmp_path, hosts="cp.example.com,10.0.0.7")
    assert _value(_env(tmp_path, "10.0.0.7"), "WORKER_NAME") == "worker-01"


def test_a_user_prefix_does_not_reach_the_filename_or_the_address(tmp_path: Path):
    _run(tmp_path, hosts="deploy@cp.example.com,deploy@w1.example.com")
    assert (tmp_path / "deploy-envs" / "w1.example.com.env").exists()
    assert "deploy@" not in _value(_env(tmp_path, "w1.example.com"), "S3_ENDPOINT")


def test_two_hosts_that_would_share_a_filename_are_refused(tmp_path: Path):
    assert _run(tmp_path, hosts="cp.example.com,root@w1.example.com,ops@w1.example.com") == 1


def test_generated_files_are_not_world_readable(tmp_path: Path):
    _run(tmp_path)
    for path in (tmp_path / "deploy-envs").glob("*"):
        assert path.stat().st_mode & 0o077 == 0, f"{path.name} is readable by others"


# ── Cross-host values ────────────────────────────────────────────────────────


def test_the_control_plane_address_reaches_every_worker_url(tmp_path: Path):
    _run(tmp_path, "--cp-address", "10.200.0.1")
    worker = _env(tmp_path, "w1.example.com")
    for key in ("DATABASE_URL", "SYNC_DATABASE_URL", "REDIS_URL", "S3_ENDPOINT"):
        assert "10.200.0.1" in _value(worker, key), key
    cp = _env(tmp_path, "cp.example.com")
    for key in ("REDIS_EXPOSE", "POSTGRES_EXPOSE", "GARAGE_EXPOSE"):
        assert _value(cp, key).startswith("10.200.0.1:"), key


def test_the_shared_secrets_match_across_hosts(tmp_path: Path):
    """A mismatch here is invisible until a worker silently fails to authenticate."""
    _run(tmp_path)
    cp, worker = _env(tmp_path, "cp.example.com"), _env(tmp_path, "w1.example.com")
    assert _value(cp, "SECRET_KEY") == _value(worker, "SECRET_KEY")
    assert _value(cp, "S3_ACCESS_KEY") == _value(worker, "S3_ACCESS_KEY")
    assert _value(cp, "S3_SECRET_KEY") == _value(worker, "S3_SECRET_KEY")
    assert _value(cp, "POSTGRES_PASSWORD") in _value(worker, "DATABASE_URL")
    assert _value(cp, "REDIS_PASSWORD") in _value(worker, "REDIS_URL")


def test_the_garage_secrets_are_emitted(tmp_path: Path):
    """garage-entrypoint.sh falls back to a built-in RPC secret with only a warning,
    and the two-template scaffold never wrote these — so every bundled-S3 fleet ran on
    the shipped default."""
    _run(tmp_path)
    cp = _env(tmp_path, "cp.example.com")
    assert len(_value(cp, "GARAGE_RPC_SECRET")) == 64
    assert _value(cp, "GARAGE_ADMIN_TOKEN")


def test_a_vpn_map_supplies_every_address(tmp_path: Path):
    (tmp_path / "deploy-envs").mkdir()
    (tmp_path / "deploy-envs" / "vpn.json").write_text(
        json.dumps({"addresses": {"cp.example.com": "10.200.0.1", "w1.example.com": "10.200.0.2"}}),
        encoding="utf-8",
    )
    _run(tmp_path)
    assert "10.200.0.1" in _value(_env(tmp_path, "w1.example.com"), "REDIS_URL")
    assert _value(_env(tmp_path, "w1.example.com"), "WORKER_IP") == "10.200.0.2"


def test_no_vpn_warns_that_the_services_are_exposed(tmp_path: Path, capsys):
    _run(tmp_path)
    err = capsys.readouterr().err
    assert "No VPN address map" in err
    assert "protected only by their passwords" in err
    assert "DEPLOY_VPN=wireconf" in err


def test_an_explicit_cp_address_silences_the_exposure_warning(tmp_path: Path, capsys):
    _run(tmp_path, "--cp-address", "10.200.0.1")
    assert "protected only by their passwords" not in capsys.readouterr().err


def test_a_local_control_plane_without_an_address_is_refused_with_the_fix(tmp_path: Path, capsys):
    """`local` means "this machine" — there is no address in it for a worker to use,
    and guessing 127.0.0.1 would produce a fleet that silently never connects."""
    assert _run(tmp_path, hosts="local,w1.example.com") == 1
    err = capsys.readouterr().err
    assert "DEPLOY_CP_ADDRESS" in err
    assert "./logstotal deploy:vpn" in err


# ── Secrets are generated once ───────────────────────────────────────────────


def test_a_second_run_is_byte_identical(tmp_path: Path):
    _run(tmp_path)
    before = {p.name: p.read_text(encoding="utf-8") for p in (tmp_path / "deploy-envs").glob("*.env")}
    _run(tmp_path)
    after = {p.name: p.read_text(encoding="utf-8") for p in (tmp_path / "deploy-envs").glob("*.env")}
    assert before == after


def test_adding_a_host_does_not_rotate_the_existing_secrets(tmp_path: Path):
    _run(tmp_path)
    was = _value(_env(tmp_path, "cp.example.com"), "SECRET_KEY")
    _run(tmp_path, hosts="cp.example.com,w1.example.com,w2.example.com")
    assert _value(_env(tmp_path, "cp.example.com"), "SECRET_KEY") == was
    assert _value(_env(tmp_path, "w2.example.com"), "SECRET_KEY") == was


def test_force_is_the_only_way_to_rotate(tmp_path: Path):
    _run(tmp_path)
    was = _value(_env(tmp_path, "cp.example.com"), "SECRET_KEY")
    _run(tmp_path, "--force")
    assert _value(_env(tmp_path, "cp.example.com"), "SECRET_KEY") != was


def test_hand_added_keys_survive_a_regeneration(tmp_path: Path):
    """Otherwise re-running the one command is a silent config wipe."""
    _run(tmp_path)
    target = tmp_path / "deploy-envs" / "w1.example.com.env"
    target.write_text(target.read_text(encoding="utf-8") + "AI_RATE_LIMIT_PER_MINUTE=30\n", encoding="utf-8")
    _run(tmp_path)
    assert "AI_RATE_LIMIT_PER_MINUTE=30" in target.read_text(encoding="utf-8")


def test_secrets_are_seeded_from_an_existing_env_on_first_run(tmp_path: Path):
    """A single-host deployment growing into a fleet already has a SECRET_KEY that
    every live session depends on."""
    seed = tmp_path / "seed.env"
    seed.write_text("SECRET_KEY=" + "a" * 64 + "\n", encoding="utf-8")
    dfe.main(
        [
            "--hosts",
            "cp.example.com,w1.example.com",
            "--out-dir",
            str(tmp_path / "deploy-envs"),
            "--state",
            str(tmp_path / "deploy-envs" / "secrets.json"),
            "--addresses",
            str(tmp_path / "deploy-envs" / "vpn.json"),
            "--seed-from",
            str(seed),
        ]
    )
    assert _value(_env(tmp_path, "cp.example.com"), "SECRET_KEY") == "a" * 64


def test_a_placeholder_in_the_seed_is_not_adopted(tmp_path: Path):
    seed = tmp_path / "seed.env"
    seed.write_text("SECRET_KEY=change-me-in-production\n", encoding="utf-8")
    dfe.main(
        [
            "--hosts",
            "cp.example.com",
            "--out-dir",
            str(tmp_path / "deploy-envs"),
            "--state",
            str(tmp_path / "deploy-envs" / "secrets.json"),
            "--addresses",
            str(tmp_path / "deploy-envs" / "vpn.json"),
            "--seed-from",
            str(seed),
        ]
    )
    assert _value(_env(tmp_path, "cp.example.com"), "SECRET_KEY") != "change-me-in-production"


def test_the_state_file_holds_every_shared_secret(tmp_path: Path):
    _run(tmp_path)
    blob = json.loads((tmp_path / "deploy-envs" / "secrets.json").read_text(encoding="utf-8"))
    assert set(blob["secrets"]) == set(dfe.SHARED_SECRET_KEYS)


def test_an_unreadable_state_file_names_the_fix(tmp_path: Path, capsys):
    (tmp_path / "deploy-envs").mkdir()
    (tmp_path / "deploy-envs" / "secrets.json").write_text("{not json", encoding="utf-8")
    assert _run(tmp_path) == 1
    assert "Move it aside" in capsys.readouterr().err


# ── HTTPS and basic auth ─────────────────────────────────────────────────────


def test_no_domain_means_no_proxy_and_an_insecure_cookie(tmp_path: Path):
    _run(tmp_path)
    cp = _env(tmp_path, "cp.example.com")
    assert _value(cp, "COMPOSE_PROFILES") == "postgres,s3,workers"
    assert _value(cp, "COOKIE_INSECURE") == "true"
    assert "DOMAIN=" not in cp


def test_a_domain_turns_the_proxy_on_without_losing_the_other_profiles(tmp_path: Path):
    """The bundled PostgreSQL, Garage and worker relays all live behind profiles — a
    proxy switch that replaced the list would silently take the fleet's database with it."""
    _run(tmp_path, "--domain", "logs.example.com", "--acme-email", "ops@example.com")
    cp = _env(tmp_path, "cp.example.com")
    assert _value(cp, "COMPOSE_PROFILES") == "postgres,s3,workers,proxy"
    assert _value(cp, "DOMAIN") == "logs.example.com"
    assert _value(cp, "WEB_PORT") == "127.0.0.1:8000:8000"
    assert _value(cp, "COOKIE_INSECURE") == "false"
    assert _value(cp, "ENABLE_HSTS") == "true"
    assert _value(cp, "TRUST_PROXY_HEADERS") == "true"


def test_the_proxy_only_reaches_the_control_plane(tmp_path: Path):
    _run(tmp_path, "--domain", "logs.example.com")
    assert "DOMAIN=" not in _env(tmp_path, "w1.example.com")


def test_a_missing_acme_email_is_derived_rather_than_refused(tmp_path: Path):
    _run(tmp_path, "--domain", "logs.example.com")
    assert _value(_env(tmp_path, "cp.example.com"), "ACME_EMAIL") == "admin@logs.example.com"


def test_the_basic_auth_hash_is_single_quoted(tmp_path: Path):
    """A bcrypt hash is mostly `$`, Compose interpolates `$`, and
    docker-caddy-entrypoint.sh validates whitespace and braces but not that — so an
    unquoted hash reaches Caddy as a different string and every login is rejected."""
    _run(
        tmp_path,
        "--domain",
        "logs.example.com",
        "--basic-auth-user",
        "ops",
        "--basic-auth-hash",
        "$2a$14$abcdefghijklmnop",
    )
    cp = _env(tmp_path, "cp.example.com")
    assert _value(cp, "BASIC_AUTH_USER") == "ops"
    assert _value(cp, "BASIC_AUTH_HASH") == "'$2a$14$abcdefghijklmnop'"


def test_basic_auth_without_a_domain_is_refused(tmp_path: Path, capsys):
    """Caddy enforces it and only runs with the proxy profile, so without a domain the
    control plane would go out on port 8000 with no authentication at all — while the
    run banner said "Basic auth: yes" and the hashing step said "hashed"."""
    assert _run(tmp_path, "--basic-auth-user", "ops", "--basic-auth-hash", "$2a$14$x") == 1
    err = capsys.readouterr().err
    assert "DEPLOY_DOMAIN is not" in err
    assert not (tmp_path / "deploy-envs").glob("*.env").__iter__().__next__() if False else True
    assert not list((tmp_path / "deploy-envs").glob("*.env")), "nothing may be written after the refusal"


def test_a_username_with_no_hash_is_refused(tmp_path: Path, capsys):
    """The silent one, and the default state of a RE-RUN: deploy.env keeps the username
    but never the password, so a second bare `task deploy` had a user, no
    hash, and published the control plane unauthenticated — same command that secured
    it the first time. It emitted no warning at all."""
    assert _run(tmp_path, "--domain", "logs.example.com", "--basic-auth-user", "ops") == 1
    err = capsys.readouterr().err
    assert "no password or hash came with it" in err
    assert "does not remember the password" in err
    assert not list((tmp_path / "deploy-envs").glob("*.env"))


def test_no_basic_auth_at_all_is_still_fine(tmp_path: Path):
    """Refusing must be about a request that cannot be honoured, not about the feature
    being unused."""
    assert _run(tmp_path, "--domain", "logs.example.com") == 0
    assert "BASIC_AUTH_USER" not in _env(tmp_path, "cp.example.com")


def test_the_plaintext_password_is_never_a_parameter():
    """Hashing happens on the control plane; only the hash reaches this module. The
    refusal message may name the env var, but nothing here may take the value."""
    source = (REPO_ROOT / "scripts" / "deploy_fleet_env.py").read_text(encoding="utf-8")
    # Identifiers, not prose: a refusal message may name the environment variable.
    assert "--basic-auth-password" not in source
    assert "args.basic_auth_password" not in source


@pytest.mark.parametrize(
    ("entry", "expected"),
    [
        ("cp.example.com", "cp.example.com"),
        ("root@cp.example.com", "cp.example.com"),
        ("10.0.0.1", "10.0.0.1"),
        ("local", "local"),
        ("weird/name", "weird_name"),
    ],
)
def test_slugify(entry: str, expected: str):
    assert dfe.slugify(entry) == expected


# ── Bind address vs connect address ──────────────────────────────────────────
#
# REDIS_EXPOSE and friends are interpolated straight into a compose `ports:` entry, and
# Docker refuses a hostname there: the deploy dies in phase 4 with `invalid IP address:
# <host>`, pointing at nothing in the env file that caused it. With a VPN the bind and
# connect addresses are the same and the distinction is invisible.


@pytest.mark.parametrize("value", ["10.200.0.1", "192.168.1.5"])
def test_an_ip_control_plane_binds_to_itself(tmp_path: Path, value: str):
    _run(tmp_path, "--cp-address", value)
    cp = _env(tmp_path, "cp.example.com")
    assert _value(cp, "REDIS_EXPOSE") == f"{value}:6379"


def test_a_named_control_plane_binds_every_interface_rather_than_a_name(tmp_path: Path, capsys):
    _run(tmp_path)
    cp = _env(tmp_path, "cp.example.com")
    for key, port in (("REDIS_EXPOSE", 6379), ("POSTGRES_EXPOSE", 5432), ("GARAGE_EXPOSE", 3900)):
        assert _value(cp, key) == f"0.0.0.0:{port}"
    assert "Docker cannot use as a bind address" in capsys.readouterr().err


def test_the_workers_still_dial_the_name_not_the_bind_address(tmp_path: Path):
    """Where the control plane listens and where a worker connects are different
    questions; conflating them is what produced the invalid-IP failure."""
    _run(tmp_path)
    worker = _env(tmp_path, "w1.example.com")
    assert "cp.example.com" in _value(worker, "REDIS_URL")
    assert "0.0.0.0" not in worker


def test_an_explicit_bind_address_must_be_an_ip(tmp_path: Path, capsys):
    assert _run(tmp_path, "--cp-bind-address", "cp.example.com") == 1
    assert "must be an IP address" in capsys.readouterr().err


def test_an_explicit_bind_address_wins(tmp_path: Path):
    _run(tmp_path, "--cp-address", "203.0.113.9", "--cp-bind-address", "10.0.0.5")
    cp = _env(tmp_path, "cp.example.com")
    assert _value(cp, "REDIS_EXPOSE") == "10.0.0.5:6379"
    assert "203.0.113.9" in _value(_env(tmp_path, "w1.example.com"), "REDIS_URL")


def test_the_secret_state_is_not_called_fleet_json():
    """It sat beside <install>/fleet/manifest.json — the non-secret record of the fleet's
    shape, which is world-readable on purpose so it can be pasted into a bug report.

    Two files called fleet.json, one holding SECRET_KEY and the database password, is a
    support-bundle incident waiting to happen. The name is the whole mitigation."""
    for path in (REPO_ROOT / "scripts").glob("*"):
        if path.suffix not in {".sh", ".py"}:
            continue
        text = path.read_text(encoding="utf-8")
        for line in text.splitlines():
            if "fleet.json" in line and "fleet/manifest.json" not in line:
                assert "secrets.json" in line or line.lstrip().startswith("#"), f"{path.name}: {line.strip()}"
