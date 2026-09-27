"""The fleet's settings, and where they disagree — as data.

Tier 1: the module is pure and stdlib-only, so every claim `task deploy:plan` prints about
a configuration is checkable without a host, a network or a shell. That is the whole reason
the logic lives in Python rather than in `deploy-preflight.sh` beside the checks it prints
next to.

Two properties matter more than any individual finding and are asserted directly: a clean
configuration produces **no** findings (a report that always says something is a report
nobody reads), and no finding is ever fatal.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent


@pytest.fixture(scope="module")
def review_mod():
    spec = importlib.util.spec_from_file_location("deploy_config_review", REPO_ROOT / "scripts" / "deploy_config_review.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules["deploy_config_review"] = module
    spec.loader.exec_module(module)
    return module


#: A fleet with nothing wrong with it. Every test starts here and breaks one thing, so a
#: finding that fires on a healthy config fails the case that introduced it.
CLEAN = {
    "DEPLOY_HOSTS": "cp.example.com,w1.example.com",
    "DEPLOY_DOMAIN": "logs.example.com",
    "DOMAIN": "logs.example.com",
    "DEPLOY_PROXY_TLS": "acme",
    "DEPLOY_ACME_EMAIL": "admin@logs.example.com",
    "DEPLOY_ADMIN_EMAIL": "admin@logs.example.com",
    "DEPLOY_BASIC_AUTH_USER": "admin",
    "DEPLOY_BASIC_AUTH_PASSWORD": "a long passphrase",
    "DEPLOY_VPN": "wireconf",
    "DEPLOY_VPN_NETWORK": "10.200.0.0/24",
    "DEPLOY_CP_ADDRESS": "10.200.0.1",
    "DEPLOY_HUEY_WORKERS": "4",
    "DEPLOY_KEEP_RELEASES": "3",
}


def _findings(mod, **overrides):
    """Messages for CLEAN with overrides applied. A None value removes the key."""
    cfg = {**CLEAN, **overrides}
    cfg = {k: v for k, v in cfg.items() if v is not None}
    return [f.message for f in mod.build_review(cfg).findings]


def _fires(mod, needle: str, **overrides) -> bool:
    return any(needle in m for m in _findings(mod, **overrides))


# ── The two properties ───────────────────────────────────────────────────────


def test_a_healthy_fleet_produces_no_findings(review_mod):
    """The baseline every other test measures against.

    A review that always has something to say trains operators to skip it, at which point
    the ones that matter are invisible too.
    """
    assert _findings(review_mod) == []


def test_no_finding_is_ever_fatal(review_mod):
    """Levels are warn and note, and there is deliberately no third.

    deploy:plan always exits 0 and `task deploy`'s banner must not grow new ways to stop —
    so a finding cannot be allowed to become a refusal by someone adding a level later.
    """
    cfg = {
        **CLEAN,
        "DEPLOY_VPN": "bogus",
        "DEPLOY_PROXY_TLS": "custom",
        "DEPLOY_ONLY": "nowhere.example.com",
        "DEPLOY_KEEP_RELEASES": "0",
    }
    review = review_mod.build_review(cfg)
    assert review.findings, "the fixture should be broken enough to produce findings"
    assert {f.level for f in review.findings} <= {review_mod.WARN, review_mod.NOTE}


def test_warnings_are_listed_before_notes(review_mod):
    """A note above a warning buries the half that changes an outcome."""
    review = review_mod.build_review({**CLEAN, "DEPLOY_VPN": "bogus", "DEPLOY_ADMIN_EMAIL": "admin@example.com"})
    levels = [f.level for f in review.findings]
    assert review_mod.WARN in levels and review_mod.NOTE in levels
    assert levels == sorted(levels, key=lambda lv: 0 if lv == review_mod.WARN else 1)


# ── Values that do not correspond ────────────────────────────────────────────


class TestTheDomainAndTheAddresses:
    """The case this module was asked for: a setting whose value belongs to another fleet."""

    def test_an_admin_address_at_another_domain_is_noted(self, review_mod):
        assert _fires(review_mod, "is at other-corp.net, but this fleet serves logs.example.com", DEPLOY_ADMIN_EMAIL="admin@other-corp.net")

    def test_it_is_a_note_and_never_a_warning(self, review_mod):
        """An MSP serving logs.client.com from admin@their-own-domain is doing it right.

        A warning that the reader is supposed to ignore teaches them to ignore warnings,
        so this one states the fact and says when it is fine.
        """
        review = review_mod.build_review({**CLEAN, "DEPLOY_ADMIN_EMAIL": "admin@other-corp.net"})
        matching = [f for f in review.findings if "other-corp.net" in f.message]
        assert matching and all(f.level == review_mod.NOTE for f in matching)

    def test_a_subdomain_of_the_same_site_is_not_flagged(self, review_mod):
        """`logs.example.com` and `admin@mail.example.com` are the same organisation."""
        assert not _fires(review_mod, "but this fleet serves", DEPLOY_ADMIN_EMAIL="admin@mail.example.com")

    def test_a_placeholder_address_is_reported_as_a_placeholder_not_a_mismatch(self, review_mod):
        """admin@example.com mismatches every real domain, so reporting both would print
        two findings about one unedited template line."""
        msgs = _findings(review_mod, DEPLOY_ADMIN_EMAIL="admin@example.com")
        assert any("still the template's admin@example.com" in m for m in msgs)
        assert not any("but this fleet serves" in m for m in msgs)

    def test_a_malformed_address_is_a_warning(self, review_mod):
        assert _fires(review_mod, "is not an email address", DEPLOY_ADMIN_EMAIL="admin.example.com")

    def test_a_derived_acme_address_can_never_disagree(self, review_mod):
        """Unset, it becomes admin@<domain> — so an unset value must produce silence, not
        a mismatch against the placeholder it never had."""
        assert not _fires(review_mod, "but this fleet serves", DEPLOY_ACME_EMAIL=None)


class TestTheTwoDomainKeys:
    def test_a_stale_plain_domain_is_a_warning(self, review_mod):
        """task deploy:init writes DOMAIN and DEPLOY_DOMAIN; deploy-smoke.sh reads DOMAIN
        first, so editing only one silently points the smoke test at the old host."""
        assert _fires(review_mod, "so it will test old.example.com", DOMAIN="old.example.com")

    def test_agreeing_keys_say_nothing(self, review_mod):
        assert not _fires(review_mod, "disagree")


# ── Configurations that break after a green deploy ───────────────────────────


class TestSilentBreakage:
    def test_custom_tls_has_no_deploy_knob_for_its_certificates(self, review_mod):
        """PROXY_TLS=custom needs PROXY_TLS_CERT/_KEY, which no DEPLOY_* setting writes,
        so Caddy exits 1 at start on a fleet that just passed every check."""
        assert _fires(review_mod, "no DEPLOY_* setting writes them", DEPLOY_PROXY_TLS="custom")

    def test_the_placeholder_hash_is_caught(self, review_mod):
        """`$2a$14$...` is what deploy.env.example and `task deploy:init` both ship, and it
        passes deploy-fleet.sh's bcrypt prefix test and the entrypoint's — so uncommenting
        that line deploys clean and rejects every login."""
        assert _fires(review_mod, "still the template placeholder", DEPLOY_BASIC_AUTH_HASH=review_mod.HASH_PLACEHOLDER)

    def test_a_real_hash_is_accepted(self, review_mod):
        assert not _fires(
            review_mod,
            "template placeholder",
            DEPLOY_BASIC_AUTH_HASH="$2a$14$Ck9tE8VUJx1qk3nL0oPqSePBUXPGwqzQ1pQ0m3rLxYyBqz3Yh0Xy2",
            DEPLOY_BASIC_AUTH_PASSWORD=None,
        )

    def test_an_unknown_vpn_mode_is_caught_before_the_vpn_step(self, review_mod):
        """vpn_mode passes a typo through verbatim and deploy-bootstrap.sh compares
        `= wireconf`, so WireGuard is skipped silently until step 4 refuses."""
        assert _fires(review_mod, "DEPLOY_VPN=wireguard is not a mode", DEPLOY_VPN="wireguard")

    def test_deploy_only_outside_the_host_list_is_caught_before_the_last_phase(self, review_mod):
        """deploy-multiserver.sh dies on this at phase 5 of 5 — after bootstrap, the VPN
        and the env push have already run against the whole fleet."""
        assert _fires(review_mod, "which is not in DEPLOY_HOSTS", DEPLOY_ONLY="w9.example.com")

    def test_deploy_only_naming_a_real_host_is_silent(self, review_mod):
        assert not _fires(review_mod, "not in DEPLOY_HOSTS", DEPLOY_ONLY="w1.example.com")

    def test_a_user_prefix_does_not_make_a_host_unknown(self, review_mod):
        """DEPLOY_HOSTS entries may be `user@host`; DEPLOY_ONLY may name either form."""
        assert not _fires(review_mod, "not in DEPLOY_HOSTS", DEPLOY_HOSTS="root@cp.example.com,root@w1.example.com", DEPLOY_ONLY="w1.example.com")


class TestSecurityControlsThatAreNotWhatWasAsked:
    def test_basic_auth_over_plain_http_is_a_warning(self, review_mod):
        assert _fires(review_mod, "sends the credentials in clear text", DEPLOY_PROXY_TLS="off", DEPLOY_DOMAIN="logs.example.com")

    def test_a_password_with_no_username_is_caught_before_the_control_plane_hashes_it(self, review_mod):
        """deploy-fleet.sh SSHes to the control plane and runs `caddy hash-password` at
        step 5 before deploy_fleet_env.py refuses for want of a username."""
        assert _fires(review_mod, "the deploy will refuse after hashing it", DEPLOY_BASIC_AUTH_USER=None)

    def test_a_password_and_a_hash_together_says_which_one_wins(self, review_mod):
        assert _fires(
            review_mod,
            "the hash wins and the password is ignored",
            DEPLOY_BASIC_AUTH_HASH="$2a$14$Ck9tE8VUJx1qk3nL0oPqSePBUXPGwqzQ1pQ0m3rLxYyBqz3Yh0Xy2",
        )


class TestTheTunnel:
    def test_a_control_plane_address_outside_the_mesh_is_a_warning(self, review_mod):
        """An explicit --cp-address overrides the VPN address map unconditionally, so one
        stale value takes every worker off a tunnel that is still built and reported up."""
        assert _fires(review_mod, "is outside DEPLOY_VPN_NETWORK", DEPLOY_CP_ADDRESS="192.168.1.5")

    def test_it_names_the_address_that_would_be_right(self, review_mod):
        review = review_mod.build_review({**CLEAN, "DEPLOY_CP_ADDRESS": "192.168.1.5"})
        assert any("10.200.0.1" in f.fix for f in review.findings)

    def test_an_address_inside_the_mesh_is_silent(self, review_mod):
        assert not _fires(review_mod, "outside DEPLOY_VPN_NETWORK")

    def test_a_leftover_address_with_no_tunnel_is_a_warning(self, review_mod):
        assert _fires(review_mod, "with DEPLOY_VPN=none", DEPLOY_VPN="none")

    def test_a_malformed_network_does_not_raise(self, review_mod):
        """A typo in a CIDR must produce a review, not a traceback out of deploy:plan."""
        assert isinstance(_findings(review_mod, DEPLOY_VPN_NETWORK="10.200.0.0/notacidr"), list)


class TestSettingsThatAreSilentlyIgnored:
    def test_tls_without_a_domain_is_inert(self, review_mod):
        """deploy_fleet_env.py builds the proxy block from bool(domain), so this is
        configured and then dropped."""
        assert _fires(review_mod, "DEPLOY_PROXY_TLS is set but DEPLOY_DOMAIN is not", DEPLOY_DOMAIN=None, DOMAIN=None)

    def test_an_acme_address_without_a_domain_is_inert(self, review_mod):
        assert _fires(review_mod, "DEPLOY_ACME_EMAIL is set but DEPLOY_DOMAIN is not", DEPLOY_DOMAIN=None, DOMAIN=None)

    def test_an_acme_address_under_another_tls_mode_is_noted(self, review_mod):
        assert _fires(review_mod, "no certificate is requested", DEPLOY_PROXY_TLS="internal")


class TestACertificateAuthorityCannotIssueForThis:
    @pytest.mark.parametrize(
        ("domain", "reason"),
        [
            ("logs.internal", "a private suffix"),
            ("logs.local", "a private suffix"),
            ("logstotal", "a single-label name"),
            ("192.168.1.10", "an IP address"),
        ],
    )
    def test_acme_with_an_unissuable_name(self, review_mod, domain, reason):
        """deploy-fleet.sh's own help advertises DEPLOY_DOMAIN=logs.internal with
        PROXY_TLS=internal, so the wrong pairing is one word away."""
        assert _fires(review_mod, reason, DEPLOY_DOMAIN=domain, DOMAIN=domain, DEPLOY_ACME_EMAIL=None, DEPLOY_ADMIN_EMAIL=None)

    def test_the_same_name_under_internal_tls_is_correct(self, review_mod):
        assert not _fires(
            review_mod,
            "no public CA will issue",
            DEPLOY_DOMAIN="logs.internal",
            DOMAIN="logs.internal",
            DEPLOY_PROXY_TLS="internal",
            DEPLOY_ACME_EMAIL=None,
            DEPLOY_ADMIN_EMAIL=None,
        )


class TestNumbersInterpolatedIntoRemoteShell:
    def test_zero_snapshots_deletes_the_rollback_point(self, review_mod):
        """The prune runs after the snapshot, so 0 removes the one just taken."""
        assert _fires(review_mod, "leaving nothing to roll back to", DEPLOY_KEEP_RELEASES="0")

    @pytest.mark.parametrize("key", ["DEPLOY_HUEY_WORKERS", "DEPLOY_KEEP_RELEASES", "DEPLOY_VPN_PORT", "DEPLOY_HEALTH_ATTEMPTS", "DEPLOY_HEALTH_DELAY"])
    def test_a_non_numeric_value_is_caught(self, review_mod, key):
        assert _fires(review_mod, "is not a number", **{key: "lots"})

    def test_a_port_outside_the_range_is_caught(self, review_mod):
        assert _fires(review_mod, "is outside 1-65535", DEPLOY_VPN_PORT="70000")

    def test_sensible_values_say_nothing(self, review_mod):
        assert not _fires(review_mod, "is not a number", DEPLOY_VPN_PORT="51820", DEPLOY_HEALTH_ATTEMPTS="30", DEPLOY_HEALTH_DELAY="2")


# ── The settings block ───────────────────────────────────────────────────────


class TestTheSettingsBlock:
    def test_the_domain_is_shown_as_a_value(self, review_mod):
        """The whole complaint: deploy:plan read DEPLOY_DOMAIN only as a boolean, so the
        one question a plan is asked most had no answer in its output."""
        review = review_mod.build_review(CLEAN)
        assert any(s.label == "Domain" and s.value == "logs.example.com" for s in review.settings)

    def test_provenance_is_carried_per_setting(self, review_mod):
        review = review_mod.build_review(CLEAN, {"DEPLOY_DOMAIN": "deploy.env"})
        domain = next(s for s in review.settings if s.label == "Domain")
        assert domain.source == "deploy.env"

    def test_a_setting_nobody_supplied_reads_as_a_default(self, review_mod):
        """Not blank: "where did this come from" is the question, and an empty column
        answers it with silence."""
        review = review_mod.build_review({"DEPLOY_HOSTS": "cp.example.com"})
        assert all(s.source for s in review.settings)
        assert next(s for s in review.settings if s.label == "Install dir").source == "a default"

    def test_provenance_follows_the_key_that_holds_the_value(self, review_mod):
        """The TLS row names a mode and an address; reporting the first key's source
        unconditionally printed `from deploy.env` for a file that mentions neither."""
        review = review_mod.build_review({"DEPLOY_HOSTS": "cp", "DEPLOY_DOMAIN": "d.example"}, {"DEPLOY_DOMAIN": "deploy.env"})
        assert next(s for s in review.settings if s.label == "TLS").source == "a default"

    def test_the_derived_acme_address_is_shown_and_labelled(self, review_mod):
        """It is what the CA will be told, so it belongs on screen — and it is derived,
        so it must not look like something the operator typed."""
        cfg = {k: v for k, v in CLEAN.items() if k != "DEPLOY_ACME_EMAIL"}
        review = review_mod.build_review(cfg)
        tls = next(s for s in review.settings if s.label == "TLS")
        assert "admin@logs.example.com" in tls.note and "derived" in tls.note

    def test_no_domain_says_where_the_app_actually_is(self, review_mod):
        review = review_mod.build_review({"DEPLOY_HOSTS": "cp.example.com"})
        domain = next(s for s in review.settings if s.label == "Domain")
        assert domain.value == "none" and "cp.example.com:8000" in domain.note

    def test_basic_auth_off_is_stated_rather_than_omitted(self, review_mod):
        """A row that disappears when unset makes "is auth on?" unanswerable without
        knowing the row could have been there."""
        review = review_mod.build_review({"DEPLOY_HOSTS": "cp"})
        assert next(s for s in review.settings if s.label == "Basic auth").value == "off"


# ── Rendering ────────────────────────────────────────────────────────────────


class TestRendering:
    def test_colour_never_emits_escapes(self, review_mod):
        out = review_mod.render_text(review_mod.build_review({**CLEAN, "DEPLOY_VPN": "bogus"}), color="never")
        assert "\033" not in out

    def test_colour_always_emits_escapes(self, review_mod):
        out = review_mod.render_text(review_mod.build_review(CLEAN), color="always")
        assert "\033" in out

    def test_the_provenance_column_is_aligned_on_the_visible_width(self, review_mod):
        """Padding on the coloured string pushes the column right by the escapes' byte
        count, which is invisible in a test and ragged on screen."""
        plain = review_mod.render_text(review_mod.build_review(CLEAN), color="never")
        colored = review_mod.render_text(review_mod.build_review(CLEAN), color="always")
        strip = lambda s: s.replace("\033[1m", "").replace("\033[2m", "").replace("\033[0m", "")  # noqa: E731
        assert [strip(x) for x in colored.splitlines()] == plain.splitlines()

    def test_findings_only_output_carries_no_settings_heading(self, review_mod):
        """It is folded into the plan's own check output, where a second title reads as a
        second section."""
        review = review_mod.build_review({**CLEAN, "DEPLOY_VPN": "bogus"})
        review.settings = []
        out = review_mod.render_text(review, color="never")
        assert "Fleet configuration" not in out
        assert out.startswith("  WARN")

    def test_the_summary_says_findings_do_not_stop_a_deploy(self, review_mod):
        """A reader who has to infer it will either ignore all of them or stop on all."""
        out = review_mod.render_text(review_mod.build_review({**CLEAN, "DEPLOY_VPN": "bogus"}), color="never")
        assert "none of them stops a deploy" in out

    def test_a_clean_review_renders_no_finding_section(self, review_mod):
        out = review_mod.render_text(review_mod.build_review(CLEAN), color="never")
        assert "WARN" not in out and "NOTE" not in out

    def test_json_carries_every_finding_and_its_keys(self, review_mod):
        import json

        payload = json.loads(review_mod.to_json(review_mod.build_review({**CLEAN, "DEPLOY_VPN": "bogus"})))
        assert payload["counts"]["warnings"] >= 1
        assert payload["control_plane"] == "cp.example.com"
        assert payload["workers"] == ["w1.example.com"]
        assert all(f["keys"] for f in payload["findings"]), "a finding must name the settings it is about"

    def test_json_is_valid_for_an_empty_configuration(self, review_mod):
        import json

        assert json.loads(review_mod.to_json(review_mod.build_review({})))


class TestTheCli:
    def test_it_parses_set_and_source_pairs(self, review_mod, capsys):
        rc = review_mod.main(["--set", "DEPLOY_HOSTS=cp", "--set", "DEPLOY_DOMAIN=d.example", "--source", "DEPLOY_DOMAIN=deploy.env", "--color", "never"])
        out = capsys.readouterr().out
        assert rc == 0
        assert "d.example" in out and "from deploy.env" in out

    def test_a_value_containing_an_equals_sign_survives(self, review_mod, capsys):
        """A bcrypt hash and a passphrase both can; splitting on every `=` truncated them."""
        review_mod.main(["--set", "DEPLOY_HOSTS=cp", "--set", "DEPLOY_ADMIN_EMAIL=a=b@example.com", "--color", "never"])
        assert "a=b@example.com" in capsys.readouterr().out

    def test_findings_only_on_a_clean_config_prints_nothing(self, review_mod, capsys):
        rc = review_mod.main(["--set", "DEPLOY_HOSTS=cp", "--findings-only", "--color", "never"])
        assert rc == 0
        assert capsys.readouterr().out == ""

    def test_every_reviewed_key_is_actually_read(self, review_mod):
        """REVIEWED_KEYS is what the shell shim iterates to build its argument list, so a
        name here that the review ignores means the shim passes a value nothing reads."""
        source = (REPO_ROOT / "scripts" / "deploy_config_review.py").read_text(encoding="utf-8")
        body = source.split("REVIEWED_KEYS = (", 1)[0]
        missing = [k for k in review_mod.REVIEWED_KEYS if f'"{k}"' not in body]
        assert not missing, f"declared in REVIEWED_KEYS but never read: {missing}"


class TestTheShellShim:
    """`config_review` in scripts/lib/common.sh collects the values; the module judges them.

    The split is the network_plan arrangement, and its one seam is the key list: the shim
    hardcodes it rather than paying a second python3 start-up per render to ask, so the
    two halves have to be pinned against each other.
    """

    @staticmethod
    def _shim_keys() -> list[str]:
        import re

        text = (REPO_ROOT / "scripts" / "lib" / "common.sh").read_text(encoding="utf-8")
        block = re.search(r'_CONFIG_REVIEW_KEYS="(.*?)"', text, re.S)
        assert block, "the shim's key list is gone or renamed"
        return block.group(1).replace("\\\n", " ").split()

    def test_the_shim_passes_every_key_the_module_reviews(self, review_mod):
        missing = [k for k in review_mod.REVIEWED_KEYS if k not in self._shim_keys()]
        assert not missing, f"reviewed by the module but never collected by the shim: {missing}"

    def test_the_shim_passes_nothing_the_module_ignores(self, review_mod):
        """The other direction: a key collected and not read is a setting an operator is
        invited to believe is checked."""
        extra = [k for k in self._shim_keys() if k not in review_mod.REVIEWED_KEYS]
        assert not extra, f"collected by the shim but not reviewed: {extra}"
