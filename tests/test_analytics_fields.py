"""Tests for app.analytics_fields — config loading and validation."""

from __future__ import annotations

import pytest

from app.analytics_fields import load_analytics_fields


class TestLoadAnalyticsFields:
    def test_valid_yaml(self, tmp_path):
        cfg = tmp_path / "fields.yaml"
        cfg.write_text(
            """
ip_keys: [SourceIP, DestinationIP]
hash_keys: [Hashes]
image_keys: [Image]
domain_keys: [TargetDomainName]
cmdline_keys: [CommandLine]
user_keys: [SubjectUserName]
noise_users: [SYSTEM, LOCAL SERVICE]
cmdline_exts: [.ps1, .bat]
service_keys: [ServiceName]
task_keys: [TaskName]
"""
        )
        result = load_analytics_fields(cfg)
        assert "SourceIP" in result.ip_keys
        assert "DestinationIP" in result.ip_keys
        assert "Hashes" in result.hash_keys
        assert result.noise_users == frozenset({"system", "local service"})

    def test_missing_file(self, tmp_path):
        with pytest.raises(FileNotFoundError):
            load_analytics_fields(tmp_path / "nope.yaml")

    def test_invalid_yaml(self, tmp_path):
        cfg = tmp_path / "bad.yaml"
        cfg.write_text("[ unclosed")
        with pytest.raises(Exception):
            load_analytics_fields(cfg)

    def test_missing_required_keys(self, tmp_path):
        cfg = tmp_path / "incomplete.yaml"
        cfg.write_text("ip_keys: [SourceIP]\n")
        with pytest.raises(ValueError, match="missing required keys"):
            load_analytics_fields(cfg)

    def test_non_mapping_yaml(self, tmp_path):
        cfg = tmp_path / "list.yaml"
        cfg.write_text("- item1\n- item2\n")
        with pytest.raises(ValueError, match="must be a mapping"):
            load_analytics_fields(cfg)

    def test_hostname_keys_optional_defaults_empty(self, tmp_path):
        cfg = tmp_path / "fields.yaml"
        cfg.write_text(
            """
ip_keys: [SourceIP]
hash_keys: [Hashes]
image_keys: [Image]
domain_keys: [TargetDomainName]
cmdline_keys: [CommandLine]
user_keys: [SubjectUserName]
noise_users: [SYSTEM]
cmdline_exts: [.ps1]
"""
        )
        result = load_analytics_fields(cfg)
        assert result.hostname_keys == frozenset()

    def test_hostname_keys_parsed(self, tmp_path):
        cfg = tmp_path / "fields.yaml"
        cfg.write_text(
            """
ip_keys: [SourceIP]
hash_keys: [Hashes]
image_keys: [Image]
domain_keys: [TargetDomainName]
cmdline_keys: [CommandLine]
user_keys: [SubjectUserName]
noise_users: [SYSTEM]
cmdline_exts: [.ps1]
hostname_keys: [hostname, node]
"""
        )
        result = load_analytics_fields(cfg)
        assert result.hostname_keys == frozenset({"hostname", "node"})


class TestShippedConfig:
    """Guards over config/analytics_fields.yaml — Linux/auditd coverage."""

    def test_shipped_config_linux_fields(self):
        cfg = load_analytics_fields()
        assert {"hostname", "node", "_HOSTNAME"} <= cfg.hostname_keys
        assert {"auid", "uid"} <= cfg.user_keys
        assert "a0" in cfg.image_keys
        assert "name" in cfg.cmdline_keys
        assert "unset" in cfg.noise_users
