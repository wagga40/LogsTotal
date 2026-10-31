from __future__ import annotations

import time
from pathlib import Path

import yaml

from app.json_utils import dumps as json_dumps
from app.json_utils import loads as json_loads
from app.tools.base import ToolAdapter, ToolOutput
from app.tools.catalog import TOOLS
from app.tools.mapping import MetadataMapping, OutputMapping, Selector, list_tags
from app.yaml_utils import safe_load as yaml_safe_load


class ChopChopGoAdapter(ToolAdapter):
    """
    Adapter for ChopChopGo (https://github.com/M00NLIG7/ChopChopGo) —
    Sigma detection over Linux syslog, auditd and journald logs.

    ChopChopGo writes matches to **stdout** (one JSON object per matched
    event, no output-file flag), so this adapter overrides
    ``_execute_and_parse`` to capture stdout and persist the JSON payload as
    the expected output file — job analytics re-reads matched events from it.

    The per-event output carries no severity; ``normalize`` recovers the Sigma
    ``level`` by looking the rule id up in ``rules_path`` (a directory of
    native Sigma YAML rules).
    """

    name = "chopchopgo"
    output_mapping = OutputMapping(
        finding=MetadataMapping(
            rule_name=Selector((("Title",),), default="Unknown Rule", transforms=(str,)),
            rule_id=Selector((("ID",),), default="", transforms=(str,)),
            tags=Selector((("Tags",),), default=[], transforms=(list_tags,)),
        ),
        raw_overrides={
            "rule_name": Selector((("Title",),), default="", fallback="missing"),
            "rule_id": Selector((("ID",),), default="", fallback="missing"),
            "tags": Selector(default=[]),
        },
        rule_metadata=lambda adapter, rule_id: adapter._rule_severity(rule_id),
    )

    # journald is NOT supported: ChopChopGo's journald target reads the live systemd
    # journal via the sd-journal API and rejects -file, so it cannot analyze an
    # uploaded journal export. Journald uploads are routed to Zircolite (-j) instead.
    SUPPORTED_TYPES = TOOLS["chopchopgo"].supported_types

    def _target(self) -> str:
        """ChopChopGo -target value: explicit config wins, else the log type."""
        configured = self.config.get("target")
        if configured:
            return str(configured)
        if self._log_type in self.SUPPORTED_TYPES:
            return str(self._log_type)
        return "syslog"

    # ── subclass hooks ───────────────────────────────────────────────────

    def _build_local_cmd(
        self,
        tool_path: Path,
        file_path: Path,
        output_file: Path,
    ) -> tuple[list[str] | None, str]:
        err = self._check_binary_executable(tool_path)
        if err:
            return None, err

        abs_rules = Path(self.rules_path).resolve()
        if not abs_rules.exists():
            return None, f"Rules path not found: {abs_rules}"

        cmd = [
            str(tool_path),
            "-target",
            self._target(),
            "-rules",
            str(abs_rules),
            "-file",
            str(file_path),
            "-out",
            "json",
        ]
        mapping = self.config.get("mapping_path") or self._default_mapping(tool_path)
        if mapping:
            cmd.extend(["-mapping", str(mapping)])
        cmd.extend(self._extra_args)
        return cmd, ""

    def _default_mapping(self, tool_path: Path) -> Path | None:
        """The release ships per-target field mappings beside the binary; ChopChopGo's
        own fallback resolves them relative to CWD, so pass the path explicitly."""
        candidate = tool_path.parent / "mappings" / f"{self._target()}.yml"
        return candidate if candidate.exists() else None

    def _execute_and_parse(self, cmd: list[str], output_file: Path) -> ToolOutput:
        t0 = time.monotonic()
        rc, stdout, stderr = self._exec(cmd, timeout=self._timeout_seconds, cancel_event=self._cancel_event)
        duration_ms = int((time.monotonic() - t0) * 1000)

        events = self._extract_json_events(stdout)
        cancelled = self._cancel_event is not None and self._cancel_event.is_set()
        if rc != 0 and (cancelled or not events):
            return ToolOutput(
                success=False,
                error=stderr or stdout or (f"Command timed out after {self._timeout_seconds}s" if rc == -1 else f"Exit code {rc}"),
                stdout=stdout,
                stderr=stderr,
                duration_ms=duration_ms,
            )

        if rc != 0:
            self._diagnostics.incomplete("The engine exited before completing its analysis.")
        if events is None:
            return ToolOutput(success=False, error="Missing or invalid ChopChopGo JSON output", stdout=stdout, stderr=stderr, duration_ms=duration_ms)

        try:
            output_file.write_text(json_dumps(events), encoding="utf-8")
            # ChopChopGo prints no counters. It writes one JSON array after the last
            # event, so a whole array on a zero exit is the evidence that it finished.
            return self._parse_output(output_file, stdout, stderr, duration_ms, finished=rc == 0)
        except Exception as exc:
            return ToolOutput(
                success=False,
                error=f"Failed to parse output: {exc}",
                stdout=stdout,
                stderr=stderr,
                duration_ms=duration_ms,
            )

    @staticmethod
    def _extract_json_events(stdout: str) -> list | None:
        """Pull the JSON result array out of stdout, tolerating banner noise."""
        text = stdout.strip()
        if not text:
            return None
        for candidate in (text, text[text.find("[") : text.rfind("]") + 1] if "[" in text else ""):
            if not candidate:
                continue
            try:
                parsed = json_loads(candidate)
            except ValueError:
                continue
            # Go encodes the nil result slice as null when no rule matches.
            if parsed is None:
                return []
            if isinstance(parsed, list):
                return parsed
        return None

    def _rule_severity(self, rule_id: str) -> tuple[str, str]:
        """Return (normalized severity, rule YAML text) for a Sigma rule id."""
        rule_yaml = self._lookup_rule_yaml(rule_id)
        if not rule_yaml:
            return "informational", ""
        try:
            data = yaml_safe_load(rule_yaml)
            level = data.get("level", "informational") if isinstance(data, dict) else "informational"
        except yaml.YAMLError:
            return "informational", rule_yaml
        return self._normalize_severity(str(level)), rule_yaml
