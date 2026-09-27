from __future__ import annotations

import logging
import time
from pathlib import Path
from typing import Any

import yaml

from app.json_utils import dumps as json_dumps
from app.json_utils import loads as json_loads
from app.tools.base import NormalizedFinding, ToolAdapter, ToolOutput
from app.yaml_utils import safe_load as yaml_safe_load

_log = logging.getLogger(__name__)


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

    # journald is NOT supported: ChopChopGo's journald target reads the live systemd
    # journal via the sd-journal API and rejects -file, so it cannot analyze an
    # uploaded journal export. Journald uploads are routed to Zircolite (-j) instead.
    SUPPORTED_TYPES = {"auditd", "syslog"}

    def _target(self) -> str:
        """ChopChopGo -target value: explicit config wins, else the log type."""
        configured = self.config.get("target")
        if configured:
            return str(configured)
        if self._log_type in self.SUPPORTED_TYPES:
            return str(self._log_type)
        return "syslog"

    # ── subclass hooks ───────────────────────────────────────────────────

    def _output_filename(self, file_path: Path) -> str:
        return f"{file_path.stem}_chopchopgo.json"

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

        if rc != 0:
            return ToolOutput(
                success=False,
                error=stderr or stdout or (f"Command timed out after {self._timeout_seconds}s" if rc == -1 else f"Exit code {rc}"),
                stdout=stdout,
                stderr=stderr,
                duration_ms=duration_ms,
            )

        events = self._extract_json_events(stdout)
        if events is None:
            return ToolOutput(success=True, findings=[], stdout=stdout, stderr=stderr, duration_ms=duration_ms)

        try:
            output_file.write_text(json_dumps(events), encoding="utf-8")
            findings = self.normalize(events)
            return ToolOutput(success=True, findings=findings, stdout=stdout, stderr=stderr, duration_ms=duration_ms)
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
            if isinstance(parsed, list):
                return parsed
        return None

    # ── normalize ────────────────────────────────────────────────────────

    def normalize(self, raw: Any) -> list[NormalizedFinding]:
        """
        ChopChopGo JSON output: a list of per-matched-event objects
        ``{Timestamp, Message, User, Exe, Terminal, PID, Tags, Author, ID, Title}``.
        Group events by rule title; severity comes from the Sigma rule YAML.
        """
        grouped: dict[str, NormalizedFinding] = {}
        severity_cache: dict[str, tuple[str, str]] = {}
        skipped = 0

        for event in self._dict_records(raw):
            try:
                title = str(event.get("Title") or "Unknown Rule")
                rule_id = str(event.get("ID") or "")

                finding = grouped.get(title)
                if finding is None:
                    severity, rule_content = severity_cache.get(rule_id) or self._rule_severity(rule_id)
                    severity_cache[rule_id] = (severity, rule_content)
                    tags = event.get("Tags") or []
                    finding = NormalizedFinding(
                        rule_name=title,
                        severity=severity,
                        count=0,
                        rule_id=rule_id,
                        tags=tags if isinstance(tags, list) else [str(tags)],
                        rule_content=rule_content,
                    )
                    grouped[title] = finding

                finding.count += 1
                if len(finding.details) < self.max_details:
                    finding.details.append(event)
            except Exception:
                # Per-record isolation — see the same guard in the Hayabusa adapter.
                skipped += 1

        if skipped:
            _log.warning("chopchopgo: skipped %d unparseable event(s)", skipped)
        return list(grouped.values())

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
