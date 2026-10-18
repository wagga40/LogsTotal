"""RSigma batch evaluation with full evidence and explicit completion checks."""

from __future__ import annotations

import os
import re
import tempfile
import time
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

import yaml

from app.json_utils import dumps, loads
from app.tools.base import ToolAdapter, ToolOutput
from app.tools.catalog import TOOLS
from app.tools.mapping import MetadataMapping, OutputMapping, Selector, decode_records, file_records
from app.tools.output import RawMatch
from app.tools.rsigma_windows import CATEGORIES, SERVICES, input_filter, normalize_event
from app.yaml_utils import safe_load

_TOOL_DIR = Path(__file__).resolve().parents[2] / "tools" / "rsigma"
_SUMMARY = re.compile(r"Processed (\d+) (?:EVTX records|events), (\d+) matches\.")
_ERRORS = re.compile(r"(?im)^\s*(?:error\b|warning\b|failed\b|invalid\b|jq .*error\b)")
_RESERVED = frozenset(
    {
        "--dry-run",
        "--no-detections",
        "--fail-on-detection",
        "--pretty",
        "--quiet",
        "-q",
        "--no-stats",
        "--config",
        "--jq",
        "--jsonpath",
        "--event",
        "-e",
        "--rules",
        "-r",
        "--output-format",
        "--input-format",
        "--include-event",
    }
)


def _validate_detection(record: Any) -> None:
    if not isinstance(record, dict) or "correlation_type" in record or not isinstance(record.get("event"), dict) or not record.get("rule_title"):
        raise ValueError("Invalid RSigma detection record (correlation output is not supported)")
    tags = record.get("tags") or []
    if not isinstance(tags, list) or any(not isinstance(tag, str) for tag in tags):
        raise ValueError("Invalid RSigma detection tags")


class RsigmaAdapter(ToolAdapter):
    name = "rsigma"
    output_mapping = OutputMapping(
        finding=MetadataMapping(
            rule_name=Selector((("rule_title",),), transforms=(str,)),
            rule_id=Selector((("rule_id",),), default="", transforms=(str,)),
            severity=Selector((("level",),), fallback="missing"),
            tags=Selector((("tags",),), default=[]),
        ),
        format="jsonl",
        events=Selector((("event",),), fallback="missing", transforms=(lambda event: [event],)),
        event_transform=normalize_event,
        timestamp=lambda event: event.get("Timestamp"),
        validate=_validate_detection,
        strict=True,
        iterable_input=True,
        grouping="identity",
        lookup_empty_id=True,
    )
    SUPPORTED_TYPES = TOOLS["rsigma"].supported_types

    def __init__(self, config: dict[str, Any]):
        super().__init__(config)
        self._deadline: float | None = None
        if len(self.rules_paths) != 1:
            raise ValueError("rsigma requires a single rules_path")
        if config.get("docker_image") or config.get("dockerfile"):
            raise ValueError("rsigma supports local binaries only")
        if self._threads != 1:
            raise ValueError("rsigma eval is single-threaded; omit threads or set threads: 1")
        if any(arg.split("=")[0] in _RESERVED for arg in self._extra_args):
            raise ValueError("rsigma extra_args cannot override input, output, or completion flags")

    def _build_local_cmd(self, tool_path: Path, file_path: Path, output_file: Path):
        if error := self._check_binary_executable(tool_path):
            return None, error
        if not Path(self.rules_path).exists():
            return None, f"Rules path not found: {self.rules_path}"
        mapping = Path(self.config.get("mapping_path") or _TOOL_DIR / "mappings/windows.yml")
        if not mapping.is_file():
            return None, f"RSigma mapping not found: {mapping}"
        return [
            str(tool_path),
            "engine",
            "eval",
            "--config",
            str(_TOOL_DIR / "config/rsigma.yml"),
            "--rules",
            str(Path(self.rules_path).resolve()),
            "--event",
            "@" + str(file_path.resolve()),
            "--input-format",
            "json",
            "--output-format",
            "ndjson",
            "--color",
            "never",
            "--include-event",
            "--pipeline",
            str(mapping.resolve()),
            "--jq",
            input_filter(self._log_type or "evtx"),
            *self._extra_args,
        ], ""

    def _check_budget(self, deadline: float) -> None:
        if self._cancel_event is not None and self._cancel_event.is_set():
            raise ValueError("cancelled")
        if time.monotonic() >= deadline:
            raise ValueError("Command timed out during RSigma evaluation")

    def _validate_rules(self, deadline: float) -> None:
        root = Path(self.rules_path)
        paths = root.rglob("*") if root.is_dir() else [root]
        for path in paths:
            self._check_budget(deadline)
            if not path.is_file() or path.suffix.lower() not in {".yml", ".yaml"}:
                continue
            rule = safe_load(path.read_text(encoding="utf-8"))
            if not isinstance(rule, dict) or "correlation" in rule or "filter" in rule:
                raise ValueError(f"RSigma requires detection rules: {path}")
            source = rule.get("logsource") or {}
            if not isinstance(source, dict):
                raise ValueError(f"Invalid rule logsource: {path}")
            category, service = source.get("category"), source.get("service")
            if (category and category not in CATEGORIES) or (service and service not in SERVICES) or source.get("product") != "windows":
                raise ValueError(f"Unsupported Windows logsource in {path}: {source}")

    @contextmanager
    def _prepared_input(self, file_path: Path, deadline: float) -> Iterator[Path]:
        """Strip a JSON BOM for both validation and the CLI, leaving evidence intact."""
        if self._log_type == "evtx":
            yield file_path
            return
        with file_path.open("rb") as source:
            if source.read(3) != b"\xef\xbb\xbf":
                yield file_path
                return
            with tempfile.TemporaryDirectory(prefix="logstotal-rsigma-") as temp_dir:
                prepared = Path(temp_dir) / file_path.name
                with prepared.open("wb") as dest:
                    while chunk := source.read(1024 * 1024):
                        self._check_budget(deadline)
                        dest.write(chunk)
                yield prepared

    def _run_local(self, file_path: Path, output_file: Path) -> ToolOutput:
        # Upstream can skip malformed JSON lines and exit zero. Audit the stream
        # and its rule logsource mappings within the same timeout/cancellation budget.
        start = time.monotonic()
        deadline = start + self._timeout_seconds
        try:
            self._validate_rules(deadline)
            with self._prepared_input(file_path, deadline) as prepared:
                if self._log_type != "evtx":
                    with prepared.open("rb") as stream:
                        for line_no, line in enumerate(stream, 1):
                            self._check_budget(deadline)
                            if not line.strip():
                                continue
                            if not isinstance(loads(line), dict):
                                raise ValueError(f"line {line_no} is not an event object")
                self._check_budget(deadline)
                self._deadline = deadline
                result = super()._run_local(prepared, output_file)
                result.duration_ms = int((time.monotonic() - start) * 1000)
                return result
        except (OSError, ValueError, yaml.YAMLError) as exc:
            error = str(exc) if str(exc) == "cancelled" else f"Invalid RSigma input or rules: {exc}"
            return ToolOutput(success=False, error=error, duration_ms=int((time.monotonic() - start) * 1000))
        finally:
            self._deadline = None

    def _execute_and_parse(self, cmd: list[str], output_file: Path) -> ToolOutput:
        start = time.monotonic()
        deadline = self._deadline if self._deadline is not None else start + self._timeout_seconds
        partial = output_file.with_suffix(output_file.suffix + ".partial")
        stderr = ""
        try:
            self._check_budget(deadline)
            rc, _, stderr = self._exec(
                cmd,
                timeout=max(0.01, deadline - time.monotonic()),
                cancel_event=self._cancel_event,
                stdout_path=partial,
                env={key: value for key, value in os.environ.items() if not key.startswith("RSIGMA_")},
            )
            self._check_budget(deadline)
            if rc != 0:
                self._diagnostics.incomplete("The engine exited before completing its analysis.")
            if _ERRORS.search(stderr):
                self._diagnostics.incomplete("The engine reported skipped or invalid input or rules.")

            # Publish only validated NDJSON. Analytics must see exactly the usable
            # evidence retained here, even when the original stream is truncated.
            clean = partial.with_suffix(".validated")

            def checked_records():
                with clean.open("w", encoding="utf-8") as stream:
                    for record in file_records(partial, format="jsonl", diagnostics=self._diagnostics):
                        self._check_budget(deadline)
                        try:
                            self._match(record)
                            if not isinstance(record.get("rule_id", ""), str) or not isinstance(record["rule_title"], str):
                                raise ValueError("Invalid rule identity")
                        except (ValueError, TypeError, KeyError, AttributeError):
                            self._diagnostics.skip_record()
                            continue
                        stream.write(dumps(record) + "\n")
                        yield record

            findings = self.normalize(checked_records())
            summary = _SUMMARY.search(stderr)
            if summary is not None:
                self._diagnostics.processed_events = int(summary[1])
            if summary is None or int(summary[2]) != sum(f.count for f in findings):
                self._diagnostics.incomplete("The completion summary is missing or disagrees with the detections.")
            loaded = re.search(r"Loaded (\d+) rules\b", stderr)
            if loaded:
                self._diagnostics.rules_loaded = int(loaded[1])
                if int(loaded[1]) == 0:
                    self._diagnostics.incomplete("The engine loaded no detection rules.")
            if self._diagnostics.completion == "incomplete" and not findings:
                raise ValueError("RSigma did not complete its analysis and returned no usable detections")
            if self._diagnostics.completion != "incomplete":
                self._diagnostics.completion = "complete"
            self._check_budget(deadline)
            clean.replace(output_file)
            return ToolOutput(success=True, findings=findings, stderr=stderr, duration_ms=int((time.monotonic() - start) * 1000), diagnostics=self._diagnostics)
        except (OSError, ValueError) as exc:
            return ToolOutput(success=False, error=str(exc), stderr=stderr, duration_ms=int((time.monotonic() - start) * 1000), diagnostics=self._diagnostics)

    @staticmethod
    def _records(path: Path) -> Iterator[dict]:
        return file_records(path, format="jsonl", strict=True)

    @staticmethod
    def _match(record: Any) -> RawMatch:
        detection = next(decode_records([record], RsigmaAdapter.output_mapping, purpose="raw"))
        event = detection.events[0]
        return RawMatch(event, detection.rule_name, detection.rule_id, detection.severity, detection.tags, event.get("Timestamp"))
