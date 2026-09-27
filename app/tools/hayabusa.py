from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from app.tools.base import NormalizedFinding, ToolAdapter

_log = logging.getLogger(__name__)

# Hayabusa's own `-m/--min-level` vocabulary, which happens to coincide with LogsTotal's
# severities but is not the same list — it names the levels of the *rules loaded*, not of
# the findings produced. `MIN_LEVEL_FLAGS` is the dedupe set: `_core_args` appends
# `extra_args` verbatim, so a workflow that already passes the flag there must not get a
# second copy from `options` (the `-AU`/`-S`/`-j` rule in zircolite.py).
MIN_LEVELS = frozenset({"informational", "low", "medium", "high", "critical"})
MIN_LEVEL_FLAGS = ("-m", "--min-level")


class HayabusaAdapter(ToolAdapter):
    """
    Adapter for Hayabusa (https://github.com/Yamato-Security/hayabusa).

    Execution modes (set in workflow YAML):

    - **tool_path** — local binary
      (``hayabusa dfir-timeline --output-type jsonl -f <file> …``). Requires Hayabusa 4.
      This is what every shipped
      workflow uses; the binaries are vendored under ``tools/hayabusa/``.
    - **docker_image** / **dockerfile** — run inside a Docker container.  Upstream
      publishes no official image, so this means one you build yourself; it works
      because :meth:`_core_args` is shared with the local path and takes its log,
      output and rules as *refs*, so the Docker override simply passes
      container-side paths.  Contrast :mod:`app.tools.chainsaw`, which needs more
      paths mounted than the base runner binds and so stays local-only.

    Extra config (nested under ``options``):

    - ``min_level`` — the lowest rule level to load, one of :data:`MIN_LEVELS`. Omit it to
      take Hayabusa's own default (``informational``, i.e. every rule).
    """

    name = "hayabusa"

    SUPPORTED_TYPES = {"evtx"}

    # ── subclass hooks ───────────────────────────────────────────────────

    def _output_filename(self, file_path: Path) -> str:
        return f"{file_path.stem}_hayabusa.json"

    def _core_args(
        self,
        log_ref: str,
        output_ref: str,
        rules_ref: str,
    ) -> list[str]:
        """Hayabusa CLI flags shared between local and Docker modes."""
        args = [
            "dfir-timeline",
            "-f",
            log_ref,
            "-o",
            output_ref,
            "-r",
            rules_ref,
            "-q",
            "--no-wizard",
            "--output-type",
            "jsonl",
            "-p",
            "super-verbose",
            "-K",
        ]
        # In v4, -t selects the output format. Only the long flag sets threads.
        args += ["--threads", str(self._threads)]
        args += self._min_level_args()
        args.extend(self._extra_args)
        return args

    def _min_level_args(self) -> list[str]:
        """``options.min_level`` → ``-m <level>``, or nothing.

        An unrecognised level is dropped with a warning rather than passed through:
        Hayabusa exits non-zero on a bad ``-m``, so a typo in an optional knob would fail
        the whole task instead of the run it was meant to narrow.
        """
        options = self.config.get("options") or {}
        level = str(options.get("min_level") or "").strip().lower()
        if not level:
            return []
        if any(flag in self._extra_args for flag in MIN_LEVEL_FLAGS):
            return []
        if level not in MIN_LEVELS:
            _log.warning("hayabusa: ignoring unknown min_level %r (expected one of %s)", level, ", ".join(sorted(MIN_LEVELS)))
            return []
        return ["-m", level]

    def _build_local_cmd(
        self,
        tool_path: Path,
        file_path: Path,
        output_file: Path,
    ) -> tuple[list[str] | None, str]:
        if err := self._check_binary_executable(tool_path):
            return None, err

        rules_path = Path(self.rules_path)
        cmd = [
            str(tool_path),
            *self._core_args(str(file_path), str(output_file), str(rules_path)),
        ]
        return cmd, ""

    def _docker_tool_args(
        self,
        container_log: str,
        container_rules: str,
        container_out: str,
    ) -> list[str]:
        return self._core_args(container_log, container_out, container_rules)

    def _load_output(self, path: Path) -> Any:
        return self._load_jsonl(path)

    # ── normalize ────────────────────────────────────────────────────────

    def normalize(self, raw: Any) -> list[NormalizedFinding]:
        """
        Hayabusa NDJSON format per event:
        {"Timestamp": "…", "Level": "high", "RuleTitle": "…",
         "RuleID": "…", "MitreTags": "T1234", "Details": {…}}

        Group by RuleTitle to aggregate.
        """
        grouped: dict[str, NormalizedFinding] = {}
        skipped = 0

        for event in self._dict_records(raw):
            try:
                rule_name = str(event.get("RuleTitle") or event.get("Channel") or "Unknown Rule")
                level = self._normalize_severity(event.get("Level", "informational"))
                rule_id = str(event.get("RuleID") or event.get("RuleFile") or "")
                mitre = event.get("MitreTags", "")
                if isinstance(mitre, list):
                    tags = [str(t).strip() for t in mitre if t]
                elif mitre:
                    tags = [t.strip() for t in str(mitre).split(",") if t.strip()]
                else:
                    tags = []

                if rule_name not in grouped:
                    grouped[rule_name] = NormalizedFinding(
                        rule_name=rule_name,
                        severity=level,
                        count=0,
                        rule_id=rule_id,
                        tags=tags,
                        details=[],
                        rule_content=self._lookup_rule_yaml(rule_id) if rule_id else "",
                    )

                entry = grouped[rule_name]
                entry.count += 1
                if len(entry.details) < self.max_details:
                    entry.details.append(
                        {
                            "Timestamp": event.get("Timestamp"),
                            "Computer": event.get("Computer"),
                            "EventID": event.get("EventID"),
                            "Details": event.get("Details"),
                        }
                    )
            except Exception:
                # Per-record isolation: one unexpected shape must not discard the rest of
                # the file. `run()` catches around all of `normalize()`, so an escape here
                # is reported as "0 findings".
                skipped += 1

        if skipped:
            _log.warning("hayabusa: skipped %d unparseable event(s)", skipped)
        return list(grouped.values())
