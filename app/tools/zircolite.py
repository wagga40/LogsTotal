from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from app.tools.base import NormalizedFinding, ToolAdapter

_log = logging.getLogger(__name__)


class ZircoliteAdapter(ToolAdapter):
    """
    Adapter for Zircolite (https://github.com/wagga40/Zircolite).

    Execution modes (set in workflow YAML):

    - **docker_image** — use a pre-built image (e.g. ``wagga40/zircolite:latest``).
    - **dockerfile** — build from a Dockerfile.  Optional:
      ``docker_build_context``, ``docker_build_tag`` (default:
      ``logstotal-zircolite:local``).
    - **tool_path** — run the Python script directly
      (``python3 <tool_path> …``).

    ``rules_path`` can be a compiled JSON ruleset file **or** a directory
    of native Sigma YAML rules.
    """

    name = "zircolite"

    SUPPORTED_TYPES = {"evtx", "json_evtx", "json_winlogbeat", "xml_evtx", "auditd", "sysmon_linux", "journald"}

    # log_type → Zircolite input-format flag aliases; the first alias is emitted,
    # the rest are recognised for dedupe when a workflow sets them via extra_args.
    #
    # Every SUPPORTED_TYPE except plain EVTX gets an entry, so the input format is always
    # stated rather than inferred.
    #
    # Zircolite *does* sniff the format (verified against wagga40/zircolite:latest: events
    # parsed are identical with and without the explicit flag — auditd 35/35, sysmon_linux
    # 5/5, json_winlogbeat 2/2, json_evtx 4/4). These flags are belt-and-braces, not the
    # thing that makes parsing work. They are kept because the sniffing is a heuristic with
    # documented opt-outs (`--no-auto-mode`, `--no-auto-detect`), older pinned images lack
    # it, and the failure
    # mode when it does misfire is silent: the wrong parser yields zero events, and the job
    # reports "0 findings" — which reads as *clean* rather than *not analysed*.
    # `_JSON_INPUT` is shared by the three JSON-shaped types; a test iterates
    # SUPPORTED_TYPES against this map so a newly supported type cannot be forgotten.
    _JSON_INPUT: tuple[str, ...] = ("-j", "--json-input", "--jsononly", "--jsonline", "--jsonl")

    # Windows event XML comes in two shapes, and Zircolite reads them with *different*,
    # mutually exclusive flags — measured against wagga40/zircolite:latest on a 4-event
    # sample:
    #
    #                                     -x        --evtxtract-input
    #   rootless (repeated <Event>)       1/4              4/4
    #   rooted   (<?xml?><Events>…)       4/4              0/4
    #
    # Both flags are correct; each for the shape the other cannot read. `wevtutil qe
    # /f:xml` emits the rootless form, `Get-WinEvent | ToXml` wrapped by hand emits the
    # rooted one, and both are common in the wild. Picking one statically would silently
    # parse a fraction of every file of the other shape and report the resulting count as
    # a complete analysis — the precise failure this adapter's other flags exist to
    # prevent. So the shape is sniffed from the file, not assumed from the log type.
    _XML_ROOTED_FLAGS: tuple[str, ...] = ("-x", "--xml-input", "--xml")
    _XML_ROOTLESS_FLAGS: tuple[str, ...] = ("--evtxtract-input", "--evtxtract")

    _INPUT_FLAGS: dict[str, tuple[str, ...]] = {
        "auditd": ("-AU", "--auditd-input", "--auditd"),
        "sysmon_linux": ("-S", "--sysmon-linux-input", "--sysmon-linux", "--sysmon4linux"),
        "journald": _JSON_INPUT,
        "json_evtx": _JSON_INPUT,
        "json_winlogbeat": _JSON_INPUT,
        # Placeholder so the "every supported type declares a flag" test passes; the
        # emitted flag is chosen per-file by _input_flags() below.
        "xml_evtx": _XML_ROOTLESS_FLAGS,
    }

    # Zircolite puts every input-format option in one argparse *mutually exclusive* group,
    # so supplying two of them is a hard usage error, not a last-one-wins override:
    #   zircolite.py: error: argument --json-array-input/--jsonarray/--json-array:
    #                 not allowed with argument -j/--json-input/--jsononly/--jsonline/--jsonl
    # A workflow that legitimately sets `--json-array-input` for a JSON *array* export would
    # therefore be broken by us auto-adding `-j`. Dedupe against the whole group rather than
    # just the current type's aliases: any explicit format flag means the author has decided.
    # (Aliases of the *same* option are safe to repeat — only cross-option pairs error — but
    # suppressing on any of them is simpler and strictly safer.)
    _ALL_INPUT_FORMAT_FLAGS: frozenset[str] = frozenset(
        {
            "-j",
            "--json-input",
            "--jsononly",
            "--jsonline",
            "--jsonl",
            "--json-array-input",
            "--jsonarray",
            "--json-array",
            "--db-input",
            "-D",
            "--dbonly",
            "-S",
            "--sysmon-linux-input",
            "--sysmon4linux",
            "--sysmon-linux",
            "-AU",
            "--auditd-input",
            "--auditd",
            "-x",
            "--xml-input",
            "--xml",
            "--evtxtract-input",
            "--evtxtract",
            "--csv-input",
            "--csvonly",
        }
    )

    # The one supported type for which we emit no input-format flag; every other type has an
    # entry in `_INPUT_FLAGS` (see the sniffing note above).
    _NATIVE_TYPE = "evtx"

    def _sniff_xml_shape(self) -> tuple[str, ...]:
        """Which XML flag family this file needs — rooted ``<Events>`` or rootless.

        Reads only the first bytes, and falls back to the rootless family (what
        ``wevtutil qe /f:xml`` produces, and what the shipped sample is) when the file
        cannot be read.
        """
        path = self._input_path
        if path is None:
            return self._XML_ROOTLESS_FLAGS
        try:
            with open(path, "rb") as fh:
                head = fh.read(4096).decode("utf-8", errors="ignore")
        except OSError:
            return self._XML_ROOTLESS_FLAGS
        head = head.lstrip("﻿").lstrip()
        if head.startswith("<?xml"):
            head = head.split("?>", 1)[-1].lstrip()
        # "<Events" (plural) is the wrapper; "<Event " / "<Event>" is a bare record.
        return self._XML_ROOTED_FLAGS if head[:7].lower() == "<events" else self._XML_ROOTLESS_FLAGS

    def _input_flags(self) -> list[str]:
        """Input-format flag for the current log type (EVTX needs none)."""
        aliases = self._INPUT_FLAGS.get(self._log_type or "")
        if self._log_type == "xml_evtx":
            aliases = self._sniff_xml_shape()
        if not aliases:
            return []
        configured = self._extra_args or self.config.get("zircolite_args", [])
        if any(arg in self._ALL_INPUT_FORMAT_FLAGS for arg in configured):
            return []
        return [aliases[0]]

    # ── subclass hooks ───────────────────────────────────────────────────

    def _output_filename(self, file_path: Path) -> str:
        return f"{file_path.stem}_zircolite.json"

    def _config_flags(self, rules_dir: str) -> list[str]:
        """``-c <config>`` for the workflow's ``options.config``, resolved beside the rules.

        The value is a bare *filename*, never a path, and is looked up in ``rules_dir``.
        That is deliberate and load-bearing: the base runner bind-mounts exactly one rules
        directory at ``/rules``, so a sibling file is the only extra input reachable in
        Docker without a second mount — and resolving it relative to the rules means the
        same YAML works for both the local and the containerised command, which a literal
        path in ``extra_args`` could not.

        **``rules_dir`` is a directory, not the rules ref.** Taking the ref's parent with
        ``rsplit('/', 1)`` is only correct when ``rules_path`` names a *file*, as the
        journald workflow's does; with a directory ``rules_path`` — what every other shipped
        workflow uses — it walks one level too far up locally, and yields the filesystem
        root under Docker (``/rules`` rsplits to the empty string).

        Used by the journald workflow, where the config supplies the field aliases that let
        a SIGMA ruleset written for sysmon/auditd field names match journald's.
        """
        name = (self.config.get("options") or {}).get("config")
        if not name:
            return []
        name = str(name).strip()
        # A bare filename only — a path would escape the mounted directory.
        if not name or "/" in name or "\\" in name or name in (".", ".."):
            return []
        if any(flag in self._extra_args for flag in ("-c", "--config")):
            return []  # workflow set it explicitly; don't pass it twice
        return ["-c", f"{rules_dir.rstrip('/')}/{name}"]

    def _build_local_cmd(
        self,
        tool_path: Path,
        file_path: Path,
        output_file: Path,
    ) -> tuple[list[str] | None, str]:
        if not tool_path.exists():
            return None, f"Zircolite script not found: {tool_path}"

        abs_rules = Path(self.rules_path).resolve()
        if not abs_rules.exists():
            return None, f"Rules path not found: {abs_rules}"

        cmd = [
            "python3",
            str(tool_path),
            "-e",
            str(file_path),
            "-r",
            str(abs_rules),
            "-o",
            str(output_file),
        ]
        cmd.extend(self._input_flags())
        cmd.extend(self._config_flags(str(abs_rules.parent if abs_rules.is_file() else abs_rules)))
        cmd.extend(self._extra_args or self.config.get("zircolite_args", []))
        return cmd, ""

    def _docker_tool_args(
        self,
        container_log: str,
        container_rules: str,
        container_out: str,
    ) -> list[str]:
        args = [
            "-e",
            container_log,
            "-r",
            container_rules,
            "-o",
            container_out,
        ]
        args.extend(self._input_flags())
        # Always the mount point, never `container_rules`: the runner binds one directory
        # at /rules whether `rules_path` names a file or a directory, so the sibling config
        # is at /rules/<name> in both cases.
        args.extend(self._config_flags(self._CONTAINER_RULES))
        args.extend(self._extra_args or self.config.get("zircolite_args", []))
        return args

    # ── normalize ────────────────────────────────────────────────────────

    def normalize(self, raw: Any) -> list[NormalizedFinding]:
        """
        Zircolite output format: list of objects with
        title, id, description, sigmafile, sigma, rule_level, tags, count, matches.
        Severity is in rule_level (e.g. "high"); matches holds sample events.
        """
        findings = []
        skipped = 0
        for item in self._dict_records(raw):
            try:
                matches = item.get("matches") or []
                if not isinstance(matches, list):
                    matches = []
                severity_raw = item.get("rule_level") or item.get("level", "informational")

                sigma_list = item.get("sigma", [])
                rule_content = ""
                if isinstance(sigma_list, list) and sigma_list:
                    rule_content = sigma_list[0] if len(sigma_list) == 1 else "\n---\n".join(str(s) for s in sigma_list)
                elif isinstance(sigma_list, str) and sigma_list:
                    rule_content = sigma_list

                count = item.get("count", len(matches))
                if not isinstance(count, int):
                    count = len(matches)

                tags = item.get("tags") or []
                if not isinstance(tags, list):
                    tags = [str(tags)]

                findings.append(
                    NormalizedFinding(
                        rule_name=str(item.get("title") or "Unknown Rule"),
                        severity=self._normalize_severity(severity_raw),
                        count=count,
                        rule_id=str(item.get("id") or ""),
                        tags=tags,
                        details=matches[: self.max_details],
                        rule_content=rule_content,
                    )
                )
            except Exception:
                # Per-record isolation — see the same guard in the Hayabusa adapter.
                skipped += 1

        if skipped:
            _log.warning("zircolite: skipped %d unparseable rule block(s)", skipped)
        return findings
