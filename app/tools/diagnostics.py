"""Completion evidence shared by adapters and persisted with their findings."""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass, field
from typing import Literal


@dataclass
class CompletionDiagnostics:
    completion: Literal["complete", "incomplete", "unknown"] = "unknown"
    processed_events: int | None = None
    rules_loaded: int | None = None
    rules_skipped: int | None = None
    records_skipped: int = 0
    warnings: list[str] = field(default_factory=list)

    def incomplete(self, message: str) -> None:
        self.completion = "incomplete"
        if message not in self.warnings:
            self.warnings.append(message)

    def skip_record(self) -> None:
        self.records_skipped += 1
        self.incomplete("Some detection records could not be read.")

    def as_dict(self) -> dict:
        return {"schema_version": 1, **asdict(self)}

    def read_summary(self, tool: str, output: str) -> None:
        """Extract only known engine counters; absent evidence stays unknown."""
        output = re.sub(r"\x1b\[[0-9;]*[A-Za-z]", "", output)
        patterns = {
            "zircolite": (r"Total events processed: ([\d,]+)", r"(\d[\d,]*) rules loaded"),
            "hayabusa": (r"Events with hits\s*/\s*Total events:\s*[\d,]+\s*/\s*([\d,]+)", r"Total detection rules:\s*([\d,]+)"),
            "chainsaw": (None, r"Loaded ([\d,]+) detection rules"),
        }
        events, rules = patterns.get(tool, (None, None))
        for name, pattern in (("processed_events", events), ("rules_loaded", rules)):
            match = re.search(pattern, output, re.I) if pattern else None
            if match:
                setattr(self, name, int(match[1].replace(",", "")))
        if tool == "chainsaw" and (skipped := re.search(r"\(([\d,]+) not loaded\)", output)):
            self.rules_skipped = int(skipped[1].replace(",", ""))
            if self.rules_skipped:
                self.incomplete("Some detection rules could not be loaded.")
        if self.rules_loaded == 0:
            self.incomplete("The engine loaded no detection rules.")
        # Do not expose raw diagnostics: engine messages may contain event data
        # or local paths. Known error prefixes become a fixed public warning.
        if re.search(r"(?im)^\s*(?:\[error\]|\[warning\]|error:|warning:|failed to (?:parse|load|read))", output):
            self.incomplete("The engine reported errors or warnings; coverage may be incomplete.")
