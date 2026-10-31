"""Completion evidence shared by adapters and persisted with their findings."""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass, field
from typing import Literal


def reported_engine_version(tool: str, output: str) -> str | None:
    """Read a known startup banner, never a rule title or an image tag."""
    if tool != "zircolite":
        return None
    # Only inspect startup output, before event data and detection summaries.
    startup = re.sub(r"\x1b\[[0-9;]*[A-Za-z]", "", output[:2048])
    match = re.search(
        r"(?m)^[ \t]*-= Standalone Sigma Detection tool for EVTX/Auditd/Sysmon Linux =-[ \t]*\r?\n"
        r"[ \t]*v(\d+\.\d+\.\d+)[ \t]*\r?$",
        startup,
    )
    return match[1] if match else None


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

    def failure(self) -> str:
        """The error for an incomplete run that left nothing usable behind."""
        return "Incomplete analysis with no usable detections: " + " ".join(self.warnings)

    def read_summary(self, tool: str, output: str) -> bool:
        """Extract only known engine counters; absent evidence stays unknown.

        Returns whether the engine printed its end-of-run summary — the evidence that it
        finished the analysis, which a zero exit code alone is not.
        """
        output = re.sub(r"\x1b\[[0-9;]*[A-Za-z]", "", output)
        if tool == "chopchopgo":
            # This unconditional CLI startup warning concerns live-system access.
            # Uploaded files are checked by the process; a read failure exits nonzero.
            output = output.replace("Warning: not running as superuser - some accesses might fail!", "")
        # (events processed, rules loaded, end-of-run summary), as each pinned CLI prints them.
        patterns = {
            "zircolite": (r"Total events processed: ([\d,]+)", r"(\d[\d,]*) rules loaded", r"Detections\s+(?:None|[\d,]+ )"),
            "hayabusa": (r"Events with hits\s*/\s*Total events:\s*[\d,]+\s*/\s*([\d,]+)", r"Total detection rules:\s*([\d,]+)", r"Events with hits\s*/\s*Total events:"),
            "chainsaw": (None, r"Loaded ([\d,]+) detection rules", r"[\d,]+ Detections found on [\d,]+ documents"),
        }
        events, rules, summary = patterns.get(tool, (None, None, None))
        for name, pattern in (("processed_events", events), ("rules_loaded", rules)):
            match = re.search(pattern, output, re.I) if pattern else None
            if match:
                setattr(self, name, int(match[1].replace(",", "")))
        if tool == "chainsaw" and (skipped := re.search(r"\(([\d,]+) not loaded\)", output)):
            # Counted, not a gap in this run: shipped Sigma rules this Chainsaw build
            # cannot load, the same few hundred on every run whatever the input.
            self.rules_skipped = int(skipped[1].replace(",", ""))
        if self.rules_loaded == 0:
            self.incomplete("The engine loaded no detection rules.")
        # Do not expose raw diagnostics: engine messages may contain event data
        # or local paths. Known error prefixes become a fixed public warning.
        if re.search(r"(?im)^\s*(?:\[error\]|\[warning\]|error:|warning:|failed to (?:parse|load|read))", output):
            self.incomplete("The engine reported errors or warnings; coverage may be incomplete.")
        return bool(summary and re.search(summary, output, re.I))
