"""YAML parsing through PyYAML's libyaml bindings, with the pure-Python parser as fallback.

``yaml.CSafeLoader`` swaps the scanner and parser for libyaml's C implementation and keeps
``SafeLoader``'s constructor and resolver, so it builds the same Python objects as
``yaml.safe_load``. On the ~9,500 Sigma rule files vendored under ``tools/`` it parses in
about a tenth of the time, which is most of the cost of ``ToolAdapter._build_rule_index``.

Error messages are worded slightly differently by the two parsers; the exception classes
are the same. A PyYAML built without libyaml has no ``CSafeLoader`` and uses ``SafeLoader``.
"""

from __future__ import annotations

from typing import IO, Any

import yaml

_LOADER = getattr(yaml, "CSafeLoader", yaml.SafeLoader)


def safe_load(stream: str | bytes | IO[str] | IO[bytes]) -> Any:
    """Drop-in for ``yaml.safe_load`` that uses libyaml when PyYAML was built with it."""
    return yaml.load(stream, Loader=_LOADER)  # noqa: S506 - _LOADER is CSafeLoader or SafeLoader


def bounded_load(text: str) -> Any:
    """Rule documents cannot contain aliases or unbounded structural complexity.

    Inspect events before constructing objects: SafeLoader alone permits recursive
    aliases and compact graphs whose later string conversion expands exponentially.
    The caller separately bounds encoded document bytes.
    """
    depth = 0
    for count, event in enumerate(yaml.parse(text, Loader=_LOADER), 1):
        if count > 100_000:
            raise yaml.YAMLError("document has too many YAML events")
        if isinstance(event, yaml.AliasEvent):
            raise yaml.YAMLError("YAML aliases are not allowed")
        if isinstance(event, (yaml.MappingStartEvent, yaml.SequenceStartEvent)):
            depth += 1
            if depth > 16:
                raise yaml.YAMLError("YAML nesting exceeds 16 levels")
        elif isinstance(event, (yaml.MappingEndEvent, yaml.SequenceEndEvent)):
            depth -= 1
    return safe_load(text)
