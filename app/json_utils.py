"""Fast JSON helpers backed by orjson with stdlib fallback."""

from __future__ import annotations

from pathlib import Path
from typing import Any

try:
    import orjson

    def loads(data: str | bytes) -> Any:
        if isinstance(data, str):
            data = data.encode("utf-8")
        return orjson.loads(data)

    def dumps(obj: Any) -> str:
        return orjson.dumps(obj).decode("utf-8")

    def load_file(path: Path) -> Any:
        with open(path, "rb") as f:
            return orjson.loads(f.read())

except ImportError:
    import json as _json

    def loads(data: str | bytes) -> Any:  # type: ignore[misc]
        return _json.loads(data)

    def dumps(obj: Any) -> str:  # type: ignore[misc]
        return _json.dumps(obj)

    def load_file(path: Path) -> Any:  # type: ignore[misc]
        with open(path, encoding="utf-8") as f:
            return _json.load(f)
