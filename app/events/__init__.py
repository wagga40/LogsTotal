"""The event store: every event of an upload, parsed by LogsTotal itself, as columnar Parquet.

Pure modules here (no FastAPI, Huey or SQLAlchemy): `timeparse`, `flatten`, `census`, the
per-format `parsers`, `spool` and `manifest`. Only `build` (a subprocess entrypoint) and, on
the web side, `engine` import duckdb; `tests/test_events_import_graph.py` pins both rules.
"""
