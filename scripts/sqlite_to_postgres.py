"""Copy a LogsTotal SQLite database into an empty PostgreSQL one.

Why a script and not a `sqlite3 .dump | psql` recipe: the dump is not portable here.
``LogFile.log_type`` and friends are stored as text either way, but two column kinds
change representation with the dialect —

* ``GUID`` (every ``user.id`` foreign key) is ``CHAR(36)`` on SQLite and native
  ``uuid`` on PostgreSQL;
* every ``Boolean`` is ``0``/``1`` on SQLite, and PostgreSQL rejects an integer
  literal for a ``boolean`` column outright;

— and a SQLite dump also carries ``AUTOINCREMENT``/``BEGIN TRANSACTION`` syntax
PostgreSQL will not parse. Reading through the ORM makes the conversion happen by
construction: the same model metadata describes both sides, so SQLAlchemy binds each
value with the target dialect's type.

Usage (see docs/runbooks/sqlite-to-postgres.md):

    python3 scripts/sqlite_to_postgres.py \
        --sqlite-url sqlite:///logstotal.db \
        --postgres-url postgresql+psycopg2://logstotal:PASS@localhost:5432/logstotal

The target must already have the schema (run ``python3 -m app.migrations`` against it
first) and must hold no rows: this refuses to merge into a populated database.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from sqlalchemy import create_engine, func, insert, inspect, select
from sqlalchemy.engine import Engine

from app.database import Base
from app.models import *  # noqa: F403  (import side effect: registers every table on Base)

BATCH = 500


def _ordered_tables():
    """Parent tables before children, so foreign keys resolve as we go."""
    return Base.metadata.sorted_tables


def _row_count(engine: Engine, table) -> int:
    with engine.connect() as conn:
        return conn.execute(select(func.count()).select_from(table)).scalar_one()


def _assert_target_ready(target: Engine) -> None:
    existing = set(inspect(target).get_table_names())
    missing = [t.name for t in _ordered_tables() if t.name not in existing]
    if missing:
        raise SystemExit(f"Target is missing {len(missing)} table(s), e.g. {missing[:3]}. Run `python3 -m app.migrations` against it first.")

    populated = [t.name for t in _ordered_tables() if _row_count(target, t) > 0]
    # alembic_version is written by the migration step and is expected to hold a row.
    populated = [name for name in populated if name != "alembic_version"]
    if populated:
        raise SystemExit(f"Target already has rows in: {', '.join(populated)}. Point at an empty database — this does not merge.")


def _resync_sequences(target: Engine) -> None:
    """Advance each identity sequence past the ids we inserted explicitly.

    Without this the first insert after the move collides with an existing primary key.
    """
    with target.begin() as conn:
        for table in _ordered_tables():
            for col in table.primary_key.columns:
                if not col.autoincrement or not str(col.type).lower().startswith(("integer", "bigint")):
                    continue
                # Identifiers cannot be bound parameters, and these are not user input:
                # every name comes from Base.metadata, i.e. from app/models.py.
                conn.exec_driver_sql(
                    f"""SELECT setval(pg_get_serial_sequence('"{table.name}"', '{col.name}'),
                                      COALESCE((SELECT MAX("{col.name}") FROM "{table.name}"), 1),
                                      (SELECT MAX("{col.name}") FROM "{table.name}") IS NOT NULL)
                        WHERE pg_get_serial_sequence('"{table.name}"', '{col.name}') IS NOT NULL"""  # noqa: S608
                )


def copy_database(sqlite_url: str, postgres_url: str, *, verbose: bool = True) -> dict[str, int]:
    source = create_engine(sqlite_url)
    target = create_engine(postgres_url)
    try:
        _assert_target_ready(target)
        copied: dict[str, int] = {}

        for table in _ordered_tables():
            if table.name == "alembic_version":
                continue  # owned by the migration step, already correct on the target
            total = 0
            with source.connect() as src, target.begin() as dst:
                result = src.execute(select(table))
                while rows := result.fetchmany(BATCH):
                    dst.execute(insert(table), [dict(row._mapping) for row in rows])
                    total += len(rows)
            copied[table.name] = total
            if verbose and total:
                print(f"  {table.name}: {total}")

        _resync_sequences(target)
        return copied
    finally:
        source.dispose()
        target.dispose()


def verify(sqlite_url: str, postgres_url: str) -> list[str]:
    """Return a list of mismatch descriptions; empty means every table matched."""
    source = create_engine(sqlite_url)
    target = create_engine(postgres_url)
    try:
        problems = []
        for table in _ordered_tables():
            if table.name == "alembic_version":
                continue
            src_n, dst_n = _row_count(source, table), _row_count(target, table)
            if src_n != dst_n:
                problems.append(f"{table.name}: source {src_n} != target {dst_n}")
        return problems
    finally:
        source.dispose()
        target.dispose()


def main() -> int:
    parser = argparse.ArgumentParser(description="Copy a LogsTotal SQLite database into an empty PostgreSQL one.")
    parser.add_argument("--sqlite-url", default="sqlite:///logstotal.db")
    parser.add_argument("--postgres-url", required=True, help="e.g. postgresql+psycopg2://user:pass@host:5432/logstotal")
    args = parser.parse_args()

    print(f"Copying {args.sqlite_url} -> {args.postgres_url.rsplit('@', 1)[-1]}")
    copy_database(args.sqlite_url, args.postgres_url)

    problems = verify(args.sqlite_url, args.postgres_url)
    if problems:
        print("\nFAILED — row counts do not match:")
        for p in problems:
            print(f"  {p}")
        return 1
    print("\nOK — every table matched on row count. Now point DATABASE_URL/SYNC_DATABASE_URL at PostgreSQL and run `./logstotal doctor`.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
