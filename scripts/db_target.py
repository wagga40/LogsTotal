"""Resolve operational database paths and check rollback compatibility without writes."""

from __future__ import annotations

import argparse
import ast
import os
import sqlite3
from pathlib import Path
from urllib.parse import unquote

from backup_lifecycle import effective_db_backend, effective_env


def sqlite_path(root: Path, env: dict[str, str], context: str = "auto") -> Path:
    if effective_db_backend(env) != "sqlite":
        raise ValueError("The configured database is PostgreSQL; use backup:postgres / restore:postgres.")
    url = env.get("DATABASE_URL", "") or ""
    path = unquote(url.split(":///", 1)[1].split("?", 1)[0]) if ":///" in url else ""
    if path == ":memory:":
        raise ValueError("An in-memory database cannot be backed up or restored from another process.")
    if context == "auto":
        if path.startswith("/data/") and (root / "docker-compose.yml").exists():
            context = "docker"
        elif path:
            context = "host"
        elif (root / "logstotal.db").exists() and (root / "data/logstotal.db").exists():
            raise ValueError("Both host and Docker databases exist. Set BACKUP_CONTEXT=host or docker.")
        elif (root / "data").is_dir() or ((root / "docker-compose.yml").exists() and not (root / "logstotal.db").exists() and not (root / ".venv").exists()):
            context = "docker"
        else:
            context = "host"
    if context == "docker":
        # Mirrors docker-entrypoint.sh, including its relative-URL rewrite.
        path = path if path.startswith("/") else "/data/logstotal.db"
        for container, host in (("/data/", "data/"), ("/app/uploads/", "uploads/")):
            if path.startswith(container):
                return root / host / path.removeprefix(container)
        raise ValueError("SQLite path is outside the standard Compose mounts; use BACKUP_CONTEXT=host with its host DATABASE_URL.")
    return root / (path or "logstotal.db")


def snapshot_revisions(snapshot: Path) -> set[str]:
    revisions = set()
    for file in (snapshot / "alembic/versions").glob("*.py"):
        tree = ast.parse(file.read_text())
        for node in tree.body:
            targets = node.targets if isinstance(node, ast.Assign) else [node.target] if isinstance(node, ast.AnnAssign) else []
            if any(isinstance(target, ast.Name) and target.id == "revision" for target in targets):
                value = ast.literal_eval(node.value)
                if isinstance(value, str):
                    revisions.add(value)
    return revisions


def check_rollback(snapshot: Path, root: Path, env: dict[str, str], context: str) -> None:
    supported = snapshot_revisions(snapshot)
    if effective_db_backend(env) == "sqlite":
        path = sqlite_path(root, env, context)
        with sqlite3.connect(path.resolve().as_uri() + "?mode=ro", uri=True) as con:
            current = {row[0] for row in con.execute("SELECT version_num FROM alembic_version")}
    else:
        from sqlalchemy import create_engine, text

        # On Docker, the entrypoint has resolved the real connection URL already.
        url = env.get("SYNC_DATABASE_URL") or env.get("DATABASE_URL", "").replace("+asyncpg", "+psycopg2")
        if not url or "postgres" not in url:
            raise ValueError("Run the rollback database check inside the web container to resolve PostgreSQL configuration.")
        engine = create_engine(url)
        try:
            with engine.connect() as con:
                current = set(con.execute(text("SELECT version_num FROM alembic_version")).scalars())
        finally:
            engine.dispose()
    if not current or not current <= supported:
        raise ValueError("Database revision is absent or unsupported by the snapshot. Restore the pre-upgrade database first.")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("sqlite-path", "rollback"))
    parser.add_argument("snapshot", nargs="?", type=Path)
    parser.add_argument("--context", choices=("auto", "host", "docker"), default=os.environ.get("BACKUP_CONTEXT") or "auto")
    args = parser.parse_args()
    root = Path.cwd()
    env = effective_env(root)
    try:
        if args.action == "sqlite-path":
            print(sqlite_path(root, env, args.context))
        else:
            if args.snapshot is None:
                raise ValueError("A snapshot directory is required.")
            check_rollback(args.snapshot, root, env, args.context)
    except Exception as exc:
        # DB driver exceptions can contain credentials; only our own validation text is safe.
        detail = str(exc) if isinstance(exc, ValueError) else "Could not read the database revision or snapshot. Check the database target and connectivity."
        parser.exit(1, f"ERROR: {detail}\n")


if __name__ == "__main__":
    main()
