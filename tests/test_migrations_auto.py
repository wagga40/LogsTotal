"""Tests for app/migrations.py — automatic Alembic migrations at startup.

All tests run against a file-based SQLite database in tmp_path with the
settings sync URL monkeypatched, and fakeredis for the init lock.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from sqlalchemy import create_engine, inspect, text

INITIAL_REVISION = "09db4ba71a7c"  # first migration in the chain


@pytest.fixture()
def tmp_db(monkeypatch, tmp_path: Path, fake_redis):
    """Point settings at a file-based SQLite DB; return its path."""
    from app.config import settings

    db_path = tmp_path / "migrations_test.db"
    monkeypatch.setattr(settings, "sync_database_url", f"sqlite:///{db_path}")
    monkeypatch.setattr(settings, "auto_migrate", True)
    return db_path


def _connect(db_path: Path):
    return create_engine(f"sqlite:///{db_path}").connect()


def _tables(db_path: Path) -> set[str]:
    with _connect(db_path) as conn:
        return set(inspect(conn).get_table_names())


def _stamped_revision(db_path: Path) -> str | None:
    with _connect(db_path) as conn:
        if "alembic_version" not in inspect(conn).get_table_names():
            return None
        return conn.execute(text("SELECT version_num FROM alembic_version")).scalar()


def _create_all_only(db_path: Path) -> None:
    """Simulate a legacy pre-Alembic bootstrap: create_all, no stamp."""
    import app.models  # noqa: F401
    from app.database import Base

    engine = create_engine(f"sqlite:///{db_path}")
    Base.metadata.create_all(engine)
    engine.dispose()


def test_fresh_db_created_and_stamped_at_head(tmp_db):
    from app.migrations import get_head_revision, run_auto_migrate

    run_auto_migrate()

    tables = _tables(tmp_db)
    assert "user" in tables
    assert "sitesettings" in tables
    assert _stamped_revision(tmp_db) == get_head_revision()
    # Newest schema element must be present (the hand-rolled patcher misses it;
    # create_all covers it on fresh DBs)
    with _connect(tmp_db) as conn:
        cols = {c["name"] for c in inspect(conn).get_columns("sitesettings")}
    assert "show_process_tree" in cols


def test_legacy_unstamped_db_adopted(tmp_db):
    from app.migrations import get_head_revision, run_auto_migrate

    _create_all_only(tmp_db)
    assert _stamped_revision(tmp_db) is None

    run_auto_migrate()

    assert _stamped_revision(tmp_db) == get_head_revision()


def test_drifted_legacy_db_not_stamped(tmp_db, caplog):
    from app.migrations import run_auto_migrate

    _create_all_only(tmp_db)
    # Introduce drift: a stray table that the models don't know about.
    engine = create_engine(f"sqlite:///{tmp_db}")
    with engine.begin() as conn:
        conn.execute(text("CREATE TABLE stray_leftover (id INTEGER PRIMARY KEY)"))
    engine.dispose()

    run_auto_migrate()  # must not raise

    assert _stamped_revision(tmp_db) is None
    assert any("NOT stamping" in rec.message for rec in caplog.records)


def test_stamped_behind_db_upgraded_to_head(tmp_db):
    from alembic import command
    from app.migrations import _alembic_config, get_head_revision, run_auto_migrate

    command.upgrade(_alembic_config(), INITIAL_REVISION)
    assert _stamped_revision(tmp_db) == INITIAL_REVISION

    run_auto_migrate()

    assert _stamped_revision(tmp_db) == get_head_revision()
    with _connect(tmp_db) as conn:
        cols = {c["name"] for c in inspect(conn).get_columns("sitesettings")}
    assert "show_process_tree" in cols


def test_parity_alembic_head_matches_models(tmp_db):
    """Invariant the fresh-stamp path relies on: migrating an empty DB to head
    produces exactly the schema of the current models. Fails when someone adds
    a model change without a matching Alembic revision (or vice versa)."""
    from alembic import command
    from app.migrations import _alembic_config, schema_matches_models

    command.upgrade(_alembic_config(), "head")

    with _connect(tmp_db) as conn:
        diffs = schema_matches_models(conn)
    assert diffs == [], f"Alembic head and ORM models have diverged: {diffs}"


def test_provider_prompt_limits_migration_preserves_saved_budgets(tmp_db):
    from alembic import command
    from app.migrations import _alembic_config

    config = _alembic_config()
    command.upgrade(config, "c63d1e4a902b")
    with _connect(tmp_db) as conn:
        conn.execute(text("INSERT INTO ai_provider (name, base_url, model, max_output_tokens) VALUES ('existing', 'http://localhost/v1', 'test', 4321)"))
        conn.commit()

    command.upgrade(config, "e8a42c97f310")
    with _connect(tmp_db) as conn:
        row = conn.execute(text("SELECT max_output_tokens, job_max_prompt_chars, case_max_prompt_chars FROM ai_provider WHERE name = 'existing'")).one()
        assert tuple(row) == (4321, None, None)
        conn.execute(text("INSERT INTO ai_provider (name, base_url, model) VALUES ('new', 'http://localhost/v1', 'test')"))
        assert conn.scalar(text("SELECT max_output_tokens FROM ai_provider WHERE name = 'new'")) == 20_000
        conn.execute(text("UPDATE ai_provider SET job_max_prompt_chars = 12000, case_max_prompt_chars = 90000 WHERE name = 'existing'"))
        conn.commit()

    command.downgrade(config, "c63d1e4a902b")
    with _connect(tmp_db) as conn:
        assert conn.scalar(text("SELECT max_output_tokens FROM ai_provider WHERE name = 'existing'")) == 4321
        columns = {column["name"] for column in inspect(conn).get_columns("ai_provider")}
        assert "job_max_prompt_chars" not in columns and "case_max_prompt_chars" not in columns


def test_auto_migrate_disabled_uses_legacy_path(tmp_db, monkeypatch):
    from app.config import settings
    from app.migrations import run_auto_migrate

    monkeypatch.setattr(settings, "auto_migrate", False)
    run_auto_migrate()

    tables = _tables(tmp_db)
    assert "user" in tables
    assert _stamped_revision(tmp_db) is None  # legacy path never stamps


@pytest.mark.parametrize("legacy", [False, True], ids=["alembic", "legacy"])
def test_upload_selection_limit_migration_preserves_existing_settings(tmp_db, monkeypatch, legacy):
    from sqlalchemy import Boolean, MetaData, Table

    from alembic import command
    from app.config import settings
    from app.migrations import _alembic_config, run_auto_migrate

    config = _alembic_config()
    command.upgrade(config, "f5d18b73a209")
    with _connect(tmp_db) as conn:
        previous = Table("sitesettings", MetaData(), autoload_with=conn)
        flags = {column.name: False for column in previous.columns if isinstance(column.type, Boolean)}
        conn.execute(previous.insert().values(id=1, max_finding_details=25, **flags))
        conn.commit()
    if legacy:
        monkeypatch.setattr(settings, "auto_migrate", False)
        run_auto_migrate()
    else:
        command.upgrade(config, "a76e3b9c214d")
    with _connect(tmp_db) as conn:
        assert tuple(conn.execute(text("SELECT max_upload_files, max_finding_details FROM sitesettings WHERE id = 1")).one()) == (50, 25)
        conn.execute(text("UPDATE sitesettings SET max_upload_files = 125 WHERE id = 1"))
        conn.commit()
    if legacy:
        return
    command.downgrade(config, "f5d18b73a209")
    with _connect(tmp_db) as conn:
        assert "max_upload_files" not in {column["name"] for column in inspect(conn).get_columns("sitesettings")}
        assert conn.scalar(text("SELECT max_finding_details FROM sitesettings WHERE id = 1")) == 25


def test_waiter_returns_when_other_replica_reaches_head(tmp_db, monkeypatch):
    """When the lock is held elsewhere and the schema is already at head, the
    waiter returns instead of migrating."""
    import app.migrations as migrations

    # Bring the DB to head first (with the lock available).
    migrations.run_auto_migrate()

    monkeypatch.setattr(migrations, "_try_lock", lambda: False)
    monkeypatch.setattr(migrations, "POLL_INTERVAL", 0.01)
    migrations.run_auto_migrate()  # must return promptly, not raise


def test_waiter_times_out_without_head(tmp_db, monkeypatch):
    import app.migrations as migrations

    monkeypatch.setattr(migrations, "_try_lock", lambda: False)
    monkeypatch.setattr(migrations, "POLL_INTERVAL", 0.01)
    monkeypatch.setattr(migrations, "WAIT_TIMEOUT", 0.05)
    with pytest.raises(RuntimeError, match="did not finish"):
        migrations.run_auto_migrate()


def test_migration_status_states(tmp_db):
    from app.migrations import migration_status, run_auto_migrate

    status = migration_status()
    assert status.state == "fresh"

    _create_all_only(tmp_db)
    status = migration_status()
    assert status.state == "unmanaged"

    run_auto_migrate()
    status = migration_status()
    assert status.state == "at_head"
    assert status.pending_count == 0
    assert status.current == status.head


def test_migration_status_behind_counts_pending(tmp_db):
    from alembic import command
    from app.migrations import _alembic_config, migration_status

    command.upgrade(_alembic_config(), INITIAL_REVISION)
    status = migration_status()
    assert status.state == "behind"
    assert status.pending_count >= 1


def test_workers_never_import_migrations():
    """Schema changes are the web/init role — pin that worker modules don't
    import the migration machinery."""
    root = Path(__file__).resolve().parent.parent
    for mod in ("app/workers/huey_app.py", "app/workers/tasks.py"):
        source = (root / mod).read_text(encoding="utf-8")
        assert "app.migrations" not in source, f"{mod} must not import app.migrations"
        assert "create_db_and_tables" not in source, f"{mod} must not bootstrap the schema"


def test_workers_never_import_the_web_tier():
    """The Huey worker must not reach into the FastAPI routers.

    Importing the analytics computation from `app.routers.jobs` would pull every route
    handler, `templates_config` and Jinja into the worker process just to compute a dict.
    The computation lives in the pure `app/analytics.py`.

    FastAPI itself still loads, via `app.models` → `fastapi_users_db_sqlalchemy` (the User
    table base), so this asserts the layering rule, not the absence of the dependency.
    """
    root = Path(__file__).resolve().parent.parent
    for mod in ("app/workers/huey_app.py", "app/workers/tasks.py"):
        source = (root / mod).read_text(encoding="utf-8")
        assert "app.routers" not in source, f"{mod} must not import a FastAPI router"
        assert "templates_config" not in source, f"{mod} must not import the Jinja environment"


def test_analytics_module_is_free_of_web_and_queue_imports():
    """`app/analytics.py` is a pure computation module, like app/intel/event_timeline.py."""
    source = (Path(__file__).resolve().parent.parent / "app" / "analytics.py").read_text(encoding="utf-8")
    for banned in ("fastapi", "app.routers", "huey", "templates_config"):
        assert banned not in source, f"app/analytics.py must not import {banned}"


# ── Init lock ownership ──────────────────────────────────────────────────────
#
# _unlock() must not DELETE unconditionally with a constant lock value. A migration
# outliving LOCK_TTL lets a second replica acquire the lock; the first would then
# delete *that* replica's lock on its way out, admitting a third to run
# `alembic upgrade head` concurrently with the second.


def test_lock_release_removes_our_own_lock(fake_redis):
    from app import migrations

    assert migrations._try_lock() is True
    assert fake_redis.get(migrations.LOCK_KEY) is not None
    migrations._unlock()
    assert fake_redis.get(migrations.LOCK_KEY) is None


def test_lock_value_is_not_a_shared_constant(fake_redis):
    """Two acquisitions must be distinguishable, or ownership cannot be checked."""
    from app import migrations

    migrations._try_lock()
    first = fake_redis.get(migrations.LOCK_KEY)
    migrations._unlock()
    migrations._try_lock()
    assert fake_redis.get(migrations.LOCK_KEY) != first


def test_release_does_not_delete_a_successors_lock(fake_redis, caplog):
    """The TTL-expiry scenario: our lock lapsed and another replica took it."""
    from app import migrations

    assert migrations._try_lock() is True
    # Simulate expiry + re-acquisition by a different replica while we were migrating.
    fake_redis.set(migrations.LOCK_KEY, "some-other-replica-token")

    migrations._unlock()

    assert fake_redis.get(migrations.LOCK_KEY) == "some-other-replica-token", "deleted another replica's lock"
    assert "longer than LOCK_TTL" in caplog.text, "exceeding the TTL must not be silent"


def test_contended_lock_is_not_released_by_the_loser(fake_redis):
    """A replica that never acquired the lock must not be able to release it."""
    from app import migrations

    fake_redis.set(migrations.LOCK_KEY, "leader-token")
    assert migrations._try_lock() is False
    migrations._unlock()
    assert fake_redis.get(migrations.LOCK_KEY) == "leader-token"


# ── legacy adoption must not lose the indexes ───────────────────────────────


def _drop_index(db_path: Path, name: str) -> None:
    engine = create_engine(f"sqlite:///{db_path}")
    with engine.begin() as conn:
        conn.execute(text(f"DROP INDEX IF EXISTS {name}"))
    engine.dispose()


def _indexes(db_path: Path, table: str) -> set[str]:
    with _connect(db_path) as conn:
        return {ix["name"] for ix in inspect(conn).get_indexes(table)}


def test_legacy_adoption_creates_indexes_added_after_the_table(tmp_db):
    """`create_all(checkfirst=True)` skips an existing table wholesale — indexes included.

    A long-lived instance would therefore be adopted into Alembic *stamped at head* while
    missing every index added since its tables were first created, and stamping means
    `alembic upgrade head` will never run those revisions — silently dropping index work on
    exactly the databases large enough to need it.
    """
    _create_all_only(tmp_db)
    # Simulate a database bootstrapped before these indexes existed.
    for name in ("ix_finding_task_severity", "ix_finding_task_rule_name"):
        _drop_index(tmp_db, name)
    assert "ix_finding_task_severity" not in _indexes(tmp_db, "finding")

    from app.migrations import get_head_revision, run_auto_migrate

    run_auto_migrate()

    assert _stamped_revision(tmp_db) == get_head_revision(), "still adopted"
    have = _indexes(tmp_db, "finding")
    assert "ix_finding_task_severity" in have
    assert "ix_finding_task_rule_name" in have


def test_index_patch_is_idempotent(tmp_db):
    from app.migrations import run_auto_migrate

    _create_all_only(tmp_db)
    run_auto_migrate()
    before = _indexes(tmp_db, "finding")
    run_auto_migrate()
    assert _indexes(tmp_db, "finding") == before


def test_every_enum_widened_in_a_migration_learns_its_new_label_on_postgresql():
    """`alter_column` cannot widen a native PostgreSQL enum. Only `ADD VALUE` can.

    SQLAlchemy renders `Enum` as a bare VARCHAR on SQLite, so an `alter_column` that swaps
    one `sa.Enum(...)` for a longer one is a no-op there; on PostgreSQL it emits a same-type
    cast, which is *also* a no-op. So the migration applies cleanly, the test suite passes on
    SQLite, a fresh PostgreSQL is fine because `create_all` writes every label — and only an
    **upgraded** PostgreSQL is left with a type that is missing a member.

    `b7e4f2a91c38` does exactly this to `aianalysisstatus` (its own comment points at the
    `autocommit_block()` + `ADD VALUE IF NOT EXISTS` form that works), and `d3f81a6c92be`
    adds the label. Without it, writing `CANCELLED` fails, and `/admin/tasks` — which merely
    *reads* `status.in_([COMPLETED, FAILED, CANCELLED])` — returns a 500 on every upgraded
    PostgreSQL instance, whether or not anyone has ever stopped an AI run. Reproduced against
    postgres:16 (`invalid input value for enum aianalysisstatus: "CANCELLED"`).

    The rule: an enum named as the *target* of an `alter_column` inside `upgrade()` must have
    an `ALTER TYPE <name> ADD VALUE` somewhere in the revision history. Scoped to `upgrade()`
    because downgrades legitimately name the narrower type.
    """
    import ast

    versions = Path(__file__).resolve().parent.parent / "alembic" / "versions"
    trees = {p: ast.parse(p.read_text(encoding="utf-8")) for p in sorted(versions.glob("*.py"))}

    # SQL that is actually *executed*, not raw file text. Matching the file bytes passes
    # with the bug present: `b7e4f2a91c38`'s own comment
    # quotes `ALTER TYPE aianalysisstatus ADD VALUE 'CANCELLED'` while explaining that it is
    # the thing the migration does not do. A comment describing the fix is not the fix.
    executed = []
    for tree in trees.values():
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                called = node.func.attr if isinstance(node.func, ast.Attribute) else getattr(node.func, "id", "")
                if called == "execute":
                    for arg in node.args:
                        if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                            executed.append(arg.value)
    all_sql = "\n".join(executed)

    def enum_name(node):
        """The `name=` of an `sa.Enum(...)` call, else None."""
        if not isinstance(node, ast.Call):
            return None
        fn = node.func
        label = fn.attr if isinstance(fn, ast.Attribute) else getattr(fn, "id", "")
        if label != "Enum":
            return None
        for kw in node.keywords:
            if kw.arg == "name" and isinstance(kw.value, ast.Constant):
                return kw.value.value
        return None

    offenders = []
    for path, tree in trees.items():
        upgrades = [n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "upgrade"]
        for fn in upgrades:
            for node in ast.walk(fn):
                if not isinstance(node, ast.Call):
                    continue
                called = node.func.attr if isinstance(node.func, ast.Attribute) else getattr(node.func, "id", "")
                if called != "alter_column":
                    continue
                for kw in node.keywords:
                    if kw.arg != "type_":
                        continue
                    name = enum_name(kw.value)
                    if name and f"ALTER TYPE {name} ADD VALUE" not in all_sql:
                        offenders.append(f"{path.name}: alter_column widens `{name}` with no `ALTER TYPE {name} ADD VALUE` anywhere")

    assert not offenders, "enum never learns its new label on an upgraded PostgreSQL:\n  " + "\n  ".join(sorted(set(offenders)))


@pytest.mark.parametrize("legacy_unstamped", [False, True])
def test_submission_metadata_migration_preserves_types_but_not_unverified_names(tmp_db, legacy_unstamped):
    from alembic import command
    from app.migrations import _alembic_config, run_auto_migrate, schema_matches_models

    command.upgrade(_alembic_config(), "59aefc585fb3")
    with _connect(tmp_db) as conn:
        conn.execute(
            text(
                "INSERT INTO logfile (id, original_filename, stored_filename, sha256, size_bytes, log_type, detected_type) VALUES (1, 'secret.evtx', 'blob', :sha, 1, 'SYSLOG', 'EVTX')"
            ),
            {"sha": "a" * 64},
        )
        conn.execute(text("INSERT INTO workflowdef (id, name, log_types, tasks_yaml, is_default) VALUES (1, 'test', '[]', 'tasks: []', FALSE)"))
        conn.execute(text("INSERT INTO analysisjob (file_id, workflow_id, status) VALUES (1, 1, 'COMPLETED')"))
        if legacy_unstamped:
            conn.execute(text("DROP TABLE alembic_version"))
        conn.commit()
    run_auto_migrate()
    with _connect(tmp_db) as conn:
        assert conn.execute(text("SELECT effective_log_type, submitted_filename FROM analysisjob")).one() == ("SYSLOG", None)
        assert conn.execute(text("SELECT original_filename FROM logfile")).scalar() == "secret.evtx"
        assert not schema_matches_models(conn)


@pytest.mark.parametrize("has_source_deleted_at", [False, True])
@pytest.mark.parametrize("has_autoincrement", [False, True])
def test_case_ai_followup_repairs_already_applied_revision(tmp_db, has_source_deleted_at, has_autoincrement):
    """An early b92 install was stamped before its column and ID policy were final."""
    from alembic.migration import MigrationContext
    from alembic.operations import Operations
    from sqlalchemy import select
    from sqlalchemy.orm import Session

    from alembic import command
    from app.migrations import _alembic_config, get_head_revision, run_auto_migrate, schema_matches_models
    from app.models import CaseAiAnalysis

    command.upgrade(_alembic_config(), "b92a7e13c640")
    with _connect(tmp_db) as conn:
        with Operations(MigrationContext.configure(conn)).batch_alter_table(
            "case_ai_analysis", recreate="always", table_kwargs={"sqlite_autoincrement": has_autoincrement}
        ) as batch:
            if not has_source_deleted_at:
                batch.drop_column("source_deleted_at")
        conn.execute(text("INSERT INTO investigation_case (id, name) VALUES (3, 'Migration regression')"))
        insert_run = text(
            "INSERT INTO case_ai_analysis "
            "(id, case_id, provider_name, model, status, content, source_jobs_json, evidence_captured_at) "
            "VALUES (:id, 3, 'Saved provider', 'saved-model', 'COMPLETED', 'Saved report', '[]', '2026-09-20 10:00:00')"
        )
        conn.execute(insert_run, {"id": 42})
        if has_source_deleted_at:
            conn.execute(text("UPDATE case_ai_analysis SET source_deleted_at = '2026-09-20 11:00:00' WHERE id = 42"))
        conn.execute(insert_run, {"id": 99})
        conn.execute(text("DELETE FROM case_ai_analysis WHERE id = 99"))
        before = dict(conn.execute(text("SELECT * FROM case_ai_analysis WHERE id = 42")).mappings().one())
        indexes = inspect(conn).get_indexes("case_ai_analysis")
        foreign_keys = inspect(conn).get_foreign_keys("case_ai_analysis")
        conn.commit()

    run_auto_migrate()
    run_auto_migrate()  # Startup must also succeed once the repair is applied.

    assert _stamped_revision(tmp_db) == get_head_revision()
    with _connect(tmp_db) as conn:
        with Session(conn) as db:
            # The exact ORM query that failed on the already-stamped database.
            runs = db.scalars(select(CaseAiAnalysis).where(CaseAiAnalysis.case_id == 3).order_by(CaseAiAnalysis.created_at.desc(), CaseAiAnalysis.id.desc()).limit(20)).all()
            assert len(runs) == 1
            assert runs[0].id == 42
            assert (runs[0].source_deleted_at is not None) == has_source_deleted_at
        after = dict(conn.execute(text("SELECT * FROM case_ai_analysis WHERE id = 42")).mappings().one())
        assert {key: after[key] for key in before} == before
        assert inspect(conn).get_indexes("case_ai_analysis") == indexes
        assert sorted(inspect(conn).get_foreign_keys("case_ai_analysis"), key=lambda fk: fk["constrained_columns"]) == sorted(
            foreign_keys, key=lambda fk: fk["constrained_columns"]
        )
        assert not schema_matches_models(conn)
        assert not conn.execute(text("PRAGMA foreign_key_check")).all()
        # A deleted report's queued task/cancel flag must never refer to a new run.
        conn.execute(text("DELETE FROM case_ai_analysis WHERE id = 42"))
        new_id = conn.execute(
            text("INSERT INTO case_ai_analysis (case_id, provider_name, model, status) VALUES (3, 'New provider', 'new-model', 'PENDING') RETURNING id")
        ).scalar_one()
        assert new_id > (99 if has_autoincrement else 42)
