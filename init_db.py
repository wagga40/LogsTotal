"""
Bootstrap script: create DB tables, load default workflows, create first admin.
Run once: python3 init_db.py
"""

import asyncio
import os
import uuid
from pathlib import Path

# Load .env if present. Guarded like sync_workflows.py: the import has to sit inside the
# try, or a missing python-dotenv raises before the handler can catch it.
try:
    from dotenv import load_dotenv  # type: ignore

    load_dotenv()
except ImportError:
    pass


def _pause_before_container_exit(seconds: int = 30) -> None:
    """Slow a fatal-config exit down inside a container, so it reads as a message.

    docker-compose runs this script as `sh -c "python3 init_db.py && uvicorn ..."` under
    `restart: unless-stopped`, and `docker compose up -d` reports success regardless. A
    bare non-zero exit therefore spins the container fast enough that the banner above
    scrolls past between restarts. Pausing makes `docker compose logs web` legible and
    makes the loop visibly a loop. No effect outside a container.
    """
    if not Path("/.dockerenv").exists():
        return
    import time

    print(f"  Container detected — pausing {seconds}s before exit so this message stays readable.")
    print("  (compose will restart this container; fix .env and it will come up.)")
    time.sleep(seconds)


async def main():
    from fastapi_users.exceptions import UserAlreadyExists
    from sqlalchemy import select

    from app.auth.schemas import UserCreate
    from app.database import async_session_maker

    async with async_session_maker() as session:
        # Load default workflows from YAML files (path relative to project root)
        _project_root = Path(__file__).resolve().parent
        workflows_dir = _project_root / "workflows"
        if workflows_dir.exists():
            from app.detection.workflow_runner import sync_workflows_from_dir

            loaded, updated, errors = await sync_workflows_from_dir(session, workflows_dir)
            await session.commit()
            for err in errors:
                print(f"  Error loading workflow {err}")
            print(f"  Summary: {loaded} loaded, {updated} updated.")
        else:
            print("  No workflows/ directory found — add YAML files and re-run init, or create workflows in /admin.")

        # The shared rules and their lists, seeded from a directory of YAML files by a
        # function a task can re-run, never from a migration. The file updates what nobody
        # edited: a row still equal to what it was seeded with takes the file's newer
        # version, an admin's edit is left alone.
        rules_dir = _project_root / "rules"
        if rules_dir.exists():
            from app.intel.rules_yaml import sync_rules_from_dir

            result = await sync_rules_from_dir(session, rules_dir)
            await session.commit()
            for err in result.errors:
                print(f"  Error loading rule {err}")
            print(f"  Shared rules — {result.summary()}.")
        else:
            print("  No rules/ directory found — add YAML files and re-run init, or run `./logstotal sync-rules`.")

    # Create first admin user
    admin_email = os.environ.get("ADMIN_EMAIL", "admin@example.com")
    admin_password = os.environ.get("ADMIN_PASSWORD", "changeme123")

    from fastapi_users.exceptions import InvalidPasswordException
    from fastapi_users_db_sqlalchemy import SQLAlchemyUserDatabase

    from app.database import async_session_maker
    from app.models import User

    async with async_session_maker() as session:
        # Skip before validating the password: manager.create() validates first,
        # and a stale ADMIN_PASSWORD in .env must not break restarts of a
        # deployment whose admin already exists (Docker runs init on every boot).
        existing_admin = await session.scalar(select(User).where(User.email == admin_email))
        if existing_admin is not None:
            print(f"\nAdmin user {admin_email} already exists — skipping.")
            return

        user_db = SQLAlchemyUserDatabase(session, User)
        from app.auth.users import UserManager

        manager = UserManager(user_db)
        try:
            _ = await manager.create(
                UserCreate(
                    email=admin_email,
                    password=admin_password,
                    is_superuser=True,
                    is_active=True,
                    role="admin",
                )
            )
            print(f"\nAdmin user created: {admin_email}")
            print("IMPORTANT: change the password after first login!")
            if len(admin_password) < 12:
                print("")
                print("  WARNING: the admin password is shorter than 12 characters.")
                print("  Set a stronger ADMIN_PASSWORD in .env, or change it at /admin/users.")
        except InvalidPasswordException as exc:
            # Mirror the SECRET_KEY placeholder guard: refuse to create an admin
            # with the shipped default / a weak password instead of warning.
            print("")
            print("  ╔════════════════════════════════════════════════════════════════╗")
            print("  ║  REFUSING TO CREATE ADMIN — WEAK ADMIN_PASSWORD                ║")
            print("  ╚════════════════════════════════════════════════════════════════╝")
            print(f"  {exc.reason}")
            print("  Set a strong ADMIN_PASSWORD in .env and re-run init.")
            print('  Generate one: ./logstotal gen-secrets -- --write  (or: python3 -c "import secrets; print(secrets.token_urlsafe(18))")')
            _pause_before_container_exit()
            raise SystemExit(1) from None
        except UserAlreadyExists:
            print(f"\nAdmin user {admin_email} already exists — skipping.")


# Per-process lock token. `logstotal:init_lock` is the SAME key app/migrations.py uses, and
# both refuse to delete a lock they no longer own — compare the stored token first, and warn
# when the TTL was exceeded. Deleting unconditionally would let a bootstrap that outran the
# 60s TTL (workflow upserts plus a bcrypt admin create, on a cold DB) release a *different*
# replica's migration lock and let a third run `alembic upgrade head` concurrently with it.
_INIT_LOCK_KEY = "logstotal:init_lock"
_init_lock_token = uuid.uuid4().hex


def _redis_client():
    import redis

    url = os.environ.get("REDIS_URL")
    if url:
        return redis.Redis.from_url(url)
    return redis.Redis(
        host=os.environ.get("REDIS_HOST", "localhost"),
        port=int(os.environ.get("REDIS_PORT", "6379")),
        password=os.environ.get("REDIS_PASSWORD", "") or None,
    )


def _acquire_init_lock(timeout: int = 60) -> bool:
    """Try to acquire the Redis init lock. Returns True if acquired."""
    try:
        r = _redis_client()
        acquired = r.set(_INIT_LOCK_KEY, _init_lock_token, nx=True, ex=timeout)
        r.close()
        return bool(acquired)
    except Exception:
        return True


def _release_init_lock():
    """Release the lock only if we still hold it."""
    try:
        r = _redis_client()
        current = r.get(_INIT_LOCK_KEY)
        if current is not None and current.decode() == _init_lock_token:
            r.delete(_INIT_LOCK_KEY)
        elif current is not None:
            print("WARNING: init took longer than the lock TTL; another instance holds it now — not releasing.")
        r.close()
    except Exception:
        pass


if __name__ == "__main__":
    import logging
    import time

    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")

    # Schema first: create/upgrade/adopt via Alembic (manages its own Redis lock,
    # waits for a concurrent replica instead of racing it).
    from app.migrations import run_auto_migrate

    print("Preparing database schema...")
    run_auto_migrate()
    print("  Done.")

    if _acquire_init_lock():
        try:
            asyncio.run(main())
        finally:
            _release_init_lock()
    else:
        print("Another instance is running init_db — waiting...")
        for _ in range(60):
            time.sleep(1)
            if _acquire_init_lock():
                try:
                    asyncio.run(main())
                finally:
                    _release_init_lock()
                break
        else:
            print("Init lock not released after 60s — running anyway.")
            asyncio.run(main())
