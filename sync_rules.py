"""
Seed the shared rules (lolbin, privileged, …) and their lists from rules/*.yml.

Idempotent. The file updates what nobody edited: a rule or list still equal to what it was
seeded with takes the file's newer version; one an admin edited on the Rules page is left
alone.

A file that does not parse is a real failure, the `sync_workflows.py` stance: every error is
printed and the exit code is 1.

The app does this on startup too, so this is for a deployment that booted with the database
unreachable, or for putting things right after a built-in was deleted.

It does NOT label existing entities: run the Built-in labels backfill from the admin
Maintenance tab once for that.

Run: ./logstotal sync-rules
"""

import asyncio
import sys

# Load .env if present
try:
    from dotenv import load_dotenv  # type: ignore

    load_dotenv()
except ImportError:
    pass


async def main() -> int:
    from app.database import async_session_maker
    from app.intel.rules_yaml import rules_dir, sync_rules_from_dir

    directory = rules_dir()
    async with async_session_maker() as session:
        result = await sync_rules_from_dir(session, directory)
        await session.commit()

    for err in result.errors:
        print(f"Error loading rule {err}")
    print(f"Shared rules from {directory} — {result.summary()}.")
    return 1 if result.errors else 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
