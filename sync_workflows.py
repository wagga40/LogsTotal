"""
Sync workflow definitions from workflows/*.yml into the database.
Use after editing YAML files so the DB reflects file changes.
Run: ./logstotal sync-workflows
"""

import asyncio
import sys
from pathlib import Path

# Load .env if present
try:
    from dotenv import load_dotenv  # type: ignore

    load_dotenv()
except ImportError:
    pass


async def main() -> int:
    from app.database import async_session_maker
    from app.detection.workflow_runner import sync_workflows_from_dir

    project_root = Path(__file__).resolve().parent
    workflows_dir = project_root / "workflows"
    if not workflows_dir.exists():
        print("workflows/ directory not found.", file=sys.stderr)
        return 1

    async with async_session_maker() as session:
        added, updated, errors = await sync_workflows_from_dir(session, workflows_dir)
        await session.commit()

    for err in errors:
        print(f"  Skip {err}", file=sys.stderr)
    print(f"Workflows synced: {added} added, {updated} updated.")
    # A file that would not parse is a real failure, not a cosmetic one: the workflow it
    # describes is silently absent from the upload form afterwards.
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
