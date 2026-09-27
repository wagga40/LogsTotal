"""
Helpers for loading the single-row SiteSettings record.
Creates the row with defaults on first access (idempotent).

The create is a check-then-insert, so two callers can race it — and on a brand-new
deployment they do: the first page load and an uptime probe arriving together is enough,
since ``GET /`` reads the settings. The loser's ``commit`` raises ``IntegrityError`` on the
primary key, which in a route would be an unhandled 500 on the very first request a new
install ever serves. Rather than lock or pre-seed, both helpers treat "somebody else inserted it"
as success and re-read: that is the true outcome, it needs no coordination, and it stays
correct on PostgreSQL where the constraint is actually enforced.
"""

from __future__ import annotations

from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import Session

from app.models import SiteSettings


async def get_site_settings(db: AsyncSession) -> SiteSettings:
    """Return the SiteSettings row, creating it with defaults if missing."""
    row = await db.get(SiteSettings, 1)
    if row is not None:
        return row
    row = SiteSettings(id=1)
    db.add(row)
    try:
        await db.commit()
    except IntegrityError:
        # Another request created it between the read and the insert.
        await db.rollback()
        existing = await db.get(SiteSettings, 1)
        if existing is None:  # pragma: no cover - would mean the insert failed for another reason
            raise
        return existing
    await db.refresh(row)
    return row


def get_site_settings_sync(db: Session) -> SiteSettings:
    """Sync version for Huey workers."""
    row = db.get(SiteSettings, 1)
    if row is not None:
        return row
    row = SiteSettings(id=1)
    db.add(row)
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        existing = db.get(SiteSettings, 1)
        if existing is None:  # pragma: no cover - see the async twin
            raise
        return existing
    db.refresh(row)
    return row
