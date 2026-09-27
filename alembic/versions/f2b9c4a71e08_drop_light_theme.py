"""drop the light theme — reset users who had it selected

The light theme was removed from ALLOWED_THEMES, so `_valid_theme` already
clamps a stale value to "classic" at render time. This clears the stored
preference too, so the column never carries a theme that no longer exists.

Data-only: no schema change, so it does not affect the alembic-head/ORM
parity test.

Revision ID: f2b9c4a71e08
Revises: a2c9f60b13e5
Create Date: 2026-08-08 10:00:00.000000
"""

from typing import Sequence, Union

import sqlalchemy as sa

from alembic import op

revision: str = "f2b9c4a71e08"
down_revision: Union[str, None] = "a2c9f60b13e5"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.execute(sa.text("UPDATE \"user\" SET theme = NULL WHERE theme = 'light'"))


def downgrade() -> None:
    # The old preference is not recoverable — NULL simply falls back to the cookie.
    pass
