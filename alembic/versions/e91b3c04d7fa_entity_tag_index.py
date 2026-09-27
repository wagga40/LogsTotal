"""index entity_tag.tag for the dashboard tag filter

Revision ID: e91b3c04d7fa
Revises: c4a1d70b96e2
Create Date: 2026-08-03 11:00:00.000000
"""

from typing import Sequence, Union

from alembic import op

revision: str = "e91b3c04d7fa"
down_revision: Union[str, None] = "c4a1d70b96e2"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # uq_entity_tag leads with entity_id, so `WHERE tag IN (...)` had no usable index.
    op.create_index(op.f("ix_entity_tag_tag"), "entity_tag", ["tag"], unique=False)


def downgrade() -> None:
    op.drop_index(op.f("ix_entity_tag_tag"), table_name="entity_tag")
