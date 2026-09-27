"""job tags

The same analyst tag vocabulary, now applicable to a job as well as an entity.

A second link table rather than a polymorphic `(target_type, target_id)` pair — the
`Comment` argument: the target set is closed, so polymorphism would only cost referential
integrity and the ORM cascades. Names and colours still live in `tag_definition`, so a tag
means one thing with one colour on both sides; `app/tags.py` owns the writes that keep that
true across the two tables.

`tag` is indexed on its own as well as leading-column-second in `uq_job_tag`, for the same
reason `entity_tag.tag` is: the jobs-list filter is a `WHERE tag IN (...)`, which the
composite cannot serve.

Revision ID: 8b5d1d21e8f8
Revises: 32229ad1d2b0
Create Date: 2026-08-16 13:46:33.825669
"""

from collections.abc import Sequence
from typing import Union

import fastapi_users_db_sqlalchemy
import sqlalchemy as sa
from alembic import op

revision: str = "8b5d1d21e8f8"
down_revision: Union[str, None] = "32229ad1d2b0"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "job_tag",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("job_id", sa.Integer(), nullable=False),
        sa.Column("tag", sa.String(length=50), nullable=False),
        sa.Column("color", sa.String(length=20), server_default="gray", nullable=False),
        sa.Column("created_at", sa.DateTime(), server_default=sa.text("(CURRENT_TIMESTAMP)"), nullable=False),
        sa.Column("created_by_user_id", fastapi_users_db_sqlalchemy.generics.GUID(), nullable=True),
        sa.ForeignKeyConstraint(["created_by_user_id"], ["user.id"]),
        sa.ForeignKeyConstraint(["job_id"], ["analysisjob.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("job_id", "tag", name="uq_job_tag"),
    )
    with op.batch_alter_table("job_tag", schema=None) as batch_op:
        batch_op.create_index(batch_op.f("ix_job_tag_job_id"), ["job_id"], unique=False)
        batch_op.create_index(batch_op.f("ix_job_tag_tag"), ["tag"], unique=False)


def downgrade() -> None:
    with op.batch_alter_table("job_tag", schema=None) as batch_op:
        batch_op.drop_index(batch_op.f("ix_job_tag_tag"))
        batch_op.drop_index(batch_op.f("ix_job_tag_job_id"))

    op.drop_table("job_tag")
