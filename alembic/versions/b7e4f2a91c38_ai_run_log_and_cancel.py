"""ai runs: verbose log column and a cancelled state

Revision ID: b7e4f2a91c38
Revises: a4c7e1d90b52
Create Date: 2026-08-15 03:30:00.000000
"""

from typing import Sequence, Union

import sqlalchemy as sa

from alembic import op

revision: str = "b7e4f2a91c38"
down_revision: Union[str, None] = "a4c7e1d90b52"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

_STATUSES_OLD = ("PENDING", "RUNNING", "COMPLETED", "FAILED")
_STATUSES_NEW = (*_STATUSES_OLD, "CANCELLED")


def upgrade() -> None:
    with op.batch_alter_table("job_ai_analysis", schema=None) as batch_op:
        batch_op.add_column(sa.Column("log_output", sa.Text(), nullable=True))
        # SQLAlchemy renders Enum as a bare VARCHAR(9) on SQLite with no CHECK constraint
        # (create_constraint has defaulted False since 1.4), and "CANCELLED" is the same
        # length as "COMPLETED" — so this alter_column is a no-op there. It is also a no-op
        # on PostgreSQL: alter_column emits a same-type cast, not the
        # `ALTER TYPE aianalysisstatus ADD VALUE 'CANCELLED'` the native enum needs.
        # See b7c4e92d1a63 / 2140405f6ea4 for the autocommit_block form that works.
        batch_op.alter_column(
            "status",
            existing_type=sa.Enum(*_STATUSES_OLD, name="aianalysisstatus"),
            type_=sa.Enum(*_STATUSES_NEW, name="aianalysisstatus"),
            existing_nullable=False,
        )


def downgrade() -> None:
    # A run already cancelled has no representation in the old set; fold it into FAILED so
    # the column stays readable after a downgrade. PostgreSQL cannot drop an enum value, and
    # an unused extra member is harmless.
    op.execute("UPDATE job_ai_analysis SET status = 'FAILED' WHERE status = 'CANCELLED'")
    with op.batch_alter_table("job_ai_analysis", schema=None) as batch_op:
        batch_op.alter_column(
            "status",
            existing_type=sa.Enum(*_STATUSES_NEW, name="aianalysisstatus"),
            type_=sa.Enum(*_STATUSES_OLD, name="aianalysisstatus"),
            existing_nullable=False,
        )
        batch_op.drop_column("log_output")
