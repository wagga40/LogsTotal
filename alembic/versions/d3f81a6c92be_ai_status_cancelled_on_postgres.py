"""add CANCELLED to the aianalysisstatus enum, which b7e4f2a91c38 never did

Revision ID: d3f81a6c92be
Revises: c8f24a1b6d90
Create Date: 2026-08-24 13:05:00.000000

`b7e4f2a91c38` widened `AiAnalysisStatus` with `batch_alter_table.alter_column`, and its own
comment says why that is a no-op on both backends — SQLite renders the column as a bare
VARCHAR, and on PostgreSQL `alter_column` emits a same-type cast rather than the
`ALTER TYPE ... ADD VALUE` a native enum needs. It then pointed at `b7c4e92d1a63` /
`2140405f6ea4` for the form that works, and never used it.

The consequence is confined to **upgraded** PostgreSQL instances — a fresh one gets all five
labels from `create_all`, and SQLite has no enum type at all — which is why it survived a
release: the deployments that hit it are exactly the ones a release is for. Three sites bind
the missing label, and the third is the one that hurts:

* `routers/ai.py::ai_cancel` and `workers/tasks.py` — writes; stopping a run fails.
* `routers/admin.py` — a *read*, `status.in_([COMPLETED, FAILED, CANCELLED])` in the recent-AI
  block of `/admin/tasks`. It binds a label the type does not have, so the whole page 500s
  whether or not anyone ever stops a run.

Idempotent (`IF NOT EXISTS`), so it is safe on an instance whose type already carries the
label — including every fresh install created by `create_all`.
"""

from typing import Sequence, Union

from alembic import op

revision: str = "d3f81a6c92be"
down_revision: Union[str, None] = "c8f24a1b6d90"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # SQLite stores Enum columns as VARCHAR — nothing to alter there. PostgreSQL
    # uses native enum types, which must learn the new member name.
    # ADD VALUE cannot run inside a transaction block, hence autocommit.
    if op.get_bind().dialect.name == "postgresql":
        with op.get_context().autocommit_block():
            op.execute("ALTER TYPE aianalysisstatus ADD VALUE IF NOT EXISTS 'CANCELLED'")


def downgrade() -> None:
    # PostgreSQL enums cannot drop values; the extra member is harmless. No-op.
    pass
