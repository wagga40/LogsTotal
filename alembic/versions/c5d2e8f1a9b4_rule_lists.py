"""rules as data: seed_hash on intel_rule, and the named lists a condition can test

Revision ID: c5d2e8f1a9b4
Revises: a94e5d20c1f7
Create Date: 2026-09-06 15:40:00.000000

The shipped label rules are seeded from `rules/*.yml` now, with criteria written in the
search grammar instead of `attr:` pointers. Two things that needed a column:

`intel_rule.seed_hash` — the hash of the definition a row was last seeded with. The seeder
applies the file's newer version to a row that still equals its hash (nobody edited it) and
leaves a row that differs alone (an admin's edit). NULL on rules people wrote. Existing
built-ins predate the column and are treated as unedited when they still carry the old
seed's `attr:<key>` criteria — the rules feature has not shipped in a release, so nothing
an operator wrote is at stake.

`rule_list` / `rule_list_value` — the named sets `list:<name>` tests (LOLBAS, GTFOBins,
suspicious TLDs, and whatever an admin adds). Rows rather than a text column, so the term
compiles to an EXISTS over the `(list_id, value)` unique index and nothing has to be
resolved at parse time or cached across processes. `pattern` is the LIKE form for suffix
lists, computed at write time.

Purely additive: no `drop_table`, no `drop_column`, so nothing to add to the
rollback-unsafe list in `docs/runbooks/upgrading.md`.
"""

from typing import Sequence, Union

import sqlalchemy as sa

from alembic import op

revision: str = "c5d2e8f1a9b4"
down_revision: Union[str, None] = "a94e5d20c1f7"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    with op.batch_alter_table("intel_rule") as batch:
        batch.add_column(sa.Column("seed_hash", sa.String(length=64), nullable=True))

    op.create_table(
        "rule_list",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("name", sa.String(length=50), nullable=False),
        sa.Column("match", sa.String(length=16), nullable=False, server_default="exact"),
        sa.Column("description", sa.String(length=500), nullable=True),
        sa.Column("seed_hash", sa.String(length=64), nullable=True),
        sa.Column("created_at", sa.DateTime(), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(), server_default=sa.func.now(), nullable=False),
        sa.UniqueConstraint("name", name="uq_rule_list_name"),
    )
    op.create_table(
        "rule_list_value",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("list_id", sa.Integer(), sa.ForeignKey("rule_list.id", ondelete="CASCADE"), nullable=False),
        sa.Column("value", sa.String(length=200), nullable=False),
        sa.Column("pattern", sa.String(length=220), nullable=False),
        sa.UniqueConstraint("list_id", "value", name="uq_rule_list_value"),
    )


def downgrade() -> None:
    op.drop_table("rule_list_value")
    op.drop_table("rule_list")
    with op.batch_alter_table("intel_rule") as batch:
        batch.drop_column("seed_hash")
