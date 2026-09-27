"""rules over jobs: a scope on intel_rule, and a second match table for job alerts

Revision ID: f1a2c37b5e08
Revises: d3f81a6c92be
Create Date: 2026-08-30 20:05:00.000000

A rule could only ever ask a question about *entities*. `IntelRule.scope` adds the other
half: `job` criteria are the jobs list's `?q=` grammar, matched against the finished job
itself rather than against the observables inside it.

`scope` is a `String(16)` with a server default of `'entity'`, so every existing row is an
entity rule with no data migration. Not an `Enum`: on PostgreSQL a native enum can only gain
a label through `ALTER TYPE … ADD VALUE` inside an autocommit block, and `d3f81a6c92be`
exists solely because an earlier revision got that wrong and shipped. A two-value set that
may grow is not worth buying that with.

`job_rule_match` is a second table rather than a nullable `entity_id` on `intel_rule_match`,
and the reason is not stylistic. `uq_intel_rule_match(rule_id, entity_id, job_id)` is what
makes a re-run raise no duplicate alert, and **both SQLite and PostgreSQL treat NULL as
distinct in a UNIQUE index** — so `(5, NULL, 42)` would insert without limit, for exactly
the rows this feature adds and for nothing else. The guarantee would break silently and only
for the new thing. `JobTag` beside `EntityTag` is the same argument, one release earlier.

Purely additive: no `drop_table`, no `drop_column`, so nothing to add to the
rollback-unsafe list in `docs/runbooks/upgrading.md`.
"""

from typing import Sequence, Union

import fastapi_users_db_sqlalchemy
import sqlalchemy as sa
from alembic import op

revision: str = "f1a2c37b5e08"
down_revision: Union[str, None] = "d3f81a6c92be"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # batch_alter_table because SQLite cannot ALTER a column in place; a no-op wrapper on
    # PostgreSQL. The server default is what makes every existing row a valid entity rule.
    with op.batch_alter_table("intel_rule") as batch:
        batch.add_column(sa.Column("scope", sa.String(length=16), nullable=False, server_default="entity"))
    op.create_index("ix_intel_rule_scope", "intel_rule", ["scope"])

    op.create_table(
        "job_rule_match",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("rule_id", sa.Integer(), sa.ForeignKey("intel_rule.id"), nullable=False),
        sa.Column("job_id", sa.Integer(), sa.ForeignKey("analysisjob.id"), nullable=False),
        sa.Column("created_at", sa.DateTime(), server_default=sa.func.now(), nullable=False),
        sa.Column("acknowledged_at", sa.DateTime(), nullable=True),
        sa.Column("acknowledged_by_user_id", fastapi_users_db_sqlalchemy.generics.GUID(), sa.ForeignKey("user.id"), nullable=True),
        sa.UniqueConstraint("rule_id", "job_id", name="uq_job_rule_match"),
    )
    op.create_index("ix_job_rule_match_rule_id", "job_rule_match", ["rule_id"])
    op.create_index("ix_job_rule_match_job_id", "job_rule_match", ["job_id"])
    op.create_index("ix_job_rule_match_created_at", "job_rule_match", ["created_at"])
    op.create_index("ix_job_rule_match_rule_created", "job_rule_match", ["rule_id", "created_at"])


def downgrade() -> None:
    op.drop_index("ix_job_rule_match_rule_created", table_name="job_rule_match")
    op.drop_index("ix_job_rule_match_created_at", table_name="job_rule_match")
    op.drop_index("ix_job_rule_match_job_id", table_name="job_rule_match")
    op.drop_index("ix_job_rule_match_rule_id", table_name="job_rule_match")
    op.drop_table("job_rule_match")
    op.drop_index("ix_intel_rule_scope", table_name="intel_rule")
    with op.batch_alter_table("intel_rule") as batch:
        batch.drop_column("scope")
