"""labels become rules: is_builtin / builtin_key on intel_rule, and a switch above them

Revision ID: a94e5d20c1f7
Revises: f1a2c37b5e08
Create Date: 2026-08-30 20:55:00.000000

`lolbin`, `dga`, `privileged` and the rest were **system labels**: derived from
`Entity.attributes_json` at render time, never stored, and impossible to modify — you could
not recolour one, turn one off, or add a nineteenth beside them, because the vocabulary was
a Python dict rather than data. They are ordinary rules now, seeded by
`init_db.py::sync_builtin_rules` from `app/intel/builtin_rules.py`.

`is_builtin` is what three code paths branch on, and each fails *silently* without it: a
built-in has no owner and would therefore skip every private job; `MAX_MATCHES_PER_RULE`
would cap labelling at 100 entities per job; and it must not spend anybody's
`WATCH_RULES_MAX_PER_USER` budget. `builtin_key` is the seed's identity, so re-syncing
updates rather than duplicates and a deleted built-in can be restored.

`sitesettings.builtin_rules_enabled` gates the whole pass. It is the one switch above the
nineteen individual toggles, and it gates *evaluation* rather than display because that is
where the cost is: labelling writes a row per entity per job, the only thing in this app
that does.

**The rows are not created here.** Seeding is policy, and policy a task re-syncs does not
belong in a schema revision — `WorkflowDef` has been loaded from `init_db.py` since the
first release for the same reason. Nor are existing entities labelled: run
`POST /admin/backfill-builtin-labels` (Maintenance tab) once after upgrading, or historical
entities carry no label tags until a job touches them again. That is the cost the
editability is worth, and `docs/runbooks/upgrading.md` says so.

Purely additive: no `drop_table`, no `drop_column`.
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "a94e5d20c1f7"
down_revision: Union[str, None] = "f1a2c37b5e08"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    with op.batch_alter_table("intel_rule") as batch:
        batch.add_column(sa.Column("is_builtin", sa.Boolean(), nullable=False, server_default="0"))
        batch.add_column(sa.Column("builtin_key", sa.String(length=50), nullable=True))
    op.create_index("ix_intel_rule_is_builtin", "intel_rule", ["is_builtin"])
    op.create_index("ix_intel_rule_builtin_key", "intel_rule", ["builtin_key"], unique=True)

    # server_default rather than a follow-up UPDATE: every existing instance had these
    # labels (they were rendered, not stored), so the upgrade must not turn them off.
    with op.batch_alter_table("sitesettings") as batch:
        batch.add_column(sa.Column("builtin_rules_enabled", sa.Boolean(), nullable=False, server_default="1"))


def downgrade() -> None:
    with op.batch_alter_table("sitesettings") as batch:
        batch.drop_column("builtin_rules_enabled")
    op.drop_index("ix_intel_rule_builtin_key", table_name="intel_rule")
    op.drop_index("ix_intel_rule_is_builtin", table_name="intel_rule")
    with op.batch_alter_table("intel_rule") as batch:
        batch.drop_column("builtin_key")
        batch.drop_column("is_builtin")
