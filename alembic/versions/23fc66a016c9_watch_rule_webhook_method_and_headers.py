"""watch rule webhook method and headers

Makes a rule's webhook configurable beyond a bare URL: the HTTP method and a JSON object of
extra headers (an auth token the receiver expects, a routing key, …).

Header values are stored in plaintext by design — the Fernet-encrypted signing secret is
the field for anything sensitive, and mixing the two would make it unclear which one is
protected.

NOTE: alembic autogenerate also proposed dropping ix_analysisjob_*, ix_backgroundtask_*,
ix_entity_type, ix_entity_value and ix_finding_rule_sig_id. Those are created by
`app/database.py` outside the ORM metadata, so they look like drift to `compare_metadata`
but are load-bearing in production. They are deliberately not dropped here.

Revision ID: 23fc66a016c9
Revises: 13a7f984fee0
Create Date: 2026-08-07
"""

from typing import Sequence, Union

import sqlalchemy as sa

from alembic import op

revision: str = "23fc66a016c9"
down_revision: Union[str, None] = "13a7f984fee0"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    with op.batch_alter_table("intel_rule", schema=None) as batch_op:
        batch_op.add_column(sa.Column("webhook_method", sa.String(length=10), server_default="POST", nullable=False))
        batch_op.add_column(sa.Column("webhook_headers_json", sa.Text(), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table("intel_rule", schema=None) as batch_op:
        batch_op.drop_column("webhook_headers_json")
        batch_op.drop_column("webhook_method")
