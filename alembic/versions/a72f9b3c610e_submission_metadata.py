"""Isolate submission filenames and effective types from deduplicated files."""

import sqlalchemy as sa

from alembic import op

revision = "a72f9b3c610e"
down_revision = "59aefc585fb3"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Reuse the existing column's enum type on PostgreSQL; do not create/drop logtype.
    file_type = next(c["type"] for c in sa.inspect(op.get_bind()).get_columns("logfile") if c["name"] == "log_type")
    if hasattr(file_type, "create_type"):
        file_type.create_type = False
    op.add_column("analysisjob", sa.Column("submitted_filename", sa.String(512), nullable=True))
    op.add_column("analysisjob", sa.Column("effective_log_type", file_type, nullable=False, server_default="UNKNOWN"))
    op.execute("UPDATE analysisjob SET effective_log_type = (SELECT log_type FROM logfile WHERE logfile.id = analysisjob.file_id)")
    # Filenames deliberately stay NULL: the shared name's submitter is unprovable.


def downgrade() -> None:
    with op.batch_alter_table("analysisjob") as batch:
        batch.drop_column("effective_log_type")
        batch.drop_column("submitted_filename")
