"""Store each rule's source text once, in rule_text, instead of on every finding.

`finding.rule_content` held the full Sigma YAML on every finding of every job; 72.7% of the
column was duplicates in the development database. Findings now reference a content-addressed
`rule_text` row by SHA-256.

The text moves in id batches and is copied as written. `RuleText.content` is the app's
`CompressedText`, which reads plaintext unchanged; the compression backfill encodes these rows
later, so this migration needs no codec and no app import.

SQLite takes the in-place forms, `ALTER TABLE ... ADD COLUMN ... REFERENCES` and (3.35+)
`DROP COLUMN`, because Alembic's batch mode would rebuild the whole finding table, the
largest in the schema, at boot. Measured: the drop takes 23 ms on 200k rows.

Revision ID: f3a91c2e7d40
Revises: e064602640a4
"""

import hashlib
import logging
import sqlite3

import sqlalchemy as sa

from alembic import op

revision = "f3a91c2e7d40"
down_revision = "e064602640a4"
branch_labels = None
depends_on = None

_log = logging.getLogger("alembic.runtime.migration")
BATCH = 2000


def _columns(conn, table: str) -> set[str]:
    return {c["name"] for c in sa.inspect(conn).get_columns(table)}


def _insert_ignoring_duplicates(conn, rows: list[dict]) -> None:
    if not rows:
        return
    table = sa.table("rule_text", sa.column("sha256", sa.String), sa.column("content", sa.Text))
    if conn.dialect.name == "postgresql":
        from sqlalchemy.dialects.postgresql import insert
    else:
        from sqlalchemy.dialects.sqlite import insert
    conn.execute(insert(table).values(rows).on_conflict_do_nothing(index_elements=["sha256"]))


def upgrade() -> None:
    conn = op.get_bind()
    sqlite = conn.dialect.name == "sqlite"
    if "rule_text" not in sa.inspect(conn).get_table_names():
        op.create_table(
            "rule_text",
            sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
            sa.Column("sha256", sa.String(length=64), nullable=False),
            sa.Column("content", sa.Text(), nullable=False),
            sa.Column("created_at", sa.DateTime(), server_default=sa.text("(CURRENT_TIMESTAMP)"), nullable=False),
            sa.PrimaryKeyConstraint("id"),
            sa.UniqueConstraint("sha256", name="uq_rule_text_sha256"),
        )
    columns = _columns(conn, "finding")
    # Tolerant: a start with AUTO_MIGRATE=false adds rule_text_id through the legacy patcher.
    if "rule_text_id" not in columns:
        if sqlite:
            op.execute("ALTER TABLE finding ADD COLUMN rule_text_id INTEGER REFERENCES rule_text (id)")
        else:
            op.add_column("finding", sa.Column("rule_text_id", sa.Integer(), sa.ForeignKey("rule_text.id"), nullable=True))
    if "ix_finding_rule_text_id" not in {i["name"] for i in sa.inspect(conn).get_indexes("finding")}:
        op.create_index("ix_finding_rule_text_id", "finding", ["rule_text_id"])
    if "rule_content" not in columns:
        return

    finding = sa.table("finding", sa.column("id", sa.Integer), sa.column("rule_content", sa.Text), sa.column("rule_text_id", sa.Integer))
    rule_text = sa.table("rule_text", sa.column("id", sa.Integer), sa.column("sha256", sa.String))
    last, moved = 0, 0
    while True:
        rows = conn.execute(
            sa.select(finding.c.id, finding.c.rule_content)
            .where(finding.c.id > last, finding.c.rule_content.isnot(None), finding.c.rule_content != "")
            .order_by(finding.c.id)
            .limit(BATCH)
        ).all()
        if not rows:
            break
        last = rows[-1][0]
        shas = {fid: hashlib.sha256(content.encode("utf-8")).hexdigest() for fid, content in rows}
        contents = {shas[fid]: content for fid, content in rows}
        known = dict(conn.execute(sa.select(rule_text.c.sha256, rule_text.c.id).where(rule_text.c.sha256.in_(list(contents)))).all())
        _insert_ignoring_duplicates(conn, [{"sha256": sha, "content": c} for sha, c in contents.items() if sha not in known])
        known.update(conn.execute(sa.select(rule_text.c.sha256, rule_text.c.id).where(rule_text.c.sha256.in_([s for s in contents if s not in known]))).all())
        conn.execute(
            finding.update().where(finding.c.id == sa.bindparam("fid")).values(rule_text_id=sa.bindparam("rid")),
            [{"fid": fid, "rid": known[sha]} for fid, sha in shas.items()],
        )
        moved += len(rows)
        if moved % (BATCH * 25) == 0:
            _log.info("rule_text_dedupe: %d findings moved", moved)
    _log.info("rule_text_dedupe: %d findings moved to %d distinct rule texts", moved, conn.execute(sa.text("SELECT count(*) FROM rule_text")).scalar())

    if sqlite and sqlite3.sqlite_version_info >= (3, 35, 0):
        op.execute("ALTER TABLE finding DROP COLUMN rule_content")
    else:
        with op.batch_alter_table("finding") as batch:
            batch.drop_column("rule_content")


def downgrade() -> None:
    """Lossless: every finding gets its rule's text back in `rule_content`.

    Rows the compression backfill encoded (`zs1:` + base64 zstd) are decoded here, so the older
    code, which knows nothing of the encoding, reads plain YAML.
    """
    conn = op.get_bind()
    if "rule_content" not in _columns(conn, "finding"):
        op.add_column("finding", sa.Column("rule_content", sa.Text(), nullable=True))
    finding = sa.table("finding", sa.column("id", sa.Integer), sa.column("rule_content", sa.Text), sa.column("rule_text_id", sa.Integer))
    rule_text = sa.table("rule_text", sa.column("id", sa.Integer), sa.column("content", sa.Text))
    last = 0
    while True:
        rows = conn.execute(
            sa.select(finding.c.id, rule_text.c.content)
            .join(rule_text, rule_text.c.id == finding.c.rule_text_id)
            .where(finding.c.id > last)
            .order_by(finding.c.id)
            .limit(BATCH)
        ).all()
        if not rows:
            break
        last = rows[-1][0]
        conn.execute(
            finding.update().where(finding.c.id == sa.bindparam("fid")).values(rule_content=sa.bindparam("text")),
            [{"fid": fid, "text": _decoded(content)} for fid, content in rows],
        )
    op.drop_index("ix_finding_rule_text_id", table_name="finding")
    # SQLite cannot DROP a column that carries a REFERENCES clause; batch mode rebuilds the table.
    with op.batch_alter_table("finding") as batch:
        batch.drop_column("rule_text_id")
    op.drop_table("rule_text")


def _decoded(content: str) -> str:
    if not content.startswith("zs1:"):
        return content
    import base64

    try:
        from compression import zstd
    except ImportError:  # Python < 3.14
        from backports import zstd
    return zstd.decompress(base64.b64decode(content[4:])).decode("utf-8")
