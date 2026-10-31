"""Drop single-column indexes that a composite index already covers.

Each index below is on the leading column of a unique constraint or composite index on the
same table (none of them partial), so both SQLite and PostgreSQL answer an equality or range
on that column from the composite. Keeping both costs disk and a second B-tree update on every
insert into tables the worker writes in bulk (entity links, finding links, evidence).
`tests/test_index_hygiene.py` fails on a new one.

Revision ID: e064602640a4
Revises: b8d46f1e932a
"""

import sqlalchemy as sa

from alembic import op

revision = "e064602640a4"
down_revision = "b8d46f1e932a"
branch_labels = None
depends_on = None

#: (table, index, column) — the index the column-level `index=True` used to create.
REDUNDANT = (
    ("activity_event", "ix_activity_event_category", "category"),
    ("case_ai_analysis", "ix_case_ai_analysis_case_id", "case_id"),
    ("case_entity_link", "ix_case_entity_link_case_id", "case_id"),
    ("case_job_link", "ix_case_job_link_case_id", "case_id"),
    ("entity_enrichment_result", "ix_entity_enrichment_result_entity_id", "entity_id"),
    ("entity_job_link", "ix_entity_job_link_entity_id", "entity_id"),
    ("entity_job_link", "ix_entity_job_link_job_id", "job_id"),
    ("entity_relationship", "ix_entity_relationship_source_entity_id", "source_entity_id"),
    ("entity_relationship_evidence", "ix_entity_relationship_evidence_relationship_id", "relationship_id"),
    ("entity_tag", "ix_entity_tag_entity_id", "entity_id"),
    ("finding", "ix_finding_task_result_id", "task_result_id"),
    ("finding_entity_link", "ix_finding_entity_link_finding_id", "finding_id"),
    ("intel_rule", "ix_intel_rule_enabled", "enabled"),
    ("intel_rule", "ix_intel_rule_owner_user_id", "owner_user_id"),
    ("intel_rule_match", "ix_intel_rule_match_rule_id", "rule_id"),
    ("job_ai_analysis", "ix_job_ai_analysis_job_id", "job_id"),
    ("job_rule_match", "ix_job_rule_match_rule_id", "rule_id"),
    ("job_tag", "ix_job_tag_job_id", "job_id"),
    ("job_watch", "ix_job_watch_job_id", "job_id"),
    ("job_watch_event", "ix_job_watch_event_watch_id", "watch_id"),
)


def _existing(conn, table: str) -> set[str]:
    return {index["name"] for index in sa.inspect(conn).get_indexes(table)}


def upgrade() -> None:
    conn = op.get_bind()
    # Tolerant: a database whose legacy patcher never created one of these must still migrate.
    for table, index, _column in REDUNDANT:
        if index in _existing(conn, table):
            op.drop_index(index, table_name=table)


def downgrade() -> None:
    conn = op.get_bind()
    for table, index, column in REDUNDANT:
        if index not in _existing(conn, table):
            op.create_index(index, table, [column])
