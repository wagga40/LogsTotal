"""covering index on entity_job_link(job_id, entity_id) for the relationship graph

`uq_entity_job` leads with `entity_id`, which serves "which jobs is this entity in?".
The relationship graph asks the opposite question on every request — "which entities are
in this job?" — in three places: the batched per-hop neighbour query, the co-occurrence
self-join (`a.job_id == b.job_id`), and the near-clique fanout guard's `GROUP BY job_id`.
Without a job-leading index each of those is a scan, which is what stands between the
graph's raised 5,000-node ceiling and a page that loads.

`render_as_batch=True` in env.py keeps this safe on SQLite.

Revision ID: a2c9f60b13e5
Revises: 397f15ab8d0a
Create Date: 2026-08-07 22:40:00.000000
"""

from typing import Sequence, Union

from alembic import op

revision: str = "a2c9f60b13e5"
down_revision: Union[str, None] = "397f15ab8d0a"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_index("ix_entity_job_link_job_entity", "entity_job_link", ["job_id", "entity_id"], unique=False)


def downgrade() -> None:
    op.drop_index("ix_entity_job_link_job_entity", table_name="entity_job_link")
