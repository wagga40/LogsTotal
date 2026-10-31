"""No index may duplicate the leading column of a composite on the same table.

A single-column index on the column a unique constraint or composite index already leads with
answers nothing the composite does not, and costs disk plus a second B-tree update on every
insert. Twenty of them were found by this scan and dropped in migration e064602640a4; the
column-level `index=True` habit is how they appeared, so the scan runs on every build.
"""

from __future__ import annotations

import pytest
from sqlalchemy import UniqueConstraint, create_engine, text

import app.models  # noqa: F401  (registers every table)
from app.database import Base


def _composites(table) -> list[tuple[str, list[str]]]:
    found = [(c.name, [col.name for col in c.columns]) for c in table.constraints if isinstance(c, UniqueConstraint) and len(c.columns) > 1]
    for index in table.indexes:
        partial = any(options.get("where") is not None for options in index.dialect_options.values())
        if len(index.columns) > 1 and not partial:
            found.append((index.name, [col.name for col in index.columns]))
    return found


def test_no_single_column_index_repeats_a_composites_leading_column():
    redundant = []
    for table in Base.metadata.sorted_tables:
        leaders = {cols[0]: name for name, cols in _composites(table)}
        for index in table.indexes:
            cols = [col.name for col in index.columns]
            if len(cols) == 1 and not index.unique and cols[0] in leaders:
                redundant.append(f"{table.name}.{index.name} (covered by {leaders[cols[0]]})")
    assert redundant == [], "drop index=True on these columns — the composite already serves them"


@pytest.mark.parametrize(
    "table, column",
    [
        ("entity_job_link", "job_id"),
        ("entity_job_link", "entity_id"),
        ("finding", "task_result_id"),
        ("finding_entity_link", "finding_id"),
        ("entity_tag", "entity_id"),
        ("job_tag", "job_id"),
        ("entity_relationship_evidence", "relationship_id"),
        ("intel_rule_match", "rule_id"),
        ("case_job_link", "case_id"),
    ],
)
def test_lookups_on_a_dropped_column_still_use_an_index(table, column):
    """The point of dropping them safely: the planner answers from the composite instead."""
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    with engine.connect() as conn:
        plan = " ".join(str(row[-1]) for row in conn.execute(text(f"EXPLAIN QUERY PLAN SELECT * FROM {table} WHERE {column} = 1")))
    assert "USING INDEX" in plan or "USING COVERING INDEX" in plan, plan
