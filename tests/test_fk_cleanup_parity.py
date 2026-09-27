"""Every FK to ``user.id`` and ``analysisjob.id`` must be handled when the parent goes.

Neither ``_USER_REFERENCES`` nor ``_delete_job`` can be derived from the schema at runtime
— they encode a policy (anonymise vs delete) that only a human can choose — so the risk is
that a new model adds an FK and nobody updates the list. That failure is invisible in
development: SQLite does not enforce foreign keys by default, so the orphaned rows just sit
there, and the first symptom is a ``ForeignKeyViolation`` on a production PostgreSQL when an
admin deletes a job or a user.

Both lists carry a comment asking to be kept in lock-step. These tests are that comment,
mechanised. They cover three user FKs (``intel_rule``, ``intel_rule_match``,
``tag_definition``) and two job FKs (``intel_rule_match``, ``webhook_delivery``) that had
gone missing. ``test_delete_job_and_user_with_foreign_keys_enforced`` is the behavioural
half — this file only checks that nothing was forgotten.
"""

from __future__ import annotations

import inspect

import app.models  # imported for Base.metadata as well as the direct references below
from app.database import Base


def _fks_to(target: str) -> set[str]:
    """``{"table.column"}`` for every FK pointing at *target* (e.g. ``"user.id"``)."""
    return {f"{table.name}.{column.name}" for table in Base.metadata.sorted_tables for column in table.columns for fk in column.foreign_keys if str(fk.target_fullname) == target}


def _model_name(table: str) -> str:
    """``"intel_rule_match"`` -> ``"IntelRuleMatch"``."""
    return "".join(part.title() for part in table.split("_"))


def _database_cleans(ref: str, target: str) -> bool:
    table, column = ref.split(".")
    return any(fk.target_fullname == target and fk.ondelete in {"CASCADE", "SET NULL"} for fk in Base.metadata.tables[table].c[column].foreign_keys)


def test_every_user_fk_is_either_anonymised_or_deleted():
    from app.routers import admin

    anonymised = {f"{model.__tablename__}.{column}" for model, column in admin._USER_REFERENCES}
    source = inspect.getsource(admin._clear_user_references)

    missing = []
    for ref in sorted(_fks_to("user.id")):
        if _database_cleans(ref, "user.id"):
            continue
        if ref in anonymised:
            continue
        # Not anonymised, so it must be deleted outright — the choice made for rows that
        # would still *act* without an owner rather than merely record who acted.
        if f"delete({_model_name(ref.split('.')[0])})" not in source:
            missing.append(ref)

    assert not missing, (
        f"FK(s) to user.id unhandled when a user is deleted: {missing}. Add the column to "
        f"admin._USER_REFERENCES to anonymise it, or delete the rows in "
        f"_clear_user_references if an ownerless row would still act (a token still "
        f"authenticates; an intel rule still fires webhooks)."
    )


def _code_only(source: str) -> str:
    """*source* with comments and docstrings stripped, so prose cannot satisfy a check."""
    import io
    import tokenize

    kept = []
    prev = tokenize.INDENT
    for tok in tokenize.generate_tokens(io.StringIO(source).readline):
        if tok.type == tokenize.COMMENT:
            continue
        # A string alone on a logical line is a docstring, not an expression.
        if tok.type == tokenize.STRING and prev in (tokenize.INDENT, tokenize.NEWLINE, tokenize.NL):
            continue
        kept.append(tok.string)
        if tok.type not in (tokenize.NL, tokenize.NEWLINE, tokenize.INDENT, tokenize.DEDENT):
            prev = tok.type
        else:
            prev = tok.type
    return " ".join(kept)


def _job_fks_missing_from(*sources: str) -> list[str]:
    """Every FK to ``analysisjob.id`` that no single *source* deletes **by job**.

    Three things this has to resist, each of which produced a green run while the real
    delete was gone:

    * **The delete must be job-scoped**, not merely present. Both cleanup paths call an
      entity-side helper that also deletes from ``comment``, ``intel_rule_match`` and
      ``webhook_delivery`` — scoped to an orphaned *entity*, not to the job.
    * **Both halves must be in the same function.** Concatenating the sources let the
      helper's ``delete(IntelRuleMatch)`` stand in for the job-scoped one next door.
    * **Comments and docstrings do not count.** ``_delete_job`` explains itself with the
      words ``IntelRuleMatch.job_id`` directly above the call, which satisfied a plain
      substring test on its own.

    Every table with an FK to ``analysisjob.id`` carries a ``job_id`` column by
    construction, so requiring the predicate is safe for all of them.
    """
    # taskresult is the one genuine ORM cascade and so needs no explicit delete.
    assert 'cascade="all, delete-orphan"' in inspect.getsource(app.models.AnalysisJob)

    bodies = [_code_only(s) for s in sources]
    missing = []
    for ref in sorted(_fks_to("analysisjob.id")):
        if _database_cleans(ref, "analysisjob.id"):
            continue
        table = ref.split(".")[0]
        if table == "taskresult":
            continue
        model = _model_name(table)
        if not any(f"delete ( {model} )" in b and f"{model} . job_id" in b for b in bodies):
            missing.append(ref)
    return missing


def test_every_job_fk_is_cleared_before_the_job_row_goes():
    from app.intel import entities
    from app.routers import jobs

    # _delete_job plus the helper it delegates the entity-side cleanup to.
    missing = _job_fks_missing_from(inspect.getsource(jobs._delete_job), inspect.getsource(entities.remove_entity_links_for_job_async))

    assert not missing, (
        f"FK(s) to analysisjob.id with no cleanup before the job row is deleted: {missing}. "
        f"Add an explicit delete() to _delete_job — none of these columns carries "
        f"ondelete=, and AnalysisJob declares no parent-side relationship to them, so no "
        f"cascade fires."
    )


def test_the_upload_prune_sweep_clears_the_same_job_fks():
    """The worker deletes jobs too, and the guard has to know that.

    An admin clicking Delete was never the only path to `db.delete(job)`: the nightly
    upload prune removes the jobs that own an expired file. It cleared nothing, which is
    exactly the gap this file exists to catch — a second call site nobody kept in
    lock-step. Worse there than in the route, because the sweep had already deleted the
    upload from storage by the time the commit raised, so the rollback restored a row
    pointing at a file that was gone.
    """
    from app.intel import entities
    from app.workers import tasks

    missing = _job_fks_missing_from(
        inspect.getsource(tasks._clear_job_references),
        inspect.getsource(entities.remove_entity_links_for_job_sync),
    )

    assert not missing, (
        f"FK(s) to analysisjob.id left dangling by the upload retention sweep: {missing}. "
        f"Add an explicit delete() to tasks._clear_job_references — the worker path gets "
        f"no ORM cascade either, and here the IntegrityError arrives after the upload has "
        f"already been removed from storage."
    )
