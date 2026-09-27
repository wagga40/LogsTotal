"""AI interpretation of a finished job.

Split the way ``app/intel/`` and ``app/similarity/`` are:

* :mod:`app.ai.digest` and :mod:`app.ai.providers` are **pure** — no FastAPI, no Huey, no
  SQLAlchemy, no network. They take plain dicts and return plain dicts, so they are Tier-1
  testable and cannot trip a lazy load when called from a worker thread.
* :mod:`app.ai.client` is the impure half: one sync outbound request, worker-side only.
"""
