"""An id or page number past what the database can bind is a 404, never a 500.

FastAPI accepts any Python int for an `int` path or query parameter. SQLite refuses a value
past int8 at bind time (`OverflowError`) and PostgreSQL one past int4 (`DataError`), and
both escaped as a 500 — on anonymous routes such as `/jobs/{job_id}` too. The guard lives in
one app-wide dependency, so this walks the live route table rather than sampling it: a new
`{..._id}` route is covered the moment it is registered.
"""

from __future__ import annotations

import re

import pytest
from starlette.routing import Mount

from app.database import INT4_MAX, parse_row_id
from app.main import app

HUGE = "99999999999999999999"


def _get_paths_with_ids() -> list[str]:
    out: list[str] = []

    def walk(routes, prefix: str) -> None:
        for r in routes:
            if type(r).__name__ == "_IncludedRouter":
                walk(r.original_router.routes, prefix + getattr(r.include_context, "prefix", ""))
            elif isinstance(r, Mount):
                continue
            elif "GET" in (getattr(r, "methods", None) or set()):
                path = prefix + r.path
                if re.search(r"\{\w+_id\}", path):
                    out.append(path)

    walk(app.router.routes, "")
    return sorted(set(out))


def test_the_walk_finds_the_routes():
    """Otherwise the parametrised test below could pass by testing nothing."""
    paths = _get_paths_with_ids()
    assert "/jobs/{job_id}" in paths
    assert len(paths) > 40


@pytest.mark.parametrize("path", _get_paths_with_ids())
async def test_an_out_of_range_id_is_not_a_server_error(admin_client, path):
    url = re.sub(r"\{\w+_id\}", HUGE, path)
    resp = await admin_client.get(url)
    assert resp.status_code < 500, (url, resp.status_code)


@pytest.mark.parametrize("path", ["/jobs/2147483648", "/jobs/2147483648/similar"])
async def test_an_id_past_postgresql_int4_is_a_404(test_client, path):
    """SQLite would happily look up 2**31 and find nothing; PostgreSQL raises binding it.
    Refusing at the boundary is what makes the two backends answer alike."""
    assert (await test_client.get(path)).status_code == 404


@pytest.mark.parametrize("path", ["/jobs", "/jobs/table-partial", "/admin/users", "/admin/activity"])
async def test_an_out_of_range_page_is_not_a_server_error(admin_client, path):
    resp = await admin_client.get(f"{path}?page={HUGE}")
    assert resp.status_code < 500, (path, resp.status_code)


@pytest.mark.parametrize(
    "value", [f"-{HUGE}", f"+{HUGE}", f"{HUGE}.0", "9" * 4500, "\uff19" * 20, "²"], ids=["negative", "positive-sign", "decimal", "long", "unicode", "superscript"]
)
async def test_numeric_variants_never_escape_the_route_bounds(test_client, value):
    assert (await test_client.get(f"/jobs/{value}")).status_code == 404
    assert (await test_client.get("/jobs", params={"page": value})).status_code == 404


@pytest.mark.parametrize(
    "value", ["1" + "0" * 4500, "9" * 4500, "\uff19" * 4500, "²", str(INT4_MAX + 1)], ids=["long-power", "long-nines", "unicode", "superscript", "int4-overflow"]
)
def test_row_id_parser_refuses_unbindable_values(value):
    assert parse_row_id(value) is None


@pytest.mark.parametrize("value, expected", [(str(INT4_MAX), INT4_MAX), ("0" * 4500 + "1", 1), ("0" * 4500, 0)], ids=["int4-max", "leading-zeroes", "zero"])
def test_row_id_parser_preserves_small_values(value, expected):
    assert parse_row_id(value) == expected
