"""Tier-2 test: the attr: query kind narrows entities by attributes_json via SQL."""

from __future__ import annotations

from sqlalchemy import select

import app.models  # noqa: F401 — populate Base.metadata
from app.intel.attributes import compute_attributes
from app.intel.queries import apply_entity_filters, parse_search_query
from app.json_utils import dumps as json_dumps
from app.models import Entity


def _seed(db, value, etype):
    attrs = compute_attributes(value, etype)
    db.add(Entity(value=value, entity_type=etype, attributes_json=json_dumps(attrs) if attrs else None))


def _run(db, q):
    parsed = parse_search_query(q)
    stmt = apply_entity_filters(select(Entity), parsed_query=parsed)
    return sorted(e.value for e in db.execute(stmt).scalars().all())


def test_attr_lolbin_narrows_to_lolbins(sync_db):
    _seed(sync_db, "certutil.exe", "executable")  # LOLBIN
    _seed(sync_db, "my-custom-tool.exe", "executable")  # not
    sync_db.commit()
    assert _run(sync_db, "attr:lolbin") == ["certutil.exe"]


def test_attr_private_narrows_to_rfc1918(sync_db):
    _seed(sync_db, "10.0.0.1", "ip_address")
    _seed(sync_db, "8.8.8.8", "ip_address")
    sync_db.commit()
    assert _run(sync_db, "attr:private") == ["10.0.0.1"]


def test_attr_md5_does_not_match_sha256(sync_db):
    _seed(sync_db, "A" * 32, "hash")  # md5
    _seed(sync_db, "B" * 64, "hash")  # sha256
    sync_db.commit()
    assert _run(sync_db, "attr:md5") == ["A" * 32]


def test_attr_dga_does_not_falsely_match_suspicious_only(sync_db):
    # domain with suspicious_tld=True but looks_dga=False must NOT match attr:dga
    _seed(sync_db, "shop.tk", "domain")
    _seed(sync_db, "x7k9q2m4p8w1z5b3n6v0.com", "domain")  # dga
    sync_db.commit()
    assert _run(sync_db, "attr:dga") == ["x7k9q2m4p8w1z5b3n6v0.com"]
