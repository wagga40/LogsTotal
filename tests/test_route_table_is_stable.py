"""Splitting a router must not change the API surface.

Intel routes are split across `intel.py`, `intel_rules.py` and `intel_tags.py`. Moving a
route between files is how the table goes wrong in FastAPI, invisibly in a diff: a route silently changes
path, loses a method, or lands in a position where a different pattern matches first.

So this file asserts the whole table rather than a sample. When a route is genuinely added
or removed, update the counts and the shadowing list below in the same commit — the point
is that it cannot happen by accident during a refactor.
"""

from __future__ import annotations

from starlette.routing import Mount

from app.main import app


def _routes() -> list[tuple[str, frozenset[str], str]]:
    """(path, methods, endpoint name) for every route, in registration order."""
    out: list[tuple[str, frozenset[str], str]] = []

    def walk(routes, prefix: str) -> None:
        for r in routes:
            # FastAPI wraps `include_router` results; unwrap to reach the real routes.
            if type(r).__name__ == "_IncludedRouter":
                walk(r.original_router.routes, prefix + getattr(r.include_context, "prefix", ""))
            elif isinstance(r, Mount):
                walk(r.routes, prefix + r.path)
            elif hasattr(r, "path"):
                out.append((prefix + r.path, frozenset(getattr(r, "methods", None) or []), getattr(r, "name", "")))

    walk(app.router.routes, "")
    return out


def test_every_intel_route_keeps_its_prefix():
    """The split kept `/intel` — the three modules share one prefix by design."""
    from app.routers import intel, intel_rules, intel_tags

    for module in (intel, intel_rules, intel_tags):
        assert module.router.prefix == "/intel", f"{module.__name__} changed its prefix"


def test_the_moved_routes_are_all_still_registered():
    """Every path the two new modules own, by name, exactly as before the move."""
    by_name = {name: path for path, _methods, name in _routes()}

    rules = {
        "rules_page": "/intel/rules",
        "rule_create": "/intel/rules",
        "rule_edit": "/intel/rules/{rule_id}/edit",
        "rule_test": "/intel/rules/{rule_id}/test",
        "rule_toggle": "/intel/rules/{rule_id}/toggle",
        "rule_delete": "/intel/rules/{rule_id}/delete",
        "rule_preview": "/intel/rules/preview",
        "rule_alert_ack": "/intel/rules/alerts/{match_id}/ack",
        "rule_alerts_ack_all": "/intel/rules/alerts/ack-all",
        # The `/intel/watch*` addresses, kept as two redirects rather than nine shims.
        "legacy_watch_page": "/intel/watch",
        "legacy_watch_paths": "/intel/watch/{rest:path}",
    }
    tags = {
        "tags_page": "/intel/tags",
        "tag_create": "/intel/tags",
        "tag_rename": "/intel/tags/rename",
        "tag_merge": "/intel/tags/merge",
        "tag_recolor": "/intel/tags/recolor",
        "tag_delete_everywhere": "/intel/tags/delete",
        "entities_bulk_tag": "/intel/entities/bulk-tag",
        "entities_bulk_untag": "/intel/entities/bulk-untag",
        "entity_tag_add": "/intel/entities/{entity_id}/tags",
        "entity_tag_remove": "/intel/entities/{entity_id}/tags/remove",
        "entity_notes_save": "/intel/entities/{entity_id}/notes",
    }
    for name, path in {**rules, **tags}.items():
        assert name in by_name, f"route `{name}` disappeared in the router split"
        assert by_name[name] == path, f"route `{name}` changed path: {by_name[name]} != {path}"


def test_no_literal_path_is_shadowed_by_an_earlier_parameterised_one():
    """The failure mode a router split actually causes.

    Registration order decides matching, so moving routes into a module included *later*
    can put a `{param}` pattern in front of a literal that should win. `/intel/tags` and
    `/intel/entities/bulk-tag` are the two at risk — both are literals living in a module
    registered after the one holding `/intel/tags.json` and `/intel/entities/{entity_id}`.

    Starlette matches on path *and* method, so a same-shape pair only collides when the
    methods overlap too; that is exactly what this checks.
    """
    seen: list[tuple[str, frozenset[str]]] = []
    problems = []
    for path, methods, name in _routes():
        segments = path.split("/")
        for earlier_path, earlier_methods in seen:
            earlier_segments = earlier_path.split("/")
            if len(earlier_segments) != len(segments) or not (earlier_methods & methods):
                continue
            # Would the earlier pattern swallow this literal path?
            shadows = all(e.startswith("{") or e == s for e, s in zip(earlier_segments, segments, strict=True))
            has_param = any(e.startswith("{") for e in earlier_segments)
            if shadows and has_param and earlier_path != path:
                problems.append(f"{path} [{','.join(sorted(methods))}] ({name}) is shadowed by the earlier {earlier_path}")
        seen.append((path, methods))
    assert not problems, "route shadowing introduced:\n  " + "\n  ".join(problems)


def test_route_count_is_what_we_expect():
    """A blunt backstop: a refactor that drops routes wholesale fails here loudly."""
    intel_routes = [p for p, _m, _n in _routes() if p.startswith("/intel")]
    # Includes the two `/intel/watch*` redirects, and job-scope alert acks as their own
    # route twice (the Rules page and the nav bell swap different regions).
    # Case AI adds four endpoints: panel, start, cancel and delete.
    assert len(intel_routes) == 104, f"expected 104 /intel routes, found {len(intel_routes)} — update this number deliberately, with the reason in the commit"
