"""Writing a rule on the Rules page, and what happens when it will not save.

Three behaviours here, each of which can fail in a way no route test sees because the
*status code* is right and the *experience* is not.

* **A refused save keeps the draft.** As a plain `method=POST` form, a validation error
  raising `HTTPException(400, errors[0])` would make the browser replace the page with the
  400 error screen and lose everything typed. The form submits through htmx and a refusal
  comes back as the messages alone, aimed by `HX-Retarget` at a slot inside the form, which
  leaves every field alone.
* **Every error, not the first.** `validate_spec` returns a list; the route must not take
  `[0]`.
* **The form is not on the page.** Thirty-eight of them would be 1.29 MB and 9,227 DOM nodes
  to show at most one. A row offers `GET /intel/rules/{id}/form-partial` and htmx fetches it
  once, on the first click of Edit.

The condition field's hanging indent is pinned in `tests/test_control_primitives.py`, with
the rest of the `.lt-*` guards.
"""

from __future__ import annotations

import json
import re

import pytest
from sqlalchemy import func, select

from app.models import Entity, IntelRule, RuleList, RuleListValue

HX = {"HX-Request": "true"}


def _form(**over):
    base = {"name": "A rule", "scope": "entity", "query": '"cmd.exe"', "webhook_method": "POST"}
    base.update(over)
    return base


@pytest.fixture()
async def rule(async_db, member_user):
    r = IntelRule(name="Original", owner_user_id=member_user.id, query='"cmd.exe"', entity_types="[]")
    async_db.add(r)
    await async_db.commit()
    await async_db.refresh(r)
    return r


@pytest.fixture()
async def a_list(async_db):
    """One named list, so `list:lolbas` resolves and `list:nope` does not."""
    lst = RuleList(name="lolbas", match="exact")
    async_db.add(lst)
    await async_db.flush()
    async_db.add(RuleListValue(list_id=lst.id, value="certutil.exe", pattern="certutil.exe"))
    await async_db.commit()
    return lst


class TestARefusedSaveKeepsTheDraft:
    async def test_an_unknown_list_does_not_replace_the_page(self, member_client, async_db, a_list):
        before = await async_db.scalar(select(func.count(IntelRule.id)))
        resp = await member_client.post("/intel/rules", data=_form(query="list:nope"), headers=HX)
        # 200, not 400: htmx does not swap a 4xx, so the correct status would show the
        # reader nothing at all.
        assert resp.status_code == 200
        assert resp.headers["HX-Retarget"] == "#rule-form-errors-new"
        assert resp.headers["HX-Reswap"] == "innerHTML"
        assert "unknown list: nope" in resp.text
        # The response is the messages ALONE. A whole-region reply would have carried the
        # form with it, re-rendered from the database and empty of everything typed.
        assert "rules-region" not in resp.text
        assert await async_db.scalar(select(func.count(IntelRule.id))) == before

    async def test_editing_retargets_at_that_rules_own_slot(self, member_client, async_db, rule, a_list):
        resp = await member_client.post(f"/intel/rules/{rule.id}/edit", data=_form(name="Renamed", query="list:nope"), headers=HX)
        assert resp.status_code == 200
        assert resp.headers["HX-Retarget"] == f"#rule-form-errors-{rule.id}"
        await async_db.refresh(rule)
        # Nothing was applied — not even the fields that were fine.
        assert rule.name == "Original"

    async def test_the_slot_the_server_names_exists_in_the_form(self, member_client, rule):
        """`HX-Retarget` names a selector and htmx drops the response when nothing matches,
        so the two halves have to agree. They are written in different files."""
        page = (await member_client.get("/intel/rules")).text
        assert 'id="rule-form-errors-new"' in page
        assert f'id="rule-form-errors-{rule.id}"' in (await member_client.get(f"/intel/rules/{rule.id}/form-partial")).text

    async def test_every_error_is_reported_not_just_the_first(self, member_client, a_list):
        resp = await member_client.post(
            "/intel/rules",
            data=_form(query="list:nope", webhook_url="not a url", webhook_enabled="1"),
            headers=HX,
        )
        assert "unknown list: nope" in resp.text
        assert resp.text.lower().count("<li>") >= 2

    async def test_without_htmx_it_is_still_a_400(self, member_client, a_list):
        """A caller with no slot to aim at is owed the status code."""
        resp = await member_client.post("/intel/rules", data=_form(query="list:nope"))
        assert resp.status_code == 400

    async def test_a_full_rule_budget_reports_into_the_form_too(self, member_client, monkeypatch, async_db, member_user):
        from app.config import settings

        monkeypatch.setattr(settings, "watch_rules_max_per_user", 0)
        resp = await member_client.post("/intel/rules", data=_form(), headers=HX)
        assert resp.status_code == 200
        assert resp.headers["HX-Retarget"] == "#rule-form-errors-new"
        assert "max 0" in resp.text


class TestANewlineIsWhitespace:
    """Both grammars treat a newline as a space, so a long condition can be laid out one
    term to a line. A hanging indent on the field applies to a typed newline exactly as to a
    soft wrap, which reads as Enter inserting a tab — and the layout is a supported thing to
    do, so it is worth a test."""

    async def test_a_multiline_condition_saves_and_means_the_same(self, member_client, async_db, a_list):
        entity = Entity(value="certutil.exe", entity_type="executable")
        async_db.add(entity)
        await async_db.commit()

        one_line = (await member_client.get("/intel/rules/preview", params={"query": "list:lolbas -tag:x", "scope": "entity"})).text
        multi = (await member_client.get("/intel/rules/preview", params={"query": "list:lolbas\n-tag:x", "scope": "entity"})).text
        assert one_line == multi

        resp = await member_client.post("/intel/rules", data=_form(query="list:lolbas\n-tag:x"), headers=HX)
        assert resp.status_code == 200
        saved = (await async_db.execute(select(IntelRule).where(IntelRule.name == "A rule"))).scalar_one()
        assert "\n" in saved.query


class TestTheFormIsFetched:
    async def test_the_page_carries_no_edit_form(self, member_client, rule):
        page = (await member_client.get("/intel/rules")).text
        assert f'action="/intel/rules/{rule.id}/edit"' not in page
        assert f'hx-get="/intel/rules/{rule.id}/form-partial"' in page
        # The create form is still rendered with the page, deliberately: "Start a rule from
        # this" seeds fields that have to already exist.
        assert 'action="/intel/rules"' in page

    async def test_the_partial_is_the_form(self, member_client, rule):
        resp = await member_client.get(f"/intel/rules/{rule.id}/form-partial")
        assert resp.status_code == 200
        assert f'action="/intel/rules/{rule.id}/edit"' in resp.text
        assert 'name="query"' in resp.text
        # Everything the form reads that is NOT in the route's context is a Jinja global; a
        # key missed here renders a working form over an empty help panel.
        assert "Condition syntax" in resp.text
        assert "tagCombobox(" in resp.text

    async def test_a_basic_user_is_refused(self, user_client, rule):
        """403 from the dependency, before the route runs — Intel is member-or-above."""
        assert (await user_client.get(f"/intel/rules/{rule.id}/form-partial")).status_code == 403

    async def test_a_missing_rule_is_a_404(self, member_client):
        assert (await member_client.get("/intel/rules/999999/form-partial")).status_code == 404


class TestOneActionSwapsOneThing:
    async def test_toggle_returns_the_button_alone(self, member_client, async_db, rule):
        resp = await member_client.post(f"/intel/rules/{rule.id}/toggle", headers=HX)
        assert resp.status_code == 200
        # Not the region: a full swap here destroyed every open edit form on the page along
        # with anything typed into one.
        assert "rules-region" not in resp.text
        assert resp.text.strip().startswith("<button")
        assert "Off" in resp.text
        assert 'hx-target="this"' in resp.text

    async def test_test_reports_beside_its_own_rule(self, member_client, async_db, rule):
        rule.webhook_url = "https://example.com/hook"
        rule.webhook_enabled = False
        await async_db.commit()
        resp = await member_client.post(f"/intel/rules/{rule.id}/test", headers=HX)
        assert resp.status_code == 200
        assert "rules-region" not in resp.text
        # `deliver_webhook` opens with `if not rule.webhook_enabled: return`, so "queued —
        # check the Activity tab" would point at a tab that stays empty for ever.
        assert "Send deliveries" in resp.text

    async def test_the_button_is_not_even_offered_while_deliveries_are_off(self, member_client, async_db, rule):
        rule.webhook_url = "https://example.com/hook"
        rule.webhook_enabled = False
        await async_db.commit()
        assert f'hx-post="/intel/rules/{rule.id}/test"' not in (await member_client.get("/intel/rules")).text
        rule.webhook_enabled = True
        await async_db.commit()
        assert f'hx-post="/intel/rules/{rule.id}/test"' in (await member_client.get("/intel/rules")).text


class TestTheDryRunAgreesWithThePreview:
    async def test_an_unknown_list_is_named_by_both(self, member_client, a_list):
        params = {"query": "list:nope", "scope": "entity"}
        preview = (await member_client.get("/intel/rules/preview", params=params)).text
        dry = (await member_client.post("/intel/rules/dry-run", data=params)).text
        assert "unknown list: nope" in preview
        # Not "0 alerts across 0 jobs. Nothing was written." — which is what a correct,
        # narrow rule looks like.
        assert "unknown list: nope" in dry


class TestTheHeadingCountsAgree:
    async def test_the_pill_reconciles_itself_with_the_tab_badge(self, member_client, rule):
        """The pill counted the analyst's own rules and the badge counts every rule behind
        the tab. Both were right and they sat one line apart disagreeing."""
        page = (await member_client.get("/intel/rules")).text
        assert "1 of 1 rules" in page

    async def test_the_heading_is_inside_the_region_that_gets_swapped(self, member_client):
        """Outside it, acknowledging an alert updated the tab badge and left the red
        "2 alerts" pill beside the title saying two until a reload."""
        fragment = (await member_client.get("/intel/rules", headers=HX)).text
        assert "<h1" in fragment and "Rules" in fragment
        assert fragment.index('id="rules-region"') < fragment.index("<h1")


class TestHidingTheWebhookSectionKeepsTheWebhook:
    """ "Hide webhook" collapses the section with `x-if`, which takes its inputs out of the
    form. The edit route read every absent webhook field as "cleared", so hide-then-save
    silently deleted the URL, headers, delivery switch and job-watch forwarding. A shown
    section always posts `webhook_url` (a text input submits even when empty); a hidden one
    posts none of them, and that is how the two are told apart."""

    @pytest.fixture()
    async def hooked(self, async_db, rule):
        rule.webhook_url = "https://hooks.example.com/x"
        rule.webhook_method = "PUT"
        rule.webhook_headers_json = '{"X-Team": "soc"}'
        rule.webhook_enabled = True
        rule.notify_job_watch = True
        await async_db.commit()
        return rule

    async def test_a_save_with_the_section_hidden_leaves_the_webhook_alone(self, member_client, async_db, hooked):
        body = {"name": "Renamed", "scope": "entity", "query": '"cmd.exe"'}  # what a collapsed form posts
        resp = await member_client.post(f"/intel/rules/{hooked.id}/edit", data=body, headers=HX)
        assert resp.status_code == 200, resp.text

        await async_db.refresh(hooked)
        assert hooked.name == "Renamed"
        assert (hooked.webhook_url, hooked.webhook_method, json.loads(hooked.webhook_headers_json)) == ("https://hooks.example.com/x", "PUT", {"X-Team": "soc"})
        assert hooked.webhook_enabled is True and hooked.notify_job_watch is True

    async def test_clearing_the_url_in_the_shown_section_still_removes_it(self, member_client, async_db, hooked):
        resp = await member_client.post(f"/intel/rules/{hooked.id}/edit", data=_form(webhook_url=""), headers=HX)
        assert resp.status_code == 200, resp.text
        await async_db.refresh(hooked)
        assert not hooked.webhook_url


class TestListsAndImportKeepTheDraftToo:
    """The list forms, Promote to a list and Import YAML had the failure the rule form was
    fixed for. The list forms and Promote were plain `method=POST` forms answered with a
    400, which replaced the page with an error screen naming only the first problem; a
    refused import swapped the whole region, which re-rendered its panel closed and its
    textarea empty; and a refused list delete was a 400 htmx does not swap, so the rules
    blocking it reached the reader as "Request failed (400)"."""

    async def test_a_refused_list_create_reports_into_its_own_form(self, admin_client, a_list):
        resp = await admin_client.post("/intel/rules/lists", data={"name": "lolbas", "values": "x"}, headers=HX)
        assert resp.status_code == 200
        assert resp.headers["HX-Retarget"] == "#list-form-errors-new"
        assert resp.headers["HX-Reswap"] == "innerHTML"
        assert "already exists" in resp.text
        assert "rules-region" not in resp.text

    async def test_a_refused_list_edit_reports_into_that_lists_form(self, admin_client, async_db, a_list):
        too_many = "\n".join(f"v{i}.exe" for i in range(2001))
        resp = await admin_client.post(f"/intel/rules/lists/{a_list.id}/edit", data={"match": "exact", "values": too_many}, headers=HX)
        assert resp.status_code == 200
        assert resp.headers["HX-Retarget"] == f"#list-form-errors-{a_list.id}"
        assert await async_db.scalar(select(func.count(RuleListValue.id))) == 1

    async def test_a_refused_promotion_reports_beside_its_form(self, admin_client, async_db, a_list):
        shared = IntelRule(name="Remote exec", query="in:(psexec.exe,wmic.exe)", is_builtin=True, scope="entity")
        async_db.add(shared)
        await async_db.commit()
        resp = await admin_client.post(f"/intel/rules/{shared.id}/promote-set", data={"name": "lolbas"}, headers=HX)
        assert resp.status_code == 200
        assert resp.headers["HX-Retarget"] == f"#promote-errors-{shared.id}"
        await async_db.refresh(shared)
        assert shared.query.startswith("in:(")

    async def test_a_refused_list_delete_names_the_rules_in_the_region(self, admin_client, async_db, member_user, a_list):
        async_db.add(IntelRule(name="Tests it", owner_user_id=member_user.id, query="list:lolbas", entity_types="[]"))
        await async_db.commit()
        resp = await admin_client.post(f"/intel/rules/lists/{a_list.id}/delete", headers=HX)
        assert resp.status_code == 200
        assert "Tests it" in resp.text and 'id="rules-region"' in resp.text
        assert await async_db.get(RuleList, a_list.id) is not None

    async def test_a_refused_import_leaves_the_pasted_document_alone(self, member_client):
        resp = await member_client.post("/intel/rules/import", data={"yaml_text": "rules:\n  - name: Two\n    condition: 'list:nosuch'\n"}, headers=HX)
        assert resp.status_code == 200
        assert resp.headers["HX-Retarget"] == "#rules-import-errors"
        assert "unknown list: nosuch" in resp.text
        assert "rules-region" not in resp.text

    async def test_the_slots_the_server_names_exist_and_the_forms_are_htmx(self, admin_client, async_db, a_list):
        async_db.add(IntelRule(name="Remote exec", query="in:(psexec.exe,wmic.exe)", is_builtin=True, scope="entity"))
        await async_db.commit()
        page = (await admin_client.get("/intel/rules")).text
        for slot in ("list-form-errors-new", f"list-form-errors-{a_list.id}", "rules-import-errors"):
            assert f'id="{slot}"' in page, slot
        assert 'id="promote-errors-' in page
        assert 'hx-post="/intel/rules/lists"' in page
        assert f'hx-post="/intel/rules/lists/{a_list.id}/edit"' in page
        assert re.search(r'hx-post="/intel/rules/\d+/promote-set"', page)
