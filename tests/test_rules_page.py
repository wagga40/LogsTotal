"""Rules is a destination, and `/intel/watch` still finds it.

Rules live at `/intel/rules`, in the top-level nav beside Tags, for the reason Tags is
there: a rule acts on jobs *and* entities, so hanging it inside either one says the wrong
thing about which owns it.

The redirects are the part worth testing rather than assuming. `/intel/watch` can sit in
older documentation and in whatever bookmarks people made, and five of the nine redirected
paths are POSTs — which a 302 would silently downgrade to GETs.
"""

from __future__ import annotations

import pytest

from app.models import IntelRule

pytestmark = pytest.mark.anyio


@pytest.fixture()
async def a_rule(async_db, member_client):
    """One rule with a delete button, so the page has something to render."""
    from sqlalchemy import select

    from app.models import User

    owner = (await async_db.execute(select(User))).scalars().first()
    rule = IntelRule(name="Rule One", query="label:dga", owner_user_id=owner.id if owner else None)
    async_db.add(rule)
    await async_db.commit()
    await async_db.refresh(rule)
    return rule


class TestTheDestination:
    async def test_it_is_in_the_top_level_nav(self, member_client):
        """Reached from the nav on every page, the way Tags is — not from one tab."""
        for page in ("/jobs", "/intel", "/intel/tags"):
            body = (await member_client.get(page)).text
            assert 'href="/intel/rules"' in body, f"{page} does not offer Rules in the nav"

    async def test_a_plain_user_is_not_offered_it(self, user_client):
        """Member-and-above, like the rest of the Intel group it sits in."""
        body = (await user_client.get("/jobs")).text
        assert 'href="/intel/rules"' not in body
        assert (await user_client.get("/intel/rules")).status_code == 403

    async def test_it_goes_home_not_back_to_intel(self, member_client):
        """`TestPageChrome` asserts this across every nav-level page; named here too,
        because an `Intel /` breadcrumb is the tempting mistake and Intel is not above it."""
        body = (await member_client.get("/intel/rules")).text
        assert "&larr; Home" in body

    async def test_it_says_what_a_rule_is_and_what_it_is_not(self, member_client):
        """Two things on this platform are called rules and only one is yours to write.

        The explainer mirrors the Intel dashboard's opening line; without the second half
        of it, "Rules" beside a workflow full of SIGMA detection rules is a coin flip.
        """
        body = (await member_client.get("/intel/rules")).text
        assert "SIGMA detection rules" in body

    async def test_it_carries_a_count_pill(self, member_client, a_rule):
        body = (await member_client.get("/intel/rules")).text
        assert "1 rule" in body

    async def test_the_three_sections_render(self, member_client, a_rule):
        body = (await member_client.get("/intel/rules")).text
        for heading in ("Alerts", "Rules", "Webhook deliveries"):
            assert heading in body, f"the {heading} section is missing"


class TestTheOldAddressStillWorks:
    async def test_the_page_redirects(self, member_client):
        resp = await member_client.get("/intel/watch", follow_redirects=False)
        assert resp.status_code == 307
        assert resp.headers["location"] == "/intel/rules"

    async def test_it_lands_somewhere_real(self, member_client):
        resp = await member_client.get("/intel/watch", follow_redirects=True)
        assert resp.status_code == 200
        assert 'id="rules-region"' in resp.text

    @pytest.mark.parametrize(
        ("old", "new"),
        [
            ("/intel/watch/rules", "/intel/rules"),
            ("/intel/watch/rules/7/edit", "/intel/rules/7/edit"),
            ("/intel/watch/rules/7/test", "/intel/rules/7/test"),
            ("/intel/watch/rules/7/toggle", "/intel/rules/7/toggle"),
            ("/intel/watch/rules/7/delete", "/intel/rules/7/delete"),
            ("/intel/watch/rules/preview", "/intel/rules/preview"),
            ("/intel/watch/alerts/7/ack", "/intel/rules/alerts/7/ack"),
            ("/intel/watch/alerts/ack-all", "/intel/rules/alerts/ack-all"),
        ],
    )
    async def test_every_old_path_points_at_its_replacement(self, member_client, old, new):
        """The inner `rules/` segment is the whole of the translation; nine shims would be
        nine chances to forget one."""
        resp = await member_client.post(old, follow_redirects=False)
        # `/intel/watch/rules/preview` is the one GET among them.
        if resp.status_code == 405:
            resp = await member_client.get(old, follow_redirects=False)
        assert resp.status_code == 307, f"{old} answered {resp.status_code}, not a redirect"
        assert resp.headers["location"] == new

    async def test_a_post_keeps_its_method_and_body(self, member_client, async_db):
        """A 302 turns a POST into a GET, which here means a form that reports success and
        saves nothing. 307 is the only status that does not."""
        from sqlalchemy import select

        resp = await member_client.post("/intel/watch/rules", data={"name": "via the old address", "query": "evil"}, follow_redirects=True)
        assert resp.status_code == 200, resp.text
        names = (await async_db.execute(select(IntelRule.name))).scalars().all()
        assert "via the old address" in names

    async def test_the_bell_routes_are_not_swept_up_by_the_catch_all(self, member_client):
        """`/intel/watchlist-events-partial` shares a prefix but not a segment boundary."""
        resp = await member_client.get("/intel/watchlist-events-partial?count_only=1", follow_redirects=False)
        assert resp.status_code == 200


class TestJobsYouWatch:
    """Watching is a feature of Rules, not a second thing with the same name.

    The subscriptions list is the *same partial* `/jobs?tab=watching` renders, mounted a
    second time rather than copied — its buttons post to their own routes and swap
    `#jobs-watching-region`, so they work here unchanged.
    """

    @pytest.fixture()
    async def a_watch(self, async_db, member_client):
        import uuid as _uuid

        from sqlalchemy import select

        from app.models import AnalysisJob, JobStatus, JobWatch, LogFile, LogType, User, WorkflowDef

        owner = (await async_db.execute(select(User).where(User.is_superuser.is_(False)))).scalars().first()
        lf = LogFile(
            original_filename="watched.evtx",
            stored_filename=f"{_uuid.uuid4()}.evtx",
            sha256=_uuid.uuid4().hex * 2,
            size_bytes=1,
            log_type=LogType.EVTX,
            detected_type=LogType.EVTX,
        )
        async_db.add(lf)
        await async_db.flush()
        wf = WorkflowDef(name="WF", description="", log_types='["evtx"]', tasks_yaml="tasks: []", is_default=True)
        async_db.add(wf)
        await async_db.flush()
        job = AnalysisJob(
            submitted_filename=lf.original_filename, effective_log_type=lf.log_type, file_id=lf.id, workflow_id=wf.id, status=JobStatus.COMPLETED, submitted_by_user_id=owner.id
        )
        async_db.add(job)
        await async_db.flush()
        async_db.add(JobWatch(job_id=job.id, user_id=owner.id))
        await async_db.commit()
        return job

    async def test_the_section_lists_them(self, member_client, a_watch):
        body = (await member_client.get("/intel/rules")).text
        assert "Jobs you watch" in body
        assert "watched.evtx" in body

    async def test_it_is_the_same_partial_not_a_copy(self, member_client, a_watch):
        """One implementation, two mounts. A second copy is how the two come to disagree
        about what "Stop watching" does."""
        body = (await member_client.get("/intel/rules")).text
        assert 'id="jobs-watching-region"' in body
        assert f"/jobs/watching/{a_watch.id}/stop" in body

    async def test_the_jobs_tab_still_has_it(self, member_client, a_watch):
        """`/jobs/watching` is `current_user_required` and this page is member-and-above, so
        moving it would take watching away from the one role that has it and no Intel."""
        resp = await member_client.get("/jobs/watching", headers={"HX-Request": "true"})
        assert resp.status_code == 200
        assert "watched.evtx" in resp.text

    async def test_a_plain_user_keeps_it_where_they_can_reach_it(self, user_client, async_db):
        assert (await user_client.get("/intel/rules")).status_code == 403
        assert (await user_client.get("/jobs/watching", headers={"HX-Request": "true"})).status_code == 200


class TestTheDryRun:
    """ "How many match right now" is the cheap question. "Would this bury me" is the one
    people get wrong, and otherwise the only way to find out is to turn the rule on."""

    @pytest.fixture()
    async def a_finished_job(self, async_db, member_client):
        import uuid as _uuid

        from sqlalchemy import select

        from app.models import AnalysisJob, Entity, EntityJobLink, JobStatus, LogFile, LogType, User, WorkflowDef

        owner = (await async_db.execute(select(User).where(User.is_superuser.is_(False)))).scalars().first()
        lf = LogFile(
            original_filename="intrusion.evtx",
            stored_filename=f"{_uuid.uuid4()}.evtx",
            sha256=_uuid.uuid4().hex * 2,
            size_bytes=1,
            log_type=LogType.EVTX,
            detected_type=LogType.EVTX,
        )
        async_db.add(lf)
        await async_db.flush()
        wf = WorkflowDef(name="WF", description="", log_types='["evtx"]', tasks_yaml="tasks: []", is_default=True)
        async_db.add(wf)
        await async_db.flush()
        job = AnalysisJob(
            submitted_filename=lf.original_filename, effective_log_type=lf.log_type, file_id=lf.id, workflow_id=wf.id, status=JobStatus.COMPLETED, submitted_by_user_id=owner.id
        )
        async_db.add(job)
        await async_db.flush()
        ent = Entity(value="certutil.exe", entity_type="executable", job_count=1)
        async_db.add(ent)
        await async_db.flush()
        async_db.add(EntityJobLink(entity_id=ent.id, job_id=job.id, occurrence_count=1))
        await async_db.commit()
        return job

    async def test_it_counts_what_would_have_been_raised(self, member_client, a_finished_job):
        resp = await member_client.post("/intel/rules/dry-run", data={"query": "certutil", "scope": "entity"})
        assert resp.status_code == 200
        assert "1</strong> alert" in resp.text
        assert "Nothing was written" in resp.text

    async def test_it_writes_nothing(self, member_client, async_db, a_finished_job):
        """No alert, no tag, no `last_evaluated_at` — the whole point of a dry run."""
        from sqlalchemy import select

        from app.models import EntityTag, IntelRuleMatch

        await member_client.post("/intel/rules/dry-run", data={"query": "certutil", "scope": "entity", "action_tag": "triage"})

        assert (await async_db.execute(select(IntelRuleMatch))).scalars().all() == []
        assert (await async_db.execute(select(EntityTag))).scalars().all() == []
        assert (await async_db.execute(select(IntelRule))).scalars().all() == []

    async def test_the_job_scope_counts_jobs(self, member_client, a_finished_job):
        resp = await member_client.post("/intel/rules/dry-run", data={"query": "intrusion", "scope": "job"})
        assert "1</strong> would have matched" in resp.text

    async def test_a_bad_query_is_reported(self, member_client, a_finished_job):
        resp = await member_client.post("/intel/rules/dry-run", data={"query": "status:notastatus", "scope": "job"})
        assert "text-red-400" in resp.text

    async def test_it_says_so_when_there_is_nothing_to_test_against(self, member_client):
        resp = await member_client.post("/intel/rules/dry-run", data={"query": "certutil"})
        assert "No finished jobs" in resp.text

    async def test_it_only_looks_at_jobs_the_caller_can_see(self, admin_client, member_user, async_db):
        """Otherwise it is an oracle for how many private submissions other people hold."""
        import uuid as _uuid

        from sqlalchemy import select

        from app.models import AnalysisJob, JobStatus, LogFile, LogType, User, WorkflowDef

        admin = (await async_db.execute(select(User).where(User.is_superuser.is_(True)))).scalars().first()
        lf = LogFile(
            original_filename="secret.evtx",
            stored_filename=f"{_uuid.uuid4()}.evtx",
            sha256=_uuid.uuid4().hex * 2,
            size_bytes=1,
            log_type=LogType.EVTX,
            detected_type=LogType.EVTX,
        )
        async_db.add(lf)
        await async_db.flush()
        wf = WorkflowDef(name="WF", description="", log_types='["evtx"]', tasks_yaml="tasks: []", is_default=True)
        async_db.add(wf)
        await async_db.flush()
        async_db.add(
            AnalysisJob(
                submitted_filename=lf.original_filename,
                effective_log_type=lf.log_type,
                file_id=lf.id,
                workflow_id=wf.id,
                status=JobStatus.COMPLETED,
                is_private=True,
                submitted_by_user_id=admin.id,
            )
        )
        await async_db.commit()

        client = admin_client
        assert "last 1 job" in (await client.post("/intel/rules/dry-run", data={"query": "secret", "scope": "job"})).text

        # One client, logged in twice — the two fixtures share it and the later login wins.
        await client.post("/auth/cookie/login", data={"username": "member@test.example.com", "password": "testpass123"})
        assert "No finished jobs" in (await client.post("/intel/rules/dry-run", data={"query": "secret", "scope": "job"})).text


def _rule_row_markup(body: str, needle: str) -> str:
    """The markup of one rule row, isolated by its `data-rule-search` attribute.

    Row assertions have to be scoped to the row. The page is 1 MB of forms and partials, so
    a bare `in body` check will happily find its needle in something unrelated and report a
    pass it did not earn.
    """
    chunks = body.split('data-rule-search="')[1:]
    for chunk in chunks:
        if needle in chunk.split('"', 1)[0]:
            return chunk
    raise AssertionError(f"no rule row matching {needle!r}; found {len(chunks)} rows")


class TestTheTabStrip:
    """Four panes over one region, and the strip is the only thing that says which is open.

    Stacked, the page is six sections and 4,560 px, two of them empty states. Rules is
    top-level, so this is the only strip on the page.
    """

    def test_the_four_tabs_are_in_reading_order(self):
        from app.routers.intel_rules import _build_rules_tabs

        tabs = _build_rules_tabs(rule_total=37, list_total=9, alert_total=2, watched=1)
        # Rules leads: the page is named for them, and the nav bell already carries alerts.
        assert [t["key"] for t in tabs] == ["rules", "lists", "alerts", "activity"]
        by_key = {t["key"]: t for t in tabs}
        assert by_key["rules"]["badge"] == 37
        assert by_key["lists"]["badge"] == 9
        assert by_key["alerts"]["badge"] == 2
        assert by_key["activity"]["badge"] == 1

    def test_a_zero_count_carries_no_badge(self):
        """`tab_badge` hides at a falsy count; passing 0 rather than None would render an
        empty span that reads as a rendering fault rather than as nothing to see."""
        from app.routers.intel_rules import _build_rules_tabs

        tabs = _build_rules_tabs(rule_total=0, list_total=0, alert_total=0, watched=0)
        assert all(t["badge"] is None for t in tabs)

    def test_every_pane_is_eager(self):
        """No `lazy_event` anywhere, deliberately.

        `_render_rules` loads all four panes in one pass, so lazy panes would need four new
        routes to buy back bytes this page re-sends on every action anyway — every POST here
        swaps the whole `#rules-region` — and would put the section headings behind a fetch.
        """
        from app.routers.intel_rules import _build_rules_tabs

        tabs = _build_rules_tabs(rule_total=1, list_total=1, alert_total=1, watched=1)
        assert all(t["lazy_event"] is None for t in tabs)

    def test_the_macro_draws_every_icon_the_tabs_name(self):
        """A tab naming a glyph the dictionary lacks renders **nothing, silently**, because
        the macro's lookup simply misses. Mirrors `test_ai_routes.py::TestTabIcons`."""
        import re
        from pathlib import Path

        from app.routers.intel_rules import _build_rules_tabs

        src = Path("app/templates/partials/_icons.html").read_text()
        block = src[src.index("{%- set d = {") : src.index("} -%}")]
        known = set(re.findall(r"^\s*'([a-z_]+)':", block, re.M))
        for tab in _build_rules_tabs(rule_total=1, list_total=1, alert_total=1, watched=1):
            assert tab.get("icon"), f"tab {tab['key']!r} has no icon"
            assert tab["icon"] in known, f"tab {tab['key']!r} names an undrawable glyph {tab['icon']!r}"

    async def test_the_page_mounts_the_shared_tab_component(self, member_client):
        body = (await member_client.get("/intel/rules")).text
        # Single quotes around the attribute: `| tojson` escapes & < > ' but *not* ", so a
        # double-quoted attribute truncates at the first key and the strip never initialises.
        assert "x-data='resourceTabs(" in body
        for key in ("rules", "lists", "alerts", "activity"):
            assert f"select('{key}')" in body, f"no button selects the {key} pane"
            assert f"tab === '{key}'" in body, f"no pane is bound to {key}"

    async def test_nothing_jumps_into_a_pane_by_assigning_the_property(self, member_client):
        """`select()` writes the hash; a bare `tab = 'x'` moves the pane without it, and the
        tab would then not survive the region swap every action on this page performs."""
        body = (await member_client.get("/intel/rules")).text
        assert "tab = '" not in body


class TestRowsAreOneLine:
    """The condition truncates rather than wrapping.

    At thirty-six rules, every second row being two lines is most of what makes the page
    read as a wall.
    """

    async def test_a_long_condition_is_clipped_not_wrapped(self, member_client, async_db):
        from app.models import IntelRule

        long_query = "cidr:" + ",".join(f"10.{n}.0.0/16" for n in range(20))
        async_db.add(IntelRule(name="Wide", query=long_query, is_builtin=True, scope="entity"))
        await async_db.commit()

        body = (await member_client.get("/intel/rules")).text
        # `truncate` on the collapsed cell, and the full text still reachable two ways:
        # the `title` on the cell, and the expander's `whitespace-pre-wrap` copy.
        assert f'title="{long_query}"' in body
        assert "break-all whitespace-pre-wrap" in body
        assert 'break-all">' not in body, "the old wrapping condition cell is still rendered"

    async def test_every_row_is_searchable_by_the_filter(self, member_client, a_rule):
        """The filter reads `data-rule-search` off the DOM after each swap rather than a
        server-passed id list — the `jobSelection` arrangement, for the same reason."""
        body = (await member_client.get("/intel/rules")).text
        assert "data-rule-search=" in body
        assert "$store.rulesFilter.matches($el)" in body

    async def test_a_member_can_open_a_shared_rule_it_cannot_edit(self, member_client, async_db):
        """Truncation is only safe because the text stays reachable. The expander is
        deliberately outside the `can_edit` gate the form sits behind.

        Asserted against **this row's own markup**, not the whole page. Looking for
        `x-show="open"` anywhere in the body always passes, because an unrelated component
        elsewhere on the page happens to use the same expression — a guard that cannot fail
        is worse than no guard.
        """
        from app.models import IntelRule

        async_db.add(IntelRule(name="Shared thing", query="list:lolbas", is_builtin=True, scope="entity"))
        await async_db.commit()

        row = _rule_row_markup((await member_client.get("/intel/rules")).text, "shared thing")
        assert 'x-show="open"' in row, "a member cannot open the row to read the full condition"
        # ...and the form underneath it still is not theirs.
        assert "/intel/rules/" not in row.replace("/intel/rules/lists", ""), "a member was handed an edit form"


class TestTheConditionEditor:
    """A highlight overlay behind a real `<textarea>`, and the textarea is still the field.

    The whole design rests on that. Anything that mirrors the value into a hidden input puts
    a serializer on Alpine's scheduler — htmx serialises a form synchronously, Alpine applies
    bindings on its own tick — which is the race `caseEntityFilter._refetch` exists to avoid.
    """

    async def test_the_textarea_is_still_what_the_form_posts(self, member_client):
        body = (await member_client.get("/intel/rules")).text
        assert 'name="query"' in body
        # The preview and the dry-run both read the field through htmx; if the editor had
        # taken the name onto a mirror, these would be serialising an empty box.
        assert 'hx-get="/intel/rules/preview"' in body
        assert 'hx-include="closest form"' in body

    async def test_nothing_mirrors_the_value_into_a_hidden_input(self, member_client):
        body = (await member_client.get("/intel/rules")).text
        assert 'type="hidden" name="query"' not in body
        # The editor reaches the field through `x-ref`, never a binding. (`x-model="query"`
        # does appear on this page — it is the tag combobox's own search box, an unrelated
        # property of the same name — so the assertion has to be about *this* textarea.)
        editor = body[body.index('class="lt-cond__input"') - 400 : body.index('class="lt-cond__input"') + 400]
        assert 'x-ref="search"' in editor
        assert "x-model" not in editor

    async def test_the_grammar_ships_once_per_page(self, member_client):
        """Up to thirty-seven condition fields render on this page and they all read the
        same grammar; interpolating it into each form's `x-data` was ~26 KB of duplicate."""
        body = (await member_client.get("/intel/rules")).text
        assert body.count('id="condition-grammar"') == 1
        assert body.count("conditionEditor()") >= 1
        assert "conditionEditor({ grammar:" not in body

    async def test_the_grammar_block_is_data_not_script(self, member_client):
        """`type="application/json"` — the `index.html` idiom. A `<script>` that assigns a
        global would run before Alpine on some paths and after it on others."""
        body = (await member_client.get("/intel/rules")).text
        assert '<script type="application/json" id="condition-grammar">' in body

    async def test_both_layers_are_present_and_only_one_is_focusable(self, member_client):
        body = (await member_client.get("/intel/rules")).text
        assert 'class="lt-cond__hl" aria-hidden="true"' in body, "the overlay must be hidden from the AT tree"
        assert 'class="lt-cond__input"' in body

    def test_the_container_never_carries_pre_wrap(self):
        """`white-space: pre-wrap` on `.lt-cond` renders the template's own indentation
        between the two layers as real lines — measured at 106 px of empty space under an
        otherwise correct field. It belongs on the layers, which hold text that must keep
        its spaces."""
        import re
        from pathlib import Path

        css = Path("app/templates/base.html").read_text()
        block = css[css.index(".lt-cond {") : css.index(".lt-cond__hl, .lt-cond__input")]
        # Comments explain the rule and would otherwise satisfy the search for it.
        declarations = re.sub(r"/\*.*?\*/", "", block, flags=re.S)
        assert "white-space" not in declarations, ".lt-cond must not set white-space; put it on the layers"

    def test_the_editor_declares_the_knobs_it_reads(self):
        """`--lt-px` and `--lt-radius` are per-control knobs, not `:root` variables. Reading
        one without declaring it makes the whole `padding` shorthand invalid at
        computed-value time and it silently resolves to 0 — which is what happened, and
        which `test_every_lt_var_read_by_base_html_is_defined` cannot catch, because it
        deliberately excludes these four."""
        import re
        from pathlib import Path

        css = Path("app/templates/base.html").read_text()
        start = css.index(".lt-cond {")
        block = css[start : css.index(".lt-cond-bad")]
        for knob in set(re.findall(r"var\((--lt-(?:px|h|fs|radius))\)", block)):
            assert f"{knob}:" in block, f".lt-cond reads {knob} without declaring it"


class TestSharedRulesSayWhereTheyStand:
    """`seed_hash` decides which shared rules the seeder leaves alone, and the page has to
    say so, or "why did the upgrade not change this rule" has no answer there."""

    async def test_an_unedited_shared_rule_carries_no_marker(self, member_client, async_db):
        from app.intel.rules_yaml import RuleSpec, apply_spec, spec_from_rule, spec_hash
        from app.models import IntelRule

        rule = IntelRule(name="Pristine", is_builtin=True, builtin_key="pristine", scope="entity")
        apply_spec(rule, RuleSpec(name="Pristine", key="pristine", criteria="list:lolbas"))
        async_db.add(rule)
        await async_db.flush()
        rule.seed_hash = spec_hash(spec_from_rule(rule))
        await async_db.commit()

        row = _rule_row_markup((await member_client.get("/intel/rules")).text, "pristine")
        assert ">edited<" not in row

    async def test_a_shared_rule_edited_here_says_so(self, member_client, async_db):
        from app.intel.rules_yaml import RuleSpec, apply_spec
        from app.models import IntelRule

        rule = IntelRule(name="Changed", is_builtin=True, builtin_key="changed", scope="entity")
        apply_spec(rule, RuleSpec(name="Changed", key="changed", criteria="list:lolbas"))
        # The hash of something else: what an admin's edit leaves behind.
        rule.seed_hash = "0" * 64
        async_db.add(rule)
        await async_db.commit()

        row = _rule_row_markup((await member_client.get("/intel/rules")).text, "changed")
        assert ">edited<" in row, "an edited shared rule must say the file no longer updates it"

    async def test_there_is_no_reset_button(self, admin_client, async_db):
        """A marker, deliberately not a ceremony. A Modified/Reset control would fire on
        every row after an upgrade; the seeding policy already handles the update, and this
        only explains why one row was skipped."""
        from app.models import IntelRule

        rule = IntelRule(name="Changed", is_builtin=True, builtin_key="changed", scope="entity", query="list:lolbas", seed_hash="0" * 64)
        async_db.add(rule)
        await async_db.commit()

        body = (await admin_client.get("/intel/rules")).text
        assert "/reset" not in body
        assert "Reset to shipped" not in body


class TestStartingARuleFromAnother:
    """Thirty-six shared rules ship, a member may not edit any, and "like that but mine" is
    the commonest thing to want from one."""

    @pytest.fixture()
    async def a_shared_rule(self, async_db):
        from app.models import IntelRule

        rule = IntelRule(name="LOLBin", is_builtin=True, builtin_key="lolbin", scope="entity", query="list:lolbas -tag:known-good")
        async_db.add(rule)
        await async_db.commit()
        return rule

    async def test_the_button_carries_the_condition_and_the_scope(self, member_client, a_shared_rule):
        row = _rule_row_markup((await member_client.get("/intel/rules")).text, "lolbin")
        assert 'data-seed-name="Copy of LOLBin"' in row
        assert 'data-seed-scope="entity"' in row
        assert "data-seed-query=" in row

    async def test_the_values_ride_on_data_attributes_not_through_tojson(self, member_client, a_shared_rule):
        """`| tojson` escapes `& < > '` and **not** `"`, so a JSON string inside a
        double-quoted attribute closes it at its own opening quote — the handler then fails
        to compile and the button silently does nothing. That is how it first shipped."""
        row = _rule_row_markup((await member_client.get("/intel/rules")).text, "lolbin")
        assert "$el.dataset.seedName" in row
        assert "seed-new-rule', { name: \"" not in row

    async def test_a_member_gets_it_on_a_rule_it_cannot_edit(self, member_client, a_shared_rule):
        row = _rule_row_markup((await member_client.get("/intel/rules")).text, "lolbin")
        assert "Start a rule from this" in row
        # …and still no edit form.
        assert "/intel/rules/" not in row.replace("/intel/rules/lists", "")


async def test_an_admins_rule_budget_counts_only_the_rules_they_wrote(admin_client, async_db, member_user, monkeypatch):
    """An admin sees every member's rules on this page. The budget line and the "rules you
    wrote" pill counted that whole list, so with a member's seven rules an admin who owned
    none read "7 of 5 used" — and could still create rules."""
    import re

    from app.models import IntelRule

    monkeypatch.setattr("app.config.settings.watch_rules_max_per_user", 5)
    for i in range(7):
        async_db.add(IntelRule(name=f"member rule {i}", owner_user_id=member_user.id, query="x", entity_types="[]"))
    await async_db.commit()

    text = re.sub(r"\s+", " ", (await admin_client.get("/intel/rules")).text)
    assert "0 of 5 used" in text
    assert "0 of 7 rules" in text
