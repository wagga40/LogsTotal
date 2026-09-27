"""Markdown for analyst prose, and the reason it needs no sanitiser.

Notes and comments are written by logged-in analysts, but "logged-in" is not "trusted with
raw HTML": a member typing `<img src=x onerror=…>` into a *shared* case note would run
script in every other member's session. The usual defence is a second dependency scrubbing
the renderer's output, which makes the page's safety depend on two libraries agreeing about
what HTML means.

`app/markdown_render.py` takes the other route — configure the parser so dangerous output
is never produced. That is only true while the configuration holds, and a one-word change
to it (`html: True`, adding `linkify`) reintroduces the hole silently, with every existing
test still passing. **These tests are that configuration, asserted from the outside.**
"""

from __future__ import annotations

import pytest

from app.markdown_render import MAX_INPUT_CHARS, render


class TestItRendersMarkdown:
    def test_basic_formatting(self):
        out = str(render("**bold** and `code`"))
        assert "<strong>bold</strong>" in out
        assert "<code>code</code>" in out

    def test_lists_and_headings(self):
        out = str(render("# Title\n\n- one\n- two"))
        assert "<h1>Title</h1>" in out
        assert out.count("<li>") == 2

    def test_fenced_code_survives_intact(self):
        """An IOC pasted into a note is the commonest thing anyone fences."""
        out = str(render("```\nC:\\Windows\\System32\\cmd.exe /c whoami\n```"))
        assert "<pre>" in out
        assert "cmd.exe /c whoami" in out

    def test_empty_input_is_empty_output(self):
        assert str(render("")) == ""
        assert str(render(None)) == ""


class TestItCannotEmitAttackerHtml:
    """The whole security argument. Each of these is a working XSS if the config slips."""

    @pytest.mark.parametrize(
        "payload",
        [
            "<script>alert(1)</script>",
            '<img src=x onerror="alert(1)">',
            "<iframe src=//evil></iframe>",
            '<a href="#" onclick="alert(1)">x</a>',
            "<svg/onload=alert(1)>",
            "<style>body{display:none}</style>",
        ],
    )
    def test_raw_html_is_escaped_not_passed_through(self, payload):
        out = str(render(payload))
        assert "<script" not in out.lower()
        assert "<img" not in out.lower()
        assert "<iframe" not in out.lower()
        assert "<svg" not in out.lower()
        assert "onerror" not in out.lower() or "&lt;" in out
        # The text itself survives, escaped — the analyst still sees what was written.
        assert "&lt;" in out

    @pytest.mark.parametrize(
        "scheme",
        ["javascript:alert(1)", "JaVaScRiPt:alert(1)", "vbscript:msgbox(1)", "data:text/html;base64,PHNjcmlwdD4="],
    )
    def test_script_bearing_link_schemes_never_become_hrefs(self, scheme):
        out = str(render(f"[click]({scheme})"))
        assert "href" not in out.lower(), f"{scheme} produced a link"

    def test_an_ordinary_link_still_works_and_is_hardened(self):
        out = str(render("[ok](https://example.com/path)"))
        assert 'href="https://example.com/path"' in out
        # noopener: the opened page must not be able to navigate this tab.
        assert 'rel="noopener nofollow ugc"' in out
        assert 'target="_blank"' in out

    def test_bare_domains_are_not_auto_linked(self):
        """Notes here are full of IOCs. Turning one into a live hyperlink is an accident."""
        out = str(render("The C2 was evil.example.com and 10.0.0.1"))
        assert "<a " not in out

    def test_images_do_not_produce_a_request(self):
        """CSP is `img-src 'self' data:`, so a remote image is a broken box at best."""
        out = str(render("![x](https://evil.example/track.png)"))
        assert "<img" not in out.lower()


class TestBounds:
    def test_absurd_input_is_truncated_rather_than_rendered_whole(self):
        out = str(render("a" * (MAX_INPUT_CHARS + 5_000)))
        assert "truncated" in out
        assert len(out) < MAX_INPUT_CHARS + 2_000


class TestTheToggleIsHonoured:
    """The macro, not the filter, is what templates must use — see `_rich_text.html`."""

    def test_every_prose_surface_goes_through_the_macro(self):
        from pathlib import Path

        root = Path(__file__).resolve().parent.parent / "app" / "templates"
        surfaces = [
            root / "intel" / "partials" / "_case_notes.html",
            root / "intel" / "partials" / "_entity_notes.html",
            root / "partials" / "_comment_thread.html",
            # The AI pane is prose too — the longest on the site — and was the one surface
            # this list did not cover, so nothing stopped it reaching for `| markdown`.
            root / "partials" / "_ai_analysis.html",
        ]
        import re

        for path in surfaces:
            text = path.read_text()
            assert "rich_text(" in text, f"{path.name} does not render prose through rich_text()"
            # Jinja comments are stripped before the check: `_ai_analysis.html` explains in
            # prose *why* it does not call the filter, and a naive substring search reads
            # that explanation as the violation it warns about.
            markup = re.sub(r"\{#.*?#\}", "", text, flags=re.DOTALL)
            assert "| markdown" not in markup, f"{path.name} calls the filter directly, bypassing the site setting"

    def test_the_macro_keeps_a_plain_branch(self):
        """Switching the setting off must restore the previous rendering exactly."""
        from pathlib import Path

        macro = (Path(__file__).resolve().parent.parent / "app" / "templates" / "partials" / "_rich_text.html").read_text()
        assert "whitespace-pre-wrap" in macro, "the disabled branch must preserve author line breaks"
        assert "render_markdown" in macro

    def test_a_missing_site_settings_still_renders_markdown(self):
        """Jinja's `Undefined` is not `None`, and the macro must treat both as "on".

        A caller whose own context lacks `site_settings` passes `Undefined`. An `is not
        none` test would take the *disabled* branch there and silently drop Markdown on
        that one surface, while every other surface kept it — the kind of inconsistency
        nobody reports as a bug, they just assume the feature is flaky.
        """
        from jinja2 import Undefined

        from app.templates_config import templates

        macro = templates.env.get_template("partials/_rich_text.html").module.rich_text
        for absent in (None, Undefined(name="site_settings")):
            assert "<strong>x</strong>" in str(macro("**x**", absent)), f"{absent!r} took the plain branch"


class TestTheEditorsTellTheTruth:
    """A placeholder promising "plain text" over a Markdown-rendering field is worse than
    no hint: it tells the analyst their asterisks are safe, and then eats them."""

    @staticmethod
    def _macros():
        from app.templates_config import templates

        return templates.env.get_template("partials/_markdown_help.html").module

    def test_the_placeholder_follows_the_setting(self):
        from types import SimpleNamespace

        m = self._macros()
        on = str(m.editor_placeholder(SimpleNamespace(render_markdown=True), "Write a comment…", 4000))
        off = str(m.editor_placeholder(SimpleNamespace(render_markdown=False), "Write a comment…", 4000))
        assert "Markdown supported" in on and "Plain text" not in on
        assert "Plain text" in off and "Markdown" not in off
        # Both still state the cap — that was the only useful part of the original text.
        assert "4000" in on and "4000" in off

    def test_the_help_icon_appears_only_when_markdown_is_on(self):
        from types import SimpleNamespace

        m = self._macros()
        assert "Markdown help" in str(m.markdown_help(SimpleNamespace(render_markdown=True)))
        assert str(m.markdown_help(SimpleNamespace(render_markdown=False))).strip() == ""

    def test_every_prose_editor_uses_the_shared_placeholder(self):
        """Three editors; a hand-written placeholder on any of them drifts on the next change."""
        from pathlib import Path

        root = Path(__file__).resolve().parent.parent / "app" / "templates"
        for path in (
            root / "partials" / "_comment_thread.html",
            root / "intel" / "partials" / "_case_notes.html",
            # The entity note editor lives in the Overview tab's partial, which is
            # self-contained, like the case one.
            root / "intel" / "partials" / "_entity_notes.html",
        ):
            text = path.read_text()
            assert "editor_placeholder(" in text, f"{path.name} hand-writes its placeholder"
            assert "Plain text, line breaks preserved. Max" not in text, f"{path.name} still hardcodes the old wording"


class TestDocumentedCapabilitiesAreReal:
    """Two capabilities of the parser that the UI advertises.

    The help panel and `/docs` both claim them, so the claims need to be able to fail — a
    documented feature with no test is how a doc quietly
    becomes a lie.
    """

    def test_pipe_tables_render(self):
        """`commonmark` omits tables — they are a GFM extension — so this is a deliberate
        `md.enable("table")`, and a preset change would silently drop it."""
        html = str(render("| rule | count |\n| --- | --- |\n| evil.exe | 3 |"))
        assert "<table>" in html
        assert "<th>rule</th>" in html
        assert "<td>evil.exe</td>" in html

    def test_a_mermaid_fence_becomes_a_mermaid_block_not_a_code_block(self):
        """The client renderer keys off `pre.mermaid` inside `.lt-prose`; anything else is
        a code block, which is what the diagram degrades to when it fails to parse."""
        html = str(render("```mermaid\nflowchart LR\n  A --> B\n```"))
        assert '<pre class="mermaid">' in html
        assert "flowchart LR" in html

    def test_a_mermaid_fence_still_escapes_its_content(self):
        """The source is emitted into the DOM, so it goes through the same escaping every
        other fence does — a diagram is not an HTML escape hatch."""
        html = str(render('```mermaid\nflowchart LR\n  A["<img src=x onerror=alert(1)>"] --> B\n```'))
        assert "<img" not in html
        assert "&lt;img" in html

    def test_an_ordinary_fence_is_untouched(self):
        html = str(render("```python\nprint(1)\n```"))
        assert 'class="mermaid"' not in html
        assert "<code" in html

    def test_the_help_panel_names_both(self):
        """Said in the one place an analyst looks before typing."""
        from pathlib import Path

        panel = (Path(__file__).resolve().parent.parent / "app" / "templates" / "partials" / "_markdown_help.html").read_text()
        assert "table" in panel
        assert "mermaid" in panel
