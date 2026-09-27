"""Markdown for analyst-written prose — case notes, entity notes, comment threads.

Pure module (stdlib + ``markdown_it``): no FastAPI, no SQLAlchemy. The *caller* decides
whether rendering is on, by reading ``SiteSettings.render_markdown``; this module only
knows how to turn text into safe HTML.

**Why no sanitiser.** Every input here is written by a logged-in analyst, but "logged-in"
is not "trusted with raw HTML" — a member typing ``<img src=x onerror=...>`` into a shared
case note would run script in every other member's session. The usual answer is a second
dependency (bleach/nh3) scrubbing the renderer's output, which means the security of the
page depends on two libraries agreeing about what HTML means. Instead the renderer is
configured so dangerous output is never produced in the first place:

* ``html=False`` — raw HTML in the source is **escaped to text**, not passed through. This
  is the whole XSS surface for a Markdown renderer and it is closed at the parser, not
  patched afterwards.
* ``markdown_it``'s default ``validateLink`` rejects ``javascript:``, ``vbscript:``,
  ``file:`` and ``data:`` URLs (bar a short image allowlist that excludes SVG, which can
  carry script). So ``[click](javascript:alert(1))`` renders as inert text.
* ``linkify`` stays **off**: auto-linking bare strings is exactly wrong for this app, where
  notes are full of IOCs. Turning ``evil.example.com`` in an analyst's note into a live
  hyperlink is a one-click accident waiting to happen.

Links that *are* written deliberately get ``target=_blank`` plus ``rel="noopener
nofollow ugc"`` — a note is user-generated content pointing somewhere off-site, and
without ``noopener`` the opened page can navigate this tab.
"""

from __future__ import annotations

from functools import lru_cache

from markdown_it.common.utils import escapeHtml
from markupsafe import Markup

# The fence language that becomes a rendered diagram rather than a code block. One name,
# shared by the renderer, the client and the AI system prompt that asks for it.
MERMAID_FENCE_LANG = "mermaid"

# Ceiling on what one note or comment is worth rendering. `Comment.body` is capped at 4,000
# characters and notes at 8,000 by the write paths, so this only ever catches a caller that
# forgot its own cap — rendering is linear, but an unbounded input is still an unbounded
# response.
MAX_INPUT_CHARS = 20_000


@lru_cache(maxsize=1)
def _parser():
    """One configured parser, built lazily.

    Cached because a thread's first render otherwise pays the plugin-chain setup, and this
    runs inside request handlers. The parser is stateless across `render()` calls.
    """
    from markdown_it import MarkdownIt

    md = MarkdownIt("commonmark", {"html": False, "linkify": False, "typographer": False})
    # Tables, on top of the commonmark preset (which omits them — they are a GFM extension).
    # This costs nothing in safety: `table` is a block rule that emits `<table><thead>…`
    # from pipe syntax, and `html=False` still governs the entire raw-HTML surface. It earns
    # its place because a comparison is the one thing prose is genuinely bad at — and
    # because a language model writing an assessment reaches for a table by default, so
    # without this the AI Analysis pane renders rows of raw `|` pipes. Analyst notes and
    # comment threads get the same benefit.
    md.enable("table")
    # Images are off deliberately, not overlooked: the app's CSP is `img-src 'self' data:`,
    # so an external image tag renders as a broken box no matter what. Escaping the syntax
    # to visible text is the honest outcome — the reader sees the URL instead of a
    # placeholder, and no request leaves the browser.
    md.disable("image", ignoreInvalid=True)

    renderer = md.renderer
    default_fence = renderer.rules.get("fence")

    def fence(tokens, idx, options, env):
        """Emit a ```mermaid block as `<pre class="mermaid">`, the shape the client renders.

        `<pre class="mermaid">` is not a new convention — it is the one `docs/index.html`
        already uses. The diagram source is written as **escaped text**, so this adds no
        HTML surface: `mermaid.js` reads `textContent`, which unescapes back to the author's
        original characters, while anything angle-bracketed stays inert if the script never
        runs. Everything else falls through to markdown-it's own fence renderer, so ordinary
        code blocks are untouched.
        """
        token = tokens[idx]
        info = (token.info or "").strip().split(maxsplit=1)
        if info and info[0].lower() == MERMAID_FENCE_LANG:
            return f'<pre class="mermaid">{escapeHtml(token.content)}</pre>\n'
        return default_fence(tokens, idx, options, env)

    renderer.rules["fence"] = fence

    # Rules are invoked as `rules[type](tokens, idx, options, env)` — four arguments, with
    # the renderer bound by closure rather than passed. Getting this wrong raises only when
    # a link is actually rendered, which no test of plain prose would reach.
    def link_open(tokens, idx, options, env):
        tokens[idx].attrSet("target", "_blank")
        # noopener: the opened page must not be able to navigate this tab.
        # nofollow/ugc: this is user-generated content, not an endorsement.
        tokens[idx].attrSet("rel", "noopener nofollow ugc")
        return renderer.renderToken(tokens, idx, options, env)

    renderer.rules["link_open"] = link_open
    return md


def render(text: str | None) -> Markup:
    """Render *text* as Markdown and mark it safe for a Jinja template.

    ``Markup`` is only appropriate because the parser cannot emit attacker-controlled HTML
    — see the module docstring. Do not reach for this on any other input.
    """
    if not text:
        return Markup("")
    body = text if len(text) <= MAX_INPUT_CHARS else text[:MAX_INPUT_CHARS] + "\n\n…(truncated)"
    # S704 (Markup on a non-literal) is the correct thing for a linter to object to, and
    # this is the single call in the codebase where the answer is yes. The justification is
    # the parser configuration above, not this comment: `html=False` means the renderer
    # cannot emit attacker-supplied markup, and `validateLink` rejects script-bearing URL
    # schemes. If either is ever relaxed, this line becomes an XSS hole — so they are
    # asserted directly in tests/test_markdown_render.py rather than left to review.
    return Markup(_parser().render(body))  # noqa: S704
