"""
Documentation router — public (no auth required).

The whole guide renders for everyone, including anonymous visitors: the Intel and admin
sections describe features a `role=user` account cannot open, but they describe them
rather than exposing them, and a reader who cannot find out what the product does is worse
served than one who reads about a tab they lack the role for.

`user` is still injected because the template renders the shared nav, which needs it.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse

from app.auth.users import current_user_optional
from app.models import User
from app.templates_config import templates

router = APIRouter(tags=["docs"])


@router.get("/docs", response_class=HTMLResponse)
async def docs_page(
    request: Request,
    user: User | None = Depends(current_user_optional),
):
    """Render the public documentation / user guide page."""
    return templates.TemplateResponse(
        request,
        "docs/index.html",
        {"request": request, "user": user},
    )
