"""One answer to "how long do we keep this?", for the worker and the UI alike.

The override lives on `SiteSettings` and the default lives in `Settings`, so without a
shared resolver the sweep and the page that describes it would drift apart within two
releases — one reading the column, the other the environment. This module is the seam, and
it returns the *source* alongside the value so the UI can say where the number came from
instead of presenting it as if there were only ever one.
"""

from __future__ import annotations

from dataclasses import dataclass

from app.config import settings

#: Windows that can be overridden from the UI. Deliberately one entry: see
#: `SiteSettings.job_output_retention_days_override`.
OVERRIDABLE = ("job_output_retention_days",)


@dataclass(frozen=True)
class Retention:
    """A resolved window and where it came from."""

    days: int
    #: "site setting" or the name of the environment variable behind it.
    source: str

    @property
    def overridden(self) -> bool:
        return self.source == "site setting"

    @property
    def disabled(self) -> bool:
        return self.days <= 0


def effective_retention(name: str, site_settings=None) -> Retention:
    """The window in force for *name*, and its source.

    *site_settings* may be ``None`` — the worker resolves it before a session exists in
    some paths, and the environment default is the right answer then.
    """
    env_default = getattr(settings, name, 0) or 0
    if name in OVERRIDABLE and site_settings is not None:
        override = getattr(site_settings, f"{name}_override", None)
        if override is not None:
            return Retention(days=int(override), source="site setting")
    return Retention(days=int(env_default), source=name.upper())
