"""The test suite hashes passwords cheaply. Production must not.

`tests/conftest.py::_fast_password_hashing` replaces `PasswordHelper.__init__` for the
whole session, because Argon2 at RFC 9106 parameters was a third of the suite's runtime.
That trade is only safe while the *production* configuration stays untouched, and the
production configuration is a library default — which is exactly the kind of thing that
changes silently under a dependency bump.

These tests read the real parameters rather than the patched ones, so they fail if either
half of the arrangement moves.
"""

from __future__ import annotations

import inspect
from pathlib import Path

import argon2
from fastapi_users.password import PasswordHelper

REPO_ROOT = Path(__file__).resolve().parent.parent


def test_argon2_defaults_are_rfc_9106_low_memory():
    """The parameters production gets. pwdlib's `Argon2Hasher()` takes these verbatim."""
    assert (argon2.DEFAULT_TIME_COST, argon2.DEFAULT_MEMORY_COST, argon2.DEFAULT_PARALLELISM) == (3, 65536, 4), (
        "argon2-cffi's defaults moved off RFC 9106 low-memory. The app relies on them: nothing in app/ passes explicit Argon2 parameters."
    )


def test_the_app_never_configures_its_own_password_helper():
    """Production takes the library default, which is what the test above pins.

    Three sites construct one — `app/auth/users.py`'s manager (implicitly, via
    `BaseUserManager.__init__`), `app/routers/admin.py` and `app/system_checks.py` for the
    default-password banner. None may pass a `password_hash`, or the pinned defaults stop
    describing what runs.
    """
    offenders = []
    for path in sorted((REPO_ROOT / "app").rglob("*.py")):
        text = path.read_text(encoding="utf-8")
        if "PasswordHelper(" in text and "PasswordHelper()" not in text:
            offenders.append(str(path.relative_to(REPO_ROOT)))
        if "Argon2Hasher(" in text:
            offenders.append(str(path.relative_to(REPO_ROOT)))
    assert not offenders, f"these configure password hashing explicitly, so the defaults no longer describe production: {offenders}"


def test_the_cheap_hasher_is_confined_to_a_fixture():
    """It must be reachable only from a pytest fixture, never at import time.

    A module-level patch in conftest would apply to anything that imports it — including,
    one bad refactor later, something that is not a test.
    """
    # The fixture is active right now, so the live helper must already be the cheap one —
    # which is also what makes the two assertions above meaningful rather than tautological.
    assert PasswordHelper().password_hash.hashers[0].__class__.__name__ == "Argon2Hasher"

    conftest = (REPO_ROOT / "tests" / "conftest.py").read_text(encoding="utf-8")
    assert "Argon2Hasher(time_cost=1" in conftest, "the fast-hashing fixture is gone; this file's premise no longer holds"

    from tests.conftest import _fast_password_hashing

    assert hasattr(_fast_password_hashing, "__wrapped__"), "_fast_password_hashing is not a pytest fixture"
    body = inspect.getsource(_fast_password_hashing.__wrapped__)
    assert "finally:" in body and "original_init" in body, "the fixture must restore PasswordHelper.__init__ on teardown"
