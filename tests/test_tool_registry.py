"""Tests for app.tools.registry — adapter lookup."""

from __future__ import annotations

import pytest

from app.tools.chainsaw import ChainsawAdapter
from app.tools.chopchopgo import ChopChopGoAdapter
from app.tools.hayabusa import HayabusaAdapter
from app.tools.registry import get_adapter
from app.tools.zircolite import ZircoliteAdapter


class TestGetAdapter:
    def test_zircolite(self):
        a = get_adapter("zircolite", {"tool_path": "/fake"})
        assert isinstance(a, ZircoliteAdapter)

    def test_chainsaw(self):
        a = get_adapter("chainsaw", {"tool_path": "/fake"})
        assert isinstance(a, ChainsawAdapter)

    def test_hayabusa(self):
        a = get_adapter("hayabusa", {"tool_path": "/fake"})
        assert isinstance(a, HayabusaAdapter)

    def test_chopchopgo(self):
        a = get_adapter("chopchopgo", {"tool_path": "/fake"})
        assert isinstance(a, ChopChopGoAdapter)

    def test_case_insensitive(self):
        a = get_adapter("ZIRCOLITE", {"tool_path": "/fake"})
        assert isinstance(a, ZircoliteAdapter)

    def test_unknown_raises(self):
        with pytest.raises(ValueError, match="Unknown tool"):
            get_adapter("nonexistent", {})
