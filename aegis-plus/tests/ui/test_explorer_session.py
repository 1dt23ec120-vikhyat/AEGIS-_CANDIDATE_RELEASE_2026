"""Tests for the in-memory Explorer session structures (M9-P3-C)."""

from __future__ import annotations

import pytest

from ui.components.graph.panels import FilterCriteria
from ui.viewmodels.explorer_session import ExplorerSessionState, ViewportState

pytestmark = pytest.mark.ui


def test_defaults_describe_empty_session() -> None:
    state = ExplorerSessionState()
    assert state.is_empty
    assert state.focus_node == ""
    assert state.expanded_nodes == frozenset()
    assert state.timeline_cutoff == ""
    assert state.depth == 1
    assert state.viewport == ViewportState()


def test_populated_session_is_not_empty() -> None:
    state = ExplorerSessionState(
        focus_node="a",
        expanded_nodes=frozenset({"a", "b"}),
        filters=FilterCriteria(node_types=frozenset({"url"})),
        timeline_cutoff="2026-01-01T00:00",
        depth=3,
        viewport=ViewportState(scale=1.5, center_x=10.0, center_y=20.0),
    )
    assert not state.is_empty
    assert state.viewport.scale == 1.5
    assert "a" in state.expanded_nodes
