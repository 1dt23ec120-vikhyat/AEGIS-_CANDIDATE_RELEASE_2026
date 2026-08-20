"""Tests for the deterministic spring layout (M9-P3-B)."""

from __future__ import annotations

import pytest

from ui.components.graph.layout import spring_layout

pytestmark = pytest.mark.ui


def test_empty_graph_returns_empty() -> None:
    assert spring_layout([], []) == {}


def test_single_node_centres() -> None:
    positions = spring_layout(["a"], [], width=1000, height=700)
    assert positions["a"] == (500.0, 350.0)


def test_positions_within_bounds() -> None:
    nodes = [f"n{i}" for i in range(12)]
    edges = [("n0", "n1"), ("n1", "n2"), ("n2", "n3"), ("n0", "n4")]
    positions = spring_layout(nodes, edges, width=800, height=600)
    assert set(positions) == set(nodes)
    for x, y in positions.values():
        assert 0.0 <= x <= 800.0
        assert 0.0 <= y <= 600.0


def test_deterministic_for_same_seed() -> None:
    nodes = ["a", "b", "c", "d"]
    edges = [("a", "b"), ("b", "c")]
    first = spring_layout(nodes, edges, seed=7)
    second = spring_layout(nodes, edges, seed=7)
    assert first == second


def test_duplicate_ids_collapsed() -> None:
    positions = spring_layout(["a", "a", "b"], [("a", "b")])
    assert set(positions) == {"a", "b"}


def test_edges_referencing_unknown_nodes_are_ignored() -> None:
    # Should not raise when an edge references a node not in the list.
    positions = spring_layout(["a", "b"], [("a", "z")])
    assert set(positions) == {"a", "b"}
