"""Unit tests for the Graph Explorer application service (M9-P3-A)."""

from __future__ import annotations

from core.domain.events import (
    artifact_analyzed,
    campaign_created,
    incident_created,
    relationship_discovered,
    threat_recorded,
)
from core.domain.graph_view import (
    GraphAnalyticsSummary,
    GraphNodeView,
    GraphPathView,
    GraphSnapshotView,
    GraphView,
)
from infrastructure.graph import InMemoryGraphRepository
from services.events import InProcessEventBus
from services.graph import GraphBuilder, GraphExplorerService, GraphQueryService


class _FakeLogger:
    def debug(self, *a: object, **k: object) -> None: ...
    def info(self, *a: object, **k: object) -> None: ...
    def warning(self, *a: object, **k: object) -> None: ...
    def error(self, *a: object, **k: object) -> None: ...
    def exception(self, *a: object, **k: object) -> None: ...
    def critical(self, *a: object, **k: object) -> None: ...
    def bind(self, **k: object) -> _FakeLogger:
        return self


def _populated() -> tuple[InMemoryGraphRepository, GraphExplorerService]:
    """Build a small graph via the event bus (publishers unaware of the graph)."""
    repo = InMemoryGraphRepository()
    bus = InProcessEventBus(_FakeLogger())
    GraphBuilder(repo, _FakeLogger()).attach(bus)

    bus.publish(
        artifact_analyzed(
            source="url-analysis",
            artifact_id="url-1",
            artifact_type="url",
            verdict="phishing",
            risk_score=0.9,
            category="credential_harvesting",
        )
    )
    bus.publish(
        artifact_analyzed(
            source="file-analysis",
            artifact_id="file-1",
            artifact_type="file",
            verdict="legitimate",
            risk_score=0.1,
            category="none",
        )
    )
    bus.publish(threat_recorded(source="threat-intel", artifact_id="url-1", artifact_type="url"))
    bus.publish(
        incident_created(
            source="corr", incident_id="inc-1", incident_title="Phishing wave", artifact_id="url-1"
        )
    )
    bus.publish(campaign_created(source="corr", campaign_id="camp-1", campaign_name="Camp A"))
    # Shared IOC between url-1 and file-1.
    for artifact, atype in (("url-1", "url"), ("file-1", "file")):
        bus.publish(
            relationship_discovered(
                source="ioc-fusion",
                source_id=artifact,
                source_type=atype,
                target_id="ioc-1",
                target_type="ioc",
                relationship="shares_ioc",
            )
        )

    explorer = GraphExplorerService(GraphQueryService(repo), repo, _FakeLogger())
    return repo, explorer


def test_snapshot_summarizes_graph() -> None:
    _, explorer = _populated()
    snap = explorer.snapshot()
    assert isinstance(snap, GraphSnapshotView)
    assert snap.node_count >= 6  # url, file, threat, incident, campaign, ioc
    assert snap.edge_count >= 4
    assert dict(snap.node_type_counts).get("ioc") == 1


def test_node_lookup_maps_tone_and_risk() -> None:
    _, explorer = _populated()
    node = explorer.node("url-1")
    assert isinstance(node, GraphNodeView)
    assert node.tone == "danger"  # phishing verdict
    assert node.risk_percent == 90
    assert node.degree >= 2


def test_node_lookup_missing_returns_none() -> None:
    _, explorer = _populated()
    assert explorer.node("does-not-exist") is None


def test_neighbors_returns_bounded_view() -> None:
    _, explorer = _populated()
    view = explorer.neighbors("url-1")
    assert isinstance(view, GraphView)
    assert view.root_id == "url-1"
    ids = {n.node_id for n in view.nodes}
    assert "url-1" in ids
    assert view.node_count >= 2
    assert not view.truncated
    # Edges only connect nodes present in the view.
    for edge in view.edges:
        assert edge.source_id in ids
        assert edge.target_id in ids


def test_expand_missing_node_is_empty() -> None:
    _, explorer = _populated()
    view = explorer.expand("ghost", depth=2)
    assert view.root_id == "ghost"
    assert view.node_count == 0
    assert view.edge_count == 0


def test_shortest_path_found() -> None:
    _, explorer = _populated()
    path = explorer.shortest_path("file-1", "inc-1")
    assert isinstance(path, GraphPathView)
    assert path.found
    assert path.length >= 1
    assert path.nodes[0].node_id == "file-1"
    assert path.nodes[-1].node_id == "inc-1"


def test_shortest_path_not_found() -> None:
    _, explorer = _populated()
    path = explorer.shortest_path("camp-1", "inc-1")  # campaign is isolated
    assert not path.found
    assert path.length == 0


def test_shared_iocs_discovers_common_node() -> None:
    _, explorer = _populated()
    view = explorer.shared_iocs("url-1", "file-1")
    ids = {n.node_id for n in view.nodes}
    assert "ioc-1" in ids
    assert "url-1" in ids and "file-1" in ids


def test_incident_and_campaign_graphs() -> None:
    _, explorer = _populated()
    inc = explorer.incident_graph("inc-1")
    assert any(n.node_id == "url-1" for n in inc.nodes)
    camp = explorer.campaign_graph("camp-1")
    assert camp.root_id == "camp-1"


def test_investigation_graph_from_root() -> None:
    _, explorer = _populated()
    view = explorer.investigation_graph("url-1", depth=2)
    ids = {n.node_id for n in view.nodes}
    assert {"url-1", "inc-1"}.issubset(ids)


def test_search_matches_and_focuses() -> None:
    _, explorer = _populated()
    result = explorer.search("url")
    assert result.match_count >= 1
    assert result.focus_id == result.matches[0].node_id
    assert any("url" in m.node_id for m in result.matches)


def test_search_empty_query_returns_no_matches() -> None:
    _, explorer = _populated()
    result = explorer.search("   ")
    assert result.match_count == 0
    assert result.focus_id == ""


def test_search_respects_limit() -> None:
    _, explorer = _populated()
    result = explorer.search("1", limit=2)  # many ids contain "1"
    assert result.match_count <= 2


def test_analytics_reports_degrees_and_components() -> None:
    _, explorer = _populated()
    analytics = explorer.analytics(top=3)
    assert isinstance(analytics, GraphAnalyticsSummary)
    assert analytics.node_count >= 6
    assert analytics.ioc_count == 1
    assert analytics.most_connected  # non-empty
    assert analytics.most_connected[0].degree >= analytics.most_connected[-1].degree
    assert analytics.largest_component_size >= 2


def test_selection_descriptor() -> None:
    _, explorer = _populated()
    selection = explorer.selection("url-1")
    assert selection.focus_id == "url-1"
    assert len(selection.neighbor_ids) >= 2
    assert len(selection.edge_ids) >= 2


def test_selection_missing_node() -> None:
    _, explorer = _populated()
    selection = explorer.selection("ghost")
    assert selection.focus_id == "ghost"
    assert selection.neighbor_ids == ()


def test_empty_graph_is_safe() -> None:
    repo = InMemoryGraphRepository()
    explorer = GraphExplorerService(GraphQueryService(repo), repo, _FakeLogger())
    assert explorer.snapshot().node_count == 0
    assert explorer.analytics().most_connected == ()
    assert explorer.search("anything").match_count == 0
    assert explorer.node("x") is None


def test_analytics_reports_distribution_density_and_components() -> None:
    _, explorer = _populated()
    analytics = explorer.analytics(top=3)
    # Entity + relationship distributions are populated and sorted.
    assert analytics.node_type_counts
    assert analytics.relationship_type_counts
    assert list(analytics.node_type_counts) == sorted(analytics.node_type_counts)
    # Structural measures.
    assert analytics.component_count >= 1
    assert analytics.largest_component_size >= 2
    assert 0.0 <= analytics.density <= 1.0
    # A connected graph of >1 node has positive density.
    assert analytics.density > 0.0


def test_query_metrics_are_tracked() -> None:
    _, explorer = _populated()
    before = explorer.metrics()["query_count"]
    explorer.snapshot()
    explorer.analytics()
    explorer.expand("url-1")
    after = explorer.metrics()
    assert after["query_count"] >= before + 3
    assert after["total_query_ms"] >= 0.0
    assert after["avg_query_ms"] >= 0.0


def test_query_service_lightweight_analytics() -> None:
    repo, _ = _populated()
    query = GraphQueryService(repo)
    # Degree centrality is normalized and non-negative.
    assert 0.0 <= query.centrality("url-1") <= 1.0
    # Connected components partition the graph; the whole graph is one component.
    components = query.connected_components()
    assert components
    assert max(len(c) for c in components) >= 2
    # Density in range; communities intentionally empty (out of scope).
    assert 0.0 <= query.graph_density() <= 1.0
    assert query.communities() == ()
    # Attack paths reduce to the shortest path when one exists.
    paths = query.attack_paths("ioc-1", "file-1")
    assert len(paths) <= 1
    # Blast radius is the reachable set.
    assert {n.node_id for n in query.blast_radius("url-1")}


def test_query_service_analytics_empty_graph() -> None:
    query = GraphQueryService(InMemoryGraphRepository())
    assert query.centrality("ghost") == 0.0
    assert query.connected_components() == ()
    assert query.graph_density() == 0.0
    assert query.attack_paths("a", "b") == ()
