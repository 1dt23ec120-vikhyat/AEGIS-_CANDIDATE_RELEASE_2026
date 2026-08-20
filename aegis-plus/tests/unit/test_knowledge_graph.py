"""Comprehensive tests for the Knowledge Graph Domain (M9-P2)."""

from __future__ import annotations

from core.domain.events import (
    artifact_analyzed,
    campaign_created,
    incident_created,
    provider_completed,
    relationship_discovered,
    threat_recorded,
)
from core.domain.graph import (
    GraphEdge,
    GraphNode,
    GraphSnapshot,
    NodeType,
    RelationshipType,
)
from core.interfaces.graph_repository import IGraphRepository
from infrastructure.graph import InMemoryGraphRepository
from services.events import InProcessEventBus
from services.graph import GraphBuilder, GraphQueryService


class _FakeLogger:
    def debug(self, *a: object, **k: object) -> None:
        pass

    def info(self, *a: object, **k: object) -> None:
        pass

    def warning(self, *a: object, **k: object) -> None:
        pass

    def error(self, *a: object, **k: object) -> None:
        pass

    def exception(self, *a: object, **k: object) -> None:
        pass

    def critical(self, *a: object, **k: object) -> None:
        pass

    def bind(self, **k: object) -> _FakeLogger:
        return self


def _repo() -> InMemoryGraphRepository:
    return InMemoryGraphRepository()


def _query(repo: InMemoryGraphRepository | None = None) -> GraphQueryService:
    return GraphQueryService(repo or _repo())


def _logger() -> _FakeLogger:
    return _FakeLogger()


# --- Node creation ---


def test_add_node() -> None:
    repo = _repo()
    node = repo.add_node(GraphNode(node_id="n1", node_type=NodeType.FILE, display_name="test.exe"))
    assert node.node_id == "n1"
    assert repo.get_node("n1") is not None


def test_duplicate_node_suppressed() -> None:
    repo = _repo()
    repo.add_node(GraphNode(node_id="n1", node_type=NodeType.FILE))
    repo.add_node(GraphNode(node_id="n1", node_type=NodeType.FILE))
    assert repo.snapshot().node_count == 1
    assert repo.snapshot().duplicate_suppressions >= 1


def test_update_node_metadata() -> None:
    repo = _repo()
    repo.add_node(GraphNode(node_id="n1", node_type=NodeType.FILE, metadata={"a": "1"}))
    repo.update_node_metadata("n1", {"b": "2"})
    node = repo.get_node("n1")
    assert node is not None
    assert node.metadata["a"] == "1"
    assert node.metadata["b"] == "2"


# --- Edge creation ---


def test_add_edge() -> None:
    repo = _repo()
    repo.add_node(GraphNode(node_id="a"))
    repo.add_node(GraphNode(node_id="b"))
    edge = repo.add_edge(
        GraphEdge(source_id="a", target_id="b", relationship=RelationshipType.CONTAINS)
    )
    assert edge.source_id == "a"
    assert repo.snapshot().edge_count == 1


def test_duplicate_edge_suppressed() -> None:
    repo = _repo()
    repo.add_node(GraphNode(node_id="a"))
    repo.add_node(GraphNode(node_id="b"))
    repo.add_edge(
        GraphEdge(
            edge_id="e1", source_id="a", target_id="b", relationship=RelationshipType.CONTAINS
        )
    )
    repo.add_edge(
        GraphEdge(
            edge_id="e2", source_id="a", target_id="b", relationship=RelationshipType.CONTAINS
        )
    )
    assert repo.snapshot().edge_count == 1
    assert repo.snapshot().duplicate_suppressions >= 1


# --- Neighbor traversal ---


def test_neighbors() -> None:
    repo = _repo()
    repo.add_node(GraphNode(node_id="a"))
    repo.add_node(GraphNode(node_id="b"))
    repo.add_node(GraphNode(node_id="c"))
    repo.add_edge(GraphEdge(source_id="a", target_id="b", relationship=RelationshipType.CONTAINS))
    repo.add_edge(GraphEdge(source_id="a", target_id="c", relationship=RelationshipType.REFERENCES))
    assert len(repo.neighbors("a")) == 2
    assert len(repo.neighbors("a", relationship=RelationshipType.CONTAINS)) == 1


def test_edges_of() -> None:
    repo = _repo()
    repo.add_node(GraphNode(node_id="a"))
    repo.add_node(GraphNode(node_id="b"))
    repo.add_edge(GraphEdge(source_id="a", target_id="b", relationship=RelationshipType.CONTAINS))
    assert len(repo.edges_of("a")) == 1


# --- Shortest path ---


def test_shortest_path() -> None:
    repo = _repo()
    for nid in ("a", "b", "c", "d"):
        repo.add_node(GraphNode(node_id=nid))
    repo.add_edge(GraphEdge(source_id="a", target_id="b", relationship=RelationshipType.CONTAINS))
    repo.add_edge(GraphEdge(source_id="b", target_id="c", relationship=RelationshipType.REFERENCES))
    repo.add_edge(GraphEdge(source_id="c", target_id="d", relationship=RelationshipType.RELATED_TO))
    path = repo.shortest_path("a", "d")
    assert path.length == 3
    assert len(path.nodes) == 4


def test_shortest_path_no_connection() -> None:
    repo = _repo()
    repo.add_node(GraphNode(node_id="a"))
    repo.add_node(GraphNode(node_id="z"))
    path = repo.shortest_path("a", "z")
    assert path.is_empty


def test_shortest_path_same_node() -> None:
    repo = _repo()
    repo.add_node(GraphNode(node_id="a"))
    path = repo.shortest_path("a", "a")
    assert len(path.nodes) == 1
    assert path.length == 0


# --- Shared IOCs ---


def test_shared_iocs() -> None:
    repo = _repo()
    repo.add_node(GraphNode(node_id="file1", node_type=NodeType.FILE))
    repo.add_node(GraphNode(node_id="email1", node_type=NodeType.EMAIL))
    repo.add_node(GraphNode(node_id="ioc1", node_type=NodeType.IOC))
    repo.add_edge(
        GraphEdge(source_id="file1", target_id="ioc1", relationship=RelationshipType.CONTAINS)
    )
    repo.add_edge(
        GraphEdge(source_id="email1", target_id="ioc1", relationship=RelationshipType.CONTAINS)
    )
    shared = repo.shared_iocs("file1", "email1")
    assert len(shared) == 1
    assert shared[0].node_id == "ioc1"


def test_no_shared_iocs() -> None:
    repo = _repo()
    repo.add_node(GraphNode(node_id="a"))
    repo.add_node(GraphNode(node_id="b"))
    assert repo.shared_iocs("a", "b") == ()


# --- Subgraph ---


def test_subgraph_depth() -> None:
    repo = _repo()
    for nid in ("root", "d1a", "d1b", "d2a"):
        repo.add_node(GraphNode(node_id=nid))
    repo.add_edge(
        GraphEdge(source_id="root", target_id="d1a", relationship=RelationshipType.CONTAINS)
    )
    repo.add_edge(
        GraphEdge(source_id="root", target_id="d1b", relationship=RelationshipType.CONTAINS)
    )
    repo.add_edge(
        GraphEdge(source_id="d1a", target_id="d2a", relationship=RelationshipType.REFERENCES)
    )
    sub = repo.subgraph("root", max_depth=1)
    assert len(sub) == 3  # root + d1a + d1b (d2a is depth 2)
    sub2 = repo.subgraph("root", max_depth=2)
    assert len(sub2) == 4


# --- Nodes by type ---


def test_nodes_by_type() -> None:
    repo = _repo()
    repo.add_node(GraphNode(node_id="f1", node_type=NodeType.FILE))
    repo.add_node(GraphNode(node_id="f2", node_type=NodeType.FILE))
    repo.add_node(GraphNode(node_id="u1", node_type=NodeType.URL))
    assert len(repo.nodes_by_type(NodeType.FILE)) == 2


# --- Snapshot ---


def test_snapshot() -> None:
    repo = _repo()
    repo.add_node(GraphNode(node_id="a", node_type=NodeType.FILE))
    repo.add_node(GraphNode(node_id="b", node_type=NodeType.URL))
    repo.add_edge(GraphEdge(source_id="a", target_id="b", relationship=RelationshipType.CONTAINS))
    snap = repo.snapshot()
    assert snap.node_count == 2
    assert snap.edge_count == 1
    assert snap.node_type_counts["file"] == 1
    assert snap.relationship_type_counts["contains"] == 1


# --- Event-driven graph construction ---


def test_graph_builder_creates_nodes_from_events() -> None:
    repo = _repo()
    bus = InProcessEventBus(_logger())
    builder = GraphBuilder(repo, _logger())
    builder.attach(bus)

    bus.publish(
        artifact_analyzed(
            source="file_analysis",
            artifact_id="sha-abc",
            artifact_type="file",
            verdict="phishing",
            risk_score=0.85,
            category="malicious_document",
        )
    )
    node = repo.get_node("sha-abc")
    assert node is not None
    assert node.node_type is NodeType.FILE


def test_graph_builder_creates_threat_and_edge() -> None:
    repo = _repo()
    bus = InProcessEventBus(_logger())
    builder = GraphBuilder(repo, _logger())
    builder.attach(bus)

    bus.publish(
        artifact_analyzed(
            source="s",
            artifact_id="sha-abc",
            artifact_type="file",
            verdict="phishing",
            risk_score=0.85,
            category="c",
        )
    )
    bus.publish(
        threat_recorded(
            source="threat_intel",
            artifact_id="sha-abc",
            artifact_type="file",
        )
    )
    threat = repo.get_node("threat:sha-abc")
    assert threat is not None
    assert threat.node_type is NodeType.THREAT
    edges = repo.edges_of("sha-abc", relationship=RelationshipType.ASSOCIATED_WITH)
    assert len(edges) == 1


def test_graph_builder_creates_incident_relationship() -> None:
    repo = _repo()
    bus = InProcessEventBus(_logger())
    builder = GraphBuilder(repo, _logger())
    builder.attach(bus)

    bus.publish(
        artifact_analyzed(
            source="s",
            artifact_id="sha-abc",
            artifact_type="file",
            verdict="phishing",
            risk_score=0.85,
            category="c",
        )
    )
    bus.publish(
        incident_created(
            source="correlation",
            incident_id="inc-1",
            incident_title="Malicious Document",
            artifact_id="sha-abc",
        )
    )
    inc = repo.get_node("inc-1")
    assert inc is not None
    assert inc.node_type is NodeType.INCIDENT
    edges = repo.edges_of("sha-abc", relationship=RelationshipType.OBSERVED_IN)
    assert len(edges) == 1


def test_graph_builder_creates_campaign_node() -> None:
    repo = _repo()
    bus = InProcessEventBus(_logger())
    builder = GraphBuilder(repo, _logger())
    builder.attach(bus)

    bus.publish(
        campaign_created(
            source="correlation",
            campaign_id="camp-1",
            campaign_name="Phishing Wave",
        )
    )
    camp = repo.get_node("camp-1")
    assert camp is not None
    assert camp.display_name == "Phishing Wave"


def test_graph_builder_handles_relationship_events() -> None:
    repo = _repo()
    bus = InProcessEventBus(_logger())
    builder = GraphBuilder(repo, _logger())
    builder.attach(bus)

    bus.publish(
        relationship_discovered(
            source="ioc_fusion",
            source_id="file-1",
            source_type="file",
            target_id="url-1",
            target_type="url",
            relationship="contains",
        )
    )
    assert repo.get_node("file-1") is not None
    assert repo.get_node("url-1") is not None
    assert len(repo.edges_of("file-1", relationship=RelationshipType.CONTAINS)) == 1


def test_graph_builder_handles_provider_completed() -> None:
    repo = _repo()
    bus = InProcessEventBus(_logger())
    builder = GraphBuilder(repo, _logger())
    builder.attach(bus)

    bus.publish(
        artifact_analyzed(
            source="s",
            artifact_id="sha-abc",
            artifact_type="file",
            verdict="v",
            risk_score=0.0,
            category="c",
        )
    )
    bus.publish(
        provider_completed(
            provider_name="StructureProvider",
            version="1.0.0",
            execution_ms=2.5,
            evidence_count=1,
            artifact_id="sha-abc",
        )
    )
    prov = repo.get_node("provider:StructureProvider")
    assert prov is not None
    assert prov.node_type is NodeType.PROVIDER


def test_graph_builder_metrics() -> None:
    repo = _repo()
    bus = InProcessEventBus(_logger())
    builder = GraphBuilder(repo, _logger())
    builder.attach(bus)
    bus.publish(
        artifact_analyzed(
            source="s",
            artifact_id="a",
            artifact_type="file",
            verdict="v",
            risk_score=0.0,
            category="c",
        )
    )
    m = builder.metrics
    assert int(str(m["build_count"])) >= 1
    assert float(str(m["total_build_ms"])) >= 0


# --- Query service ---


def test_query_lookup() -> None:
    repo = _repo()
    repo.add_node(GraphNode(node_id="n1", node_type=NodeType.FILE))
    q = _query(repo)
    assert q.lookup("n1") is not None
    assert q.lookup("missing") is None


def test_query_investigation_subgraph() -> None:
    repo = _repo()
    for nid in ("root", "a", "b"):
        repo.add_node(GraphNode(node_id=nid))
    repo.add_edge(
        GraphEdge(source_id="root", target_id="a", relationship=RelationshipType.CONTAINS)
    )
    repo.add_edge(
        GraphEdge(source_id="root", target_id="b", relationship=RelationshipType.REFERENCES)
    )
    q = _query(repo)
    sub = q.investigation_subgraph("root")
    assert len(sub) == 3


def test_query_related_artifacts() -> None:
    repo = _repo()
    repo.add_node(GraphNode(node_id="file1", node_type=NodeType.FILE))
    repo.add_node(GraphNode(node_id="url1", node_type=NodeType.URL))
    repo.add_node(GraphNode(node_id="threat1", node_type=NodeType.THREAT))
    repo.add_edge(
        GraphEdge(source_id="file1", target_id="url1", relationship=RelationshipType.CONTAINS)
    )
    repo.add_edge(
        GraphEdge(
            source_id="file1", target_id="threat1", relationship=RelationshipType.ASSOCIATED_WITH
        )
    )
    q = _query(repo)
    related = q.related_artifacts("file1")
    assert any(n.node_id == "url1" for n in related)
    assert not any(n.node_id == "threat1" for n in related)  # threat is not an artifact type


def test_query_snapshot() -> None:
    repo = _repo()
    repo.add_node(GraphNode(node_id="a"))
    q = _query(repo)
    snap = q.snapshot()
    assert isinstance(snap, GraphSnapshot)
    assert snap.node_count == 1


# --- Analytics extension points ---


def test_analytics_stubs_return_defaults() -> None:
    q = _query()
    assert q.centrality("x") == 0.0
    assert q.connected_components() == ()
    assert q.communities() == ()
    assert q.attack_paths("a", "b") == ()


# --- Interface conformance ---


def test_repo_satisfies_interface() -> None:
    repo = _repo()
    assert isinstance(repo, IGraphRepository)


# --- Regression ---


def test_existing_analysis_still_works() -> None:
    from ai.file_analysis import HybridFileAnalyzer, StructureProvider
    from core.domain.intelligence import EvidenceSource
    from services.file_analysis.ingestion import FileIngestor

    analyzer = HybridFileAnalyzer(
        [StructureProvider()],
        weights={EvidenceSource.FILE_STRUCTURE: 1.0},
        suspicious_threshold=0.35,
        phishing_threshold=0.65,
    )
    artifact = FileIngestor().ingest("test.txt", b"safe content")
    report = analyzer.analyze(artifact)
    assert report.verdict.value == "legitimate"
