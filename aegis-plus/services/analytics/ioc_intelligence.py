"""IOC Intelligence Service (M11 Phase B).

Deterministic intelligence about IOC nodes in the knowledge graph: frequency,
prevalence, reuse, confidence, and aging. Built entirely on the existing graph
query service — it reads IOC nodes and their edges and derives scores with fixed,
explainable formulas. No persistence, no new graph algorithm.
"""

from __future__ import annotations

from datetime import datetime

from core.domain.graph import GraphEdge, GraphNode, NodeType
from core.domain.intelligence_view import IOCIntelligence
from core.interfaces.logger import ILogger
from services.analytics.observability import MeteredService, tracked
from services.graph.query import GraphQueryService

_DEFAULT_TOP = 10
# Confidence weighting: edge confidence, reuse breadth, connected-artifact risk.
_W_EDGE = 0.4
_W_REUSE = 0.3
_W_RISK = 0.3
_REUSE_SATURATION = 5.0  # reuse count at which the reuse term saturates to 1.0


class IOCIntelligenceService(MeteredService):
    """Deterministic IOC intelligence over the knowledge graph."""

    def __init__(self, query: GraphQueryService, logger: ILogger) -> None:
        """Initialize the IOC intelligence service.

        Args:
            query: The graph query service (source of IOC nodes and edges).
            logger: Injected logger.
        """
        super().__init__()
        self._query = query
        self._logger = logger

    @tracked
    def analyze(self, ioc_id: str) -> IOCIntelligence:
        """Compute intelligence for a single IOC node."""
        return self._compute(ioc_id)

    @tracked
    def rank(self, *, top: int = _DEFAULT_TOP) -> tuple[IOCIntelligence, ...]:
        """Rank all IOC nodes by confidence then frequency (deterministic)."""
        intel = [self._compute(n.node_id) for n in self._iocs()]
        intel.sort(key=lambda i: (-i.confidence, -i.frequency, i.ioc_id))
        return tuple(intel[:top])

    # --- internals -------------------------------------------------------

    def _compute(self, ioc_id: str) -> IOCIntelligence:
        edges = self._query.edges_of(ioc_id)
        node = self._query.lookup(ioc_id)
        label = node.display_name if node else ioc_id
        frequency = len(edges)
        total_artifacts = self._artifact_total()
        prevalence = frequency / total_artifacts if total_artifacts else 0.0
        first_seen, last_seen, aging = _aging(edges)
        avg_edge_conf = sum(e.confidence for e in edges) / len(edges) if edges else 0.0
        avg_risk = self._connected_risk(ioc_id)
        reuse_term = min(frequency / _REUSE_SATURATION, 1.0)
        confidence = round(
            _clamp(_W_EDGE * avg_edge_conf + _W_REUSE * reuse_term + _W_RISK * avg_risk),
            4,
        )
        rationale = (
            f"Referenced by {frequency} artifact(s)",
            f"Prevalence {prevalence * 100:.1f}% of artifacts",
            f"Mean edge confidence {avg_edge_conf:.2f}",
            f"Connected-artifact risk {avg_risk * 100:.0f}%",
        )
        return IOCIntelligence(
            ioc_id=ioc_id,
            label=label,
            frequency=frequency,
            prevalence=round(prevalence, 4),
            reuse_count=frequency,
            confidence=confidence,
            first_seen=first_seen,
            last_seen=last_seen,
            aging_days=aging,
            risk_percent=round(avg_risk * 100),
            rationale=rationale,
        )

    def _iocs(self) -> tuple[GraphNode, ...]:
        return tuple(n for n in self._query.all_nodes() if n.node_type is NodeType.IOC)

    def _artifact_total(self) -> int:
        counts = self._query.snapshot().node_type_counts
        return sum(
            counts.get(t.value, 0)
            for t in (NodeType.URL, NodeType.FILE, NodeType.EMAIL, NodeType.ARTIFACT)
        )

    def _connected_risk(self, ioc_id: str) -> float:
        neighbors = self._query.neighbors(ioc_id)
        risks = [_risk(n.metadata.get("risk_score", "")) for n in neighbors]
        present = [r for r in risks if r is not None]
        return sum(present) / len(present) if present else 0.0


def _clamp(value: float, low: float = 0.0, high: float = 1.0) -> float:
    return max(low, min(high, value))


def _risk(raw: str) -> float | None:
    try:
        return _clamp(float(raw))
    except (TypeError, ValueError):
        return None


def _aging(edges: tuple[GraphEdge, ...]) -> tuple[str, str, float]:
    stamps = sorted(e.timestamp for e in edges if e.timestamp)
    if not stamps:
        return "", "", 0.0
    first, last = stamps[0], stamps[-1]
    try:
        delta = datetime.fromisoformat(last) - datetime.fromisoformat(first)
        days = round(delta.total_seconds() / 86400.0, 3)
    except ValueError:
        days = 0.0
    return first, last, days
