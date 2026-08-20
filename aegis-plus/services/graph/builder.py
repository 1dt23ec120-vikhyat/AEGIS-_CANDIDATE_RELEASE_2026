"""Graph Builder.

Subscribes to the Internal Intelligence Event Bus and constructs the knowledge
graph automatically from intelligence events. Publishers remain entirely
unaware of the graph — the builder is a pure consumer.

Node and edge creation uses stable identifiers with deterministic deduplication
so repeated events for the same artifact produce one node, not duplicates.
"""

from __future__ import annotations

import time

from core.domain.events import EventType, IntelligenceEvent
from core.domain.graph import GraphEdge, GraphNode, NodeType, RelationshipType
from core.interfaces.event_bus import IEventBus
from core.interfaces.graph_repository import IGraphRepository
from core.interfaces.logger import ILogger

_EVENT_TO_NODE_TYPE: dict[str, NodeType] = {
    "file": NodeType.FILE,
    "url": NodeType.URL,
    "email": NodeType.EMAIL,
    "hash": NodeType.HASH,
    "domain": NodeType.DOMAIN,
    "ioc": NodeType.IOC,
    "ip_address": NodeType.IP_ADDRESS,
    "artifact": NodeType.ARTIFACT,
}


class GraphBuilder:
    """Event-driven knowledge graph constructor."""

    def __init__(
        self,
        repository: IGraphRepository,
        logger: ILogger,
    ) -> None:
        """Initialize the builder.

        Args:
            repository: The graph repository to populate.
            logger: Injected logger.
        """
        self._repo = repository
        self._logger = logger
        self._build_count = 0
        self._build_ms = 0.0

    def attach(self, bus: IEventBus) -> None:
        """Subscribe to all intelligence events on the bus."""
        bus.subscribe(EventType.ARTIFACT_ANALYZED, self._on_artifact_analyzed)
        bus.subscribe(EventType.IOC_EXTRACTED, self._on_ioc_extracted)
        bus.subscribe(EventType.THREAT_RECORDED, self._on_threat_recorded)
        bus.subscribe(EventType.INCIDENT_CREATED, self._on_incident_created)
        bus.subscribe(EventType.INCIDENT_UPDATED, self._on_incident_updated)
        bus.subscribe(EventType.CAMPAIGN_CREATED, self._on_campaign_created)
        bus.subscribe(EventType.CAMPAIGN_UPDATED, self._on_campaign_updated)
        bus.subscribe(EventType.RELATIONSHIP_DISCOVERED, self._on_relationship)
        bus.subscribe(EventType.PROVIDER_COMPLETED, self._on_provider_completed)
        self._logger.info("GraphBuilder attached to event bus")

    @property
    def metrics(self) -> dict[str, object]:
        """Builder observability metrics."""
        return {
            "build_count": self._build_count,
            "total_build_ms": round(self._build_ms, 2),
        }

    # --- event handlers --------------------------------------------------

    def _on_artifact_analyzed(self, event: IntelligenceEvent) -> None:
        start = time.monotonic()
        artifact_type = str(event.payload.get("artifact_type", "artifact"))
        node_type = _EVENT_TO_NODE_TYPE.get(artifact_type, NodeType.ARTIFACT)
        self._repo.add_node(
            GraphNode(
                node_id=event.artifact_id,
                node_type=node_type,
                display_name=event.artifact_id[:24],
                labels=(artifact_type, str(event.payload.get("verdict", ""))),
                metadata={
                    "verdict": str(event.payload.get("verdict", "")),
                    "category": str(event.payload.get("category", "")),
                    "risk_score": str(event.payload.get("risk_score", "")),
                    "source": event.source,
                },
            )
        )
        self._track(start)

    def _on_ioc_extracted(self, event: IntelligenceEvent) -> None:
        start = time.monotonic()
        ioc_count = int(event.payload.get("ioc_count", 0))
        if event.artifact_id:
            self._repo.update_node_metadata(event.artifact_id, {"ioc_count": str(ioc_count)})
        self._track(start)

    def _on_threat_recorded(self, event: IntelligenceEvent) -> None:
        start = time.monotonic()
        threat_node = self._repo.add_node(
            GraphNode(
                node_id=f"threat:{event.artifact_id}",
                node_type=NodeType.THREAT,
                display_name=f"Threat {event.artifact_id[:16]}",
                metadata={
                    "artifact_type": str(event.payload.get("artifact_type", "")),
                    "source": event.source,
                },
            )
        )
        if event.artifact_id:
            self._repo.add_edge(
                GraphEdge(
                    source_id=event.artifact_id,
                    target_id=threat_node.node_id,
                    relationship=RelationshipType.ASSOCIATED_WITH,
                    provenance=event.source,
                )
            )
        self._track(start)

    def _on_incident_created(self, event: IntelligenceEvent) -> None:
        start = time.monotonic()
        incident_id = str(event.payload.get("incident_id", ""))
        self._repo.add_node(
            GraphNode(
                node_id=incident_id,
                node_type=NodeType.INCIDENT,
                display_name=str(event.payload.get("incident_title", incident_id)),
                metadata={"source": event.source},
            )
        )
        if event.artifact_id:
            self._repo.add_edge(
                GraphEdge(
                    source_id=event.artifact_id,
                    target_id=incident_id,
                    relationship=RelationshipType.OBSERVED_IN,
                    provenance=event.source,
                )
            )
        self._track(start)

    def _on_incident_updated(self, event: IntelligenceEvent) -> None:
        start = time.monotonic()
        incident_id = str(event.payload.get("incident_id", ""))
        if incident_id:
            self._repo.update_node_metadata(incident_id, {"updated": event.timestamp})
        self._track(start)

    def _on_campaign_created(self, event: IntelligenceEvent) -> None:
        start = time.monotonic()
        campaign_id = str(event.payload.get("campaign_id", ""))
        self._repo.add_node(
            GraphNode(
                node_id=campaign_id,
                node_type=NodeType.CAMPAIGN,
                display_name=str(event.payload.get("campaign_name", campaign_id)),
                metadata={"source": event.source},
            )
        )
        self._track(start)

    def _on_campaign_updated(self, event: IntelligenceEvent) -> None:
        start = time.monotonic()
        campaign_id = str(event.payload.get("campaign_id", ""))
        if campaign_id:
            self._repo.update_node_metadata(campaign_id, {"updated": event.timestamp})
        self._track(start)

    def _on_relationship(self, event: IntelligenceEvent) -> None:
        start = time.monotonic()
        source_id = str(event.payload.get("source_id", ""))
        target_id = str(event.payload.get("target_id", ""))
        rel_type = str(event.payload.get("relationship", "related_to"))
        try:
            relationship = RelationshipType(rel_type)
        except ValueError:
            relationship = RelationshipType.RELATED_TO
        if source_id and target_id:
            source_type = str(event.payload.get("source_type", "artifact"))
            target_type = str(event.payload.get("target_type", "artifact"))
            self._repo.add_node(
                GraphNode(
                    node_id=source_id,
                    node_type=_EVENT_TO_NODE_TYPE.get(source_type, NodeType.ARTIFACT),
                    display_name=source_id[:24],
                )
            )
            self._repo.add_node(
                GraphNode(
                    node_id=target_id,
                    node_type=_EVENT_TO_NODE_TYPE.get(target_type, NodeType.ARTIFACT),
                    display_name=target_id[:24],
                )
            )
            self._repo.add_edge(
                GraphEdge(
                    source_id=source_id,
                    target_id=target_id,
                    relationship=relationship,
                    provenance=event.source,
                )
            )
        self._track(start)

    def _on_provider_completed(self, event: IntelligenceEvent) -> None:
        start = time.monotonic()
        self._repo.add_node(
            GraphNode(
                node_id=f"provider:{event.source}",
                node_type=NodeType.PROVIDER,
                display_name=event.source,
                metadata={
                    "version": str(event.payload.get("version", "")),
                    "execution_ms": str(event.payload.get("execution_ms", "")),
                },
            )
        )
        if event.artifact_id:
            self._repo.add_edge(
                GraphEdge(
                    source_id=event.artifact_id,
                    target_id=f"provider:{event.source}",
                    relationship=RelationshipType.ANALYZED_BY,
                    provenance=event.source,
                )
            )
        self._track(start)

    def _track(self, start: float) -> None:
        self._build_count += 1
        self._build_ms += (time.monotonic() - start) * 1000
