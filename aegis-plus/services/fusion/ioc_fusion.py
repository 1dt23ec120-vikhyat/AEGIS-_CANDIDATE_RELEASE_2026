"""IOC Fusion Service.

Cross-artifact IOC correlation: given IOC collections from multiple analyses
(URL, email, file), the fusion service identifies shared indicators, builds
prepared Threat Graph relationships, and produces a merged collection with
deduplication — making the platform behave as one intelligence system rather
than three independent scanners.

Relationships use stable ``ioc_id`` values so a future graph module can persist
them without changing this service.
"""

from __future__ import annotations

from core.domain.fusion import IntelligenceRelationship
from core.domain.ioc import IocCollection


class IOCFusionService:
    """Correlates IOCs across artifact types and extracts relationships."""

    def merge(self, *collections: IocCollection) -> IocCollection:
        """Merge multiple IOC collections into one, deduplicating values."""
        result = IocCollection()
        for collection in collections:
            result = result.merged_with(collection)
        return result

    def extract_relationships(
        self,
        artifact_id: str,
        artifact_type: str,
        collection: IocCollection,
    ) -> tuple[IntelligenceRelationship, ...]:
        """Build Threat Graph relationship edges from an artifact's IOCs.

        Every extracted indicator becomes an ``artifact → contains → ioc`` edge.
        Cross-artifact correlation happens when two artifacts share an IOC with
        the same ``ioc_id``.

        Args:
            artifact_id: The stable identifier of the source artifact (e.g.
                a scan ID or SHA-256).
            artifact_type: The artifact's type label (``url``, ``email``,
                ``file``).
            collection: The IOCs extracted from the artifact.

        Returns:
            A tuple of :class:`IntelligenceRelationship` edges.
        """
        relationships: list[IntelligenceRelationship] = []
        for tagged in collection.tagged():
            relationships.append(
                IntelligenceRelationship(
                    source_id=artifact_id,
                    source_type=artifact_type,
                    target_id=tagged.ioc_id,
                    target_type=tagged.indicator_type,
                    relationship="contains",
                )
            )
        return _dedupe_relationships(tuple(relationships))

    def cross_correlate(
        self,
        collections: dict[str, IocCollection],
    ) -> tuple[IntelligenceRelationship, ...]:
        """Find IOCs shared between artifacts and return linking edges.

        Args:
            collections: A mapping of ``artifact_id → IocCollection``.

        Returns:
            Edges linking artifacts that share at least one IOC value.
        """
        ioc_to_artifacts: dict[str, list[str]] = {}
        for artifact_id, collection in collections.items():
            for tagged in collection.tagged():
                ioc_to_artifacts.setdefault(tagged.ioc_id, []).append(artifact_id)

        relationships: list[IntelligenceRelationship] = []
        for _ioc_id, artifact_ids in ioc_to_artifacts.items():
            unique = list(dict.fromkeys(artifact_ids))
            if len(unique) < 2:  # noqa: PLR2004 - need at least two artifacts to correlate
                continue
            for i, source in enumerate(unique):
                for target in unique[i + 1 :]:
                    relationships.append(
                        IntelligenceRelationship(
                            source_id=source,
                            source_type="artifact",
                            target_id=target,
                            target_type="artifact",
                            relationship="shares_ioc",
                        )
                    )
        return _dedupe_relationships(tuple(relationships))


def _dedupe_relationships(
    relationships: tuple[IntelligenceRelationship, ...],
) -> tuple[IntelligenceRelationship, ...]:
    """Remove duplicate relationships by key."""
    seen: dict[str, None] = {}
    unique: list[IntelligenceRelationship] = []
    for rel in relationships:
        if rel.key not in seen:
            seen[rel.key] = None
            unique.append(rel)
    return tuple(unique)
