"""Live intelligence pipeline.

Turns analysis results into intelligence events on the internal bus, where the
subscribed ``GraphBuilder`` and ``EventHistory`` consume them. All event
construction is centralised in :class:`IntelligencePublisher` (the single
publishing seam) so no publisher logic is duplicated across services.
"""

from services.pipeline.publisher import IntelligencePublisher, RelatedEntity

__all__ = ["IntelligencePublisher", "RelatedEntity"]
