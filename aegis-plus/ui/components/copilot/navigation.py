"""Citation navigation (M12 Phase 2).

Maps a Copilot :class:`Citation` to a navigation target, reusing the existing
routing framework. Every cited entity — threat score, IOC, campaign, attack
chain, root cause, neighbourhood, central node, recommendation — corresponds to a
node (or a node pair) in the knowledge graph, so the natural, uniformly-supported
destination is the Graph Explorer focused on that node. This reuses the Explorer's
existing ``{focus, origin}`` payload contract and adds no new navigation surface.
"""

from __future__ import annotations

from core.domain.copilot import Citation
from ui.navigation.routes import Route

# Citation kinds whose source_id is a compound "a->b" identifier; the first
# component is the node to focus.
_PAIR_KINDS = frozenset({"attack_chain"})


def citation_target(citation: Citation) -> tuple[Route, dict[str, object]] | None:
    """Resolve a citation to a ``(route, payload)`` navigation target.

    Returns ``None`` when the citation carries no usable identifier.
    """
    focus = _focus_id(citation)
    if not focus:
        return None
    return Route.GRAPH_EXPLORER, {"focus": focus, "origin": Route.COPILOT}


def _focus_id(citation: Citation) -> str:
    source_id = citation.source_id.strip()
    if not source_id:
        return ""
    if citation.kind in _PAIR_KINDS and "->" in source_id:
        return source_id.split("->", 1)[0].strip()
    return source_id
