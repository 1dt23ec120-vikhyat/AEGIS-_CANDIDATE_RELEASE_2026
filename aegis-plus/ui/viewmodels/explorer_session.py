"""Explorer session state (presentation-only, in-memory).

Value objects that capture a snapshot of the analyst's Graph Explorer session —
viewport, focus, expanded nodes, active filters, and timeline position. They are
held in memory only; nothing here reads or writes storage. They exist so a future
milestone can add session persistence without reshaping the presentation layer:
the capture/restore surface is defined now, the durable backing is not.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from ui.components.graph.panels import FilterCriteria


@dataclass(frozen=True, slots=True)
class ViewportState:
    """The canvas viewport (zoom and centre) at a point in time."""

    scale: float = 1.0
    center_x: float = 0.0
    center_y: float = 0.0


@dataclass(frozen=True, slots=True)
class ExplorerSessionState:
    """A restorable snapshot of a Graph Explorer session.

    Presentation-only: it references view identifiers and UI selections, never
    domain objects or repositories. Defaults describe an empty session.
    """

    focus_node: str = ""
    expanded_nodes: frozenset[str] = field(default_factory=frozenset)
    filters: FilterCriteria = field(default_factory=FilterCriteria)
    timeline_cutoff: str = ""
    depth: int = 1
    viewport: ViewportState = field(default_factory=ViewportState)

    @property
    def is_empty(self) -> bool:
        """Whether this session has no focus and no expanded nodes."""
        return not self.focus_node and not self.expanded_nodes
