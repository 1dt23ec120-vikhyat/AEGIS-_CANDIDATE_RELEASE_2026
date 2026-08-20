"""Reusable investigation workspace panels.

Each panel reads from the unified :class:`InvestigationSummary` and renders one
section of the analyst workspace. Panels are artifact-agnostic — the same
components serve URL, email, file, and all future artifact types. The workspace
page composes them in the approved layout order.
"""

from __future__ import annotations

from PySide6.QtWidgets import QHBoxLayout, QTreeWidget, QTreeWidgetItem, QVBoxLayout, QWidget

from core.domain.investigation import (
    EvidenceNode,
    InvestigationEvent,
    InvestigationSummary,
    MetadataField,
)
from ui.components.badges import Badge
from ui.components.cards import Card
from ui.components.section import Section
from ui.components.tables import DataTable
from ui.components.text import label
from ui.theme import ThemeManager

_VERDICT_TONE = {"legitimate": "success", "suspicious": "warning", "phishing": "danger"}
_SEVERITY_TONE = {
    "critical": "danger",
    "high": "danger",
    "medium": "warning",
    "low": "info",
    "info": "neutral",
}
_KIND_TONE = {
    "analysis_started": "info",
    "provider_executed": "neutral",
    "evidence_discovered": "warning",
    "ioc_extracted": "info",
    "threat_match": "danger",
    "correlation": "warning",
    "analysis_completed": "success",
    "analyst_comment": "info",
}
_DASH = "\u2014"


class InvestigationHeader(Card):
    """Executive summary header for any artifact investigation."""

    def __init__(self, summary: InvestigationSummary, *, parent: QWidget | None = None) -> None:
        """Build the investigation header."""
        super().__init__(parent=parent)
        row = QHBoxLayout()
        row.addWidget(
            Badge(summary.verdict.upper(), tone=_VERDICT_TONE.get(summary.verdict, "neutral"))
        )
        row.addWidget(
            Badge(summary.severity.upper(), tone=_SEVERITY_TONE.get(summary.severity, "neutral"))
        )
        row.addWidget(Badge(summary.category.replace("_", " ").title(), tone="info"))
        row.addWidget(Badge(summary.artifact_type.upper(), tone="neutral"))
        row.addStretch(1)
        risk = label(f"{summary.risk_percent}% risk", role="h2")
        row.addWidget(risk)
        self.content_layout.addLayout(row)
        self.add(
            label(
                f"Confidence {round(summary.confidence * 100)}%"
                f"   \u00b7   Evidence {round(summary.evidence_strength * 100)}%"
                f"   \u00b7   Duration {summary.analysis_duration_ms:.0f} ms",
                role="muted",
            )
        )
        if summary.artifact_id:
            self.add(label(f"Artifact {summary.artifact_id}", role="caption"))


class TimelinePanel(QWidget):
    """Chronological investigation timeline."""

    def __init__(
        self,
        events: tuple[InvestigationEvent, ...],
        *,
        parent: QWidget | None = None,
    ) -> None:
        """Build the timeline panel."""
        super().__init__(parent)
        section = Section(
            "Investigation Timeline", badge=f"{len(events)} events", badge_tone="info"
        )
        if not events:
            section.add_body(label("No events recorded.", role="muted"))
        else:
            table = DataTable(["Event", "Source", "Description"])
            table.set_rows(
                [[e.kind.value.replace("_", " ").title(), e.source, e.description] for e in events]
            )
            table.setMinimumHeight(min(360, 60 + len(events) * 30))
            section.add_body(table)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.addWidget(section)


class EvidenceTreePanel(QWidget):
    """Hierarchical evidence tree: Provider → Evidence → Contribution → Recommendation → MITRE."""

    def __init__(
        self,
        nodes: tuple[EvidenceNode, ...],
        theme_manager: ThemeManager,
        *,
        parent: QWidget | None = None,
    ) -> None:
        """Build the evidence tree."""
        super().__init__(parent)
        section = Section("Evidence Tree", badge=f"{len(nodes)} source(s)", badge_tone="info")
        if not nodes:
            section.add_body(label("No evidence collected.", role="muted"))
        else:
            tree = QTreeWidget()
            tree.setHeaderLabels(["Source / Finding", "Detail", "Risk"])
            tree.setColumnCount(3)
            tree.setMinimumHeight(min(400, 80 + len(nodes) * 50))
            tree.setAlternatingRowColors(True)
            for node in nodes:
                self._add_node(tree, None, node)
            tree.expandAll()
            section.add_body(tree)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.addWidget(section)

    def _add_node(
        self,
        tree: QTreeWidget,
        parent_item: QTreeWidgetItem | None,
        node: EvidenceNode,
    ) -> None:
        item = QTreeWidgetItem(tree) if parent_item is None else QTreeWidgetItem(parent_item)
        item.setText(0, node.label)
        item.setText(1, node.detail[:120] if node.detail else _DASH)
        item.setText(2, f"{node.risk:.0%}" if node.risk else _DASH)
        for child in node.children:
            self._add_node(tree, item, child)


class IOCPanel(QWidget):
    """Indicator-of-compromise workspace with stable identifiers."""

    def __init__(
        self,
        summary: InvestigationSummary,
        *,
        parent: QWidget | None = None,
    ) -> None:
        """Build the IOC panel."""
        super().__init__(parent)
        section = Section("IOC Workspace", expanded=True)
        # Hash table
        hashes = [m for m in summary.metadata if m.category == "hashes"]
        if hashes:
            section.add_body(label("Hashes", role="caption"))
            ht = DataTable(["Algorithm", "Value"])
            ht.set_rows([[h.label, h.value] for h in hashes])
            ht.setMinimumHeight(120)
            section.add_body(ht)
        # IOC indicators from metadata-adjacent data (not repeated here if
        # the caller provides them via the indicators section).
        section.add_body(
            label(
                "IOC identifiers use stable UUID-5 values for future Threat Graph linkage.",
                role="caption",
            )
        )
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.addWidget(section)


class RelationshipPanel(QWidget):
    """Displays Threat Graph relationships from the fusion layer."""

    def __init__(
        self,
        relationships: tuple[tuple[str, str, str, str, float], ...],
        *,
        parent: QWidget | None = None,
    ) -> None:
        """Build the relationship panel."""
        super().__init__(parent)
        section = Section(
            "Relationships",
            badge=f"{len(relationships)} edge(s)",
            badge_tone="info" if relationships else "neutral",
            expanded=bool(relationships),
        )
        if not relationships:
            section.add_body(label("No relationships discovered.", role="muted"))
        else:
            table = DataTable(["Source", "Relationship", "Target", "Confidence"])
            table.set_rows(
                [
                    [f"{s_type}:{s_id[:12]}", rel, f"{t_type}:{t_id[:12]}", f"{conf:.0%}"]
                    for s_id, s_type, t_id, t_type, rel, conf in (
                        (r[0], r[1], r[2], r[3], "→", r[4]) for r in relationships
                    )
                ]
            )
            table.setMinimumHeight(min(300, 60 + len(relationships) * 30))
            section.add_body(table)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.addWidget(section)


class MetadataPanel(QWidget):
    """Adaptive metadata panel — layout is driven by the metadata fields."""

    def __init__(
        self,
        fields: tuple[MetadataField, ...],
        *,
        parent: QWidget | None = None,
    ) -> None:
        """Build the metadata panel."""
        super().__init__(parent)
        section = Section("Metadata")
        if not fields:
            section.add_body(label("No metadata available.", role="muted"))
        else:
            table = DataTable(["Field", "Value"])
            table.set_rows([[f.label, f.value] for f in fields])
            table.setMinimumHeight(min(400, 60 + len(fields) * 28))
            section.add_body(table)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.addWidget(section)


class ThreatHistoryPanel(QWidget):
    """Previous related intelligence and detection history."""

    def __init__(
        self,
        history: tuple[str, ...],
        incident_id: str = "",
        incident_title: str = "",
        campaign_name: str = "",
        *,
        parent: QWidget | None = None,
    ) -> None:
        """Build the threat history panel."""
        super().__init__(parent)
        section = Section("Threat History", expanded=bool(history or incident_id))
        entries: list[str] = []
        if incident_id:
            entries.append(f"Incident: {incident_title}")
        if campaign_name:
            entries.append(f"Campaign: {campaign_name}")
        entries.extend(history)
        if not entries:
            section.add_body(label("No previous related intelligence.", role="muted"))
        else:
            for entry in entries:
                section.add_body(label(f"\u2022 {entry}", role="body"))
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.addWidget(section)


class ProviderDiagnosticsPanel(QWidget):
    """Provider registry diagnostics for the analysis run."""

    def __init__(
        self,
        diagnostics: tuple[tuple[str, str, float, int], ...],
        *,
        parent: QWidget | None = None,
    ) -> None:
        """Build the provider diagnostics panel."""
        super().__init__(parent)
        section = Section(
            "Provider Diagnostics",
            badge=f"{len(diagnostics)} provider(s)",
            badge_tone="info",
            expanded=False,
        )
        if not diagnostics:
            section.add_body(label("No provider diagnostics available.", role="muted"))
        else:
            table = DataTable(["Provider", "Version", "Duration (ms)", "Findings"])
            table.set_rows(
                [
                    [name, version, f"{ms:.1f}", str(count)]
                    for name, version, ms, count in diagnostics
                ]
            )
            table.setMinimumHeight(min(320, 60 + len(diagnostics) * 30))
            section.add_body(table)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.addWidget(section)


class RecommendationsPanel(QWidget):
    """Consolidated analyst recommendations from the fusion layer."""

    def __init__(
        self,
        recommendations: tuple[str, ...],
        technique_ids: tuple[str, ...] = (),
        *,
        parent: QWidget | None = None,
    ) -> None:
        """Build the recommendations panel."""
        super().__init__(parent)
        section = Section("Analyst Recommendations", expanded=bool(recommendations))
        if not recommendations:
            section.add_body(label("No specific recommendations at this time.", role="muted"))
        else:
            section.add_body(label("Immediate actions", role="caption"))
            for rec in recommendations:
                section.add_body(label(f"\u2022 {rec}", role="body"))
        if technique_ids:
            section.add_body(label("MITRE ATT&CK techniques", role="caption"))
            section.add_body(label(", ".join(technique_ids), role="body"))
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.addWidget(section)


class PerformancePanel(QWidget):
    """Analysis performance metrics."""

    def __init__(
        self,
        performance: dict[str, float],
        *,
        parent: QWidget | None = None,
    ) -> None:
        """Build the performance panel."""
        super().__init__(parent)
        section = Section("Performance", expanded=False)
        if not performance:
            section.add_body(label("No performance data available.", role="muted"))
        else:
            table = DataTable(["Metric", "Duration (ms)"])
            table.set_rows(
                [[k.replace("_", " ").title(), f"{v:.1f}"] for k, v in performance.items()]
            )
            table.setMinimumHeight(min(200, 60 + len(performance) * 30))
            section.add_body(table)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.addWidget(section)
