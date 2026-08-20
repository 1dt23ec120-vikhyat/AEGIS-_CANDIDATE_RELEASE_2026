"""Copilot context collector (M12 Phase 1).

The read-only bridge between the Copilot and the platform's deterministic
intelligence. Given a query, its focus, and the selected skill's scope, the
collector calls the existing analytics, intelligence, attack, recommendation,
graph, and SOC services and renders their DTOs into ranked
:class:`~core.domain.copilot.ContextItem` blocks.

Design guarantees:

- **Read-only.** The collector only calls query/score/analyze/rank/report
  methods on already-built services. It never mutates state, never invokes a
  detection engine, and never writes to any repository.
- **No duplicated intelligence.** Every score, rationale, and relationship comes
  straight from the services that own it; the collector serializes, it does not
  recompute.
- **Intelligence-based ranking.** Items are ordered by severity first — the
  platform's own risk signal — so the most important intelligence survives the
  token budget. Graph proximity to the focus node is used to *discover* related
  intelligence via the existing graph query, making the knowledge graph the
  primary navigation engine rather than keyword matching.
"""

from __future__ import annotations

import time

from core.domain.copilot import ContextItem, CopilotContext, DetectedIntent
from core.domain.copilot_session import FocusState
from core.domain.graph import NodeType
from core.interfaces import ILogger
from core.interfaces.copilot_skill import SkillSpec
from services.analytics.attack_analysis import AttackAnalysisService
from services.analytics.campaign_intelligence import CampaignIntelligenceService
from services.analytics.graph_analytics import GraphAnalyticsService
from services.analytics.ioc_intelligence import IOCIntelligenceService
from services.analytics.observability import MeteredService, tracked
from services.analytics.recommendations import RecommendationService
from services.analytics.soc_analytics import AnalyticsOverviewService
from services.analytics.threat_scoring import ThreatScoringService
from services.copilot.context import serializers as ser
from services.graph.query import GraphQueryService

_CHARS_PER_TOKEN = 4
_DEFAULT_TOP = 5


def _estimate_tokens(text: str) -> int:
    return max(1, len(text) // _CHARS_PER_TOKEN)


class ContextCollector(MeteredService):
    """Collects and ranks deterministic platform intelligence for a query."""

    def __init__(  # noqa: PLR0913 - one collaborator per intelligence domain
        self,
        graph_query: GraphQueryService,
        graph_analytics: GraphAnalyticsService,
        ioc_intelligence: IOCIntelligenceService,
        campaign_intelligence: CampaignIntelligenceService,
        threat_scoring: ThreatScoringService,
        attack_analysis: AttackAnalysisService,
        recommendations: RecommendationService,
        analytics_overview: AnalyticsOverviewService,
        logger: ILogger,
        *,
        token_budget: int = 6000,
        max_items: int = 24,
    ) -> None:
        """Initialize the collector with the read-only intelligence services.

        Args:
            graph_query: Knowledge-graph query service (navigation).
            graph_analytics: Deterministic graph analytics (blast radius, etc.).
            ioc_intelligence: IOC intelligence service.
            campaign_intelligence: Campaign intelligence service.
            threat_scoring: Threat scoring service.
            attack_analysis: Attack analysis service.
            recommendations: Analyst recommendation engine.
            analytics_overview: Aggregate SOC analytics overview.
            logger: Injected logger.
            token_budget: Maximum estimated tokens of context to include.
            max_items: Hard cap on the number of context items.
        """
        super().__init__()
        self._query = graph_query
        self._analytics = graph_analytics
        self._ioc = ioc_intelligence
        self._campaign = campaign_intelligence
        self._scoring = threat_scoring
        self._attack = attack_analysis
        self._recommendations = recommendations
        self._overview = analytics_overview
        self._logger = logger
        self._token_budget = token_budget
        self._max_items = max_items

    @tracked
    def collect(self, intent: DetectedIntent, spec: SkillSpec, focus: FocusState) -> CopilotContext:
        """Collect ranked context for a query under the skill's scope."""
        start = time.perf_counter()
        scope = spec.context_scope
        if scope == "artifact":
            items = self._collect_artifact(intent, focus)
        elif scope == "incident":
            items = self._collect_incident(intent, focus)
        elif scope == "campaign":
            items = self._collect_campaign(intent, focus)
        else:
            items = self._collect_global()

        ranked = self._rank_and_bound(items)
        elapsed = (time.perf_counter() - start) * 1000
        total_tokens = sum(i.token_estimate for i in ranked)
        return CopilotContext(
            items=ranked,
            scope=scope,
            total_token_estimate=total_tokens,
            truncated=len(ranked) < len(items),
            collection_ms=round(elapsed, 3),
        )

    # --- scope strategies ------------------------------------------------

    def _resolve_artifact(self, intent: DetectedIntent, focus: FocusState) -> str:
        if intent.focus_type == "artifact" and intent.focus_id:
            return intent.focus_id
        if focus.current_artifact_id:
            return focus.current_artifact_id
        if focus.recent_graph_selections:
            return focus.recent_graph_selections[0]
        return ""

    def _collect_artifact(self, intent: DetectedIntent, focus: FocusState) -> list[ContextItem]:
        artifact_id = self._resolve_artifact(intent, focus)
        if not artifact_id:
            return self._collect_global()

        items: list[ContextItem] = []
        node = self._query.lookup(artifact_id)
        if node is None:
            self._logger.info("copilot: artifact %s not in graph", artifact_id)
            return self._collect_global()

        score = self._scoring.score(artifact_id)
        items.append(
            self._item(
                "threat_score",
                artifact_id,
                node.display_name or artifact_id,
                ser.render_threat_score(score),
                score.severity,
            )
        )

        blast = self._analytics.blast_radius(artifact_id)
        items.append(
            self._item(
                "blast_radius",
                artifact_id,
                node.display_name or artifact_id,
                ser.render_blast_radius(blast),
                score.severity,
            )
        )

        neigh = self._analytics.neighborhood(artifact_id, hops=1)
        items.append(
            self._item(
                "neighbourhood",
                artifact_id,
                node.display_name or artifact_id,
                ser.render_neighborhood(neigh),
                score.severity * 0.6,
            )
        )

        # IOC intelligence for each IOC neighbour (graph-driven discovery).
        for neighbour in self._query.neighbors(artifact_id):
            if neighbour.node_type is NodeType.IOC:
                intel = self._ioc.analyze(neighbour.node_id)
                items.append(
                    self._item(
                        "ioc_intelligence",
                        neighbour.node_id,
                        neighbour.display_name or neighbour.node_id,
                        ser.render_ioc_intelligence(intel),
                        intel.risk_percent / 100.0,
                    )
                )

        return items

    def _collect_incident(self, intent: DetectedIntent, focus: FocusState) -> list[ContextItem]:
        incident_id = (
            intent.focus_id
            if intent.focus_type == "incident" and intent.focus_id
            else focus.current_incident_id
        )
        if not incident_id:
            return self._collect_global()

        items: list[ContextItem] = []
        root = self._attack.root_cause(incident_id)
        items.append(
            self._item("root_cause", incident_id, incident_id, ser.render_root_cause(root), 0.9)
        )

        members = self._query.investigation_subgraph(incident_id, max_depth=2)
        artifact_types = {NodeType.ARTIFACT, NodeType.URL, NodeType.FILE, NodeType.EMAIL}
        for member in members:
            if member.node_type in artifact_types:
                score = self._scoring.score(member.node_id)
                items.append(
                    self._item(
                        "threat_score",
                        member.node_id,
                        member.display_name or member.node_id,
                        ser.render_threat_score(score),
                        score.severity,
                    )
                )

        if root.root_id:
            for member in members:
                if member.node_type in artifact_types:
                    chain = self._attack.attack_chain(root.root_id, member.node_id)
                    if chain.steps:
                        items.append(
                            self._item(
                                "attack_chain",
                                f"{root.root_id}->{member.node_id}",
                                member.display_name or member.node_id,
                                ser.render_attack_chain(chain),
                                0.8,
                            )
                        )
                        break

        return items

    def _collect_campaign(self, intent: DetectedIntent, focus: FocusState) -> list[ContextItem]:
        campaign_id = (
            intent.focus_id
            if intent.focus_type == "campaign" and intent.focus_id
            else focus.active_campaign_id
        )
        if not campaign_id:
            return self._collect_global()

        items: list[ContextItem] = []
        intel = self._campaign.analyze(campaign_id)
        items.append(
            self._item(
                "campaign_intelligence",
                campaign_id,
                intel.label or campaign_id,
                ser.render_campaign_intelligence(intel),
                intel.shared_ioc_score,
            )
        )
        return items

    def _collect_global(self) -> list[ContextItem]:
        items: list[ContextItem] = []
        for score in self._scoring.rank(top=_DEFAULT_TOP):
            items.append(
                self._item(
                    "threat_score",
                    score.artifact_id,
                    score.label or score.artifact_id,
                    ser.render_threat_score(score),
                    score.severity,
                )
            )
        for intel in self._campaign.rank(top=_DEFAULT_TOP):
            items.append(
                self._item(
                    "campaign_intelligence",
                    intel.campaign_id,
                    intel.label or intel.campaign_id,
                    ser.render_campaign_intelligence(intel),
                    intel.shared_ioc_score,
                )
            )
        for ioc in self._ioc.rank(top=_DEFAULT_TOP):
            items.append(
                self._item(
                    "ioc_intelligence",
                    ioc.ioc_id,
                    ioc.label or ioc.ioc_id,
                    ser.render_ioc_intelligence(ioc),
                    ioc.risk_percent / 100.0,
                )
            )
        for central in self._analytics.centrality_ranking(top=_DEFAULT_TOP):
            items.append(
                self._item(
                    "central_node",
                    central.node_id,
                    central.label or central.node_id,
                    ser.render_ranked_node(central, metric="Central"),
                    central.risk_percent / 100.0,
                )
            )
        for rec in self._recommendations.recommended_actions().recommendations:
            items.append(
                self._item(
                    "recommendation",
                    rec.subject_id or rec.kind,
                    rec.title,
                    ser.render_recommendation(rec),
                    rec.priority,
                )
            )
        return items

    # --- helpers ---------------------------------------------------------

    def _item(
        self, kind: str, source_id: str, label: str, summary: str, severity: float
    ) -> ContextItem:
        return ContextItem(
            kind=kind,
            source_id=source_id,
            label=label,
            summary=summary,
            severity=round(max(0.0, min(1.0, severity)), 4),
            token_estimate=_estimate_tokens(summary),
        )

    def _rank_and_bound(self, items: list[ContextItem]) -> tuple[ContextItem, ...]:
        # Deterministic ranking: severity desc, then kind, then source id.
        deduped: dict[str, ContextItem] = {}
        for item in items:
            key = item.citation_key
            existing = deduped.get(key)
            if existing is None or item.severity > existing.severity:
                deduped[key] = item
        ordered = sorted(
            deduped.values(),
            key=lambda i: (-i.severity, i.kind, i.source_id),
        )

        bounded: list[ContextItem] = []
        used_tokens = 0
        for item in ordered:
            if len(bounded) >= self._max_items:
                break
            if used_tokens + item.token_estimate > self._token_budget and bounded:
                break
            bounded.append(item)
            used_tokens += item.token_estimate
        return tuple(bounded)
