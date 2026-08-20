"""Deterministic serializers: platform DTOs to natural-language context.

Every function here renders one existing intelligence DTO to a compact, stable
text block for inclusion in the Copilot's prompt context. The rendering is pure
and deterministic — the same DTO always produces the same text — so the prompt is
reproducible and the output is never an LLM-generated summary of an LLM-generated
summary.

These serializers read the DTOs; they never recompute any intelligence. All
scores, rationales, and relationships come straight from the deterministic
services that produced the DTOs.
"""

from __future__ import annotations

from core.domain.analytics_view import BlastRadiusEstimate, NeighborhoodAnalysis, RankedNode
from core.domain.attack_view import AttackChain, KillChainMapping, RootCause
from core.domain.graph_view import GraphNodeView
from core.domain.intelligence_view import CampaignIntelligence, IOCIntelligence, ThreatScore
from core.domain.recommendation_view import Recommendation


def _pct(value: float) -> str:
    return f"{round(value * 100)}%"


def _join_rationale(rationale: tuple[str, ...]) -> str:
    if not rationale:
        return ""
    return " Rationale: " + "; ".join(rationale) + "."


def render_threat_score(score: ThreatScore) -> str:
    """Render a threat score to deterministic text."""
    return (
        f"Threat score for {score.label or score.artifact_id}: "
        f"severity {_pct(score.severity)}, confidence {_pct(score.confidence)}, "
        f"exposure {_pct(score.exposure)}, blast radius {score.blast_radius} node(s), "
        f"priority {_pct(score.priority)}, analyst urgency {_pct(score.analyst_urgency)}."
        f"{_join_rationale(score.rationale)}"
    )


def render_ioc_intelligence(ioc: IOCIntelligence) -> str:
    """Render IOC intelligence to deterministic text."""
    return (
        f"IOC {ioc.label or ioc.ioc_id}: frequency {ioc.frequency}, "
        f"prevalence {_pct(ioc.prevalence)}, reuse {ioc.reuse_count}, "
        f"confidence {_pct(ioc.confidence)}, aging {ioc.aging_days:.0f} day(s), "
        f"risk {ioc.risk_percent}%."
        f"{_join_rationale(ioc.rationale)}"
    )


def render_campaign_intelligence(campaign: CampaignIntelligence) -> str:
    """Render campaign intelligence to deterministic text."""
    return (
        f"Campaign {campaign.label or campaign.campaign_id}: "
        f"{campaign.artifact_count} artifact(s), {campaign.ioc_count} IOC(s), "
        f"{campaign.infrastructure_count} infrastructure node(s), "
        f"shared-IOC score {_pct(campaign.shared_ioc_score)}, "
        f"evolution {campaign.evolution_days:.0f} day(s)."
        f"{_join_rationale(campaign.rationale)}"
    )


def render_recommendation(rec: Recommendation) -> str:
    """Render an analyst recommendation to deterministic text."""
    subject = rec.subject_id or "the platform"
    return (
        f"Recommendation ({rec.kind}): {rec.title} — subject {subject} "
        f"[{rec.subject_type or 'n/a'}], priority {_pct(rec.priority)}."
        f"{_join_rationale(rec.rationale)}"
    )


def render_attack_chain(chain: AttackChain) -> str:
    """Render an attack chain to deterministic text."""
    if not chain.steps:
        return (
            f"Attack chain from {chain.origin_id or 'origin'} to "
            f"{chain.target_id or 'target'}: no ordered steps reconstructed."
        )
    steps = " -> ".join(
        f"{s.order}. {s.label or s.node_id} [{s.node_type}/{s.kill_chain_phase}]"
        for s in chain.steps
    )
    return (
        f"Attack chain from {chain.origin_id} to {chain.target_id} "
        f"({chain.length} step(s)): {steps}.{_join_rationale(chain.rationale)}"
    )


def render_kill_chain(mapping: KillChainMapping) -> str:
    """Render a kill-chain mapping to deterministic text."""
    if not mapping.phases:
        return "Kill-chain mapping: no phases identified."
    phases = "; ".join(
        f"{phase}: {', '.join(node_ids) if node_ids else 'none'}"
        for phase, node_ids in mapping.phases
    )
    return f"Kill-chain mapping: {phases}.{_join_rationale(mapping.rationale)}"


def render_root_cause(root: RootCause) -> str:
    """Render a root-cause analysis to deterministic text."""
    if not root.root_id:
        return f"Root cause for incident {root.incident_id}: not determined."
    return (
        f"Root cause for incident {root.incident_id}: "
        f"{root.root_label or root.root_id} [{root.root_type}], "
        f"first seen {root.first_seen or 'unknown'}, "
        f"{len(root.evidence_ids)} supporting evidence node(s)."
        f"{_join_rationale(root.rationale)}"
    )


def render_blast_radius(blast: BlastRadiusEstimate) -> str:
    """Render a blast-radius estimate to deterministic text."""
    return (
        f"Blast radius from {blast.origin_id}: "
        f"{blast.reachable_count} reachable node(s) within depth {blast.max_depth}."
    )


def render_neighborhood(neigh: NeighborhoodAnalysis) -> str:
    """Render a neighbourhood analysis to deterministic text."""
    by_type = ", ".join(f"{count} {kind}" for kind, count in neigh.by_type)
    return (
        f"Neighbourhood of {neigh.origin_id} within {neigh.hops} hop(s): "
        f"{neigh.node_count} node(s), {neigh.edge_count} edge(s)"
        f"{f' ({by_type})' if by_type else ''}."
    )


def render_ranked_node(node: RankedNode, *, metric: str) -> str:
    """Render a ranked node (centrality/degree) to deterministic text."""
    return (
        f"{metric} node {node.label or node.node_id} [{node.node_type}]: "
        f"score {node.score:.3f}, degree {node.degree}, risk {node.risk_percent}%."
    )


def render_graph_node(node: GraphNodeView) -> str:
    """Render a graph node view to deterministic text."""
    meta = ", ".join(f"{k}={v}" for k, v in sorted(node.metadata.items()))
    return (
        f"Graph node {node.label or node.node_id} [{node.node_type}]: "
        f"risk {node.risk_percent}%, degree {node.degree}"
        f"{f'; {meta}' if meta else ''}."
    )
