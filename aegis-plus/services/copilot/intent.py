"""Deterministic intent detection (M12 Phase 1).

Maps an analyst question to one of the supported :class:`IntentKind` values using
simple, explainable keyword rules plus the session focus. Detection is entirely
deterministic and rule-based — the LLM is never used to decide intent — so the
selected skill and gathered context are reproducible and auditable.

Ambiguity is resolved conservatively: when no keyword rule matches, the intent
falls back to the focus (an artifact under investigation implies a threat
investigation) and finally to a general executive summary.
"""

from __future__ import annotations

from core.domain.copilot import CopilotQuery, DetectedIntent, IntentKind
from core.domain.copilot_session import FocusState

# Ordered rules: the first intent whose terms match wins. Order encodes priority
# so that specific intents (IOC, incident, campaign) beat the general ones.
_RULES: tuple[tuple[IntentKind, tuple[str, ...]], ...] = (
    (
        IntentKind.IOC_INTELLIGENCE,
        ("ioc", "indicator", "hash", "domain", "ip address", "url reuse", "reused"),
    ),
    (
        IntentKind.INCIDENT_ANALYSIS,
        ("incident", "root cause", "kill chain", "kill-chain", "attack chain", "triage"),
    ),
    (
        IntentKind.GRAPH_REASONING,
        (
            "graph",
            "related",
            "relationship",
            "connected",
            "neighbour",
            "neighbor",
            "path",
            "blast radius",
            "propagation",
            "shared infrastructure",
        ),
    ),
    (
        IntentKind.EXECUTIVE_SUMMARY,
        (
            "summary",
            "summarise",
            "summarize",
            "overview",
            "executive",
            "posture",
            "brief",
            "report",
        ),
    ),
    (
        IntentKind.THREAT_INVESTIGATION,
        (
            "malicious",
            "why",
            "threat",
            "phishing",
            "malware",
            "risk",
            "severity",
            "verdict",
            "investigate",
            "explain",
            "confidence",
        ),
    ),
)


class IntentDetector:
    """Deterministic, rule-based intent detection."""

    def detect(self, query: CopilotQuery, focus: FocusState) -> DetectedIntent:
        """Detect the intent of a question from keywords and focus."""
        text = query.question.lower()
        focus_id, focus_type = self._resolve_focus(query, focus)

        for intent, terms in _RULES:
            matched = tuple(term for term in terms if term in text)
            if matched:
                confidence = min(1.0, 0.5 + 0.1 * len(matched))
                return DetectedIntent(
                    intent=intent,
                    confidence=round(confidence, 3),
                    focus_id=focus_id,
                    focus_type=focus_type,
                    matched_terms=matched,
                    rationale=(
                        f"Matched {len(matched)} term(s) for {intent.value}: "
                        f"{', '.join(matched)}."
                    ),
                )

        # No keyword rule matched — fall back to focus, then to a summary.
        if focus_type == "artifact":
            return DetectedIntent(
                intent=IntentKind.THREAT_INVESTIGATION,
                confidence=0.4,
                focus_id=focus_id,
                focus_type=focus_type,
                rationale="No keyword matched; defaulting to the focused artifact.",
            )
        if focus_type == "incident":
            return DetectedIntent(
                intent=IntentKind.INCIDENT_ANALYSIS,
                confidence=0.4,
                focus_id=focus_id,
                focus_type=focus_type,
                rationale="No keyword matched; defaulting to the focused incident.",
            )
        return DetectedIntent(
            intent=IntentKind.EXECUTIVE_SUMMARY,
            confidence=0.3,
            focus_id=focus_id,
            focus_type=focus_type,
            rationale="No keyword or focus matched; defaulting to an executive summary.",
        )

    def _resolve_focus(self, query: CopilotQuery, focus: FocusState) -> tuple[str, str]:
        candidates: tuple[tuple[str, str], ...] = (
            (query.artifact_id, "artifact"),
            (query.incident_id, "incident"),
            (query.campaign_id, "campaign"),
            (focus.current_artifact_id, "artifact"),
            (focus.current_incident_id, "incident"),
            (focus.active_campaign_id, "campaign"),
        )
        for identifier, kind in candidates:
            if identifier:
                return identifier, kind
        return "", ""
