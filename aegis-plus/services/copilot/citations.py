"""Copilot citation validation (M12 Phase 1).

Parses the ``[cite:KIND:ID]`` markers the model emitted and resolves each against
the context that was actually provided. Resolved markers become
:class:`Citation` value objects carrying the source label and the exact context
excerpt; unresolved markers are reported as grounding violations. This makes the
Copilot's grounding visible and checkable rather than implicit.
"""

from __future__ import annotations

import re

from core.domain.copilot import Citation, ContextItem, GroundingViolation

_CITE_PATTERN = re.compile(r"\[cite:([a-z_]+):([^\]]+)\]")


class CitationValidator:
    """Resolves citation markers against the provided context."""

    def validate(
        self, answer: str, items: tuple[ContextItem, ...]
    ) -> tuple[tuple[Citation, ...], tuple[GroundingViolation, ...]]:
        """Resolve citations in an answer against the context items.

        Args:
            answer: The raw model answer containing ``[cite:KIND:ID]`` markers.
            items: The context items that were provided to the model.

        Returns:
            A tuple of (resolved citations, grounding violations). Citations are
            de-duplicated and returned in first-seen order.
        """
        by_key = {item.citation_key: item for item in items}
        seen: set[str] = set()
        citations: list[Citation] = []
        violations: list[GroundingViolation] = []

        for match in _CITE_PATTERN.finditer(answer):
            kind, source_id = match.group(1), match.group(2).strip()
            key = f"{kind}:{source_id}"
            if key in seen:
                continue
            seen.add(key)
            item = by_key.get(key)
            if item is None:
                violations.append(
                    GroundingViolation(
                        reason="unresolved_citation",
                        detail=f"Citation {key} is not present in the provided context.",
                    )
                )
                continue
            citations.append(
                Citation(
                    kind=item.kind,
                    source_id=item.source_id,
                    label=item.label,
                    excerpt=item.summary,
                )
            )

        return tuple(citations), tuple(violations)

    @staticmethod
    def strip_markers(answer: str) -> str:
        """Remove citation markers, leaving clean prose for display."""
        cleaned = _CITE_PATTERN.sub("", answer)
        # Collapse doubled spaces left by removed markers.
        return re.sub(r"[ \t]{2,}", " ", cleaned).strip()
