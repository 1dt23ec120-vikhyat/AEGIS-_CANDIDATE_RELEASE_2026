"""Copilot grounding validation (M12 Phase 1).

Enforces the ADR-0002 grounding contract on a model answer: an answer is grounded
when it derives from the provided platform intelligence and carries citations to
it. This stage computes a grounding score from citation coverage, records
violations, and — in strict mode — refuses an ungrounded answer rather than
letting it through.

The grounding score is deterministic: the fraction of resolved citations over
all citation markers the model emitted, adjusted so that an answer with no
markers at all against a non-empty context is treated as ungrounded.
"""

from __future__ import annotations

from dataclasses import dataclass

from core.domain.copilot import Citation, ContextItem, GroundingViolation

_INSUFFICIENT_MESSAGE = (
    "The platform does not currently hold enough intelligence to answer this "
    "question. No supporting threat scores, IOCs, incidents, campaigns, or "
    "relationships were found for it."
)


@dataclass(frozen=True, slots=True)
class GroundingOutcome:
    """The result of grounding validation."""

    answer: str
    grounding_score: float
    citations: tuple[Citation, ...]
    violations: tuple[GroundingViolation, ...]


class GroundingValidator:
    """Scores and (optionally) enforces answer grounding."""

    def __init__(self, *, strict: bool = False) -> None:
        """Initialize the validator.

        Args:
            strict: When ``True``, an ungrounded answer is replaced with an
                explicit "insufficient intelligence" message. When ``False``
                (default), the answer is kept but flagged with a low score.
        """
        self._strict = strict

    def validate(
        self,
        answer: str,
        citations: tuple[Citation, ...],
        citation_violations: tuple[GroundingViolation, ...],
        items: tuple[ContextItem, ...],
    ) -> GroundingOutcome:
        """Validate the grounding of an answer.

        Args:
            answer: The cleaned answer (citation markers already stripped).
            citations: Resolved citations from the citation validator.
            citation_violations: Unresolved-citation violations.
            items: The context items provided to the model.

        Returns:
            A :class:`GroundingOutcome` with the (possibly replaced) answer, a
            grounding score in ``[0, 1]``, the citations, and all violations.
        """
        violations = list(citation_violations)

        if not items:
            # No intelligence was available; grounding is not applicable and the
            # honest answer is that the platform lacks the information.
            return GroundingOutcome(
                answer=answer if answer.strip() else _INSUFFICIENT_MESSAGE,
                grounding_score=0.0,
                citations=citations,
                violations=(
                    GroundingViolation(
                        reason="empty_context",
                        detail="No platform intelligence was available for the question.",
                    ),
                ),
            )

        total_markers = len(citations) + len(citation_violations)
        if total_markers == 0:
            violations.append(
                GroundingViolation(
                    reason="no_citations",
                    detail="The answer cited no platform intelligence.",
                )
            )
            score = 0.0
        else:
            score = round(len(citations) / total_markers, 4)

        if self._strict and not citations:
            return GroundingOutcome(
                answer=_INSUFFICIENT_MESSAGE,
                grounding_score=0.0,
                citations=(),
                violations=tuple(violations),
            )

        return GroundingOutcome(
            answer=answer,
            grounding_score=score,
            citations=citations,
            violations=tuple(violations),
        )
