# ADR-0002 — The AI Security Copilot Is Never a Source of Truth

- **Status:** Accepted (M12 Phase 1)
- **Context date:** M12
- **Deciders:** Architecture review (gated milestone approvals)

## Context

M12 introduces an AI Security Copilot: a natural-language assistant that helps
analysts understand the platform's findings. Large-language-model assistants
carry a well-known risk — they can produce fluent, plausible statements that are
not backed by any real evidence. In a security platform, an assistant that
invents a verdict, a risk score, an IOC, an incident, a campaign, or a
relationship would be actively dangerous: it could mislead an analyst during
response, contradict the deterministic engines, or manufacture confidence that
the underlying data does not support.

AEGIS+ already produces authoritative, deterministic, explainable intelligence
through its detection engines, fusion, correlation, knowledge graph, and the M11
analytics/intelligence services. The Copilot must add an interpretive layer on
top of that intelligence **without ever becoming a competing or overriding source
of it**.

## Decision

**The AI Security Copilot is never a source of truth. All deterministic platform
intelligence remains authoritative. The Copilot only explains and reasons over
deterministic intelligence.**

This principle is realised structurally, not merely by convention:

1. **Read-only consumption.** The Copilot's `ContextCollector` calls only the
   query/score/analyze/rank/report methods of already-built services. It never
   invokes a detection engine, never mutates state, and never writes to any
   repository. There is no code path from the Copilot to a write operation.

2. **No duplicated intelligence.** Every score, rationale, relationship, and
   verdict in a Copilot answer originates from the service that owns it. The
   Copilot serializes existing DTOs into prompt context; it recomputes nothing.
   No scoring, traversal, correlation, recommendation, or analytics logic is
   reimplemented.

3. **Grounding is mandatory and checked.** The system prompt instructs the model
   to answer only from the provided context, to cite every claim with a
   `[cite:KIND:ID]` marker drawn from that context, and to state plainly when the
   context is insufficient rather than guess. After generation, the
   `CitationValidator` resolves every marker against the context that was
   actually supplied, and the `GroundingValidator` scores coverage and (in strict
   mode) refuses an ungrounded answer.

4. **No verdict or score authorship.** The Copilot never emits its own verdict,
   risk score, severity, or category. It explains the platform's figures using
   the platform's own numbers.

5. **Graceful, non-authoritative failure.** When the LLM provider is
   unavailable, the Copilot returns an explicit "unavailable" response. The
   platform's deterministic intelligence remains fully available and
   authoritative in the dashboards; nothing about the platform depends on the
   Copilot.

6. **Provider-agnostic boundary.** The Copilot depends on the Core-owned
   `ILLMProvider` port. The model is an interchangeable inference backend, not a
   knowledge authority.

## Consequences

- Analysts can trust that any factual claim the Copilot makes is traceable, via a
  citation, to a specific deterministic platform output they can open and verify.
- The Copilot cannot introduce drift into the intelligence platform: it has no
  write path and authors no intelligence.
- The design generalises: new skills and (later) new providers or tools extend
  the interpretive layer without ever changing the authority model.
- The grounding and citation stages add per-query work, but that cost is the
  mechanism by which the principle is enforced, and it is bounded and observable.

## Alternatives considered

- **Let the model answer freely and trust its output.** Rejected: this is exactly
  the failure mode the platform must not have. Fluent unsupported claims in a
  security context are harmful.
- **Give the Copilot direct access to services and let it call them ad hoc.**
  Rejected for this phase: it widens the surface through which the Copilot could
  acquire a write path and complicates the read-only guarantee. Context
  collection through explicit, read-only service calls keeps the boundary simple
  and auditable. (A future Tool Router remains an available extensibility seam
  without changing this authority model.)
- **Persist Copilot conversations and derived state.** Rejected: consistent with
  the platform's in-memory-first posture, sessions are in-memory only. The
  Copilot produces no durable intelligence, so there is nothing authoritative to
  persist.
