"""Investigation builder.

Constructs a :class:`InvestigationSummary` from any scan result, bridging the
per-vertical scan DTOs and the unified investigation workspace. Each artifact
type has a builder function that populates the summary's timeline, evidence
tree, metadata, and relationships from the available data.

Future artifact types add a new builder function; the workspace and its
components are unchanged.
"""

from __future__ import annotations

from core.domain.investigation import (
    EventKind,
    EvidenceNode,
    InvestigationEvent,
    InvestigationSummary,
    MetadataField,
)

_VERDICT_TONE = {"legitimate": "success", "suspicious": "warning", "phishing": "danger"}
_NOT_REPORTED = "Not reported"
_HIGH_RISK = 0.6
_MEDIUM_RISK = 0.3
_HIGH_PCT = 60
_MEDIUM_PCT = 30


def build_file_investigation(  # noqa: PLR0913 - aggregates many scan fields
    *,
    scan_id: str,
    filename: str,
    verdict: str,
    category: str,
    risk_percent: int,
    confidence: float,
    evidence_strength: float,
    malicious: bool,
    size: int,
    sha256: str,
    sha1: str,
    md5: str,
    file_kind: str,
    detected_mime: str,
    declared_mime: str,
    extension: str,
    entropy: float,
    entropy_descriptor: str,
    is_executable: bool,
    is_script: bool,
    is_archive: bool,
    mime_mismatch: bool,
    double_extension: bool,
    indicator_count: int,
    url_count: int,
    malicious_url_count: int,
    contributions: object,
    sources: object,
    urls: object,
    indicators: object,
    incident_id: str,
    incident_title: str,
    campaign_name: str,
    correlation_rationale: str,
    severity: str = "info",
    analysis_duration_ms: float = 0.0,
    recommendations: tuple[str, ...] = (),
    technique_ids: tuple[str, ...] = (),
    provider_diagnostics: tuple[tuple[str, str, float, int], ...] = (),
    relationships: tuple[tuple[str, str, str, str, float], ...] = (),
    threat_history: tuple[str, ...] = (),
) -> InvestigationSummary:
    """Build a unified investigation summary from a file scan result."""
    timeline = _build_file_timeline(
        scan_id,
        filename,
        verdict,
        category,
        malicious,
        incident_id,
        incident_title,
        campaign_name,
        analysis_duration_ms,
        sources,
    )
    evidence_tree = _build_evidence_tree(contributions, sources)
    metadata = _build_file_metadata(
        filename,
        size,
        sha256,
        sha1,
        md5,
        file_kind,
        detected_mime,
        declared_mime,
        extension,
        entropy,
        entropy_descriptor,
        is_executable,
        is_script,
        is_archive,
        mime_mismatch,
        double_extension,
    )
    performance = {"total_ms": analysis_duration_ms}
    if provider_diagnostics:
        for name, _ver, ms, _count in provider_diagnostics:
            performance[name] = ms

    return InvestigationSummary(
        investigation_id=scan_id,
        artifact_id=sha256,
        artifact_type="file",
        analysis_duration_ms=analysis_duration_ms,
        verdict=verdict,
        severity=severity,
        confidence=confidence,
        confidence_source="hybrid evidence fusion",
        category=category,
        risk_percent=risk_percent,
        evidence_strength=evidence_strength,
        malicious=malicious,
        timeline=timeline,
        evidence_tree=evidence_tree,
        metadata=metadata,
        recommendations=recommendations,
        technique_ids=technique_ids,
        relationships=relationships,
        provider_diagnostics=provider_diagnostics,
        threat_history=threat_history,
        performance=performance,
    )


def _build_file_timeline(
    scan_id: str,
    filename: str,
    verdict: str,
    category: str,
    malicious: bool,
    incident_id: str,
    incident_title: str,
    campaign_name: str,
    duration_ms: float,
    sources: object,
) -> tuple[InvestigationEvent, ...]:
    events: list[InvestigationEvent] = [
        InvestigationEvent(
            timestamp="",
            kind=EventKind.ANALYSIS_STARTED,
            source="platform",
            description=f"Analysis started for {filename}",
        ),
    ]
    if hasattr(sources, "__iter__"):
        for source in sources:
            name = getattr(source, "source", getattr(source, "name", "unknown"))
            events.append(
                InvestigationEvent(
                    timestamp="",
                    kind=EventKind.PROVIDER_EXECUTED,
                    source=str(name),
                    description=f"Provider {name} completed",
                )
            )
    if malicious:
        events.append(
            InvestigationEvent(
                timestamp="",
                kind=EventKind.EVIDENCE_DISCOVERED,
                source="fusion",
                description=f"Verdict: {verdict} ({category})",
                detail=f"File classified as {category.replace('_', ' ')}",
            )
        )
        events.append(
            InvestigationEvent(
                timestamp="",
                kind=EventKind.THREAT_MATCH,
                source="threat_intelligence",
                description="Artifact blacklisted by SHA-256",
            )
        )
    if incident_id:
        events.append(
            InvestigationEvent(
                timestamp="",
                kind=EventKind.CORRELATION,
                source="correlation",
                description=f"Correlated to incident: {incident_title}",
                detail=f"Campaign: {campaign_name}" if campaign_name else "",
            )
        )
    events.append(
        InvestigationEvent(
            timestamp="",
            kind=EventKind.ANALYSIS_COMPLETED,
            source="platform",
            description=f"Analysis completed in {duration_ms:.0f} ms",
        ),
    )
    return tuple(events)


def _build_evidence_tree(contributions: object, sources: object) -> tuple[EvidenceNode, ...]:
    """Build the hierarchical evidence tree from contributions and sources."""
    nodes: list[EvidenceNode] = []
    if hasattr(sources, "__iter__"):
        for source in sources:
            name = getattr(source, "source", getattr(source, "name", "unknown"))
            risk_pct = getattr(source, "risk_percent", 0)
            conf = getattr(source, "confidence", 0.0)
            rationale = getattr(source, "rationale", "")
            children: list[EvidenceNode] = []
            if hasattr(contributions, "__iter__"):
                for contrib in contributions:
                    feature = getattr(contrib, "feature", "")
                    detail = getattr(contrib, "detail", "")
                    weight = getattr(contrib, "weight", 0.0)
                    technique = getattr(contrib, "technique_id", "")
                    rec = getattr(contrib, "recommendation", "")
                    sub: list[EvidenceNode] = []
                    if rec:
                        sub.append(EvidenceNode(label="Recommendation", detail=rec, tone="info"))
                    if technique:
                        sub.append(EvidenceNode(label="MITRE", detail=technique, tone="info"))
                    children.append(
                        EvidenceNode(
                            label=feature.replace("_", " ").title(),
                            detail=detail,
                            risk=weight,
                            technique_id=technique,
                            recommendation=rec,
                            tone=(
                                "danger"
                                if weight >= _HIGH_RISK
                                else "warning" if weight >= _MEDIUM_RISK else "info"
                            ),
                            children=tuple(sub),
                        )
                    )
            nodes.append(
                EvidenceNode(
                    label=str(name).replace("_", " ").title(),
                    detail=rationale,
                    risk=risk_pct / 100.0 if risk_pct else 0.0,
                    confidence=float(conf),
                    tone=(
                        "danger"
                        if risk_pct >= _HIGH_PCT
                        else "warning" if risk_pct >= _MEDIUM_PCT else "success"
                    ),
                    children=tuple(children),
                )
            )
    return tuple(nodes)


def _build_file_metadata(  # noqa: PLR0913 - file-specific metadata fields
    filename: str,
    size: int,
    sha256: str,
    sha1: str,
    md5: str,
    file_kind: str,
    detected_mime: str,
    declared_mime: str,
    extension: str,
    entropy: float,
    entropy_descriptor: str,
    is_executable: bool,
    is_script: bool,
    is_archive: bool,
    mime_mismatch: bool,
    double_extension: bool,
) -> tuple[MetadataField, ...]:
    return (
        MetadataField("Filename", filename, "identity"),
        MetadataField("Size", f"{size:,} bytes", "identity"),
        MetadataField("SHA-256", sha256, "hashes"),
        MetadataField("SHA-1", sha1 or _NOT_REPORTED, "hashes"),
        MetadataField("MD5", md5 or _NOT_REPORTED, "hashes"),
        MetadataField("File kind", file_kind, "type"),
        MetadataField("Detected MIME", detected_mime or _NOT_REPORTED, "type"),
        MetadataField("Declared MIME", declared_mime or _NOT_REPORTED, "type"),
        MetadataField("Extension", extension, "type"),
        MetadataField("Entropy", f"{entropy:.2f} bits/byte ({entropy_descriptor})", "analysis"),
        MetadataField("MIME mismatch", "Yes" if mime_mismatch else "No", "analysis"),
        MetadataField("Double extension", "Yes" if double_extension else "No", "analysis"),
        MetadataField("Executable", "Yes" if is_executable else "No", "classification"),
        MetadataField("Script", "Yes" if is_script else "No", "classification"),
        MetadataField("Archive", "Yes" if is_archive else "No", "classification"),
    )
