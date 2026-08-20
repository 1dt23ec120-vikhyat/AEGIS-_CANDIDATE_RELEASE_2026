"""FastAPI application factory.

Builds the embedded backend's FastAPI application. Feature routers are added
here as they are introduced; M1b provides identity and health endpoints. The
application is intentionally thin - business logic lives in services and the
domain, reached through injected dependencies.
"""

from __future__ import annotations

from fastapi import Depends, FastAPI

from application.api import (
    analysis,
    analytics,
    auth,
    copilot,
    email,
    file,
    gmail,
    graph,
    health,
    incidents,
    soc,
    threats,
)
from application.api.auth import require_session
from application.health import HealthRegistry
from services.analytics import AnalyticsOverviewService, GraphOverlayService
from services.auth import AuthenticationService
from services.copilot import CopilotOrchestrator, SessionManager
from services.email_analysis import EmailAnalysisService, EmailInvestigationService
from services.file_analysis import FileAnalysisService, FileInvestigationService
from services.gmail import GmailIngestionService
from services.graph import GraphExplorerService
from services.incident import IncidentCorrelationService
from services.soc import SocOverviewService
from services.threat_intelligence import ThreatIntelligenceService
from services.url_analysis import UrlAnalysisService


def create_api(  # noqa: PLR0913 - composition-root wiring of every vertical
    *,
    health_registry: HealthRegistry,
    url_analysis_service: UrlAnalysisService,
    email_analysis_service: EmailAnalysisService,
    email_investigation_service: EmailInvestigationService,
    file_analysis_service: FileAnalysisService,
    file_investigation_service: FileInvestigationService,
    threat_service: ThreatIntelligenceService,
    incident_service: IncidentCorrelationService,
    soc_service: SocOverviewService,
    graph_explorer_service: GraphExplorerService,
    analytics_overview_service: AnalyticsOverviewService,
    graph_overlay_service: GraphOverlayService,
    copilot_orchestrator: CopilotOrchestrator,
    copilot_sessions: SessionManager,
    auth_service: AuthenticationService,
    gmail_service: GmailIngestionService,
    app_name: str,
    app_version: str,
) -> FastAPI:
    """Create and configure the backend FastAPI application.

    Args:
        health_registry: The registry backing the readiness endpoint.
        url_analysis_service: The URL analysis application service.
        email_analysis_service: The email analysis application service.
        email_investigation_service: The analyst investigation service.
        file_analysis_service: The file analysis application service.
        file_investigation_service: The file investigation service.
        threat_service: The threat intelligence application service.
        incident_service: The incident correlation service.
        soc_service: The SOC command centre aggregation service.
        graph_explorer_service: The intelligence graph explorer service.
        analytics_overview_service: The SOC analytics overview aggregator.
        graph_overlay_service: The Graph Explorer overlay service.
        copilot_orchestrator: The read-only AI Security Copilot orchestrator.
        copilot_sessions: The Copilot's in-memory session manager.
        auth_service: The authentication service backing the auth API and the
            session guard on protected routers.
        gmail_service: The read-only Gmail connector service (M14).
        app_name: Application name (surfaced on the root route and docs).
        app_version: Application version.

    Returns:
        The configured :class:`~fastapi.FastAPI` application.
    """
    app = FastAPI(title=app_name, version=app_version)
    app.state.app_name = app_name
    app.state.app_version = app_version
    app.state.health_registry = health_registry
    app.state.url_analysis_service = url_analysis_service
    app.state.email_analysis_service = email_analysis_service
    app.state.email_investigation_service = email_investigation_service
    app.state.file_analysis_service = file_analysis_service
    app.state.file_investigation_service = file_investigation_service
    app.state.threat_service = threat_service
    app.state.incident_service = incident_service
    app.state.soc_service = soc_service
    app.state.graph_explorer_service = graph_explorer_service
    app.state.analytics_overview_service = analytics_overview_service
    app.state.graph_overlay_service = graph_overlay_service
    app.state.copilot_orchestrator = copilot_orchestrator
    app.state.copilot_sessions = copilot_sessions
    app.state.auth_service = auth_service
    app.state.gmail_service = gmail_service

    # Open routers: health probes and the auth surface itself.
    app.include_router(health.build_router())
    app.include_router(auth.build_router())

    # Protected routers: every analyst-facing capability requires a valid
    # session. Enforcement is at the API boundary (a router-level dependency),
    # not merely by hiding UI navigation.
    guarded = [Depends(require_session)]
    app.include_router(analysis.build_router(), dependencies=guarded)
    app.include_router(email.build_router(), dependencies=guarded)
    app.include_router(file.build_router(), dependencies=guarded)
    app.include_router(threats.build_router(), dependencies=guarded)
    app.include_router(incidents.build_router(), dependencies=guarded)
    app.include_router(soc.build_router(), dependencies=guarded)
    app.include_router(graph.build_router(), dependencies=guarded)
    app.include_router(analytics.build_router(), dependencies=guarded)
    app.include_router(copilot.build_router(), dependencies=guarded)
    app.include_router(gmail.build_router(), dependencies=guarded)
    return app
