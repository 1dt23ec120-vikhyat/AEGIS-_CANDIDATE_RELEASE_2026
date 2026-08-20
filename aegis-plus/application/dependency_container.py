"""Dependency injection container.

The single composition root for AEGIS+. It constructs concrete implementations
and wires them to Core ports, so no other module needs to know how dependencies
are built. Construction is explicit and free of hidden global state; components
receive their collaborators here and nowhere else.
"""

from __future__ import annotations

import os
from collections.abc import Callable
from typing import cast

from ai.copilot import build_provider as build_copilot_provider
from ai.email_analysis import (
    AttachmentProvider,
    AuthenticationProvider,
    HeaderAnalysisProvider,
    HybridEmailAnalyzer,
    LanguageProvider,
    SenderReputationProvider,
)
from ai.file_analysis import (
    ArchiveProvider,
    EntropyProvider,
    ExecutableProvider,
    HybridFileAnalyzer,
    IndicatorProvider,
    MetadataProvider,
    OfficeDocumentProvider,
    ScriptProvider,
    StructPeParser,
    StructureProvider,
)
from ai.url_analysis import (
    HeuristicUrlAnalyzer,
    LightGBMUrlAnalyzer,
    NullReputationProvider,
    StructuralDomainIntelligenceProvider,
)
from application.api.app import create_api
from application.api.server import BackendServer
from application.background import BackgroundServiceManager
from application.health import DatabaseHealthCheck, HealthRegistry
from config import ProjectPaths, Settings
from core.domain import EvidenceSource
from core.domain.fusion import ProviderInfo
from core.interfaces import IConfigurationProvider, ILogger, IUnitOfWork, IUrlAnalyzer
from infrastructure.ai import LightGbmModelLoader
from infrastructure.configuration import ConfigurationProvider
from infrastructure.database import Database, SqlAlchemyUnitOfWork
from infrastructure.graph import InMemoryGraphRepository
from infrastructure.integrations.gmail import (
    FileGmailTokenStore,
    HttpxGmailGateway,
    LoopbackGmailAuthFlow,
)
from infrastructure.logging import AuditLogger, get_logger
from infrastructure.repositories.auth_repository import (
    SqlAlchemyAuthSessionRepository,
    SqlAlchemyUserRepository,
)
from infrastructure.repositories.gmail_sync_state_repository import (
    SqlAlchemyGmailSyncStateRepository,
)
from infrastructure.security import ScryptPasswordHasher
from services.analytics import (
    AnalyticsOverviewService,
    AttackAnalysisService,
    CampaignIntelligenceService,
    GraphAnalyticsService,
    GraphOverlayService,
    IOCIntelligenceService,
    RecommendationService,
    ThreatScoringService,
)
from services.auth import AuthenticationService, AuthRepositories
from services.copilot import (
    CitationValidator,
    ContextCollector,
    CopilotOrchestrator,
    GroundingValidator,
    IntentDetector,
    PromptBuilder,
    ResponseFormatter,
    SessionManager,
    build_default_registry,
)
from services.email_analysis import EmailAnalysisService, EmailInvestigationService
from services.events import EventHistory, InProcessEventBus
from services.file_analysis import FileAnalysisService, FileIngestor, FileInvestigationService
from services.fusion import EvidenceFusionService, IOCFusionService, ProviderRegistry
from services.gmail import GmailIngestionService, GmailSyncStateContext
from services.graph import GraphBuilder, GraphExplorerService, GraphQueryService
from services.incident import IncidentCorrelationService
from services.pipeline import IntelligencePublisher
from services.soc import HealthComponent, SocOverviewService
from services.threat_intelligence import ThreatIntelligenceService
from services.url_analysis import UrlAnalysisService


class DependencyContainer:
    """Builds and holds the application's wired dependencies."""

    def __init__(self, settings: Settings, *, paths: ProjectPaths | None = None) -> None:
        """Construct and wire all dependencies.

        Args:
            settings: The validated configuration aggregate.
            paths: Project paths. Defaults to the repository layout.
        """
        self._settings = settings
        self._paths = paths or ProjectPaths.create()
        self._config_provider: IConfigurationProvider = ConfigurationProvider(settings)

        # Persistence.
        self._database = Database(
            self._config_provider.database_url(),
            echo=self._config_provider.database_echo(),
        )
        self._unit_of_work_factory: Callable[[], IUnitOfWork] = lambda: SqlAlchemyUnitOfWork(
            self._database.session_factory
        )

        # Audit logging with transparent persistence (call sites unchanged).
        self._audit_logger = AuditLogger(
            get_logger("audit"),
            unit_of_work_factory=self._unit_of_work_factory,
        )

        # Health checks.
        self._health_registry = HealthRegistry(get_logger("health"))
        self._health_registry.register(DatabaseHealthCheck(self._database))

        # Threat intelligence and auto-protection (reusable across verticals).
        self._threat_service = ThreatIntelligenceService(
            self._unit_of_work_factory,
            self._audit_logger,
            get_logger("threat-intel"),
        )

        # URL Intelligence Engine: a demonstration LightGBM model behind the
        # analyzer port with a heuristic fallback, combined with offline domain
        # and reputation intelligence. The bundled model validates the ML
        # infrastructure; a production model replaces it without code changes.
        # Swapping ML on/off is a configuration change only.
        ai = settings.ai
        heuristic = HeuristicUrlAnalyzer(
            suspicious_threshold=ai.suspicious_threshold,
            phishing_threshold=ai.phishing_threshold,
        )
        analyzers: list[IUrlAnalyzer] = []
        if ai.use_ml_analyzer:
            model = LightGbmModelLoader(
                self._paths.models_dir / ai.url_model_file, get_logger("model-loader")
            ).load()
            analyzers.append(
                LightGBMUrlAnalyzer(
                    model,
                    HeuristicUrlAnalyzer(
                        suspicious_threshold=ai.suspicious_threshold,
                        phishing_threshold=ai.phishing_threshold,
                    ),
                    get_logger("url-ml"),
                    suspicious_threshold=ai.suspicious_threshold,
                    phishing_threshold=ai.phishing_threshold,
                )
            )
        analyzers.append(heuristic)

        weights = {
            EvidenceSource.ML: ai.weight_ml,
            EvidenceSource.HEURISTIC: ai.weight_heuristic,
            EvidenceSource.REPUTATION: ai.weight_reputation,
            EvidenceSource.THREAT_INTEL: ai.weight_threat_intel,
            EvidenceSource.DOMAIN: ai.weight_domain,
        }
        # Live intelligence pipeline: the event bus, knowledge graph, and the
        # single publishing seam are built before the detection services so each
        # can publish intelligence events as it completes analysis.
        self._event_bus = InProcessEventBus(get_logger("event-bus"))
        self._event_history = EventHistory()
        self._event_history.attach(self._event_bus)

        self._graph_repo = InMemoryGraphRepository()
        self._graph_builder = GraphBuilder(self._graph_repo, get_logger("graph-builder"))
        self._graph_builder.attach(self._event_bus)
        self._graph_query = GraphQueryService(self._graph_repo)
        self._graph_explorer = GraphExplorerService(
            self._graph_query, self._graph_repo, get_logger("graph-explorer")
        )
        self._build_analytics_engine()
        self._intelligence_publisher = IntelligencePublisher(
            self._event_bus, get_logger("intelligence-publisher")
        )

        self._url_analysis_service = UrlAnalysisService(
            analyzers,
            StructuralDomainIntelligenceProvider(),
            NullReputationProvider(),
            self._threat_service,
            self._unit_of_work_factory,
            self._audit_logger,
            get_logger("url-analysis"),
            weights=weights,
            suspicious_threshold=ai.suspicious_threshold,
            phishing_threshold=ai.phishing_threshold,
            publisher=self._intelligence_publisher,
        )

        self._incident_service = IncidentCorrelationService(
            self._unit_of_work_factory,
            self._audit_logger,
            get_logger("incident-correlation"),
        )

        # Email Analysis vertical: reuses the URL engine per embedded URL and the
        # shared hybrid/threat/audit/persistence infrastructure.
        email_providers = [
            HeaderAnalysisProvider(),
            AuthenticationProvider(),
            SenderReputationProvider(),
            LanguageProvider(),
            AttachmentProvider(),
        ]
        email_weights = {
            EvidenceSource.HEADER: ai.weight_header,
            EvidenceSource.AUTHENTICATION: ai.weight_authentication,
            EvidenceSource.SENDER: ai.weight_sender,
            EvidenceSource.LANGUAGE: ai.weight_language,
            EvidenceSource.ATTACHMENT: ai.weight_attachment,
            EvidenceSource.URL: ai.weight_email_url,
            EvidenceSource.THREAT_INTEL: ai.weight_threat_intel,
        }
        self._email_analysis_service = EmailAnalysisService(
            HybridEmailAnalyzer(
                email_providers,
                weights=email_weights,
                suspicious_threshold=ai.email_suspicious_threshold,
                phishing_threshold=ai.email_phishing_threshold,
            ),
            self._url_analysis_service,
            self._threat_service,
            self._unit_of_work_factory,
            self._audit_logger,
            get_logger("email-analysis"),
            correlation=self._incident_service,
            publisher=self._intelligence_publisher,
        )

        self._email_investigation_service = EmailInvestigationService(
            self._unit_of_work_factory,
            self._audit_logger,
            get_logger("email-investigation"),
            publisher=self._intelligence_publisher,
        )

        file_weights = {
            EvidenceSource.FILE_STRUCTURE: 1.2,
            EvidenceSource.FILE_SCRIPT: 1.3,
            EvidenceSource.FILE_METADATA: 1.1,
            EvidenceSource.FILE_ENTROPY: 1.0,
            EvidenceSource.FILE_ARCHIVE: 1.0,
            EvidenceSource.FILE_EXECUTABLE: 1.1,
            EvidenceSource.URL: ai.weight_email_url,
            EvidenceSource.THREAT_INTEL: ai.weight_threat_intel,
        }
        self._file_analysis_service = FileAnalysisService(
            HybridFileAnalyzer(
                [
                    StructureProvider(),
                    EntropyProvider(),
                    MetadataProvider(),
                    ScriptProvider(),
                    IndicatorProvider(),
                    OfficeDocumentProvider(),
                    ArchiveProvider(),
                    ExecutableProvider(),
                ],
                weights=file_weights,
                suspicious_threshold=ai.email_suspicious_threshold,
                phishing_threshold=ai.email_phishing_threshold,
            ),
            self._url_analysis_service,
            self._threat_service,
            self._unit_of_work_factory,
            self._audit_logger,
            get_logger("file-analysis"),
            ingestor=FileIngestor(pe_parser=StructPeParser()),
            correlation=self._incident_service,
            publisher=self._intelligence_publisher,
        )
        self._file_investigation_service = FileInvestigationService(
            self._unit_of_work_factory,
            self._audit_logger,
            get_logger("file-investigation"),
            publisher=self._intelligence_publisher,
        )

        # Intelligence Fusion Layer
        self._evidence_fusion = EvidenceFusionService(
            suspicious_threshold=ai.email_suspicious_threshold,
            phishing_threshold=ai.email_phishing_threshold,
        )
        self._ioc_fusion = IOCFusionService()

        self._provider_registry = ProviderRegistry()
        for name, version, types in (
            ("StructureProvider", "1.0.0", ("file",)),
            ("EntropyProvider", "1.0.0", ("file",)),
            ("MetadataProvider", "1.0.0", ("file",)),
            ("ScriptProvider", "1.0.0", ("file",)),
            ("IndicatorProvider", "1.0.0", ("file",)),
            ("OfficeDocumentProvider", "1.0.0", ("file",)),
            ("ArchiveProvider", "1.0.0", ("file",)),
            ("ExecutableProvider", "1.0.0", ("file",)),
            ("HeuristicUrlAnalyzer", "1.0.0", ("url",)),
            ("HybridEmailAnalyzer", "1.0.0", ("email",)),
        ):
            self._provider_registry.register(
                ProviderInfo(name=name, version=version, supported_artifact_types=types)
            )

        self._soc_service = SocOverviewService(
            self._unit_of_work_factory,
            self._health_components,
            get_logger("soc-overview"),
        )

        # AI Security Copilot (M12): a read-only intelligence consumer built over
        # the deterministic analytics engine. It explains and reasons over
        # existing intelligence and is never a source of truth (ADR-0002).
        self._build_copilot()
        self._build_auth()
        self._build_gmail()

        # Embedded backend, managed as a background service.
        api = create_api(
            health_registry=self._health_registry,
            url_analysis_service=self._url_analysis_service,
            email_analysis_service=self._email_analysis_service,
            email_investigation_service=self._email_investigation_service,
            file_analysis_service=self._file_analysis_service,
            file_investigation_service=self._file_investigation_service,
            threat_service=self._threat_service,
            incident_service=self._incident_service,
            soc_service=self._soc_service,
            graph_explorer_service=self._graph_explorer,
            analytics_overview_service=self._analytics_overview,
            graph_overlay_service=self._graph_overlay,
            copilot_orchestrator=self._copilot_orchestrator,
            copilot_sessions=self._copilot_sessions,
            auth_service=self._auth_service,
            gmail_service=self._gmail_service,
            app_name=settings.application.name,
            app_version=settings.application.version,
        )
        self._backend_server = BackendServer(
            api,
            host=settings.backend.host,
            port=settings.backend.port,
            logger=get_logger("backend"),
        )
        self._background_manager = BackgroundServiceManager(get_logger("background"))
        self._background_manager.register(self._backend_server)

    # --- Accessors -------------------------------------------------------

    @property
    def settings(self) -> Settings:
        """The configuration aggregate."""
        return self._settings

    @property
    def paths(self) -> ProjectPaths:
        """Resolved project paths."""
        return self._paths

    @property
    def config_provider(self) -> IConfigurationProvider:
        """The configuration provider port."""
        return self._config_provider

    @property
    def database(self) -> Database:
        """The database (engine and session factory owner)."""
        return self._database

    @property
    def unit_of_work_factory(self) -> Callable[[], IUnitOfWork]:
        """A factory producing a fresh Unit of Work."""
        return self._unit_of_work_factory

    @property
    def audit_logger(self) -> AuditLogger:
        """The audit logger (with persistence)."""
        return self._audit_logger

    @property
    def health_registry(self) -> HealthRegistry:
        """The health-check registry."""
        return self._health_registry

    @property
    def url_analysis_service(self) -> UrlAnalysisService:
        """The URL analysis application service."""
        return self._url_analysis_service

    @property
    def threat_service(self) -> ThreatIntelligenceService:
        """The threat intelligence application service."""
        return self._threat_service

    @property
    def email_analysis_service(self) -> EmailAnalysisService:
        """The email analysis application service."""
        return self._email_analysis_service

    def _build_analytics_engine(self) -> None:
        """Construct the M11 analytics/intelligence engine over the graph query.

        All services are deterministic and compose the existing graph query and
        analytics services; none introduces persistence or new graph algorithms.
        """
        self._graph_analytics = GraphAnalyticsService(
            self._graph_query, get_logger("graph-analytics")
        )
        self._ioc_intelligence = IOCIntelligenceService(
            self._graph_query, get_logger("ioc-intelligence")
        )
        self._campaign_intelligence = CampaignIntelligenceService(
            self._graph_query, get_logger("campaign-intelligence")
        )
        self._threat_scoring = ThreatScoringService(
            self._graph_query, self._graph_analytics, get_logger("threat-scoring")
        )
        self._attack_analysis = AttackAnalysisService(
            self._graph_query, self._graph_analytics, get_logger("attack-analysis")
        )
        self._recommendations = RecommendationService(
            self._graph_analytics,
            self._ioc_intelligence,
            self._campaign_intelligence,
            self._threat_scoring,
            get_logger("recommendations"),
        )
        self._analytics_overview = AnalyticsOverviewService(
            self._threat_scoring,
            self._campaign_intelligence,
            self._ioc_intelligence,
            self._attack_analysis,
            self._recommendations,
            get_logger("analytics-overview"),
        )
        self._graph_overlay = GraphOverlayService(
            self._graph_query,
            self._graph_analytics,
            self._attack_analysis,
            get_logger("graph-overlay"),
        )

    def _build_auth(self) -> None:
        """Construct the authentication service and its session-scoped unit of work.

        Each auth operation runs in its own short-lived session from the shared
        session factory: the callable opens a session, binds the auth
        repositories, commits on success, and rolls back on error. Keeping this
        wiring in the composition root leaves the service free of SQLAlchemy.
        """
        session_factory = self._database.session_factory
        hasher = ScryptPasswordHasher()

        def run_in_uow(operation: Callable[[AuthRepositories], object]) -> object:
            session = session_factory()
            try:
                repositories = AuthRepositories(
                    users=SqlAlchemyUserRepository(session),
                    sessions=SqlAlchemyAuthSessionRepository(session),
                )
                result = operation(repositories)
                session.commit()
                return result
            except Exception:
                session.rollback()
                raise
            finally:
                session.close()

        self._auth_service = AuthenticationService(run_in_uow, hasher, get_logger("auth"))

    def _build_gmail(self) -> None:
        """Construct the read-only Gmail connector and its session-scoped state.

        Wires the OAuth loopback flow (client secret read from the environment,
        never from a file in the repo), the protected file token store (under a
        local data directory outside version control), the REST gateway, and the
        ingestion service that feeds the existing Email Analysis pipeline. Each
        dedup-state access runs in its own short-lived session, mirroring the auth
        wiring so the service stays free of SQLAlchemy.
        """
        gmail = self._settings.gmail
        client_secret = os.environ.get(gmail.client_secret_env, "")
        token_path = self._paths.root / "data" / "gmail" / "tokens.json"

        auth_flow = LoopbackGmailAuthFlow(
            client_id=gmail.client_id,
            client_secret=client_secret,
            auth_uri=gmail.auth_uri,
            token_uri=gmail.token_uri,
            scope=gmail.scope,
            loopback_host=gmail.loopback_host,
            timeout_seconds=gmail.loopback_timeout_seconds,
            request_timeout_seconds=gmail.request_timeout_seconds,
        )
        token_store = FileGmailTokenStore(token_path)
        gateway = HttpxGmailGateway(
            api_base_url=gmail.api_base_url,
            timeout_seconds=gmail.request_timeout_seconds,
        )

        session_factory = self._database.session_factory

        def sync_state_factory() -> GmailSyncStateContext:
            session = session_factory()
            return GmailSyncStateContext(
                repository=SqlAlchemyGmailSyncStateRepository(session),
                _commit=session.commit,
                _close=session.close,
            )

        self._gmail_service = GmailIngestionService(
            auth_flow=auth_flow,
            token_store=token_store,
            gateway=gateway,
            email_analysis=self._email_analysis_service,
            sync_state_factory=sync_state_factory,
            logger=get_logger("gmail"),
            incidents=self._incident_service,
            default_query=gmail.default_query,
            max_messages=gmail.max_list_results,
        )

    def _build_copilot(self) -> None:
        """Construct the read-only AI Security Copilot over the analytics engine.

        Every collaborator consumes existing services; the Copilot introduces no
        persistence, no new intelligence logic, and no write path. The LLM
        provider is selected from configuration and degrades gracefully when no
        credential is present, so the platform runs with or without it.
        """
        copilot = self._settings.copilot
        self._copilot_provider = build_copilot_provider(copilot, get_logger("copilot-provider"))
        self._copilot_sessions = SessionManager(
            max_sessions=copilot.max_sessions,
            max_turns=copilot.max_turns_per_session,
        )
        collector = ContextCollector(
            self._graph_query,
            self._graph_analytics,
            self._ioc_intelligence,
            self._campaign_intelligence,
            self._threat_scoring,
            self._attack_analysis,
            self._recommendations,
            self._analytics_overview,
            get_logger("copilot-context"),
            token_budget=copilot.context_token_budget,
            max_items=copilot.max_context_items,
        )
        self._copilot_orchestrator = CopilotOrchestrator(
            IntentDetector(),
            build_default_registry(),
            collector,
            PromptBuilder(history_turns=copilot.history_turns_in_prompt),
            self._copilot_provider,
            CitationValidator(),
            GroundingValidator(strict=copilot.strict_grounding),
            ResponseFormatter(),
            self._copilot_sessions,
            get_logger("copilot-orchestrator"),
            max_tokens=copilot.max_tokens,
            temperature=copilot.temperature,
        )

    def _health_components(self) -> tuple[HealthComponent, ...]:
        """Map the health registry and engine configuration to SOC components."""
        report = self._health_registry.run()
        components = [
            HealthComponent(name=check.name, status=check.status.value, detail=check.detail)
            for check in report.checks
        ]
        ai = self._settings.ai
        components.append(
            HealthComponent(
                name="ml-engine",
                status="healthy" if ai.use_ml_analyzer else "disabled",
                detail=(
                    f"LightGBM model {ai.url_model_file}"
                    if ai.use_ml_analyzer
                    else "ML analyzer disabled by configuration"
                ),
            )
        )
        components.append(
            HealthComponent(
                name="heuristic-engine",
                status="healthy",
                detail="Explainable heuristic analyzer active",
            )
        )
        components.append(
            HealthComponent(
                name="threat-intelligence",
                status="healthy",
                detail="Blacklist and auto-protection active",
            )
        )
        snap = self._graph_repo.snapshot()
        components.append(
            HealthComponent(
                name="knowledge-graph",
                status="healthy",
                detail=f"{snap.node_count} nodes, {snap.edge_count} edges",
            )
        )
        gm = self._graph_explorer.metrics()
        components.append(
            HealthComponent(
                name="graph-explorer",
                status="healthy",
                detail=(f"{int(gm['query_count'])} queries, " f"avg {gm['avg_query_ms']:.2f} ms"),
            )
        )
        bus_metrics = self._event_bus.metrics
        components.append(
            HealthComponent(
                name="event-bus",
                status="healthy",
                detail=(
                    f"{self._event_bus.subscriber_count()} subscribers, "
                    f"{int(cast(int, bus_metrics['total_published']))} published, "
                    f"{int(cast(int, bus_metrics['total_dispatched']))} dispatched, "
                    f"{int(cast(int, bus_metrics['total_failures']))} failures"
                ),
            )
        )
        builder_metrics = self._graph_builder.metrics
        components.append(
            HealthComponent(
                name="graph-builder",
                status="healthy",
                detail=(
                    f"{int(cast(int, builder_metrics['build_count']))} graph updates, "
                    f"{float(cast(float, builder_metrics['total_build_ms'])):.2f} ms total"
                ),
            )
        )
        pub_metrics = self._intelligence_publisher.metrics()
        pub_failures = int(pub_metrics["publish_failures"])
        components.append(
            HealthComponent(
                name="intelligence-publisher",
                status="degraded" if pub_failures else "healthy",
                detail=(
                    f"{int(pub_metrics['events_published'])} events published, "
                    f"{pub_failures} failures"
                ),
            )
        )
        analytics_metrics = self._graph_analytics.metrics()
        components.append(
            HealthComponent(
                name="graph-analytics",
                status="healthy",
                detail=(
                    f"{int(analytics_metrics['runs'])} runs, "
                    f"avg {analytics_metrics['avg_ms']:.2f} ms"
                ),
            )
        )
        intel_runs = (
            int(self._ioc_intelligence.metrics()["runs"])
            + int(self._campaign_intelligence.metrics()["runs"])
            + int(self._threat_scoring.metrics()["runs"])
            + int(self._attack_analysis.metrics()["runs"])
            + int(self._recommendations.metrics()["runs"])
            + int(self._analytics_overview.metrics()["runs"])
            + int(self._graph_overlay.metrics()["runs"])
        )
        components.append(
            HealthComponent(
                name="intelligence-engine",
                status="healthy",
                detail=(
                    f"{intel_runs} intelligence runs "
                    "(IOC, campaign, scoring, attack, recommendations)"
                ),
            )
        )
        components.append(
            HealthComponent(
                name="file-intelligence",
                status="healthy",
                detail="Static file analysis engine active (no execution)",
            )
        )
        provider = self._copilot_provider
        copilot_metrics = self._copilot_orchestrator.metrics()
        session_metrics = self._copilot_sessions.metrics()
        components.append(
            HealthComponent(
                name="ai-copilot",
                status="healthy",
                detail=(
                    f"read-only copilot active; provider {provider.provider_name()} "
                    f"{'ready' if provider.is_available() else 'not configured'}, "
                    f"{int(copilot_metrics.get('op.ask', 0))} queries, "
                    f"{int(session_metrics['active_sessions'])} active session(s)"
                ),
            )
        )
        components.append(
            HealthComponent(
                name="configuration",
                status="healthy",
                detail=f"Environment {self._settings.application.environment}",
            )
        )
        return tuple(components)

    @property
    def soc_service(self) -> SocOverviewService:
        """The SOC command centre aggregation service."""
        return self._soc_service

    @property
    def incident_service(self) -> IncidentCorrelationService:
        """The incident correlation service."""
        return self._incident_service

    @property
    def email_investigation_service(self) -> EmailInvestigationService:
        """The analyst investigation service."""
        return self._email_investigation_service

    @property
    def file_analysis_service(self) -> FileAnalysisService:
        """The file analysis application service."""
        return self._file_analysis_service

    @property
    def file_investigation_service(self) -> FileInvestigationService:
        """The file investigation service."""
        return self._file_investigation_service

    @property
    def evidence_fusion(self) -> EvidenceFusionService:
        """The evidence fusion service."""
        return self._evidence_fusion

    @property
    def ioc_fusion(self) -> IOCFusionService:
        """The IOC fusion service."""
        return self._ioc_fusion

    @property
    def provider_registry(self) -> ProviderRegistry:
        """The provider registry."""
        return self._provider_registry

    @property
    def event_bus(self) -> InProcessEventBus:
        """The in-process event bus."""
        return self._event_bus

    @property
    def event_history(self) -> EventHistory:
        """The in-memory event history."""
        return self._event_history

    @property
    def intelligence_publisher(self) -> IntelligencePublisher:
        """The single publishing seam used by the detection services."""
        return self._intelligence_publisher

    @property
    def graph_analytics(self) -> GraphAnalyticsService:
        """The deterministic graph analytics engine (M11)."""
        return self._graph_analytics

    @property
    def ioc_intelligence(self) -> IOCIntelligenceService:
        """The deterministic IOC intelligence service (M11)."""
        return self._ioc_intelligence

    @property
    def campaign_intelligence(self) -> CampaignIntelligenceService:
        """The deterministic campaign intelligence service (M11)."""
        return self._campaign_intelligence

    @property
    def threat_scoring(self) -> ThreatScoringService:
        """The deterministic threat scoring service (M11)."""
        return self._threat_scoring

    @property
    def attack_analysis(self) -> AttackAnalysisService:
        """The deterministic attack analysis engine (M11 Phase C)."""
        return self._attack_analysis

    @property
    def recommendations(self) -> RecommendationService:
        """The deterministic analyst recommendation engine (M11 Phase D)."""
        return self._recommendations

    @property
    def analytics_overview(self) -> AnalyticsOverviewService:
        """The SOC analytics overview aggregator (M11 Phase E)."""
        return self._analytics_overview

    @property
    def graph_overlay(self) -> GraphOverlayService:
        """The Graph Explorer overlay service (M11 Phase E)."""
        return self._graph_overlay

    @property
    def copilot_orchestrator(self) -> CopilotOrchestrator:
        """The read-only AI Security Copilot orchestrator (M12)."""
        return self._copilot_orchestrator

    @property
    def copilot_sessions(self) -> SessionManager:
        """The Copilot's in-memory session manager (M12)."""
        return self._copilot_sessions

    @property
    def auth_service(self) -> AuthenticationService:
        """The authentication service (M13)."""
        return self._auth_service

    @property
    def gmail_service(self) -> GmailIngestionService:
        """The read-only Gmail connector service (M14)."""
        return self._gmail_service

    @property
    def graph_query(self) -> GraphQueryService:
        """The graph query service."""
        return self._graph_query

    @property
    def graph_explorer(self) -> GraphExplorerService:
        """The intelligence graph explorer service."""
        return self._graph_explorer

    @property
    def graph_repository(self) -> InMemoryGraphRepository:
        """The graph repository."""
        return self._graph_repo

    @property
    def background_manager(self) -> BackgroundServiceManager:
        """The background-service manager."""
        return self._background_manager

    @property
    def backend_server(self) -> BackendServer:
        """The embedded backend server."""
        return self._backend_server

    def logger(self, name: str) -> ILogger:
        """Return a named logger via the centralized subsystem.

        Args:
            name: Component identifier for the logger.

        Returns:
            A logger satisfying :class:`ILogger`.
        """
        return get_logger(name)
