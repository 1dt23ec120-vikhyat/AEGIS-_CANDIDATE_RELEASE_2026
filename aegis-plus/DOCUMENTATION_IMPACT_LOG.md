# AEGIS+ — Documentation Impact Log

Per the approved workflow, the Knowledge Base is **not** modified during
implementation. This log records every change that will require a Knowledge Base
update. A single synchronized KB update is performed at the completion of each
major milestone.

Status: 🔴 pending · 🟢 applied

---

## Pending — to apply at end of Milestone 1

| # | KB Document | Required Change | Source | Status |
|---|-------------|-----------------|--------|--------|
| D1 | `Folder_Structure.md` | Reconcile entity file-naming examples (`ThreatReport.py` → `threat_report.py`) with Development Standards §13 (`snake_case`, the naming authority). | WP1 | 🔴 |
| D2 | `Folder_Structure.md` / `Development_Standards.md` | Reconcile interface naming: FSS shows suffix style (`RepositoryInterface`); Dev Standards §13 mandates `I`-prefix (`IRepository`). Adopt `I`-prefix. | WP1 | 🔴 |
| D3 | `ADR_Catalogue.md` | Record ADR: developer toolchain (Black, Ruff, Mypy, Import Linter, pre-commit) as the enforced standard. | WP1 | 🔴 |
| D4 | `ADR_Catalogue.md` | Record ADR: **decision #1** — embedded FastAPI backend over localhost; UI↔backend via HTTP. | User decision | 🔴 |
| D5 | `Folder_Structure.md` (Module Communication Rules) | Note the decision-#1 refinement to the `UI → Services` path (HTTP boundary; direct import prohibited once M1b lands). | WP1 | 🔴 |
| D6 | `ADR_Catalogue.md` | Record ADR: **Alembic** as the database migration tool. | WP1 (planned WP5) | 🔴 |
| D7 | `Folder_Structure.md` (§11.9 config) | `config/` is now a Python package (schemas, loader, validation, paths, environments, defaults, settings, exceptions) in addition to holding YAML files (decision #2). | WP2 | 🔴 |
| D8 | `ADR_Catalogue.md` | Record ADR: configuration precedence (defaults < YAML < environment) and secrets-from-environment-only policy (NFR §7). | WP2 | 🔴 |
| D9 | `Non_functional_requirements.md` (§14) / config docs | `incident_response` configurable settings deferred to the AIR milestone; note when implemented. | WP2 | 🔴 |
| D10 | `ADR_Catalogue.md` | Record ADR: centralized logging on Loguru — three sinks (console, rotating app file, structured audit), stdlib interception bridge, and secret redaction. | WP3 | 🔴 |
| D11 | `Development_Standards.md` | Record the three standing standards: centralized-logging-only, exception consolidation into `core` from WP4, and dependency-injection / no-hidden-global-state. | User decisions | 🔴 |
| D12 | `Testing_and_Quality_Assurance_Strategy.md` | Note secret-redaction and audit-channel test coverage as part of the security test baseline. | WP3 | 🔴 |
| D13 | `Folder_Structure.md` (§8 Dependency Rules, Module Communication Rules) + `ADR_Catalogue.md` | **Significant:** dependency direction realized via Dependency Inversion — source imports point Infrastructure/AI → Core (Core owns contracts). Clarify that the FSS table describes runtime/logical access; document the DIP decision and the Import Linter contracts (incl. Domain Purity). | WP4 (decisions #1–#4) | 🔴 |
| D14 | `Folder_Structure.md` (§11.5 infrastructure) | Add `infrastructure/configuration/` subpackage (config→Core port adapter). | WP4 | 🔴 |
| D15 | `Development_Standards.md` / `ADR_Catalogue.md` | Record the WP4 standards: Core-owned contracts, Domain Purity, DDD entity design, centralized exceptions, `I`-prefixed ports. | User decisions | 🔴 |
| D16 | `AI_Model_Specification.md` / interfaces docs | `IAIService` analysis methods deferred to the AI milestone; only the stable base (`name`, `is_ready`) defined in WP4. | WP4 | 🔴 |
| D17 | `Database_Architecture.md` (DP-DB-08) | Clarify interpretation: DP-DB-08 audit fields (`created_at`, `updated_at`, `created_by`, `updated_by`, `version`) live on persisted **rows** (ORM `AuditColumns` mixin); Core entities carry the lifecycle subset (`created_at`/`updated_at`). | WP5 | 🔴 |
| D18 | `Database_Architecture.md` / `ADR_Catalogue.md` | Persistence architecture ADRs: generic Repository over `IRepository`, capability-based Unit of Work, Alembic as sole authoritative migration mechanism, DB-neutral column types for SQLite/PostgreSQL interchangeability, deferred optimistic-lock enforcement. | WP5 | 🔴 |
| D19 | `Folder_Structure.md` (§11.5/§11.6) | Record concrete infrastructure persistence layout: `database/` (base, engine, models, mappers, unit_of_work) and `repositories/` (base_repository, registry). | WP5 | 🔴 |
| D20 | `Development_Standards.md` (tooling) | Record tooling refinements: `PLE1205` disabled (Loguru brace-style), `max-args=10` for entities, migrations exempt from generated-artifact lint rules. | WP5 | 🔴 |
| D21 | `Testing_and_Quality_Assurance_Strategy.md` | Note persistence test baseline: repository CRUD, UoW atomicity, audit persistence/redaction, and a live Alembic-upgrade integration test. | WP5 | 🔴 |
| D22 | `Deployment___Operations_Architecture.md` | Note the migration workflow (Alembic `upgrade head`) as the deployment schema step; `create_all` is dev/test only. | WP5 | 🔴 |
| D23 | `Folder_Structure.md` (§11.1 application) | `application/configuration.py` omitted — the dedicated `config/` package (decision #2) supersedes it. Record `application/` actual layout: `dependency_container`, `bootstrap`, `app`, `lifecycle`, `startup`, `shutdown`, `health`, `background`, and `api/` (embedded FastAPI backend). | WP6 | 🔴 |
| D24 | `Folder_Structure.md` (§8) / `ADR_Catalogue.md` | Add the `ui ⇏ services` Import Linter contract (HTTP boundary, ADR-002) once the UI HTTP client lands in WP7. | WP6 | 🔴 |
| D25 | `Deployment___Operations_Architecture.md` / `Monitoring.md` | Record health-check infrastructure and endpoints: `/health` (liveness), `/health/ready` (readiness with DB check); embedded FastAPI backend on loopback; background-service lifecycle. | WP6 | 🔴 |
| D26 | `Folder_Structure.md` (§11 ui) | UI structure supersedes the FSS sketch: `ui/theme`, `ui/components`, `ui/navigation`, `ui/shell`, `ui/pages`, `ui/viewmodels`, `ui/backend` (design-system + MVVM). Scaffolded `views/widgets/dialogs/themes` removed; `ui/icons.py` is a module. | WP7 | 🔴 |
| D27 | `Folder_Structure.md` (§8) / `ADR_Catalogue.md` | `ui ⇏ services` Import Linter contract ACTIVE: UI forbids services/infrastructure/ai/application; backend HTTP client lives in `ui/backend` (ADR-002), not `infrastructure/networking`. Resolves the D24 deferral. | WP7 | 🔴 |
| D28 | `Testing_and_Quality_Assurance_Strategy.md` | Record headless UI testing approach: `QT_QPA_PLATFORM=offscreen`, a session QApplication fixture, and a `ui` pytest marker. | WP7 | 🔴 |
| D29 | `UI_UX_Architecture.md` | Record the token-driven Light/Dark theme system, the reusable component library, the navigation/routing framework, and the eight module pages. | WP7 | 🔴 |
| D30 | `Deployment___Operations_Architecture.md` / `Database_Architecture.md` | Record startup migration application (`apply_migrations` → Alembic `upgrade head`) as the authoritative schema path at launch; `create_all` retained only for isolated unit tests. | WP8 | 🔴 |
| D31 | `AI_System_Architecture.md` / `SADD_v1_0.md` | Record the walking-skeleton composition: `main.py` composes application + UI; startup records the first audit event (`application.start`) end-to-end through the Unit of Work. | WP8 | 🔴 |
| D32 | `AI_Model_Specification.md` / `AI_System_Architecture.md` | Record the M2 URL analyzer: an explainable heuristic baseline behind the `IUrlAnalyzer` port (noisy-OR over a weighted rule table), to be replaced by the trained LightGBM detector without changes elsewhere. | M2 | 🔴 |
| D33 | `AI_System_Architecture.md` / `ADR_Catalogue.md` | New Core ports `IUrlAnalyzer` and `IAuditTrail` (services audit via Core, not infrastructure); document the ports and the analyzer-swap seam. | M2 | 🔴 |
| D34 | `Feature_Engineering_Specification.md` | Record the implemented deterministic URL feature extractor (lexical + structural feature set) and its location (`ai/url_analysis/features.py`). | M2 | 🔴 |
| D35 | `Database_Architecture.md` | New `url_scans` table (migration `bea95b07769d`), indexed on `created_at`/`verdict`; note the ScanRequest+ThreatAnalysis+ExplainabilityReport consolidation into the `UrlScan` aggregate for v1. | M2 | 🔴 |
| D36 | `SADD_v1_0.md` / `Deployment___Operations_Architecture.md` | New endpoints `POST /api/url/scan` and `GET /api/url/scans/recent`; request validation and error semantics (422 on invalid URL). | M2 | 🔴 |
| D37 | `UI_UX_Architecture.md` | Live URL Scanner result visualization (verdict badge, risk %, confidence, indicator table), `UrlScannerViewModel`, the `AsyncRunner` off-thread pattern, and the dashboard recent-scans integration. | M2 | 🔴 |
| D38 | `AI_System_Architecture.md` / `ADR_Catalogue.md` | New Threat Intelligence module and auto-protection: Core ports `IThreatIntelligenceRepository` and `IThreatProtectionService`; `UrlAnalysisService` consults protection via the Core port (DIP), not a service import. | M3 | 🔴 |
| D39 | `Database_Architecture.md` | New `threat_entries` table (migration `5787a237aafc`): unique `artifact_hash`, indexes on `last_detected`/`verdict`; artifact-agnostic blacklist schema shared by future detection modules. | M3 | 🔴 |
| D40 | `SADD_v1_0.md` / `Deployment___Operations_Architecture.md` | New endpoints `/api/threats/check`, `/guard-open`, `GET /api/threats`, `/stats`, `/{hash}`; `/api/url/scan` extended with `blacklisted`/`blacklist_hit`. | M3 | 🔴 |
| D41 | `Functional_requirements.md` / `business_requirements.md` | Auto-blacklisting on malicious verdict, blacklist-hit short-circuit (instantaneous repeats), and in-app open prevention with a blocking warning dialog (no override). | M3 | 🔴 |
| D42 | `UI_UX_Architecture.md` | New Threat Intelligence page (table + search/sort + analysis-report detail), blocking warning dialog, URL Scanner blacklist state and guarded open, dashboard threat-stats card. | M3 | 🔴 |
| D43 | `Non_functional_requirements.md` / `Monitoring.md` | Audit events `threat.blacklisted`, `threat.blacklist_hit`, `threat.open_blocked`, `threat.viewed`; extensibility seam for whitelist/unblock/feed-sync/import-export/org blacklist. | M3 | 🔴 |
| D44 | `AI_System_Architecture.md` / `AI_Model_Specification.md` / `ADR_Catalogue.md` | URL Intelligence Engine: trained LightGBM analyzer behind `IUrlAnalyzer` with heuristic fallback and SHAP explainability; hybrid `combine_evidence` policy; new `IReputationProvider` and `IDomainIntelligenceProvider` ports; offline homograph/IDN/TLD domain intelligence; XAI 2.0 report. | M4-P1 | 🔴 |
| D45 | `Database_Architecture.md` / `SADD_v1_0.md` / `Feature_Engineering_Specification.md` | `url_scans` intelligence columns (`category`, `evidence_strength`, `sources`) + migration `400e888de0f7`; `/api/url/scan` returns category/evidence-strength/per-source scores; intelligence thresholds and source weights moved into `AISettings` configuration. | M4-P1 | 🔴 |
| D46 | `AI_System_Architecture.md` / `Functional_requirements.md` / `SADD_v1_0.md` / `ADR_Catalogue.md` | Email Threat Intelligence vertical: `EmailMessage`/`EmailAttachment` domain, `IEmailAnalyzer`/`IEmailEvidenceProvider` ports, `HybridEmailAnalyzer` over five providers (header, SPF/DKIM/DMARC authentication, sender/brand, language, attachment), URL engine reused as an evidence source, `/api/email/scan`, Email Scanner UI; new email threat categories. | M5-P1 | 🔴 |
| D47 | `Database_Architecture.md` / `AI_System_Architecture.md` / `ADR_Catalogue.md` | Multi-artifact Threat Intelligence: `ThreatEntry.artifact_type` (URL/EMAIL) + generic `record_report`; `email_scans` table + migration `36db7b14f265`; `threat_entries.artifact_type` column; threats API/UI expose artifact type; `combine_evidence` coverage normalized to evidence considered. | M5-P1 | 🔴 |
| D48 | `AI_System_Architecture.md` / `UI_UX_Architecture.md` / `Database_Architecture.md` / `Functional_requirements.md` / `ADR_Catalogue.md` | Email investigation workspace: full parsed metadata + plain/HTML/raw body views, `AuthMechanism`/`AuthStatus` per-mechanism SPF/DKIM/DMARC breakdown, sender intelligence with historical detections, attachment risk indicators with YARA/malware/sandbox placeholders, collapsible `Section` UI component; `EmailInvestigation` analyst workflow (status/priority/tags/notes) + `email_investigations` table + migration `fee449f5845f` + investigation API; authentication evidence made category-neutral so threat categories reflect attacker intent. | M5-P2 | 🔴 |
| D49 | `AI_System_Architecture.md` / `SADD_v1_0.md` / `Functional_requirements.md` / `ADR_Catalogue.md` | Incident Intelligence: `Incident` and `Campaign` aggregates, correlation domain (`ArtifactKind`/`ArtifactRef`/`CorrelationLink`, `correlate`, `subject_pattern`), `IncidentCorrelationService` correlating on sender/reply-to/domain/subject-pattern/URL/URL-hash/attachment-hash, relationship intelligence, and the extensibility contract for future artifact kinds. | M6-P1 | 🔴 |
| D50 | `Database_Architecture.md` / `UI_UX_Architecture.md` / `ADR_Catalogue.md` | `incidents` and `campaigns` tables + migration `0a1e3ad455de`; `/api/incidents`, `/api/campaigns`, `/api/relationships`, incident workflow endpoint; email scan response reports incident/campaign/rationale; live Incidents investigation page; separation of correlation (append-only evidence) from analyst workflow state. | M6-P1 | 🔴 |
| D51 | `SADD_v1_0.md` / `UI_UX_Architecture.md` / `Functional_requirements.md` / `ADR_Catalogue.md` | SOC Command Center: `SocOverviewService` single-snapshot aggregation (posture, incidents, campaigns, threat intelligence, unified timeline, analytics, analyst activity, platform health), `/api/soc/overview`, rebuilt dashboard with drill-down navigation injected via `UIContext`; `DashboardViewModel` removed. | M7-P1 | 🔴 |
| D52 | `AI_System_Architecture.md` / `Database_Architecture.md` / `ADR_Catalogue.md` | Posture scoring floors at the worst open incident; stored (naive) timestamps normalized to UTC at the aggregation boundary; `combine_evidence` gains `fallback_category` so a malicious verdict driven only by category-neutral evidence still reports a meaningful category (email passes `SUSPICIOUS_SENDER`). | M7-P1 | 🔴 |
| D53 | `UI_UX_Architecture.md` / `Development_Standards.md` | SOC Command Center refinement: reusable `MetricTile`, `HealthTile`, `IncidentCard`, `CampaignCard`, `TimelineView`, `StatusPanel` and `SkeletonPanel` components; SOC-priority information hierarchy; card-based incident/campaign triage with drill-through; professional empty, loading and recovery states replacing raw errors. Backend, API and schema unchanged. | M7-P1b | 🔴 |
| D54 | `UI_UX_Architecture.md` / `Development_Standards.md` | SOC Command Center production polish: executive status bar, Operations quick actions, avatar/keyboard-activated incident cards, campaign growth and status, grouped expandable timeline with relative timestamps, health cards reporting Version/Latency/Mode/Last check with an explicit "Not reported" state, design-token-standardized spacing and radii, hover/focus/tooltip accessibility. Backend, API and schema unchanged; dashboard UI frozen. | M7-P1c | 🔴 |
| D55 | `AI_System_Architecture.md` / `SADD_v1_0.md` | Record the File Intelligence Engine and its **artifact-first** design: analyzer/report/fingerprint contracts expressed against `AnalyzedArtifact` (`IFileAnalyzer`, `IArtifactEvidenceProvider`, `IArchiveInspector`) so future artifact types (memory dumps, PCAPs, registry exports) reuse the same ports. `HybridFileAnalyzer` composes five offline evidence providers through the shared `combine_evidence` policy. | M8-P1 | 🔴 |
| D56 | `AI_System_Architecture.md` / `Feature_Engineering_Specification.md` | Record the **platform IOC extraction engine** (`core/domain/ioc.py`) as the single reusable indicator-extraction component for URL, email, file, and report analysis (refanging + URL/domain/IPv4/email/hash extraction, dedup, merge). | M8-P1 | 🔴 |
| D57 | `AI_Model_Specification.md` / `Feature_Engineering_Specification.md` | Record the **extensible fingerprint registry** (`FingerprintProvider` port + ordered registry): SHA-256/SHA-1/MD5 now, SSDEEP/TLSH/IMPHASH/Authenticode as future providers with no domain-model change. | M8-P1 | 🔴 |
| D58 | `Database_Architecture.md` | Add `file_scans` and `file_investigations` tables (Alembic revision `98f21bd4afba`). **No file bytes are persisted** - only fingerprints (stored as an extensible JSON map, with SHA-256 also indexed), metadata, and derived findings. | M8-P1 | 🔴 |
| D59 | `Functional_requirements.md` / `UI_UX_Architecture.md` | Record the File Intelligence functional capabilities (upload, hashing, type/MIME, entropy, IOC + embedded-URL extraction, macro/script detection, threat scoring, explainable evidence, threat-intel + incident/campaign correlation, investigation workflow) and the File Scanner investigation page; `POST /api/files/scan` (multipart, static-only) + recent/investigation endpoints; SOC overview extended with file scans in the same single pass. | M8-P1 | 🔴 |
| D60 | `ADR_Catalogue.md` | Record ADR: **static-only, resource-bounded file analysis.** Files are never executed; no archive extraction to disk; hard 25 MB cap; archive path-traversal rejected as a finding; uploaded bytes held only in memory during ingestion and discarded immediately - no malware sample is stored in the primary database. Optional sample retention, if ever added, is a separate encrypted-storage capability requiring no architecture change. | M8-P1 | 🔴 |
| D61 | `AI_System_Architecture.md` / `Feature_Engineering_Specification.md` | Record the four deep file analysis providers (OfficeDocumentProvider, ArchiveProvider, ExecutableProvider, expanded ScriptProvider) and the separated PEParser → PEInfo → ExecutableProvider architecture. All stdlib-only; no olefile, pefile, or lxml. | M8-P2a | 🔴 |
| D62 | `AI_System_Architecture.md` | Record the expanded platform IOC extraction engine: IPv6, JWT, AWS keys, API keys, Discord webhooks, Bitcoin wallets, stable ioc_id (UUID-5), IOCStatistics, IOCExtractionResult, TaggedIndicator for Threat Graph preparation. | M8-P2a | 🔴 |
| D63 | `AI_Model_Specification.md` | Record provider metadata fields on Evidence (provider_name, provider_version, execution_ms) and explainability fields on FeatureContribution (technique_id, recommendation) for MITRE ATT&CK preparation. | M8-P2a | 🔴 |
| D64 | `SADD_v1_0.md` / `AI_System_Architecture.md` | Record the Intelligence Fusion Layer: `FusionResult` wrapping `IntelligenceReport` with severity/duration/recommendations/techniques/IOC-summary/provider-summaries/relationships; `EvidenceFusionService` as the single aggregation point; `ProviderRegistry` for runtime provider diagnostics; `IOCFusionService` for cross-artifact IOC correlation and Threat Graph relationship extraction. | M8-P2b | 🔴 |
| D65 | `AI_System_Architecture.md` | Record the `IntelligenceRelationship` model for Threat Graph preparation: stable-ID-based edges (`artifact → contains → ioc`, `artifact → shares_ioc → artifact`) produced by `IOCFusionService` and ready for future graph storage. | M8-P2b | 🔴 |
| D66 | `UI_UX_Architecture.md` | Record SOC dashboard extension: 'Malicious hashes' and 'Recent uploads' metrics added to the existing threat metrics in the same single snapshot pass. | M8-P2b | 🔴 |
| D67 | `UI_UX_Architecture.md` / `SADD_v1_0.md` | Record the Unified Investigation Workspace: `InvestigationSummary` domain model, `build_file_investigation` builder, 10 reusable investigation panels (InvestigationHeader, TimelinePanel, EvidenceTreePanel, RelationshipPanel, IOCPanel, MetadataPanel, ThreatHistoryPanel, ProviderDiagnosticsPanel, RecommendationsPanel, PerformancePanel), the approved layout order, and extension points for future artifact types. File Scanner rewritten on the unified workspace. | M8-P2c | 🔴 |
| D68 | `Functional_requirements.md` | Record M8 as complete: File Intelligence Engine at URL/Email maturity (deep static analysis, IOC platform, intelligence fusion, unified investigation workspace). Baseline for AEGIS+ v0.8 'Multi-Vector Intelligence Platform'. | M8-P2c | 🔴 |
| D69 | `SADD_v1_0.md` / `AI_System_Architecture.md` | Record the Internal Intelligence Event Bus: `IntelligenceEvent` domain model (14 event types, correlation IDs, typed payloads), `IEventBus` port (publish/subscribe), `InProcessEventBus` implementation (synchronous, ordered, failure-isolated, observable), `EventHistory` in-memory diagnostics. Event-driven architecture seam for the Knowledge Graph. | M9-P1 | 🔴 |
| D70 | `ADR_Catalogue.md` | Record ADR: in-process event bus over external brokers. Rationale: deterministic synchronous dispatch for a desktop application; the `IEventBus` port allows a future async or broker-backed implementation without changing publishers. | M9-P1 | 🔴 |
| D71 | `SADD_v1_0.md` / `AI_System_Architecture.md` | Record the Knowledge Graph Domain: `GraphNode`/`GraphEdge`/`GraphPath`/`GraphSnapshot` domain model (13 node types, 13 relationship types), `IGraphRepository` Core-owned port (storage-agnostic), `InMemoryGraphRepository` (BFS, dedup, adjacency index), `GraphBuilder` (event-driven construction from 9 event types), `GraphQueryService` (lookup/traversal/shortest-path/shared-IOCs/subgraph + analytics stubs). | M9-P2 | 🔴 |
| D72 | `ADR_Catalogue.md` | Record ADR: in-memory graph repository for desktop release; IGraphRepository port supports Neo4j/Neptune/JanusGraph/Cosmos DB replacement. Deterministic node/edge dedup, BFS traversal, adjacency index. | M9-P2 | 🔴 |

---

## Note

The M1a KB Synchronization package (`docs/architecture/M1a_KB_Synchronization.md`)
consolidates D1–D22 for application to the authoritative Knowledge Base. D23–D25
(WP6) will be folded into the M1b synchronization at that milestone's close.

---

## M9 Phase 3.0 — Baseline Architecture Remediation

Architecture-preserving remediation. No authoritative Knowledge Base document
requires immediate change. Two additive, low-risk KB updates are deferred to
M9 Phase 3-C to land with the Graph Explorer docs:

- API reference: file-scan response now includes an optional `investigation`
  object (unified `InvestigationSummary` DTO).
- AI System Architecture: note that PE *parsing* is now a Core pure function
  (`core.domain.pe`) behind the `IPeParser` port, while PE *detection*
  (`ExecutableProvider`) remains in the AI layer.

Full assessment: `reports/M9P3.0_Documentation_Impact_Report.md`.

---

## M9 Phase 3-A — Graph Explorer Application Layer

Additive backend capability (application service, `/api/graph/*` API, view DTOs,
BackendClient gateway). No authoritative Knowledge Base document requires immediate
change. Deferred to M9 Phase 3-C: API reference for `/api/graph/*`, and an ADR for
the Graph Explorer application boundary + graph view-DTO placement. Full assessment:
`reports/M9P3-A_Documentation_Impact_Report.md`.

## M9 Phase 3-B — Intelligence Graph Explorer (Presentation Layer)

Presentation-only (UI workspace, view-model, graph components) plus a
backward-compatible payload-aware navigation extension. No authoritative
Knowledge Base document requires an immediate change. Deferred to P3-C:
`/api/graph/*` API reference, an ADR for the Explorer boundary / view-DTO
placement / navigation hook, and UI-UX + Design-Patterns KB updates. Cross-phase
backend follow-up (not documentation): wire detection services to publish
intelligence events so the live graph populates. Full assessment:
`reports/M9P3-B_Documentation_Impact_Report.md`.

## M9 Phase 3-C — Hardening, Observability & Release (documentation completion)

Completes the documentation deferred across M9 Phase 3 and adds release
artefacts. Created: Graph Explorer architecture, backend boundary, knowledge
graph, event-bus interaction, ADR-0001, Graph API reference, developer guide,
user guide, `CHANGELOG.md`, `ROADMAP.md`. Updated `PROJECT_PROGRESS.md`,
`IMPLEMENTATION_LOG.md`. The previously deferred KB items (UI/UX for the Explorer,
MVVM/DI patterns, ADR, API reference, event-bus, knowledge graph) are now
satisfied by these repository documents. Cross-phase follow-up (not
documentation): detection-service event publishing for live graph population,
deferred to a future milestone. Full assessment:
`reports/M9P3-C_Documentation_Impact_Report.md`.

## M10 — Live Intelligence Pipeline

Created `docs/architecture/Live_Intelligence_Pipeline.md`. Updated Event Bus
Interaction, Knowledge Graph, Graph Explorer Architecture, Backend Boundary, Graph
API Reference, and the User Guide to remove the deferred-publishing caveat and
describe live population. Updated `CHANGELOG.md`, `ROADMAP.md` (M10 delivered,
live population moved from deferred to delivered, M11/persistence noted as next),
`PROJECT_PROGRESS.md`, and `IMPLEMENTATION_LOG.md`. Full assessment:
`reports/M10_Documentation_Impact_Report.md`.

## M11 — Advanced Threat Analytics & Intelligence Engine

Created `docs/architecture/Advanced_Threat_Analytics.md` (full Phase A-E engine
architecture). Updated `PROJECT_PROGRESS.md`, `IMPLEMENTATION_LOG.md`,
`CHANGELOG.md`, `ROADMAP.md`. Two additive read-only endpoints
(`/api/analytics/overview`, `/api/analytics/overlay`) documented and tested. No
existing endpoint changed; no persistence; all architectural contracts preserved.
Full assessment: `reports/M11_Documentation_Impact_Report.md`.

## M12 Phase 1 — AI Security Copilot (Reasoning Engine)

Created `docs/architecture/AI_Security_Copilot.md` (pipeline, skills, context/
grounding, provider abstraction, sessions, API, config, frozen surface) and
`docs/architecture/adr/ADR-0002-copilot-not-source-of-truth.md` (the permanent
principle that the Copilot is never a source of truth). Updated
`PROJECT_PROGRESS.md`, `IMPLEMENTATION_LOG.md`, `CHANGELOG.md`, and `ROADMAP.md`
(M12 Phase 1 delivered; persistence direction retired; Phase 2 UI + streaming
noted as next). Four additive read-only endpoints (`POST /api/copilot/ask`,
`POST /api/copilot/session/{id}/focus`, `GET`/`DELETE /api/copilot/session/{id}`)
documented and tested. New `copilot` configuration section; API key sourced from
an environment variable named in config (no secret stored). No existing endpoint
changed; no persistence; no schema change; all seven architectural contracts
preserved. Full assessment: `reports/M12P1_Documentation_Impact_Report.md`.

## M12 Phase 2 — AI Security Copilot (User Experience)

Extended `docs/architecture/AI_Security_Copilot.md` with a "Presentation layer
(M12 Phase 2)" section (components, conversation flow, launch points, citation
navigation, error handling, accessibility). Updated `PROJECT_PROGRESS.md`,
`IMPLEMENTATION_LOG.md`, `CHANGELOG.md`, and `ROADMAP.md` (M12 Phase 2 delivered;
Phase 3 noted as next). UI-only change: new Copilot view-model, page, chat
components, citation-navigation helper, `Route.COPILOT` + sidebar entry, a
`copilot` icon, a Copilot QSS section, and additive "Ask Copilot" actions on six
investigation surfaces. No API change (consumes existing Phase 1 endpoints via
`BackendClient`); no configuration change; no schema change. ADR-0002 upheld — the
UI performs no context collection or reasoning. All seven architectural contracts
preserved. Full assessment: `reports/M12P2_Documentation_Impact_Report.md`.

## M12 Phase 3 — AI Security Copilot Finalization (M12 complete)

Extended `docs/architecture/AI_Security_Copilot.md` with a "Streaming (M12 Phase
3)" section (additive provider seam, grounding-preserving `stream_ask`, SSE
transport, and UI progressive rendering + Qt lifecycle safety). Updated
`PROJECT_PROGRESS.md`, `IMPLEMENTATION_LOG.md`, `CHANGELOG.md`, and `ROADMAP.md`
(M12 Phase 3 delivered; M12 marked complete; M13 not started). New additive
endpoint `POST /api/copilot/ask/stream` (SSE) documented and tested; the
non-streaming `/ask` is unchanged. New domain type `CopilotStreamEvent`; the
`ILLMProvider` port extended only additively (optional `stream()`/
`supports_streaming()`). No configuration change; no schema change; no
persistence. ADR-0002 upheld under streaming — citation and grounding validation
run on the complete streamed text and the finalized response is the validated
one. All seven architectural contracts preserved. Full assessment:
`reports/M12P3_Documentation_Impact_Report.md`.

## M13 — Authentication & Secure Application Entry

Created ADR-0003 (scrypt hashing, server-side sessions, API-boundary enforcement,
alternatives), `docs/architecture/Authentication.md` (flow, layering, domain
model, hashing, sessions, API, startup/desktop flow, security UX, testing), and
the three M13 reports. Updated `PROJECT_PROGRESS.md`, `IMPLEMENTATION_LOG.md`,
`CHANGELOG.md`, and `ROADMAP.md` (M13 delivered; authentication considered
complete). New API surface `/api/auth/*`; all analyst routers now require a
session. New core types/ports and two new tables via one additive migration (no
drift). New UI: authentication window, shell logout action + avatar, auth-first
startup flow. No configuration change and no new dependency (scrypt is stdlib).
All 7 Import Linter contracts intact. Full assessment:
`reports/M13_Documentation_Impact_Report.md`.

## M14 — Gmail Intelligence Integration

Created ADR-0004 (httpx-over-SDK + loopback OAuth, isolation/secrets/scope/auth
boundary), `docs/architecture/Gmail-Integration.md`, `docs/architecture/Gmail-
Security.md` (Google setup, credentials, scope, token security, sync/disconnect,
troubleshooting), and the 3 M14 reports. Updated PROJECT_PROGRESS, CHANGELOG,
ROADMAP (M14 delivered; M15 next), and this log. New API surface `/api/gmail/*`
(session-guarded). New core types/ports, one config section, one additive table
(no drift). New UI page + Integrations sidebar entry. New local artifact
`data/gmail/tokens.json` (0600, gitignored). No new dependency. All 7 Import
Linter contracts intact; Google specifics isolated in infrastructure. Full
assessment: `reports/M14_Documentation_Impact_Report.md`.

---

## M14 Completion Pass — Gmail Intelligence Workspace

**Code → doc impact.** New read-model (additive migration `32799204f010`,
composite PK, non-secret metadata) and read APIs (`/api/gmail/messages`,
`/messages/{id}`, `/api/email/scans/{id}`); new Gmail workspace UI + reuse-only
navigation; additive `EmailAnalysisService.get_scan`; four-state sync taxonomy.
No existing contract, interface, or layer boundary changed; all 7 Import Linter
contracts intact; no new dependency.

**Docs updated.** `CHANGELOG.md` (M14 completion subsection + "1 error" fix),
`PROJECT_PROGRESS.md` (M14 row), `ROADMAP.md`, `IMPLEMENTATION_LOG.md`, this log,
`docs/architecture/Gmail-Integration.md` (workspace/read-model/taxonomy/preview/
multi-account), and reports `M14_Validation_Report.md`, `M14_Release_Notes.md`,
`M14_Documentation_Impact_Report.md`. Migration count 10 → 11; test count
720 → 741. Live-Gmail validation remains a documented manual step, kept distinct
from automated results. Full assessment:
`reports/M14_Documentation_Impact_Report.md`.
