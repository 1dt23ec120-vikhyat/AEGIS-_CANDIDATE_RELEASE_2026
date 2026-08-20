# AEGIS+ — Implementation Log

Chronological record of engineering decisions, completed work, deferred items,
and architectural observations. Operational artifact for development
continuity; **not** part of the official Knowledge Base.

---

## M1a · WP1 — Repository Scaffold & Developer Tooling

**Completed**

- Full architectural package tree per `Folder_Structure.md` (47 packages,
  30 resource directories). Every package declares a responsibility docstring.
- Toolchain configured in `pyproject.toml`: Black, Ruff (+isort, pep8-naming,
  pydocstyle-google), Mypy (strict-typed), Pytest, Import Linter.
- `.pre-commit-config.yaml`, `.editorconfig`, `.gitignore`, `.env.example`,
  `requirements.txt`, `requirements-dev.txt`, `README.md`, `LICENSE`.
- Import Linter contracts: Clean Architecture layers + FSS §8 prohibitions.
- Validation: Black, Ruff, Import Linter (4/4), Mypy, Pytest (7) all green.

**Decisions**

- **File naming:** `snake_case` for all Python modules (Development Standards
  §13, the naming authority) over Folder Structure's PascalCase entity examples.
- **Licensing:** proprietary / internal, all rights reserved (finalized).
- **Packaging:** application layout; top-level packages imported by name
  (`from core... import`), per KB import convention. Not a distributable library.

**Deferred**

- Decision-#1 `ui ⇏ services` HTTP boundary contract → M1b (needs FastAPI
  backend + `infrastructure/networking` client to exist first).
- Dependency lockfile (pip-tools/uv) → post-M1a.

---

## M1a · WP2 — Configuration Subsystem

**Completed**

- Modular `config/` package (decision #2), organized by responsibility:
  - `schemas/` — one Pydantic model module per config domain
    (application, database, logging, security, ui, ai).
  - `environments.py` — `Environment` enum + helpers.
  - `paths.py` — `ProjectPaths`, single source of truth for filesystem layout
    (no hardcoded paths; FSS requirement).
  - `defaults.py` — secure default constants.
  - `loader.py` — YAML + `.env` loading and precedence merge.
  - `validation.py` — environment-aware cross-field validation.
  - `settings.py` — `Settings` aggregate + cached `get_settings()` accessor.
  - `exceptions.py` — self-contained `ConfigurationError` hierarchy.
- YAML section files (`config/*.yaml`) with non-secret defaults.
- Precedence: **defaults < YAML < environment variables**. Secrets (secret key,
  API keys) sourced from the environment only — never written to YAML
  (NFR §7). `SecretStr` masks secrets in logs/repr.
- Reliability: corrupted YAML raises `ConfigurationError` with file context
  (NFR §4 "detect corrupted configuration files").
- Validation: production forbids debug mode and the insecure default secret;
  enforces minimum secret length (NFR §7).
- Unit tests covering defaults, precedence, corrupt-file handling, production
  validation, and path resolution.

**Decisions**

- **Config is a foundational leaf**: `config/` depends on no internal package,
  so every layer may read it without cycles. Enforced by an Import Linter
  `forbidden` contract (`config ⇏ application, ui, services, core,
  infrastructure, ai, data`). Consistent with the FSS "Services → Config"
  dependency (config is depended upon, never depends inward).
- **Env loading is explicit** (curated `AEGIS_*` → dotted-path map in
  `loader.py`) rather than implicit `BaseSettings` magic, for auditable,
  predictable precedence in a security product. Friendly flat env names
  (`AEGIS_LOG_LEVEL`) preserved from `.env.example`.
- Logging config modeled as a schema section (`schemas/logging.py`); the
  logging *runtime* is WP3 (`infrastructure/logging`).

**Deferred**

- `ConfigurationError` reconciliation with the centralized `core/exceptions`
  hierarchy → WP4. Config keeps its own leaf exception until then (avoids
  pulling `core` forward and preserves the leaf property). WP4 will decide
  whether `core` re-exports or `config` remains independent.
- `incident_response` config section (NFR §14 lists it) → deferred to the AIR
  milestone; defining it now without the AIR module would be speculative.
- App version currently a `defaults.py` constant; single-sourcing from package
  metadata is a minor follow-up.

**Observations**

- NFR §3 requires startup < 10 s and config load at startup; `get_settings()`
  is cached to avoid repeated disk/parse work.

---

## Standing Project Standards (recorded after WP2)

1. **Logging standard** — all logging goes through the centralized subsystem
   (`infrastructure/logging`); the stdlib `logging` module and ad-hoc loggers
   are prohibited in application code.
2. **Error-handling standard** — local exception hierarchies are permitted
   during foundation work; from WP4 onward all exceptions consolidate into the
   `core` hierarchy, with other layers deriving from or mapping to it.
3. **Dependency injection** — every component is designed for injection through
   the composition root; no hidden global state.

---

## M1a · WP3 — Logging & Audit Foundation

**Completed**

- Centralized logging subsystem in `infrastructure/logging`:
  - `protocols.py` — `LoggerProtocol` (injectable logging contract).
  - `redaction.py` — secret-redaction patcher + helpers (NFR §7).
  - `interception.py` — `InterceptHandler` bridging stdlib logging into Loguru.
  - `configuration.py` — `configure_logging()` wiring console, rotating app
    file, and structured (JSON) audit sinks from `LoggingSettings`.
  - `logger.py` — `get_logger(name)` factory.
  - `audit.py` — injectable `AuditLogger` + `AuditOutcome`.
- Three sinks: console (colorized in dev), `aegis.log` (rotating), `audit.log`
  (JSON, audit-only via `audit` context flag).
- Validation: all five gates green; Pytest 28 (9 new logging tests). Live demo
  confirmed formatting, redaction, and structured audit output.

**Decisions**

- **Logging is the one sanctioned cross-cutting singleton** (decision #3): Loguru
  is global, but configuration is explicit (no import-time side effects) and
  components consume an injected `LoggerProtocol`. Configuration state is held in
  a private in-module holder, not a rebindable global.
- **Stdlib interception** installed so third-party output (uvicorn, SQLAlchemy)
  routes through the centralized subsystem, honouring the logging standard
  process-wide. `logging` is used only as a bridge, never for app logging.
- **Secret safety, layered**: redaction patcher scrubs sensitive context keys;
  `SecretStr` self-masks in messages; Loguru `diagnose` disabled outside
  development so tracebacks cannot expose variable values.
- **`LoggerProtocol` is a foundation-phase contract**; it will align with the
  centralized `core.interfaces.ILogger` in WP4.

**Deferred**

- Persisting audit records to the `AuditLog` table → WP5. `AuditLogger` will
  receive an injected audit repository then, without changing call sites.
- Audit-log retention may need to exceed the general retention for compliance;
  revisit when audit persistence and policy are defined.

---

## Standing Project Standards (recorded after WP3)

1. **Core contracts** — all shared contracts originate from Core; Infrastructure
   implements, never defines, domain contracts.
2. **Domain purity** — Core is framework-independent (no Loguru, SQLAlchemy,
   FastAPI, PySide6, Pydantic, etc.); machine-enforced by Import Linter.
3. **Entity design** — DDD entities: identity-based equality, shared audit
   fields, no ORM coupling; persistence mapping lives in infrastructure.
4. **Interface design** — ports expressed around business capabilities, stable
   across infrastructure changes.
5. **Exception hierarchy** — centralized in Core; other layers derive from or
   map into it.
6. **Dependency injection** — composition root is the only wiring point.
7. **Documentation** — maintain tracking artifacts; KB sync only at milestone end.

---

## M1a · WP4 — Core Primitives

**Completed**

- Centralized Core exception hierarchy (`core/exceptions`): `AegisError` root
  with domain, security, infrastructure/configuration, and AI branches.
- Value objects (`core/domain`): `ValueObject` base, `EntityId` (UUID-backed).
- Entities (`core/entities`): `BaseEntity` (identity equality, audit timestamps,
  `touch()`), `AggregateRoot` — pure Python, no ORM.
- Constants (`core/constants`): `AuditOutcome` (relocated from infrastructure).
- Ports (`core/interfaces`): `ILogger` (Protocol), `IRepository[TEntity]`,
  `IConfigurationProvider`, `IAIService`.
- Reconciliation: infrastructure logging now depends on `core.ILogger` and
  `core.AuditOutcome`; `infrastructure/logging/protocols.py` removed.
- New adapter `infrastructure/configuration/ConfigurationProvider` implements
  `IConfigurationProvider` over the config leaf and maps its leaf exceptions 1:1
  into the Core hierarchy (satisfies exception-consolidation standard).
- Validation: all gates green; Pytest 45 (24 new: entities, exceptions, adapter).

**Decisions / significant observations**

- **Dependency Inversion correction (important).** Decisions #1–#4 mandate that
  Core owns contracts and Infrastructure implements them — i.e. *source* imports
  point Infrastructure→Core. The WP1 `layers` contract encoded the KB's literal
  linear flow (`core→infrastructure`), the opposite import direction. No real
  imports had crossed that boundary (Core was empty), so nothing had broken.
  Replaced the layers contract with precise per-layer `forbidden` contracts that
  encode DIP + FSS §8, plus a **Domain Purity** contract forbidding Core from
  importing infrastructure frameworks. The FSS Module Communication Rules
  describe runtime/logical access; DIP is how it is realized in source. Logged
  for KB sync (D13).
- **ILogger as Protocol; IRepository/IConfigurationProvider/IAIService as ABCs.**
  A structural `ILogger` lets a bound Loguru logger satisfy the Core contract
  with no adapter class, cleanly reconciling the former `LoggerProtocol`.
- **Config stays a Pydantic leaf; Core stays pure.** Rather than have the leaf
  derive from Core (which would break its leaf property), the infrastructure
  `ConfigurationProvider` maps leaf errors into Core — the "map into" option of
  the exception standard.
- **New `infrastructure/configuration/` subpackage** added for the config
  adapter (not in FSS §11.5's original list). Logged for KB sync (D14).

**Deferred**

- `IAIService` analysis methods → AI milestone (input/output types depend on AI
  domain models; committing now would make the contract unstable). Minimal
  stable base (`name`, `is_ready`) defined now.
- `IConfigurationProvider` returns primitives today; may evolve toward Core-owned
  config DTOs if the domain surface grows (additive, stable).

---

## Standing Project Standards (recorded after WP4)

1. **Repository pattern** — domain-oriented operations; SQLAlchemy confined to
   infrastructure; entity↔row mapping isolated from Core.
2. **Unit of Work** — transaction boundaries coordinated by a UoW; multiple
   repositories participate in one atomic operation.
3. **Database independence** — SQLite/PostgreSQL interchangeable via config;
   vendor-specific behaviour encapsulated in infrastructure adapters.
4. **Migration strategy** — Alembic is the only authoritative schema mechanism;
   no auto table creation outside controlled dev/test.
5. **Audit persistence** — `AuditLogger` integrated with persistence via DI;
   call sites unchanged.
6. **Performance** — session lifecycle, loading strategy, indexing, and
   connection management encapsulated in infrastructure, invisible to Core.
7. **Documentation** — maintain tracking artifacts; KB sync only after M1a.

---

## M1a · WP5 — Persistence Foundation

**Completed**

- Core: `AuditLog` and `Configuration` entities (pure); `IUnitOfWork` port
  (capability-based `get_repository(entity_type)`).
- Infrastructure `database/`: `Base` (naming convention), `Database` (engine +
  session factory; SQLite pragmas/connect-args; dev/test-only `create_all`;
  `dispose`), ORM row models with a shared `AuditColumns` mixin, entity↔row
  mappers, `SqlAlchemyUnitOfWork`.
- Infrastructure `repositories/`: generic `SqlAlchemyRepository` implementing
  `core.IRepository`; entity→factory registry.
- Alembic: `alembic.ini`, `env.py` (URL from config, batch mode for SQLite),
  initial migration (autogenerated, black-formatted).
- Audit persistence: `AuditLogger` gained an optional injected
  `unit_of_work_factory`; records persist in their own UoW (survive independent
  of business transactions), best-effort (failures logged, never raised),
  context redacted before persistence. Call sites unchanged.
- Validation: all gates green; Pytest 57 (12 new persistence + 4 integration,
  incl. a live `alembic upgrade head` test). `alembic check` reports no drift
  between models and the migration.

**Review findings and fixes (this WP was reviewed before acceptance)**

- **DP-DB-08 compliance gap (fixed).** Row models originally carried only
  `created_at`/`updated_at`. Added a shared `AuditColumns` mixin providing
  `created_by`, `updated_by`, and `version` to every persisted row, per DP-DB-08.
  These are persistence concerns and stay off the Core entities (entity-design
  standard). Migration regenerated authoritatively via Alembic autogenerate;
  `alembic check` confirms models↔migration parity. Logged as D17.
- Ruff/typing hardening: `RepositoryFactory` typed over `IRepository[Any]` to
  resolve generic invariance; `PLE1205` disabled project-wide (Loguru brace-style
  logging makes the stdlib-oriented rule a systematic false positive);
  `max-args` raised to 10 for data-carrying entities; generated migrations
  exempted from import-order/whitespace lint.

**Decisions / observations**

- **UoW port is capability-based** (`get_repository(entity_type)`), not
  entity-named attributes — new entities need only a registry entry, keeping the
  Core port stable (interface-design standard).
- **`Uuid` + `JSON` + timezone-aware `DateTime`** column types keep SQLite and
  PostgreSQL interchangeable (database-independence standard).
- **Optimistic-lock enforcement deferred.** The `version` column exists
  (DP-DB-08); wiring `version_id_col` needs the version carried through the
  domain round-trip and concurrency requirements — deferred to when needed.
  Logged as D18.

**M1a complete.** Knowledge Base synchronization from the Documentation Impact
Log is now due.

---

## M1a — Architecture Review & KB Synchronization

- Final M1a Architecture Review produced: `docs/architecture/M1a_Architecture_Review.md`
  (conformance confirmed, 10 ADRs consolidated, technical debt TD-1..6, risks
  R-1..4, M1b readiness verified).
- Consolidated KB Synchronization package produced:
  `docs/architecture/M1a_KB_Synchronization.md` (resolves D1–D22 with full ADR
  text, per-document edits, and a traceability table). To be applied to the
  authoritative Knowledge Base; Documentation Impact Log entries flip to 🟢 once
  applied.

---

## Standing Sequence — M1b (Walking Skeleton)

M1b implements WP6 → WP7 → WP8, delivering a polished enterprise desktop shell
over the M1a foundation while preserving Clean Architecture, DIP, Domain Purity,
Repository/UoW, and centralized logging.

## M1b · WP6 — Application Bootstrap & Composition Root

**Completed**

- `application/dependency_container.py` — the single composition root. Wires
  config provider, persistence (`Database`, UoW factory), audit logger (with
  persistence), health registry, embedded backend, and background manager to
  Core ports. No hidden global state.
- `application/health.py` — health framework: `HealthStatus`, `HealthCheck`,
  `HealthRegistry` (aggregation), `DatabaseHealthCheck` (via `Database.ping()`).
- `application/background.py` — `BackgroundService` contract and
  `BackgroundServiceManager` (ordered start, reverse-order resilient stop).
- `application/api/` — embedded FastAPI backend: `create_api` factory,
  health/readiness/root router, and `BackendServer` running uvicorn in a managed
  daemon thread (readiness gate on startup).
- `application/startup.py` / `shutdown.py` / `lifecycle.py` — ordered startup
  (configure logging → verify DB → start services), reverse shutdown, and an
  idempotent lifecycle state machine (CREATED→…→STOPPED) with context-manager
  support.
- `application/bootstrap.py` + `app.py` — `bootstrap()` assembles the
  `Application` facade (start/stop/health/backend_url).
- Added `Database.ping()` so the DB health check needs no SQLAlchemy import in
  `application`.
- Validation: all gates green; Pytest 69 (12 new: health, background, and live
  backend integration over HTTP).

**Decisions / observations**

- **Embedded backend threading (R-1).** uvicorn runs in a daemon thread via a
  `_ThreadedServer` subclass overriding `install_signal_handlers` (main-thread
  only). The main thread stays free for the PySide6 UI (WP7).
- **`application/configuration.py` intentionally omitted** — the dedicated
  `config/` package (decision #2) supersedes the FSS placeholder. Logged as D23.
- **Composition-root imports frameworks** (FastAPI/uvicorn) — permitted:
  `application` is the top layer with no Import Linter restriction; Core purity
  is unaffected (verified: 7/7 contracts still kept).

**Deferred**

- The `ui ⇏ services` HTTP-boundary Import Linter contract → WP7 (needs the UI
  and the backend HTTP client to exist). Logged as D24.
- First persisted audit event at startup → WP8 (walking skeleton).

## M1b · WP7 — Application Shell & UI Framework

**Completed**

- **Theme system** (`ui/theme/`): design tokens (Light/Dark palettes, typography,
  spacing, radii), a `Theme` aggregate, a `string.Template`-based QSS generator,
  and a `ThemeManager` that applies/toggles themes and emits `theme_changed`. All
  styling flows from tokens; no widget hardcodes colours.
- **Icon system** (`ui/icons.py`): crisp QPainter line icons (no binary assets),
  rendered to tinted pixmaps that recolour with the theme.
- **Component library** (`ui/components/`): buttons (variants + icon), cards
  (with elevation) and stat cards, badges and status dots, search input, text/
  headers, data table, empty state, and a painted mini bar chart. Consistent
  visual language, theme-styled centrally.
- **Navigation** (`ui/navigation/`): declarative route registry, a
  `QStackedWidget` router, and a self-building grouped sidebar. Adding a module =
  one route entry + a registered page.
- **Shell** (`ui/shell/`): splash screen, main window (sidebar + top bar +
  scrollable routed workspace + status bar), top bar (title, global search, theme
  toggle, notifications, avatar), and status bar (live backend indicator,
  environment, version, clock).
- **Pages** (`ui/pages/`): eight production-looking pages — Dashboard (stat cards,
  threat-activity chart, system status, recent activity), URL/Email/File scanners
  (shared scan-console base), Incidents, Reports, AI Models, and Settings (live
  theme toggle).
- **MVVM** (`ui/viewmodels/`): a view-model base and a `DashboardViewModel`; the
  dashboard consumes its view-model rather than embedding data.
- **Backend gateway** (`ui/backend/`): a synchronous `BackendClient` (the UI's
  only path to services, over HTTP) and a `BackendHealthPoller` that checks
  liveness on a worker thread and reports status on the UI thread.
- **Entry point** (`ui/desktop.py`): `create_application`, `build_main_window`,
  and `run_desktop` — the composition root's hook to launch the UI.
- Validation: all gates green; Pytest 86 (17 new UI tests, headless via the
  offscreen platform). Rendered dark/light screenshots confirm the shell paints
  as intended.

**Decisions / observations**

- **UI↔backend boundary activated (D24).** Import Linter contract updated: `ui`
  now forbids `services`, `infrastructure`, `ai`, and `application`. The HTTP
  client lives in `ui/backend` (not `infrastructure/networking`), so the UI reaches
  the backend only over HTTP (ADR-002) while importing none of them — verified
  (7/7 contracts kept).
- **Headless validation.** With no display available, widgets are built and
  exercised under `QT_QPA_PLATFORM=offscreen`; a `tests/ui/conftest.py` fixture
  provides a session QApplication. Screenshots are produced via `QWidget.grab()`.
- **UI structure supersedes the FSS `ui/` sketch (D26).** Adopted
  `theme/ components/ navigation/ shell/ pages/ viewmodels/ backend/` (a design-
  system + MVVM layout) in place of the scaffolded `views/ widgets/ dialogs/
  themes/`, which were removed.
- **Painted-vs-QSS theming.** QSS handles ~all widget styling and auto-updates on
  toggle; painted elements (icons, charts, status dots, stat-card chips) subscribe
  to `theme_changed` and refresh explicitly.

**Deferred**

- End-to-end launch (start backend lifecycle, run UI, stop on close) and the first
  persisted audit event → WP8.
- Per-page view-models beyond the dashboard grow as business logic lands.

## M1b · WP8 — Walking Skeleton

**Completed**

- **Migration runner** (`infrastructure/database/migrator.py`): `apply_migrations`
  runs Alembic `upgrade head` programmatically against an explicit URL. Alembic
  remains authoritative; migration scripts are resolved as a fixed source
  resource (relative to the package), independent of the user's data paths.
- **Alembic env** now prefers an explicitly configured URL, so the runner (and
  tests) can target a specific database.
- **Startup phases extended** (`application/startup.py`): configure logging →
  apply migrations → verify DB → start backend → record the first audit event
  (`application.start`) through the full persistence path.
- **Root entry point** (`main.py`): bootstraps the composition root, starts the
  lifecycle, launches the desktop UI pointed at the backend, and stops the
  lifecycle cleanly on exit. It is the sole place composing the application and UI
  layers, keeping the composition root free of any UI framework.
- **Walking-skeleton integration tests** (`tests/integration/test_walking_skeleton.py`):
  end-to-end verification — migrations create the schema, the first audit event is
  persisted and read back through the Unit of Work, the backend is reachable via
  the UI's HTTP client (liveness/readiness/identity), and shutdown is clean.
- Validation: all gates green; Pytest 89 (3 new walking-skeleton tests). A live
  run confirms `application.start` persisted end-to-end (UI client → FastAPI →
  persistence → SQLite) with correct outcome and context.

**Decisions / observations**

- **Migrations at startup (D30).** Applying pending migrations on launch is the
  authoritative schema path for the embedded database; `create_all` is retained
  only for isolated unit tests. WP6 bootstrap tests were updated to rely on
  startup migrations rather than `create_all`.
- **First audit event (D31).** `application.start` is recorded via the existing
  `AuditLogger` (call site unchanged), persisting through the injected Unit of
  Work in its own transaction — exercising ADR-008/009 end-to-end.
- **Composition boundary preserved.** `main.py` (a root script, outside the
  analyzed packages) composes `application` + `ui`; the `application` layer still
  imports no UI framework, and all 7 Import Linter contracts remain kept.

**M1b complete.** The platform now starts, migrates, serves, renders, and audits
end-to-end. KB synchronization (D23–D31) is due before M2.

## M2 — URL Analysis Vertical

The first functional detection feature, delivered as a complete vertical slice
across every layer so a user can submit a URL and receive a complete, explainable
analysis that is persisted and audited.

**Completed (by layer)**

- **Core (domain + ports).** `Url` value object (validation: scheme, host,
  length, no whitespace; bare host defaults to http; IP-host and HTTPS
  detection). Analysis value objects: `Verdict` (legitimate/suspicious/phishing),
  `FeatureContribution`, `UrlAnalysis` (score, confidence, features,
  contributions, `risk_percent`). `UrlScan` aggregate (`from_analysis`). New
  ports: `IUrlAnalyzer` (analyze a URL) and `IAuditTrail` (so services audit
  through Core, not infrastructure).
- **AI (`ai/url_analysis`).** Deterministic FESD feature extractor (lexical +
  structural: lengths, counts, entropy, `@`, HTTPS, IP host, subdomain depth,
  shortener, encoded chars, suspicious keywords, host digit ratio). Explainable
  `HeuristicUrlAnalyzer` implementing `IUrlAnalyzer`: a weighted rule table
  combined via noisy-OR (score stays in `[0, 1]`), verdict thresholds, and a
  confidence derived from boundary distance. Each rule yields an explainable
  contribution.
- **Services (`services/url_analysis`).** `UrlAnalysisService`: validate → analyze
  → build `UrlScan` → persist via the Unit of Work → audit success/failure →
  return; plus `recent()`. Depends only on Core ports.
- **Infrastructure.** `UrlScanRow` + mapper (features/contributions as JSON) +
  repository registration; Alembic migration `bea95b07769d_add_url_scans_table`
  (`url_scans`, indexed on `created_at`/`verdict`); `AuditLogger` now implements
  the `IAuditTrail` port.
- **Application/API.** `POST /api/url/scan` and `GET /api/url/scans/recent`
  (Pydantic request validation, 422 on invalid URL). Container builds the
  analyzer + service and injects the service into the FastAPI app.
- **UI.** `BackendClient.scan_url()`/`recent_scans()` + `ScanResult`; an
  `AsyncRunner` (off-thread calls, result on the UI thread); `UrlScannerViewModel`
  (MVVM); a live URL Scanner page rendering verdict badge, risk %, confidence, and
  an indicator table; dashboard "Recent URL Scans" card fed from the backend.
- **Tests (+23).** Unit: `Url`, feature extraction, analyzer (benign/phishing,
  ordering, determinism, explanation), service orchestration (fakes). Integration:
  end-to-end `POST /api/url/scan` through the running backend → result returned,
  listed, and persisted; 422 on invalid. UI: page builds, result rendering, scan
  parsing.

**Decisions / observations**

- **Heuristic analyzer behind the port (D32).** Training the LightGBM URL detector
  needs data (a later milestone), so M2 ships a deterministic, explainable
  heuristic analyzer behind `IUrlAnalyzer`. It is a real, working analysis; a
  trained model replaces it behind the same port with no changes elsewhere. This
  aligns with the KB (binary phishing classification with an interpretable score).
- **Audit through a Core port (D33).** Introduced `IAuditTrail` so services audit
  via an abstraction; `AuditLogger` implements it. Preserves "services → Core
  only" (verified: 7/7 contracts kept).
- **Aggregate consolidation.** The KB's ScanRequest + ThreatAnalysis +
  ExplainabilityReport are consolidated into the single `UrlScan` aggregate for
  v1 (one table, JSON features/contributions); can be normalized later if needed.
- **`Url` hardening.** Whitespace is rejected outright — a security-motivated rule
  that also removes an entire class of malformed input.
- **Live end-to-end verified.** A benign URL → LEGITIMATE (0%); a crafted phishing
  URL → PHISHING (75%) with five explainable indicators; all persisted.

**Deferred**

- Trained LightGBM URL model (behind the existing port); config-driven analyzer
  thresholds (currently sensible defaults); recent-scans query pushdown (currently
  sorted in memory). M2 KB sync (D32–D37) batched with M1b per direction.

## M3 - Threat Intelligence & Auto-Protection

An application-level protection feature layered on the M2 URL vertical: malicious
URLs are auto-remembered, blacklisted, and prevented from being reopened through
the app. Built as a reusable Threat Intelligence foundation for future Email,
File, and Network detection.

**Completed (by layer)**

- **Core.** `ThreatEntry` aggregate (artifact-agnostic: hash, artifact, verdict,
  risk, confidence, indicators, first/last detected, detection count, blocked,
  block source, notes) with `from_analysis` and `register_detection`;
  `BlockSource` enum; `Url.fingerprint` (SHA-256). New ports:
  `IThreatIntelligenceRepository` (specialized - extends the generic repository
  with `find_by_hash` and `list_recent`) and `IThreatProtectionService`
  (lookup / record_detection / register_hit).
- **Infrastructure.** `ThreatEntryRow` + mapper (indicators as JSON, enums as
  strings); `SqlAlchemyThreatIntelligenceRepository` extending the generic
  repository with hash lookup and ordered listing; registry entry; Alembic
  migration `5787a237aafc` (`threat_entries`, unique `artifact_hash`, indexes on
  `last_detected`/`verdict`).
- **Services.** `ThreatIntelligenceService` implements the protection port and
  adds delivery operations (`is_blocked`, `guard_open`, `get_by_hash`,
  `list_threats`, `stats`). `UrlAnalysisService` now consults the blacklist first
  (a hit short-circuits validation, feature extraction, and scoring - repeat
  detections are instantaneous), auto-blacklists PHISHING verdicts, and returns a
  `ScanOutcome` carrying `blacklisted`/`blacklist_hit`.
- **Application/API.** `POST /api/threats/check`, `POST /api/threats/guard-open`,
  `GET /api/threats`, `GET /api/threats/stats`, `GET /api/threats/{hash}`;
  `/api/url/scan` extended with blacklist flags. Container builds the threat
  service and injects it into both the URL service and the API.
- **UI.** Threat Intelligence sidebar page (search/sort table + selectable
  "Analysis Report" detail); blocking `ThreatWarningDialog` (threat level, risk,
  reason, date, count; Cancel / View Analysis Report - deliberately no
  "Open Anyway"); URL Scanner blacklist state (BLACKLISTED badge, "already
  identified and blocked") and a guarded "Open URL" action that checks the
  blacklist before launching the browser; dashboard threat-stats card.
- **Tests (+17).** Unit (ThreatEntry, threat service, URL-analysis blacklist
  behavior), integration (auto-blacklist -> repeat hit -> skip; check / guard-open
  / list / stats / fetch), UI (page, dialog, scanner blacklist state).

**Decisions / observations**

- **Protection via a Core port (D38).** `UrlAnalysisService` depends on
  `IThreatProtectionService`, not on the threat service directly - cross-service
  collaboration through a Core abstraction keeps DIP intact (7/7 contracts kept).
- **Specialized repository within the UoW (D39).** `IThreatIntelligenceRepository`
  extends `IRepository[ThreatEntry]`; the service obtains it through the Unit of
  Work (one localized `cast`), preserving the Repository + UoW pattern while
  adding hash lookup for instantaneous blacklist checks.
- **Reusable foundation.** The entry is artifact-agnostic and carries
  `block_source`, `blocked`, and `notes`; together with the repository seam this
  accommodates future manual whitelist/unblock, threat-feed sync, cloud
  intelligence, import/export, and shared org blacklists - none implemented now,
  as directed.
- **Blacklist hits skip the pipeline and are not re-persisted as scans;** the
  threat entry's `detection_count`/`last_detected` track repeats instead.
- **Async teardown hardening.** The UI `AsyncRunner` now suppresses delivery to a
  torn-down receiver (`contextlib.suppress(RuntimeError)`), removing a benign
  teardown race.

**Deferred**

- Manual whitelist/unblock, threat-feed synchronization, cloud intelligence,
  import/export, shared organization blacklist (architecture supports them).
  M3 KB sync (D38-D43) batched with M1b/M2 per standing direction.

## M4 Phase 1 - Advanced URL Intelligence Engine (spine)

Transformed the URL vertical from a single heuristic detector into a hybrid,
ML-backed intelligence engine, preserving every architectural boundary. Delivered
as Phase 1 of a phased M4 (P2: network reputation/WHOIS/DNS/SSL/redirect adapters;
P3: threat timeline + commercial result page + dashboard widgets).

**Completed (by layer)**

- **Core.** `core/domain/intelligence.py`: `EvidenceSource`/`ThreatCategory`
  enums, `Evidence` and `SourceScore` value objects, `IntelligenceReport`, and the
  pure `combine_evidence` policy (weight-normalized consensus blended with a
  confident-source peak, coverage/agreement-based evidence strength, primary
  category, merged ranked contributions). New ports `IReputationProvider` and
  `IDomainIntelligenceProvider`; `IUrlAnalyzer` gains a `source` property so the
  engine attributes each analyzer's evidence. `Url.fingerprint` reused.
- **AI.** `LightGBMUrlAnalyzer` (trained booster behind `IUrlAnalyzer`, SHAP
  per-feature explanations, graceful heuristic fallback when the model is missing
  or inference fails); `model_training.py` (reproducible synthetic corpus ->
  booster artifact `models/url_lightgbm.txt`); `StructuralDomainIntelligenceProvider`
  (offline homograph/IDN/mixed-script/punycode/embedded-credential/suspicious-TLD
  detection); `NullReputationProvider` (disabled, graceful). Shared
  `MODEL_FEATURE_NAMES`/`feature_vector` keep training and inference aligned.
- **Infrastructure.** `infrastructure/ai/model_loader.py` (`LightGbmModelLoader`)
  performs all model I/O and returns `None` on absence/failure - the AI layer never
  touches disk. `url_scans` extended with `category`, `evidence_strength`, and
  `sources` (JSON); migration `400e888de0f7` (additive, no drift).
- **Services.** `UrlAnalysisService` re-shaped into the hybrid engine: blacklist
  check first, then gather evidence from all analyzers + domain + reputation +
  threat-intel, re-weight per config, combine via the pure policy, persist the
  report, audit, and auto-blacklist. Returns the same `ScanOutcome`.
- **Application/Config.** `AISettings` extended with model file, ML toggle,
  thresholds, per-source weights, and provider/cache/redirect settings (yaml +
  env). Container builds the loader -> booster -> `[LightGBM(fallback=heuristic),
  heuristic]` (or heuristic-only when ML disabled), the domain and reputation
  providers, and the weight map. `/api/url/scan` response gains `category`,
  `evidence_strength`, and `sources[]`.
- **UI.** Scanner result panel now shows an executive summary (confidence,
  evidence strength, category), an Intelligence Sources table (per-source risk /
  confidence / active-or-unavailable), and the ranked explanation.
- **Tests (+13).** `combine_evidence` policy, domain intelligence
  (homograph/IDN/TLD/creds), LightGBM analyzer (prediction, fallback, JSON-native
  contributions), and the updated hybrid service test.

**Decisions / observations**

- **Confident-peak combination (D44).** A naive weighted average diluted a
  confident detection with "clean" sources. The policy now escalates on the raw
  risk of any source with confidence >= 0.5, so a strong ML/heuristic signal
  carries the verdict while corroborating moderate sources still lift borderline
  cases via consensus.
- **AI stays I/O-free (D45).** The trained model is loaded by infrastructure and
  injected; `ai` imports `lightgbm`/`numpy` (third-party) but never `infrastructure`
  - Import Linter 7/7 kept.
- **Graceful degradation.** Unavailable sources (disabled reputation here) are
  excluded from the blend; the demo runs on ML+heuristic+domain+threat-intel with
  reputation cleanly absent.
- **JSON-native contributions.** SHAP values are numpy scalars; contributions are
  cast to `float`/`bool` before persistence, guarded by a regression test.
- **Synthetic training data** is documented and swappable for a real corpus with
  no downstream code change (model sits behind the port).

**Model status clarification (per approval review)**

The bundled LightGBM booster (`models/url_lightgbm.txt`) is a **demonstration
model** trained on a synthetic dataset of 2,400 URLs (1,200 benign + 1,200
phishing, generated from hardcoded templates). It has no train/val/test split, no
held-out evaluation metrics, and no real-world generalization guarantees. It
validates the end-to-end ML infrastructure (training → artifact → loader →
analyzer → SHAP explanations → hybrid evidence → persistence → UI) but is
**not a production-quality phishing classifier**. When a real labelled dataset
becomes available, the existing ML infrastructure is reused to train and deploy a
production model without any architectural changes — only the training script and
artifact file change.

**Deferred (P2/P3)**

- Real reputation adapters (Safe Browsing / VirusTotal / PhishTank / OpenPhish),
  WHOIS / DNS / SSL-certificate domain providers, and live redirect-chain
  resolution - optional, config-gated, cached, async, gracefully degrading; not
  network-testable in this environment.
- Threat timeline persistence + timeline UI; commercial result page (evidence
  cards, cert/redirect visualization); dashboard widget suite.
- M4 KB sync (D44-D45) batched with prior milestones per standing direction.

## M5 Phase 1 - Email Threat Intelligence Engine

Delivered a complete Email Analysis vertical that reuses the platform rather than
duplicating it. The URL Intelligence Engine becomes one evidence provider inside
the email engine, and Threat Intelligence, the hybrid combination policy,
explainable AI, audit, and persistence are all shared.

**Completed (by layer)**

- **Core.** `EmailAddress`, `EmailAttachment`, and `EmailMessage` value objects
  with a stdlib-only `EmailMessage.parse` factory (headers, sender/reply-to/
  return-path, recipients, text body, attachment metadata, embedded-URL
  extraction, reported SPF/DKIM/DMARC results, fingerprint). `EmailScan`
  aggregate. Ports `IEmailAnalyzer` and `IEmailEvidenceProvider`. `EvidenceSource`
  gains HEADER/AUTHENTICATION/SENDER/LANGUAGE/ATTACHMENT/URL; `ThreatCategory`
  gains BEC/credential-harvesting/malware-delivery/brand-impersonation/
  suspicious-sender/spam. `ThreatEntry` gains an `artifact_type` discriminator and
  a generic `from_report` factory. `combine_evidence` coverage is now relative to
  the evidence actually considered (stable across verticals), not the global enum
  size.
- **AI.** `HybridEmailAnalyzer` (implements `IEmailAnalyzer`): gathers evidence
  from each provider, appends caller-supplied evidence (embedded-URL + threat
  intelligence), re-weights per config, and combines via the shared pure policy.
  Five offline providers: header consistency, authentication (parses the message's
  SPF/DKIM/DMARC results), sender reputation and brand impersonation, social-
  engineering language (urgency/credential/BEC), and attachment metadata
  (dangerous/macro/archive/double-extension).
- **Services.** `EmailAnalysisService` orchestrates: parse -> extract URLs -> run
  **each URL through the existing `UrlAnalysisService`** (service->service reuse of
  ML, hybrid detection, threat intelligence, auto-protection, persistence) -> fold
  the worst URL result in as one evidence source -> analyze -> persist `EmailScan`
  -> audit -> record malicious emails in shared Threat Intelligence as an EMAIL
  artifact. No URL logic is duplicated.
- **Infrastructure.** `email_scans` table + mapper + repository registration;
  `threat_entries.artifact_type` column (indexed, defaults "url"); one additive
  migration `36db7b14f265`, verified with no drift.
- **Application/Config/API.** `AISettings` extended with email thresholds and
  per-source weights (yaml + env). Container builds the five providers, the email
  weight map, the `HybridEmailAnalyzer`, and the `EmailAnalysisService` (reusing
  the existing URL service). `/api/email/scan` and `/api/email/scans/recent`.
  Threats API/DTO now expose `artifact_type`.
- **UI.** Live Email Scanner page (paste raw email -> verdict, category, evidence
  strength, sender/subject, Intelligence Sources table, Embedded-URL results,
  explanation). Threat Intelligence list gains an Artifact + Type column so the
  timeline identifies URL vs email entries.
- **Tests (+23, 166 total).** Email parsing, all five providers, service
  orchestration (safe not blacklisted, malicious recorded as EMAIL, URL source
  present), running-backend integration (phishing with embedded malicious URL,
  safe, invalid->422), and the email scanner UI.

**Decisions / observations**

- **Reuse over duplication (D46).** Embedded-URL analysis is delegated to
  `UrlAnalysisService` at the service layer (services->services is permitted;
  ai->services is not), so the full URL engine - including its threat intelligence
  and auto-protection - is reused verbatim. The email analyzer stays in `ai` and
  receives URL evidence as `extra_evidence`.
- **Multi-artifact Threat Intelligence (D47).** `ThreatEntry.artifact_type` plus a
  generic `record_report` let one blacklist and one timeline hold URL and email
  detections side by side, with room for file/network artifacts later.
- **Authentication scope.** Providers read the SPF/DKIM/DMARC results already
  present in the message (as a gateway would). Live DNS-based validation is a
  future network-backed enhancement.
- **Graceful degradation.** When an email has no URLs, the URL evidence source is
  marked unavailable and excluded from the blend (confirmed in the live demo).

**Deferred (P2)**

- Dashboard email-widget suite (emails scanned, malicious emails, top categories,
  common senders, email timeline visualization).
- `.eml` file upload with parsed-message drill-down and per-URL evidence cards.
- Live SPF/DKIM/DMARC validation and sender-domain DNS/WHOIS reputation
  (network-backed, config-gated, cached, gracefully degrading).
- Mailbox integrations (Outlook/Gmail/Graph/IMAP/POP3/Exchange) - architecture
  seam only; not implemented this milestone.
- KB sync (D46-D47) batched with prior milestones per standing direction.

## M5 Phase 2 - Enterprise Email Investigation & Intelligence

Elevated the Email Scanner from a result view into an analyst investigation
workspace. This phase added no new detection engine: every panel is rendered from
the existing analysis pipeline, and the only new backend capability is analyst
workflow persistence.

**Completed (by layer)**

- **Core.** `EmailMessage` now parses the full metadata set (CC, BCC, Date,
  Message-ID, MIME-Version, Content-Type, Priority) plus an HTML body, and URL
  extraction spans both plain and HTML parts. New `AuthStatus` and `AuthMechanism`
  value objects with `EmailMessage.authentication_breakdown()`, which reports SPF,
  DKIM, and DMARC individually as status + reason + security impact rather than a
  single score. `EmailAttachment` gained `is_dangerous`, `has_double_extension`,
  and `risk_indicators`, backed by the now domain-owned extension classification
  sets. New `EmailInvestigation` aggregate with `InvestigationStatus` and
  `InvestigationPriority`.
- **AI.** The attachment provider now reuses the domain's classification sets and
  double-extension rule instead of maintaining its own copies (single source of
  truth). The authentication provider is now category-neutral - see below.
- **Services.** `EmailAnalysisService` returns an enriched outcome carrying the
  parsed message and per-sender history (prior scans, prior malicious) computed in
  the same Unit of Work as the insert. New `EmailInvestigationService` for analyst
  metadata, kept separate from the detection pipeline so annotations never mutate
  detection evidence.
- **Infrastructure.** `email_investigations` table (unique `scan_id`, indexed
  status) + mapper + repository registration; migration `fee449f5845f`, verified
  with no drift.
- **API.** The scan response now carries the whole investigation payload:
  overview, per-mechanism authentication, sender intelligence, attachment detail
  with future-scan placeholders, embedded-URL results, and body views.
  `GET`/`PUT /api/email/investigations/{scan_id}` read and persist analyst state.
- **UI.** New reusable collapsible `Section` component. The page is rebuilt as a
  SOC console: executive summary, then eleven focused sections an analyst can
  expand as needed, ending with an editable Analyst Notes panel (status, priority,
  tags, notes) that persists through the backend.
- **Tests (+13, 179 total).** Full-metadata parsing, authentication breakdown
  (present and absent), attachment risk indicators, investigation state
  transitions, the API investigation payload, workflow round-trip persistence,
  sender-history accumulation, workspace section rendering, and section collapse.

**Decisions / observations**

- **Authentication is category-neutral (D48).** The live demo exposed a real
  categorization flaw: because authentication evidence carries the highest
  risk x confidence, every spoofed message was labelled Brand Impersonation -
  including BEC and credential-harvesting emails. An authentication failure proves
  a message is *spoofed*, not what the attacker is attempting, so it now
  contributes risk with `ThreatCategory.NONE` and the threat's nature is
  categorized by the sender, language, attachment, and URL providers. Verdicts and
  risk scores are unchanged; categories are now correct across all six scenarios.
  Guarded by a regression test.
- **Analyst state is separate from detection state.** Investigations are their own
  aggregate keyed by scan id, so re-analysis never overwrites analyst judgement
  and detection evidence stays immutable.
- **No duplicated classification.** Attachment extension sets live in the domain
  and are consumed by both the AI provider and the investigation panel.

**Deferred (P3)**

- Campaign detection and grouping (shared sender/reply-to/domain/subject/URL
  clustering) with campaign name, occurrences, first/last seen, affected users.
- Dashboard email analytics suite (emails scanned, malicious, authentication
  failures, top impersonated brands, top malicious senders, categories, recent
  campaigns, detection timeline, threat trend).
- Rendered HTML body preview with suspicious-element highlighting, and `.eml`
  file upload.
- Mailbox integrations (Graph/Exchange/Gmail/Outlook/IMAP/POP3) - architecture
  seam only, unchanged this phase.
- KB sync (D48) batched with prior milestones per standing direction.

## M6 Phase 1 - Incident Intelligence & Campaign Correlation

Detections are no longer isolated results. Every malicious observation is now
correlated into an incident and attributed to a campaign, giving analysts an
operational picture instead of a stream of alerts. No architectural redesign was
required; correlation is a new service consuming existing detection output.

**Completed (by layer)**

- **Core.** New correlation domain: `ArtifactKind`, `ArtifactRef` (kind + value,
  with a stable `key`), `CorrelationLink` (shared evidence, strength, rationale),
  and the pure policies `correlate()` and `subject_pattern()` - the latter
  collapsing templated lures ("Invoice 4821 overdue" and "Invoice 9142 overdue")
  onto one pattern. New `Campaign` aggregate (name, category, risk, artifacts,
  occurrences, affected users, first/last seen) and `Incident` aggregate
  (evidence + analyst workflow + append-only `IncidentEvent` history and
  `IncidentComment`s), plus `IncidentStatus`.
- **Services.** `IncidentCorrelationService` extracts every correlatable
  observable from a detection, compares it against each open incident, and either
  attaches the detection to the strongest match (updating its campaign) or opens a
  new incident and campaign. It also answers relationship questions and applies
  analyst workflow changes. `EmailAnalysisService` takes it as an optional
  collaborator and correlates after threat recording, so the email vertical is
  unchanged when correlation is absent.
- **Infrastructure.** `incidents` and `campaigns` tables with JSON-encoded
  artifacts, comments, and events; mappers and repository registrations; migration
  `0a1e3ad455de`, verified with no drift.
- **API.** `/api/incidents`, `/api/incidents/{id}`, `/api/campaigns`,
  `/api/relationships`, and `PUT /api/incidents/{id}/workflow`. The email scan
  response now also reports the incident, campaign, and correlation rationale.
- **UI.** The Incidents page is live: incident queue, discovered campaigns, and a
  selected incident rendered as an investigation view - campaign attribution,
  correlated evidence, affected users, chronological history, and workflow
  controls - reusing the collapsible `Section` component from M5-P2.
- **Tests (+22, 201 total).** Correlation policy and subject normalization,
  campaign/incident aggregate behaviour, and integration coverage for related
  emails merging, unrelated emails staying separate, shared-URL correlation across
  different senders, campaign growth, relationship statements, workflow and
  resolution, resolved incidents not absorbing new detections, and safe emails
  creating no incident.

**Decisions / observations**

- **Category alone never correlates (D49).** Two unrelated credential-phishing
  emails share a category but no infrastructure. A match therefore requires at
  least one non-category observable; category is retained as supporting evidence
  and contributes to link strength once a substantive match exists.
- **Correlation appends, workflow decides (D50).** `attach_detection` only ever
  appends artifacts, scan ids, recipients and history. Status, priority,
  assignment and tags change exclusively through `assign`, `change_status`, and
  `add_comment`, so automated correlation can never overwrite an analyst's
  judgement - covered by an explicit test.
- **Closed incidents are immutable to correlation.** Only open incidents are
  candidates, so a resolved incident is not silently reopened by a later wave; a
  new incident is created instead.
- **Extensible by construction.** The matching policy is kind-agnostic, so files,
  IP addresses, domains, processes, registry keys, and cloud resources become
  correlatable by adding an `ArtifactKind` and extending the extractor - no schema,
  algorithm, or workflow change.

**Deferred (P2)**

- Threat-graph visualization (interactive node/edge rendering of the
  incident -> campaign -> email -> sender -> domain -> URL -> attachment chain).
- Dedicated incident investigation workspace page with evidence cards and related
  incidents.
- Dashboard incident and campaign analytics (open incidents, active campaigns,
  severity mix, incident trend, most active campaigns, most targeted brands).
- KB sync (D49-D50) batched with prior milestones per standing direction.

## M7 Phase 1 - SOC Command Center

The dashboard is now the operational heart of AEGIS+: one screen that answers
"what is happening right now" across every capability. No detection logic was
added - the command centre consumes existing platform state only.

**Completed (by layer)**

- **Services.** `SocOverviewService` builds the whole operational picture from a
  single snapshot loaded in one Unit of Work - incidents, campaigns, threat
  entries, email scans, and URL scans are each read once, and every metric is
  derived from that snapshot. It produces security posture, incident metrics and
  queue, campaign intelligence, threat intelligence rollups, a unified timeline
  merging URL analysis, email analysis, threat blocks, campaign discovery and
  incident history, security analytics (risk distribution, 7-day detection trend,
  response, containment, false-positive rate), analyst activity, and platform
  health.
- **Application.** `/api/soc/overview` returns the entire dashboard in one
  request, so widgets never issue independent queries and a future auto-refresh is
  a single poll. The container supplies platform health by combining the existing
  `HealthRegistry` with ML-engine, heuristic-engine, threat-intelligence, and
  configuration components.
- **UI.** The dashboard is rebuilt as the SOC Command Center: a posture banner,
  a responsive metric grid, and sectioned widgets for incidents, campaigns,
  timeline, threat intelligence, analytics, analyst activity, and platform health.
  Drill-down is wired by injecting navigation through `UIContext.go_to`, so
  dashboard sections open the Incidents and Threat Intelligence surfaces. The
  orphaned `DashboardViewModel` (static demo metrics) was deleted.
- **Tests (+28, 229 total).** Aggregation behaviour (posture floors, timeline
  ordering and merging, analytics derivation, campaign notables, analyst activity,
  deduplicated affected users, trend windows, single-pass snapshot loading),
  end-to-end API coverage against a running backend, and dashboard rendering,
  error handling, and drill-down navigation.

**Decisions / observations**

- **One snapshot, many widgets (D51).** Aggregation happens once per request
  rather than per widget. A test asserts each repository is requested at most once
  per overview, so the "avoid duplicate queries" requirement is enforced, not just
  intended.
- **Posture never under-reports (D52).** The first formula dampened the peak
  incident risk by volume, so a single 95%-risk incident reported only "Elevated".
  Posture now takes the worst open incident as a floor and adds pressure for
  additional critical incidents.
- **Stored timestamps are normalized.** SQLite does not preserve tzinfo, so
  timestamps read back are naive while "now" is aware - which raised a 500 on any
  populated dashboard. Timestamps are normalized to UTC at the aggregation
  boundary, where stored and current times are mixed.
- **A malicious verdict always carries a category.** Since M5-P2 made
  authentication evidence category-neutral, a message flagged purely by SPF/DKIM/
  DMARC failure produced a malicious verdict with category "none" (visible as an
  incident titled "None - ..."). `combine_evidence` now takes a
  `fallback_category`, and the email analyzer passes `SUSPICIOUS_SENDER`.
- **Extensible by construction.** Future verticals (file, IP, domain, endpoint,
  network) surface on the dashboard by contributing to the same snapshot; the
  aggregation and widget shapes do not change.

**Deferred (P2)**

- Timeline filtering controls (date, severity, artifact type, incident, campaign)
  - the data already carries every field, only the controls are outstanding.
- Auto-refresh on a timer, and live widget updates.
- Threat-graph visualization and the dedicated incident investigation workspace
  (carried over from M6-P2).
- KB sync (D51-D52) batched with prior milestones per standing direction.

## M7 Phase 1b - SOC Command Center UI/UX refinement

A product-polish pass over the approved SOC backend. No service, API, schema or
aggregation logic changed: the dashboard consumes the same single
``/api/soc/overview`` payload, so a future auto-refresh or push update still only
needs to re-invoke ``refresh()``.

**Completed**

- **New presentation components.** ``MetricTile`` (icon chip, severity accent,
  large value, trend indicator, one-line description), ``HealthTile`` (subsystem
  status as a card with state dot and last-check time), ``IncidentCard`` and
  ``CampaignCard`` (severity accent bar, badges, triage fields, quick action,
  clickable), ``TimelineView`` (vertical rail with icon markers coloured by
  severity), and ``StatusPanel`` / ``SkeletonPanel`` for empty, loading and
  recovery states.
- **Information hierarchy.** The page is ordered by operational priority:
  Executive Security Overview, Critical Incidents, Campaign Overview, Threat
  Timeline, Threat Intelligence, Security Analytics, Platform Health, Analyst
  Activity. A test asserts the rendered order matches, so the hierarchy cannot
  silently regress.
- **Cards over tables.** The incident queue and campaign list are now cards
  carrying owner, affected users, detection count and age (rendered as a relative
  "4m ago" from the existing timestamps). Clicking a card - or its Investigate
  action - drills through to the Incidents surface.
- **States.** The dashboard opens on a skeleton loader, shows purposeful empty
  states per section ("No incidents detected", "No active campaigns"), and
  replaces raw connection errors with a "Waiting for the platform" recovery panel
  offering a retry. A test asserts the raw ``Errno`` text never reaches the
  analyst and that the page recovers when the backend returns.
- **Tests (+14, 243 total).** Component rendering and click emission, the
  section order, incident card fields, empty/loading/recovery states, and
  recovery-after-failure.

**Decisions / observations**

- **Two existing dashboard tests were updated rather than preserved.** They
  asserted the old presentation (raw error text, previous section names), which
  this milestone deliberately replaces; the replacements assert the new intended
  behaviour, including the absence of raw error strings.
- **Trend and age are derived from data already in the payload** (the 7-day
  detection trend and existing timestamps), so no backend change was needed to
  satisfy the trend-indicator and "time since detection" requirements.
- **Health "version" and "latency" are not rendered.** The overview payload does
  not carry them, and inventing values would misrepresent the platform. Status,
  detail and last-check time are shown; adding version/latency is a small,
  explicit backend addition for a later phase.
- **Screenshot capture ordering.** The page auto-refreshes on construction, so a
  staged state was being overwritten by the failing async result. The capture
  script now lets that settle and detaches the handler before staging - worth
  noting for future screenshot work.

**Deferred**

- Timeline filter controls (date, severity, artifact type, incident, campaign) -
  the payload already carries every field.
- Auto-refresh timer and live/WebSocket updates.
- Health version and latency reporting (requires a small backend addition).

## M7 Phase 1c - SOC Command Center production polish

The final refinement pass before the dashboard UI is frozen. No service, API,
schema or aggregation change: the page still consumes one ``/api/soc/overview``
response, so auto-refresh or push updates remain a single call to ``refresh()``.

**Completed**

- **Executive status bar.** The strip now carries compact badges for threat
  level, open incidents, active campaigns, platform status, backend connectivity,
  last update and auto-refresh readiness, so platform state reads at a glance.
  When a metric is absent the badge shows a placeholder rather than a wrong
  number, and losing the backend flips it to "BACKEND UNREACHABLE".
- **Operations quick actions.** A shortcut row jumps to the top critical
  incident, the incident queue, campaigns, threat intelligence, and a refresh.
- **Cards.** Incident cards gained an owner initial avatar (with an explicit
  "Unassigned" state), whole-card click, and Enter/Space activation for keyboard
  users. Campaign cards gained growth, status and incident count.
- **Timeline.** Relative timestamps with the absolute time on hover,
  Today/Yesterday/date grouping, artifact-type badges, and expandable entries
  behind a Details toggle. Row construction was extracted into helpers to keep
  the widget readable.
- **Platform health.** Cards report Version, Latency, Mode and Last check.
- **Consistency and accessibility.** Spacing, radii, icon sizes, chip sizes and
  minimum card heights all derive from the shared design tokens; every tile and
  card is keyboard focusable with hover and focus styling and a descriptive
  tooltip and accessible name.
- **Tests (+11, 254 total).** Status-bar summarisation and backend-loss states,
  metric fallback, quick-action navigation, incident-card click-through, keyboard
  activation, unassigned owner placeholder, explicit unreported diagnostics, and
  timeline grouping plus expand/collapse.

**Decisions / observations**

- **"Not reported" over invented data (D54).** The overview payload carries no
  per-subsystem version or latency, and no per-campaign incident count. Rather
  than fabricate values or silently omit the fields, the cards label them
  explicitly so an analyst can distinguish "healthy" from "unknown". Surfacing
  them for real is a small, deliberate backend addition for a later milestone -
  deliberately not smuggled into a UI-only pass.
- **Campaign incident count was not derived client-side.** It could have been
  counted from the incident queue, but that queue is truncated to the top five,
  so the number would frequently be wrong. A wrong number is worse than an
  honest "Not reported".
- **Two component tests were updated** where they asserted the previous card
  content; the replacements assert the new fields including the unreported-field
  behaviour.

**Deferred**

- Timeline filter controls (date, severity, artifact type, incident, campaign) -
  the payload already carries every field.
- Auto-refresh timer and live/WebSocket updates; the status bar already exposes
  the readiness indicator.
- Backend reporting of subsystem version, latency and per-campaign incident
  counts.

The dashboard UI is now considered frozen except for future feature additions.

## M8 Phase 1 - File Intelligence Engine

A complete artifact-first File Intelligence vertical slice through every
architectural layer, mirroring the URL and email engines and reusing platform
capabilities wherever appropriate. Delivered under the new continuous-delivery
policy: the packaged repository is the complete application.

**Three approved architecture strengthenings**

- **Artifact-first design.** The analyzer, report, and fingerprint contracts are
  expressed against an `AnalyzedArtifact`, not a file. `IFileAnalyzer`,
  `IArtifactEvidenceProvider`, and `AnalyzedArtifact` carry only derived,
  byte-free facts. The file is the first artifact; memory dumps, registry
  exports, and PCAPs can implement the same ports without redesign.
- **Fingerprint registry.** `FingerprintProvider = Callable[[bytes],
  Fingerprint]` with an ordered `DEFAULT_FINGERPRINT_PROVIDERS` registry.
  SHA-256/SHA-1/MD5 are three registered providers; SSDEEP, TLSH, IMPHASH, and
  Authenticode are future providers requiring no domain-model change. A test
  proves a custom provider composes without touching the model.
- **Reusable IOC engine.** `core/domain/ioc.py` is the single platform IOC
  extraction component - refanging, URL/domain/IPv4/email/hash extraction, dedup,
  merge - owned by the domain and available to URL, email, file, and report
  analysis alike. It is deliberately not embedded in `FileAnalysisService`.

**Completed by layer**

- **Core.** `ioc.py`; `file.py` (fingerprint registry, `FileType`/`FileKind`,
  `EntropyProfile`, `shannon_entropy`, magic-signature `identify_type`, MIME
  detection, `has_double_extension`, `validate_filename` path-traversal guard,
  `_pe_summary`); `FileScan` and `FileInvestigation` aggregates; the artifact
  analyzer ports. Enums extended (`EvidenceSource` file sources, `ThreatCategory`
  file categories, `ArtifactType.FILE`, `ArtifactKind.FILE_HASH/FILE_NAME`).
- **AI.** `HybridFileAnalyzer` and five offline providers - `StructureProvider`
  (double extension, MIME mismatch, dangerous extension), `EntropyProvider`
  (packing/encryption, category-neutral), `MetadataProvider` (executable/PE),
  `ScriptProvider` (macro + script tokens), `IndicatorProvider` (indicator
  volume) - combined through the shared `combine_evidence` policy.
- **Services.** `FileIngestor` (the single place raw bytes are handled; enforces
  size cap and emptiness, produces a byte-free artifact, discards bytes on
  return); `FileAnalysisService` (reuses `UrlAnalysisService` per embedded URL,
  records malicious files to `ThreatIntelligenceService` as FILE artifacts,
  correlates via the incident service); `FileInvestigationService`.
- **Infrastructure.** `file_scans` and `file_investigations` tables and mappers;
  fingerprints stored as an `algorithm -> value` JSON map (extensible) with
  SHA-256 also in an indexed column; repositories registered; one Alembic
  migration, verified no-drift.
- **Application / API.** `POST /api/files/scan` (multipart upload, static
  analysis, never executed), `GET /api/files/scans/recent`, and file
  investigation GET/PUT; wired into the app factory and container with a
  `file-intelligence` health component; SOC overview snapshot extended to load
  file scans in the same single pass and surface a "Malicious files" metric plus
  analytics/trend/risk fold-in - no per-widget queries.
- **UI.** Live File Scanner investigation workspace: file picker upload,
  executive summary, file overview (fingerprints, type, entropy), extracted
  IOCs, embedded-URL results, threat-intelligence and correlation outcomes,
  explainable evidence, and the analyst-notes workflow. Backend DTOs and client
  methods added; unavailable diagnostics shown as "Not reported".

**Reuse over duplication**

- Embedded URLs go through the existing `UrlAnalysisService`; blacklisting
  through the shared `ThreatIntelligenceService.record_report` path.
- `IncidentCorrelationService` was refactored to extract a shared `_correlate`
  flow; `correlate_email` and the new `correlate_file` both delegate to it, so
  the matching/incident/campaign logic exists once. All 254 prior tests still
  pass, confirming the email path is unchanged.

**Security posture (analyzing hostile files)**

- Never executed; static inspection only. No archive extraction to disk. Hard
  25 MB size cap. Archive entry path-traversal is rejected by `validate_filename`
  and treated as a finding, never written. Raw bytes live only inside
  `FileIngestor.ingest` and are discarded on return; only fingerprints, metadata,
  and derived findings are persisted - no malware sample enters the database.

**Provider calibration**

- Two early false positives were corrected: a benign text file with one clean
  URL was scoring "suspicious", and high-entropy-only files were mislabelled
  "suspicious executable". Indicator presence is now contextual (a weak signal
  only at high volume, since embedded URLs are independently scored by the URL
  engine), and the analyzer's fallback category for evidence with no intent is
  the neutral `SUSPICIOUS_STRUCTURE`. Benign files now score legitimate; the
  four malicious archetypes (double-extension EXE, OLE macro, JS dropper, packed
  binary) classify correctly. All calibration is covered by tests.

**Tests (+46, 300 total)**

- Unit: IOC extraction (9), file domain + fingerprint registry (10), providers +
  analyzer (10), ingestion (6). Integration: file API end-to-end (6) - detection,
  persistence, blacklisting, correlation, investigation roundtrip, SOC feed. UI:
  file scanner page + parsing (7).

**Deferred to M8 Phase 2**

- Deep inspectors behind the existing seams: OOXML/OLE macro parsing, ZIP archive
  inspection (`IArchiveInspector`), PE section analysis. YARA, PDF object
  analysis, VirusTotal, and sandbox integrations remain future providers.
- Optional encrypted sample retention (a separate capability, no architecture
  change).

## M8 Phase 2A - Advanced File Intelligence (Deep Inspectors + IOC Platform)

The deep-analysis foundation for the File Intelligence vertical, extending every
existing seam without redesign.

**Completed**

- **Platform IOC engine expansion.** Six new indicator types on the existing
  `IocCollection` (backward-compatible: new fields default to empty tuples):
  IPv6 addresses, JWT tokens, AWS access keys, API keys (context-aware pattern),
  Discord webhooks, and Bitcoin wallets (legacy + bech32). Every indicator now
  carries a deterministic `ioc_id` (UUID-5) for future Threat Graph edges.
  `IOCStatistics` and `IOCExtractionResult` prepare for confidence scoring and
  source attribution.

- **Office Document Provider.** VBA macro tokens, Auto_Open/AutoExec/
  Document_Open/Workbook_Open, DDE fields, external template injection,
  embedded OLE indicators, and OOXML relationship inspection (in-memory
  `zipfile` for `.docx`/`.xlsx`/`.pptx` — detects .exe/.dll/.js/.vbs/.ps1
  references in relationship XML). OLE detection is header-based with string
  scanning; a future `OleParserProvider` slots in behind the same port. Stdlib
  only — no `olefile`, no `lxml`.

- **Archive Provider.** Dangerous embedded file types, nested archives,
  filename masquerading (double-extension inside archives, independent from the
  existing structure provider since archive context differs), zip-bomb heuristics
  (ratio > 100:1 or decompressed > 1 GB), password-protected ZIP detection,
  path-traversal entries, recursive depth limits. Never extracts to disk.

- **Executable Provider.** Static PE parser (`ai/file_analysis/pe_parser.py`)
  using only `struct`, separated from the detection layer per the approved
  `PEParser → PEInfo → ExecutableProvider` architecture. Parses DOS header, PE
  signature, COFF header, optional header (32/64), section table (name, sizes,
  per-section entropy), import table (DLL names), data directories
  (exports, Authenticode signature, debug). Detection layer flags: suspicious
  section names, packer indicators, suspicious imports, unsigned binaries,
  unexpected exports on non-DLLs, VersionInfo anomalies (missing company/product),
  future compile timestamps, high section entropy. Stdlib only — no `pefile`.

- **Script Provider expansion.** Obfuscation patterns (chr(), fromCharCode(),
  atob(), btoa(), string concatenation, format operator abuse, environment
  variable expansion), download cradles (Invoke-WebRequest, Net.WebClient,
  curl, wget, certutil, bitsadmin), dangerous PowerShell flags (-ExecutionPolicy
  Bypass, -NoProfile, -WindowStyle Hidden, -EncodedCommand), ActiveX
  (CreateObject, GetObject, Scripting.FileSystemObject), WMI abuse
  (Win32_Process, wmic, Get-WmiObject).

- **Provider metadata.** Every `Evidence` now carries `provider_name`,
  `provider_version`, and `execution_ms`. Every `FeatureContribution` carries
  optional `technique_id` and `recommendation`. These are backward-compatible
  (empty-string/zero defaults) and prepare for VirusTotal, YARA, and Sandbox
  providers plus MITRE ATT&CK enrichment without contract change.

- **MITRE ATT&CK preparation.** Technique IDs populated where applicable:
  T1036.007/.008 (masquerading), T1059 (command/scripting), T1204.002 (malicious
  file), T1221 (template injection), T1559.002 (DDE), T1027/.002/.006
  (obfuscation/packing), T1055 (process injection imports), T1552.001
  (credentials in files), T1070.006 (timestomping). Empty where not yet mapped.

- **Threat Graph preparation.** `TaggedIndicator` with deterministic `ioc_id`
  (UUID-5 namespace), `indicator_type`, and `value`. `IocCollection.tagged()`
  returns the full set. `IOCExtractionResult` carries `source` and
  `artifact_id` for future graph edge construction.

**Tests (+29, 329 total)**

Unit: expanded IOC extraction (14), PE parser (3), deep providers (12 —
office/archive/executable/script detection, provider metadata, recommendations,
technique IDs).

**Deferred to M8·P2b**

Wiring the new evidence into the report pipeline, extending threat-intel
correlation with file/hash/IOC artifacts, and surfacing new metrics in the SOC
dashboard snapshot.

## M8 Phase 2B - Intelligence Fusion Layer

Transforms the URL, email, and file intelligence engines into a unified
intelligence system rather than three independent scanners.

**Completed**

- **Fusion domain model** (`core/domain/fusion.py`). `Severity` enum with
  `severity_from_score` (critical/high/medium/low/info from the risk score);
  `ProviderInfo` and `ProviderSummary` for provider diagnostics;
  `IntelligenceRelationship` for Threat Graph edge preparation (source/target
  stable IDs, relationship type, confidence, dedup key);
  `FusionResult` wrapping the existing `IntelligenceReport` with severity,
  analysis duration, recommendations, MITRE technique IDs, IOC summary,
  provider summaries, and prepared relationships.

- **Evidence Fusion Service** (`services/fusion/evidence_fusion.py`). The single
  source of truth for intelligence aggregation. Deduplicates evidence by
  source/rationale/risk, delegates verdict computation to the existing
  `combine_evidence` policy (additive, not replacing), computes overall severity,
  collects per-provider summaries (name, version, execution_ms, evidence count,
  risk, confidence, techniques), gathers unique analyst recommendations and MITRE
  technique IDs across all evidence, and tracks total analysis duration.

- **Provider Registry** (`services/fusion/provider_registry.py`). Runtime
  registry of all evidence providers: name, version, enabled status, supported
  artifact types, supported indicator types, configuration. Supports future
  VirusTotal/YARA/Sandbox/Sigma/Cloud providers without contract change. 10
  providers registered at container build time (8 file + 1 URL heuristic + 1
  email hybrid).

- **IOC Fusion Service** (`services/fusion/ioc_fusion.py`). Cross-artifact IOC
  correlation: merge multiple collections (dedup), extract artifact→IOC
  relationship edges using stable `ioc_id`, and cross-correlate to find artifacts
  sharing the same IOC values. Relationships use deterministic UUID-5 identifiers
  so a future graph module can persist them without changing this service.

- **SOC dashboard extension.** Two new threat metrics in the existing snapshot
  (same single UoW pass, no per-widget queries): "Malicious hashes" (unique
  SHA-256s from malicious file scans) and "Recent uploads" (total file scan
  count).

- **Threat Graph preparation.** `IntelligenceRelationship` carries stable
  source/target IDs and a typed relationship label. `IOCFusionService` produces
  `artifact → contains → ioc` and `artifact → shares_ioc → artifact` edges.
  Graph storage is not implemented; the relationship model is ready.

**What was NOT changed**

- No schema changes, no new tables, no new migrations.
- No API route changes — existing endpoints already return the enriched reports.
- No redesign of existing services — fusion is additive.
- `combine_evidence` policy untouched — fusion wraps it, does not replace it.

**Tests (+16, 345 total)**

Unit: severity mapping, evidence fusion (dedup, recommendations, IOC summary,
relationships, provider summaries), provider registry (register/query/filter/
summary), IOC fusion (merge, extract relationships, cross-correlate, no-overlap),
relationship key determinism, integration-level evidence compatibility check,
multi-artifact IOC correlation through the fusion service.

**Deferred to M8·P2c**

Expanded investigation workspace (timeline, evidence tree, IOC table, hash table,
relationships, threat history, analyst recommendations).

## M8 Phase 2C - Unified Investigation Workspace

The platform's standard analyst investigation experience, built entirely on
artifact-agnostic components that serve every current and future artifact type
without redesign.

**Completed**

- **Unified Investigation Domain Model** (`core/domain/investigation.py`).
  `InvestigationSummary` — the single model consumed by every workspace. Every
  field defaults safely so a URL investigation simply leaves file-specific
  fields empty and the workspace adapts. `InvestigationEvent` (timeline),
  `EvidenceNode` (hierarchical tree), `MetadataField` (adaptive key-value),
  `EventKind` enum.

- **Investigation Builder** (`services/investigation/builder.py`).
  `build_file_investigation` constructs a unified summary from a file scan
  result, populating timeline (analysis started → provider executed → evidence
  discovered → threat match → correlation → analysis completed), evidence tree
  (provider → evidence → contribution → recommendation → MITRE), and adaptive
  metadata. Future artifact types add a builder function; the workspace is
  unchanged.

- **10 Reusable Investigation Panels** (`ui/components/investigation/`).
  `InvestigationHeader`, `TimelinePanel`, `EvidenceTreePanel` (QTreeWidget with
  hierarchical expansion), `RelationshipPanel`, `IOCPanel`, `MetadataPanel`,
  `ThreatHistoryPanel`, `ProviderDiagnosticsPanel`, `RecommendationsPanel`,
  `PerformancePanel`. All artifact-agnostic — they read from
  `InvestigationSummary` and render regardless of artifact type.

- **File Scanner rewritten** on the unified workspace with the approved layout
  order: Header → Timeline → Evidence Tree → Relationships → IOC Workspace →
  Indicators → Metadata → Embedded URLs → Threat History → Provider
  Diagnostics → Recommendations → Performance → Analyst Notes. The page
  composes the reusable panels; artifact-specific sections (indicators, URLs)
  are still present but could be refactored into panels in a future pass.

- **Extension points** prepared for memory/registry/PCAP/cloud/identity/
  container/mobile artifact types — each would add a builder function and
  optionally a few artifact-specific sections. The workspace and its 10
  panels require no change.

**Tests (+2, 347 total)**

UI: unified workspace section presence assertion (12 sections verified),
evidence tree node rendering check.

**What completes M8**

With P2c, Milestone 8 is complete. The File Intelligence Engine has reached
the same maturity level as the URL and email engines: deep static analysis
(Office, archive, PE, script), an extensible IOC platform, an intelligence
fusion layer, and a unified investigation workspace — all on the same Clean
Architecture foundation.

## M9 Phase 1 - Internal Intelligence Event Bus

An in-process, lightweight, deterministic event system that decouples
intelligence producers from downstream consumers — the foundation for the
event-driven intelligence architecture and the Knowledge Graph.

**Completed**

- **Event model** (`core/domain/events.py`). `IntelligenceEvent` frozen VO with
  event_id (UUID-4), event_type, ISO timestamp, correlation_id,  source,
  artifact_id, and a typed payload dict. `EventType` enum with 14 values. 11
  typed convenience constructors (one per logical event). New event types are
  added by extending the enum and writing a constructor — no handler or bus
  change required.

- **IEventBus port** (`core/interfaces/event_bus.py`). Core-owned contract:
  publish, subscribe, subscriber_count. `EventHandler` type alias. A future
  async dispatch, external broker, or distributed event system would implement
  the same interface.

- **InProcessEventBus** (`services/events/bus.py`). Synchronous, ordered,
  failure-isolated dispatcher. Handlers for a given event type are invoked in
  registration order; a failing handler is logged (via the injected `ILogger`)
  but does not prevent subsequent handlers from executing. Accumulated
  observability metrics: total_published, total_dispatched, total_failures,
  total_publish_ms, per-type counts.

- **EventHistory** (`services/events/history.py`). In-memory ring buffer
  (configurable max, default 1000) that attaches to the bus and records every
  event. Exposes: recent (newest first), count (lifetime), type_statistics,
  recent_by_type, summary (for SOC dashboards). Events are not persisted in
  this phase — the history is ephemeral.

- **Container wiring.** Bus and history created during container initialization.
  History attaches to all 14 event types. `event-bus` health component reports
  subscriber count. Accessor properties for bus, history.

- **Threat Graph seam.** A future `GraphRelationshipBuilder` subscribes to
  `RELATIONSHIP_DISCOVERED` events without changing any publisher — the bus
  dispatches to all registered handlers for that type. The same seam supports
  `ARTIFACT_ANALYZED` → graph node creation, `IOC_EXTRACTED` → graph edge
  creation, etc.

- **Correlation identifiers.** Every event carries a `correlation_id` that
  links it to an investigation chain. A `source` identifies the publishing
  component, `artifact_id` the subject. These prepare for future distributed
  tracing without implementing it.

**What was NOT changed**

- No existing service was modified. The bus is purely additive.
- No schema change, no new tables, no new migrations.
- No external dependency (no Kafka, RabbitMQ, Redis, Celery).
- Existing services continue working without the bus.

**Tests (+19, 366 total)**

Event model (stable fields, all convenience constructors), publication and
subscription (delivery, multiple subscribers, ordered dispatch, type filtering,
no-subscriber publish), failure isolation (failing handler doesn't block others,
failure metric incremented), correlation ID propagation, subscriber count,
metrics accumulation, event history (recording, ring buffer eviction, type
statistics, recent-by-type, summary), IEventBus interface conformance, provider
event metadata, and a regression test confirming file analysis still works.

**Deferred**

- Wiring event publication into existing services (file/email/URL analysis,
  correlation, threat intelligence) — this is an M9·P2 concern.
- Async dispatch behind the same IEventBus contract.
- Event persistence.
- Graph subscription.

## M9 Phase 2 - Knowledge Graph Domain

The knowledge graph as a platform capability — the domain model, repository,
event-driven builder, and query service that every future feature consumes.

**Completed**

- **Graph domain model** (`core/domain/graph.py`). `GraphNode` (node_id,
  node_type, display_name, labels, metadata, timestamps; 13 NodeType values),
  `GraphEdge` (edge_id, relationship, source/target, confidence, provenance,
  timestamp, metadata; 13 RelationshipType values), `GraphPath` (ordered nodes
  + edges, length, is_empty), `GraphSnapshot` (node/edge/type counts, duplicate
  suppressions, build duration). All frozen dataclasses with deterministic
  deduplication keys.

- **Graph repository port** (`core/interfaces/graph_repository.py`).
  `IGraphRepository` — Core-owned, storage-agnostic contract. Mutations:
  add_node (dedup), add_edge (dedup), update_metadata. Queries: get_node,
  get_edge, neighbors, edges_of, nodes_by_type, shortest_path (BFS),
  shared_iocs, subgraph, snapshot. Replaceable with Neo4j, Neptune,
  JanusGraph, or Cosmos DB Gremlin — no application code depends on storage.

- **In-memory repository** (`infrastructure/graph/in_memory.py`).
  Dict-backed with an adjacency index for O(1) neighbor lookup. BFS traversal
  powers shortest_path, subgraph, and shared_iocs. Deterministic deduplication
  by node_id and edge key. Duplicate suppression counter for observability.

- **Graph Builder** (`services/graph/builder.py`). Subscribes to 9 event types
  (ARTIFACT_ANALYZED, IOC_EXTRACTED, THREAT_RECORDED, INCIDENT_CREATED/UPDATED,
  CAMPAIGN_CREATED/UPDATED, RELATIONSHIP_DISCOVERED, PROVIDER_COMPLETED) on the
  Internal Event Bus. Publishers remain unaware of the graph. Creates artifact
  nodes (typed by artifact_type), threat nodes, incident nodes, campaign nodes,
  provider nodes, and relationship edges (OBSERVED_IN, ASSOCIATED_WITH,
  ANALYZED_BY, CONTAINS, RELATED_TO) automatically. Tracks build count and
  duration for observability.

- **Graph Query Service** (`services/graph/query.py`). High-level, storage-
  agnostic query interface: lookup, neighbors, edges_of, related_artifacts,
  shared_iocs, incident_relationships, campaign_relationships,
  investigation_subgraph, shortest_path, reachable, snapshot. Analytics
  extension points: centrality, connected_components, communities, attack_paths,
  blast_radius — stubs that carry the correct signatures for future algorithms.

- **Container wiring.** Repository, builder, and query service created during
  initialization. Builder attaches to the event bus. `knowledge-graph` health
  component reports node/edge counts. Accessor properties for query service
  and repository.

**Graph consistency**

- Stable node IDs: the node_id from the event (e.g. SHA-256, incident UUID)
  is the graph's primary key. Adding the same node twice returns the existing one.
- Deterministic edge keys: `source→relationship→target`. Adding a duplicate
  edge is silently suppressed and counted.
- Metadata updates merge rather than replace.

**Future preparation**

- The graph supports live Threat Intelligence, YARA, VirusTotal, Sigma, Sandbox,
  Case Management, AI Copilot, and graph visualization as subscribers or query
  consumers — no domain or repository change needed.
- Analytics stubs (centrality, components, communities, attack paths, blast
  radius) carry the correct signatures; implementing them is a localized change.

**Tests (+29, 395 total)**

Node creation + dedup, edge creation + dedup, metadata merge, neighbor traversal
(filtered + unfiltered), shortest path (connected + disconnected + same-node),
shared IOCs, subgraph depth, nodes by type, snapshot, event-driven construction
(artifact, threat, incident, campaign, relationship, provider events), builder
metrics, query service (lookup, subgraph, related artifacts, snapshot),
analytics stubs, IGraphRepository conformance, regression.

---

## M9 Phase 3.0 — Baseline Architecture Remediation

**Scope:** Strictly limited to the two pre-existing Import Linter violations found
during M9 Phase 3 verification. No new features; no redesign of completed
functionality; minimum changes to restore compliance; full backward compatibility.

### Violation 1 — Services → AI (contract: *Services depend inward only*)

`services.file_analysis.ingestion` imported `ai.file_analysis.pe_parser.parse_pe`
directly.

- Relocated the pure, stdlib-only `parse_pe` byte→VO function to **`core.domain.pe`**,
  beside its siblings (`compute_fingerprints`, `identify_type`, `shannon_entropy`,
  `extract_iocs`). Behaviour and output unchanged.
- Added Core port **`core/interfaces/pe_parser.py :: IPeParser`** (`parse(bytes) -> PEInfo`),
  exported from `core.interfaces`.
- `ai/file_analysis/pe_parser.py` now re-exports `parse_pe` (backward compatibility)
  and provides the **`StructPeParser(IPeParser)`** adapter.
- `FileIngestor` gained an injectable `pe_parser: IPeParser | None` field; PE parsing
  routes through the injected adapter, defaulting to the pure core `parse_pe` so a bare
  `FileIngestor()` is unchanged. The composition root injects `StructPeParser()`.

### Violation 2 — UI → Services (contract: *UI depends on Core only*)

`ui.pages.file_scanner` imported `services.investigation.build_file_investigation`
and constructed the investigation summary client-side.

- Summary construction moved **behind the API boundary**: `application/api/file.py`
  builds the unified `InvestigationSummary` server-side (via the existing
  `build_file_investigation` service) and serializes it onto the file-scan response
  as an `InvestigationSummaryModel` (recursive evidence tree included).
- `BackendClient` reconstructs the `InvestigationSummary` from the DTO and exposes it
  on `FileScanResult.investigation`.
- `ui/pages/file_scanner.py` now consumes `result.investigation`; the `services`
  import is removed. UI reaches application logic only through `BackendClient`.

### Tests

- Updated `tests/ui/test_file_scanner.py` fixture to carry the backend-produced
  `investigation` payload (generated with the real service builder + API serializer,
  preventing drift).
- Added 2 regression tests locking the DTO-delivered investigation contract.
- 385 → 387 test functions.

### Gates (clean extraction)

Black ✅ · Ruff ✅ · Mypy strict ✅ (300 files) · Import Linter ✅ **7/7** ·
Pytest ✅ (324 non-UI + 73 UI = 397) · Alembic no-drift ✅.

**Outcome:** frozen as the new architectural baseline for M9 Phase 3.

---

## M9 Phase 3-A — Graph Explorer Application Layer

**Scope:** Reusable backend capability establishing the application contracts
between the Knowledge Graph and the future Intelligence Graph Explorer UI. No
presentation implementation in this phase. Additive and fully backward compatible;
no frozen module modified.

### Presentation contracts — `core/domain/graph_view.py`

Pure, framework-free view DTOs: `GraphNodeView`, `GraphEdgeView`, `GraphView`,
`GraphSelection`, `GraphPathView`, `GraphSnapshotView`, `GraphAnalyticsSummary`,
`ConnectedEntity`, `GraphSearchResult`. Placed in `core.domain` (same precedent as
`InvestigationSummary`) so the producing service and the consuming UI share one
contract without duplication. Domain purity preserved (stdlib only).

### Application service — `services/graph/explorer.py`

`GraphExplorerService` orchestrates the frozen `GraphQueryService` for all
traversal/query and reuses `IGraphRepository` for node enumeration
(`nodes_by_type`) needed by search and analytics — both listed under the phase's
reuse set. It reimplements no traversal. Responsibilities: map domain graph
objects to view DTOs, derive display tone (verdict → danger/warning/success, else
by node type) and risk percent (from `risk_score` metadata), and bound views
(cap 250 nodes, `truncated` flag; edges restricted to endpoints inside the view).
Operations: `snapshot`, `node`, `neighbors`/`expand`, `shortest_path`,
`shared_iocs`, `investigation_graph`, `incident_graph`, `campaign_graph`,
`search`, `selection`, `analytics` (most-connected via degree, IOC count,
largest connected component via reused `reachable` BFS, reachability from the top
node).

### REST API — `application/api/graph.py`

Thin router exposing `/api/graph/{snapshot,analytics,search,path,shared-iocs,
investigation/{root},incident/{id},campaign/{id},nodes/{id},nodes/{id}/neighbors,
nodes/{id}/selection}`. Returns presentation DTOs only (Pydantic response models);
domain graph objects are never serialized. 404 on missing node lookup; 422 on empty
search query.

### DI wiring

`GraphExplorerService` constructed in `DependencyContainer` from the existing
`GraphQueryService` + graph repository; injected into `create_api`
(`graph_explorer_service` param → `app.state`); router registered. New `graph_explorer`
accessor on the container.

### BackendClient gateway — `ui/backend/client.py`

Typed graph methods (`graph_snapshot`, `graph_analytics`, `graph_search`,
`graph_node`, `graph_neighbors`, `graph_selection`, `graph_shortest_path`,
`graph_shared_iocs`, `graph_investigation`, `graph_incident`, `graph_campaign`)
returning reconstructed `core.domain.graph_view` DTOs, with safe defaults on
`httpx` error. View DTOs re-exported from `ui.backend`. UI reaches the graph only
over HTTP.

### Dependency layering (Import Linter 7/7)

`UI → BackendClient → REST API → GraphExplorerService → GraphQueryService → IGraphRepository`.

### Tests (+37 → 434 collected)

- `tests/unit/test_graph_explorer.py` — full service behaviour incl. tone/risk
  mapping, bounded views, path found/not-found, search focus/limit/empty, analytics,
  selection, empty-graph safety.
- `tests/integration/test_graph_api.py` — every endpoint via FastAPI `TestClient`,
  DTO mapping, 404 and 422 paths.
- `tests/ui/test_graph_client.py` — API-model → JSON → client-DTO round trips for all
  view types, plus gateway error-handling defaults.

### Gates

Black ✅ · Ruff ✅ · Mypy strict ✅ (306 files) · Import Linter ✅ **7/7** ·
Pytest ✅ (353 non-UI + 81 UI = 434) · Alembic no-drift ✅.

**Outcome:** backend capability complete; presented for architectural review before P3-B.

## M9 Phase 3-B — Intelligence Graph Explorer (MVVM Presentation Layer)

Presentation-only phase building the analyst-facing Graph Explorer on the frozen
P3-A backend, reached exclusively over HTTP via `BackendClient`.

### Delivered
- `ui/components/graph/`: `layout.py` (pure deterministic spring layout),
  `identity.py` (node-type colour/glyph/label), `items.py` (node/edge scene
  items), `canvas.py` (interactive QGraphicsView), `toolbar.py`, `panels.py`
  (search/filters/timeline/node-details/relationship-details/analytics/legend),
  `__init__.py`.
- `ui/viewmodels/graph_explorer.py`: `GraphExplorerViewModel` (MVVM state +
  orchestration, client-side filtering/timeline, expand-merge, observability)
  with an **injectable `runner_factory`** (Dependency Inversion).
- `ui/pages/graph_explorer.py`: `GraphExplorerPage` (thin view).
- Navigation: `GRAPH_EXPLORER` route + sidebar entry; backward-compatible
  payload-aware `Router.navigate` / `UIContext.go_to` with an `on_navigated`
  page hook; registered in the shell.
- Investigation integration: "Open in Graph Explorer" action on the File
  Investigation workspace; "Back to investigation" in the explorer.

### Notes
- **UI → Core-only** contract preserved: the explorer imports only
  `core.domain.graph_view` and `ui.*`, never `services` or the graph repository.
- **Testability:** VM/page accept a synchronous runner in tests, giving
  deterministic execution and avoiding native Qt worker-thread teardown crashes.
- **Known follow-up (backend, out of scope):** detection services do not yet
  publish intelligence events; the live graph is populated only in tests.

### Gates

Black ✅ · Ruff ✅ · Mypy strict ✅ (321 files) · Import Linter ✅ **7/7** ·
Pytest ✅ (353 non-UI + 116 UI = 469) · Alembic no-drift ✅.

**Outcome:** presentation capability complete; presented for architectural review before P3-C.

## M9 Phase 3-C — Graph Explorer Hardening, Observability & Release

Finalisation phase. No new architectural subsystems, no persistence, no
event-publisher wiring; in-memory adapters intact.

### Delivered
- **Lightweight analytics:** fleshed out `GraphQueryService` extension points into
  real BFS-based implementations (`centrality`, `connected_components`,
  `graph_density`, `blast_radius`, shortest-path `attack_paths`); `communities`
  left out of scope. Extended `GraphAnalyticsSummary` with
  `relationship_type_counts`, `component_count`, `density` (additive); explorer
  aggregation reuses `connected_components` (removed the duplicate
  `_largest_component`). Propagated through API model, client parser, and the
  Analytics panel (entity/relationship distributions + structure).
- **Observability:** view-model `metrics_ready` signal (backend-query/layout/
  render/expansion/search/timeline durations; node/edge/visible/hidden/expansion/
  depth counts) rendered in the Analytics panel; `GraphExplorerService.metrics()`
  via a `@_tracked` leaf decorator, surfaced as a `graph-explorer` health
  component.
- **Session preparation:** in-memory `ExplorerSessionState`/`ViewportState`
  (`ui/viewmodels/explorer_session.py`); VM `session_state()`/`restore_session()`;
  page capture/restore; canvas viewport primitives. No persistence.
- **Polish:** canvas keyboard navigation (+/- zoom, F/Home fit, arrow-key pan).
- **Documentation:** architecture, backend boundary, knowledge graph, event-bus
  interaction, ADR-0001, Graph API reference, developer + user guides,
  `CHANGELOG.md`, `ROADMAP.md`.

### Notes
- Analytics DTO changes are additive/backward-compatible; no schema change.
- Deferred to M10: graph + session persistence behind unchanged ports; live-graph
  population via detection-service event publishers.

### Gates

Black ✅ · Ruff ✅ · Mypy strict ✅ (323 files) · Import Linter ✅ **7/7** ·
Pytest ✅ (357 non-UI + 123 UI = 480) · Alembic no-drift ✅.

**Outcome:** Graph Explorer finalised and documented; presented for architectural review before M10.

## M10 — Live Intelligence Pipeline

Event-driven integration. No persistence, no database technology, no
repository-interface change, no duplicated publisher logic; bus/builder/graph
reused as-is.

### Delivered
- **Single publishing seam** `IntelligencePublisher` (`services/pipeline/`):
  centralises all intelligence-event construction. `analysis_completed` emits
  `artifact_analyzed` (+ `ioc_extracted` from enumerated `iocs` or a bare
  `ioc_count`, per-IOC `shares_ioc` and per-`related` `relationship_discovered`,
  and `threat_recorded` when malicious); plus `incident_opened`,
  `campaign_observed`, `investigation_recorded`. Best-effort `_emit` isolates
  failures; `metrics()` exposes totals + per-type counts.
- **`investigation_completed`** constructor added to `core/domain/events.py`.
- **Detection services** (URL/email/file) inject an optional `publisher`
  (default `None`) and publish at completion; email/file also publish
  incident/campaign on correlation. **Investigation services** publish on save.
- **Container** restructured: event bus, knowledge graph, and publisher built
  before the detection services; publisher injected into all five services.
- **Observability:** enriched `event-bus` health; new `graph-builder` and
  `intelligence-publisher` health components.
- **GraphBuilder unchanged** — publishers emit only event types it already
  subscribes to.

### Tests
- 7 publisher unit tests + 7 end-to-end pipeline integration tests (URL/email/file
  live population, event flow bus→builder→graph, accumulation, investigation
  publish, health observability).

### Gates

Black ✅ · Ruff ✅ · Mypy strict ✅ (327 files) · Import Linter ✅ **7/7** ·
Pytest ✅ (371 non-UI + 123 UI = 494) · Alembic no-drift ✅ (no schema change).

**Outcome:** live event-driven pipeline delivered; graph populates automatically;
zero regressions. Presented for architectural review before M11.

## M11 — Advanced Threat Analytics & Intelligence Engine

Deterministic analytics engine composed over the existing platform. No redesign,
no persistence, no database, no repository change, no duplicated algorithms.

### Delivered
- **Phase A** `GraphAnalyticsService` — degree, centrality ranking, connected
  components, density, blast radius, reachability, shortest attack paths, multi-hop
  neighbourhood, shared-infrastructure discovery, threat propagation, composing
  `GraphQueryService`.
- **Phase B** `IOCIntelligenceService`, `CampaignIntelligenceService`,
  `ThreatScoringService` — deterministic, explainable IOC/campaign/threat scoring.
- **Phase C** `AttackAnalysisService` — attack chains, kill-chain mapping,
  compromise paths, root cause, infrastructure clusters, attack timeline,
  propagation.
- **Phase D** `RecommendationService` — deterministic recommendations that reuse
  the B/C scores and carry their rationale forward.
- **Phase E** `AnalyticsOverviewService` + `GraphOverlayService`;
  `/api/analytics/{overview,overlay}` + `BackendClient` gateway; additive SOC
  dashboard "Advanced Threat Analytics" section; Explorer "Analytics Overlay"
  toggle reusing `highlight_nodes`.
- **Shared** `MeteredService` + `tracked` (uniform observability, no duplicated
  timing); `GraphQueryService.all_nodes()`; container `_build_analytics_engine()`
  + `graph-analytics`/`intelligence-engine` health.

### Notes
- All DTOs frozen/framework-free in `core/domain/*_view.py`; additive endpoints and
  UI only; no schema change.

### Gates

Black ✅ · Ruff ✅ · Mypy strict ✅ (347 files) · Import Linter ✅ **7/7** ·
Pytest ✅ (402 non-UI + 125 UI = 527) · Alembic no-drift ✅. Zero regressions.

**Outcome:** M11 complete across Phases A–E; presented for review before M12.

---

## M12 Phase 1 — AI Security Copilot (Reasoning Engine)

**Objective:** Introduce a read-only AI Security Copilot that consumes the
platform's deterministic intelligence and explains it in natural language — no
redesign, no persistence, no database change, no repository change, no duplicated
intelligence logic. The Copilot is never a source of truth (ADR-0002).

### Delivered
- **Core** `core/domain/copilot.py`, `core/domain/copilot_session.py`;
  `core/interfaces/llm_provider.py`, `core/interfaces/copilot_skill.py` — frozen,
  framework-free domain and ports.
- **Pipeline** (`services/copilot/**`): `IntentDetector` (deterministic keyword +
  focus rules), `SkillRegistry` + `BaseSkill` + five skills, `ContextCollector`
  (+ deterministic DTO serializers), `PromptBuilder` (+ versioned templates,
  `PromptMetadata`), `CitationValidator`, `GroundingValidator`,
  `ResponseFormatter`, `SessionManager`, and `CopilotOrchestrator` sequencing the
  full pipeline.
- **Provider** (`ai/copilot/**`): `BaseLLMProvider`, `ClaudeProvider`
  (Anthropic Messages API over `httpx`), and a config-driven `build_provider`
  factory; graceful failure on missing key / transport / HTTP / malformed body.
- **API** `application/api/copilot.py` (`/ask`, `/session/{id}` GET/DELETE,
  `/session/{id}/focus`) registered in `app.py`.
- **Wiring** container `_build_copilot()`, accessors, and an `ai-copilot` health
  component (optional; never degrades platform status).
- **UI gateway** `BackendClient.copilot_ask`/`copilot_update_focus`/
  `copilot_close_session` + response parser (reuses Core copilot DTOs).
- **Config** `CopilotSettings` + `config/copilot.yaml`; loader section + env
  overrides `AEGIS_COPILOT_{ENABLED,PROVIDER,MODEL}`; API key via
  `copilot.api_key_env` (no secret in config).

### Notes
- Read-only by construction: the collector calls only query/score/analyze/rank/
  report methods; no write path exists. Grounding + citation stages enforce that
  answers derive from, and cite, the supplied deterministic context.
- Additive only; no schema change, no migration, no new runtime dependency
  (`httpx` already present). One SOC integration point touched: the `ai-copilot`
  health component reports healthy (optional subsystem) so platform status is
  unaffected — protected by two new bootstrap tests.

### Gates

Black ✅ · Ruff ✅ · Mypy strict ✅ (365 files) · Import Linter ✅ **7/7** ·
Pytest ✅ (447 non-UI + 125 UI = 572) · Alembic no-drift ✅ (8 migrations). Zero
regressions (527 prior + 45 new).

**Outcome:** M12 Phase 1 complete; presented for review before M12 Phase 2
(UI + streaming).

---

## M12 Phase 2 — AI Security Copilot (User Experience)

**Objective:** Expose the Phase 1 Copilot backend through a clean MVVM desktop
interface — UI-only, no new intelligence logic, no new detection, no new graph
algorithms, no direct service access. The UI communicates exclusively through
`BackendClient` and the existing REST API.

### Delivered
- **View-model** `ui/viewmodels/copilot.py`: `CopilotViewModel` + `ChatTurn`.
  Owns the active-session conversation; runs `copilot_ask`/`copilot_update_focus`/
  `copilot_close_session` off the UI thread via an injected `AsyncRunner`; exposes
  `turn_started`/`turn_completed`/`busy_changed`/`error`/`cleared`/`focus_changed`;
  handles ask/regenerate/clear and analyst-friendly error mapping. A single
  `_dispatch`/`_ask` seam isolates the provider call for future streaming.
- **Page** `ui/pages/copilot.py`: `CopilotPage(BasePage)` — auto-scrolling
  transcript, composer, context-aware suggested prompts, clear/regenerate/copy,
  developer-mode metadata, citation click-through, and an
  `on_navigated({focus, kind, origin, prompt})` launch hook.
- **Components** `ui/components/copilot/chat.py`: `MessageBubble`, `CitationChip`,
  `CitationsRow`, `MetadataRow`, `TypingIndicator`, `SuggestedPrompts`,
  `ChatComposer` (Enter=send, Shift+Enter=newline). Plus
  `ui/components/copilot/navigation.py` (`citation_target`).
- **Shell** `Route.COPILOT` + "AI Copilot" nav entry; page registered in
  `main_window`; new `copilot` icon drawer; Copilot QSS section in
  `ui/theme/stylesheet.py`.
- **Launch points** additive "Ask Copilot" header actions on URL/email/file
  investigations, incident triage, Graph Explorer (selected node), and the SOC
  dashboard (global), each navigating with `{focus, kind, origin}`.

### Notes
- No context collection in the UI: launch points forward a focus id and the
  *backend* collects the matching intelligence. Citations navigate to the Graph
  Explorer via the existing `{focus, origin}` contract.
- Provider streaming is not advertised in Phase 1, so the standard path is used
  with graceful fallback; the seam is documented for Phase 3.
- One icon-drawer (`_settings`) was briefly disturbed during editing and restored
  byte-for-byte against the M11 baseline (verified identical).

### Gates

Black ✅ · Ruff ✅ · Mypy strict ✅ (373 files) · Import Linter ✅ **7/7** ·
Pytest ✅ (447 non-UI + 163 UI = 610) · Alembic no-drift ✅ (8 migrations). Zero
regressions (572 prior + 38 new). No API, config, or schema change.

**Outcome:** M12 Phase 2 complete; presented for review before M12 Phase 3.

---

## M12 Phase 3 — AI Security Copilot Finalization (M12 complete)

**Objective:** Make the Copilot production-ready — implement the reserved
streaming seam, complete the integration/grounding/session/provider reliability
passes, polish the UX, and harden Qt lifecycle safety — without redesigning the
Phase 1 backend or adding engines/graph algorithms/persistence/a database/new AI
abstractions. The `ILLMProvider` contract is extended only additively.

### Delivered
- **Core (additive)** `LLMStreamChunk` + optional `supports_streaming()`/
  `stream()` on `ILLMProvider` (safe default yields a terminal "unsupported"
  chunk). New `CopilotStreamEvent` domain type.
- **Provider** `BaseLLMProvider.stream()` (SSE over httpx; every failure → a
  terminal `success=False` chunk, never raises; abstract `_parse_stream_line`
  hook). `ClaudeProvider.supports_streaming()` → `True` and an Anthropic SSE
  parser (`content_block_delta`/`message_start`/`message_delta`).
- **Orchestrator** refactored into shared `_prepare` (stages 1–4) and `_finalize`
  (stages 6–8); `ask()` behaviour unchanged. New `stream_ask()` streams raw
  tokens but runs citation + grounding validation on the complete text and emits
  the validated response on the terminal `final` event — grounding preserved.
- **API** additive `POST /api/copilot/ask/stream` returning `text/event-stream`;
  `/ask` unchanged.
- **Client** `BackendClient.copilot_stream()` generator + `_parse_stream_line`;
  graceful transport-error fallback event.
- **UI** lifecycle-safe `StreamWorker` (owned `QThread`, cooperative cancellation,
  post-cancel signal suppression, quit+join on `stop()`); view-model
  `token_received` signal, streaming dispatch with automatic non-streaming
  fallback, injectable `stream_worker_factory`, and `dispose()`; page progressive
  token rendering, generating state, scroll-during-generation, `closeEvent` +
  `aboutToQuit` disposal, and an injectable `view_model` seam for tests.

### Notes
- **Grounding under streaming:** the streamed tokens are never authoritative; the
  finalized answer is validated exactly as in the non-streaming path, so ADR-0002
  holds (an ungrounded stream finalizes as an honest "insufficient" answer).
- **Qt lifecycle:** audited timers/workers/runner/signals/page-destruction/
  shutdown; the full UI suite exits cleanly (exit 0). Fixed a real defect where
  pre-existing view-model tests, once streaming defaulted on, spawned real stream
  workers against a fake client and aborted the process — those tests now pin the
  non-streaming path and page tests use the injected view-model seam.
- `stream_ask()` is intentionally **not** `@tracked`: that decorator's `finally`
  fires at generator creation, not consumption, which is wrong for a generator.

### Gates

Black ✅ · Ruff ✅ · Mypy strict ✅ (378 files) · Import Linter ✅ **7/7** ·
Pytest ✅ (459 non-UI + 178 UI = 637; UI exits cleanly) · Alembic no-drift ✅
(8 migrations). Zero regressions (610 prior + 27 new). No schema/persistence/
config change; provider contract extended additively only.

**Outcome:** M12 Phase 3 complete. **M12 is complete.** Presented for
architectural review; M13 not started.

---

## M13 — Authentication & Secure Application Entry

**Objective:** Introduce a professional single-user local authentication system —
first-launch registration, login, secure password hashing, session management,
logout, API-level route protection, and a premium authentication UI covering all
states — without redesigning any completed system and without enterprise-identity
scope.

### Delivered
- **Core** `domain/auth.py` (`User`, `AuthSession` with tz-safe expiry,
  `AuthenticatedUser`); ports `IPasswordHasher`, `IUserRepository`,
  `IAuthSessionRepository`; `security/auth_policy.py` (validation + normalization).
- **Infrastructure** `ScryptPasswordHasher` (stdlib `hashlib.scrypt`, no new
  dependency; per-account salt; self-describing hash; constant-time verify;
  `False` on malformed); `UserAccountRow`/`AuthSessionRow`; SQLAlchemy
  repositories (case-insensitive identifier lookup, single-account check, conflict
  detection, expiry purge).
- **Migration** `f163ed341c79_auth_accounts_and_sessions` (autogenerated,
  reviewed): `user_accounts` + `auth_sessions` with indexes. No drift; 9
  migrations.
- **Services** `AuthenticationService`: register/login/logout/current-user/
  purge-expired via a caller-supplied session-scoped unit of work. Generic
  `INVALID_CREDENTIALS` with a dummy-hash verification for uniform timing (no
  enumeration); single-account enforced; never logs secrets.
- **API** `application/api/auth.py`: DTOs (hashes never returned), `require_session`
  dependency (401 + `WWW-Authenticate`), `/api/auth/status|register|login|me|
  logout`. `create_api` mounts health + auth open and guards every analyst router
  with `require_session`. Container `_build_auth` wires the hasher and a
  session-scoped UoW closure over the shared session factory.
- **Client** token storage (`set_token`/`clear_token`/`has_token`),
  `set_unauthorized_handler` for 401→session-expired, auth-aware `_get/_post/
  _put/_delete` wrappers applied to all 34 existing call sites (bearer attached,
  including the copilot stream), and `auth_status/register/login/logout/
  current_user` returning typed `AuthResult`/`AuthUser`.
- **UI** `AuthViewModel` (off-thread status/login/register via AsyncRunner);
  `AuthWindow` (branded hero + stacked login/register/loading/success cards; all
  13 states; inline validation; password visibility; strength meter; Tab order;
  Enter-submit; `notify_session_expired`; page-owned success `QTimer`);
  `auth_fields` components; 5 new line icons (`lock`, `user`, `eye`, `eye-off`,
  `log-out`); auth QSS section. `DesktopAuthFlow` shows auth before the shell,
  builds+shows `MainWindow` on `authenticated`, returns to auth on logout, and
  routes back with a notice on 401. Shell top bar gains a logout action + account
  avatar.

### Notes / defects fixed
- Route protection broke 34 pre-existing integration tests (they hit now-protected
  endpoints without a token) — fixed with a shared `install_auth` helper
  (register+login, auto-attach bearer header); no feature-test logic changed.
- Auth UI layout: register input/error overlap (root cause: height-constrained
  `QStackedLayout`) fixed with reserved fixed-height error lines + card sizing to
  content; stuck "Signing in…" during the first-launch status check; cramped
  spacing. All corrected during M13.
- Clean Qt shutdown: `BackendHealthPoller` could emit after the shell was torn
  down on logout — fixed with an active guard + draining in-flight tasks on stop,
  and by not eagerly deleting the window mid-emit.

### Gates
Black ✅ · Ruff ✅ · Mypy strict ✅ (396 files) · Import Linter ✅ **7/7** ·
Pytest ✅ (479 non-UI + 199 UI = 678; UI exits cleanly) · Alembic no-drift ✅ (9
migrations). Zero regressions (637 prior + 41 new). Real launch verified:
first-launch register → login → SOC → navigate → logout → subsequent-launch login;
protected route 200 with token / 401 without.

**Outcome:** Authentication experience complete. STOP for architectural review;
Gmail/M14/candidate-release not started.

## M14 — Gmail Intelligence Integration

**Objective.** Add Gmail as a read-only input connector feeding the existing Email
Analysis pipeline — no new analyzer, IOC engine, scoring, graph, or Copilot skill.

**Approach.** Core → config → infrastructure → services → API → UI, with Gmail
messages fetched as raw RFC-822 (`format=raw`) and passed straight to the existing
`EmailAnalysisService.analyze(raw_email)`. OAuth uses the installed-app loopback
flow over httpx (no Google SDK; ADR-0004): system browser, ephemeral `127.0.0.1`
callback, `state` nonce, lifecycle-safe listener. Scope strictly `gmail.readonly`
(config validator). Tokens in a 0600 file under `data/gmail/` (gitignored); client
secret from `AEGIS_GMAIL_CLIENT_SECRET`. Deduplication by Gmail message id via an
additive `gmail_processed_messages` table (migration `2e323b64d4cd`). All
`/api/gmail/*` routes behind the M13 session guard, separate from the Gmail OAuth
identity. Polished `GmailPage` + off-thread `GmailViewModel`; Integrations sidebar
entry.

**Key decisions.** httpx not Google SDK; loopback not copy/paste/webview;
read-only scope enforced at load; secrets outside the repo; reuse of the email
pipeline verbatim; minimal dedup persistence; auth boundary preserved.

**Validation.** Black · Ruff · Mypy strict (414 files) · Import Linter 7/7
(Google code isolated; email/graph/Copilot never import Gmail types) · Pytest
(513 non-UI + 207 UI = 720; UI exits cleanly) · Alembic no-drift (10 migrations).
Zero regressions (678 prior + 42 new). E2E: fake Gmail → GmailIngestionService →
real EmailAnalysisService → real graph nodes → SOC; dedup across syncs. Live
Google OAuth is a documented manual step (Google domains not on this env's
allowlist; not faked).

**Outcome.** Complete read-only Gmail connector reusing the existing intelligence
pipeline. STOP for architectural review; M15 Candidate Release not started.

---

## M14 Completion Pass — Gmail Intelligence Analyst Workspace

**Objective.** Turn the working Gmail connector/status page into a genuine
intelligence workspace: see the account's messages, their EXISTING AEGIS+
analysis and evidence, and navigate into the existing Investigation / Graph /
Copilot / SOC — without any Gmail-specific intelligence.

**Approach (read-model + presentation + navigation + integration).**
- **Read-model.** Expanded `gmail_processed_messages` to composite PK
  `(account_email, message_id)` + non-secret metadata (`sender/subject/
  received_at/snippet/status/thread_id`) via additive migration
  `32799204f010` (batch-safe; no drift; 11 migrations). New account-aware
  `IGmailSyncStateRepository` + SQLAlchemy implementation. Domain adds
  `GmailMessageStatus` (4-state) and `GmailProcessedMessage`.
- **Service.** Rewrote `GmailIngestionService`: account-scoped dedup; the
  four-state taxonomy (unsupported/transient/failed distinguished; transient not
  recorded → retried); `list_messages(filter, search)` and `message_detail(id)`
  that project the EXISTING `EmailScan` + investigation + incident/campaign
  (read-only reuse of `IncidentCorrelationService`) and a safe on-demand preview
  (`EmailMessage.parse` → plain text, URLs untrusted, attachments metadata). Added
  additive `EmailAnalysisService.get_scan()`; no existing contract modified.
- **API.** `GET /api/gmail/messages` (filter/search), `GET /api/gmail/messages/{id}`,
  `GET /api/email/scans/{id}` — all session-guarded, DTOs only, no token leakage.
- **UI.** New Gmail workspace (filter chips, search, message list, detail panel
  with verdict/evidence/IOCs/correlation/safe preview) + `Open Investigation` /
  `Open in Graph Explorer` / `Ask Copilot` via existing focus contracts. Added
  `EmailScannerPage.on_navigated({"scan_id"})` so a Gmail message opens the
  EXISTING investigation. Off-thread throughout; existing page tests preserved.

**The "1 error".** Confirmed from source + reproduced in test: an unparseable
message raised `ValidationError` and was collapsed into a generic error. Now
classified `UNSUPPORTED`, recorded, shown without a stack trace, and it does not
fail the synchronization.

**Validation.** Gates all green: Black · Ruff · Mypy strict (416 files) · Import
Linter **7/7** (UI still Core-only over HTTP) · Pytest **741** (528 non-UI + 213
UI) · Alembic no-drift. +21 tests (10 workspace integration, 5 API, 6 UI), zero
regressions. Headless `MainWindow` smoke: Gmail workspace + all deep-links
navigate; clean shutdown. Live Gmail = documented manual step (not faked).

**Outcome.** Gmail is now a real, navigable AEGIS+ intelligence source reusing
the existing ecosystem. STOP; M15 Candidate Release not started.
