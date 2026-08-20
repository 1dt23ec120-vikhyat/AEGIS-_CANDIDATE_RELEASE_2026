# AEGIS+ — M1a Knowledge Base Synchronization Package

Single consolidated update derived from the Documentation Impact Log (D1–D22).
Apply to the authoritative Knowledge Base at the close of Milestone 1a. Each
section names the target KB document and the exact change; ADRs are provided in
full for insertion into `ADR_Catalogue.md`.

Traceability: every item cites its Documentation Impact Log ID.

---

## Part A — Architecture Decision Records (add to `ADR_Catalogue.md`)

### ADR-001 — Developer Toolchain (D3)
**Status:** Accepted. **Context:** Standards must be enforced from the first
commit. **Decision:** Black (format), Ruff (lint + isort + naming + docstrings),
Mypy (typing), Import Linter (architecture boundaries), pre-commit (gate).
Configuration centralized in `pyproject.toml`. **Consequences:** Consistent,
machine-enforced quality; contributors run identical checks locally and in hooks.

### ADR-002 — Embedded FastAPI Backend (D4)
**Status:** Accepted. **Context:** Desktop UI needs clean separation from
application logic and future extensibility. **Decision:** An in-process FastAPI
service bound to loopback; the PySide6 UI communicates with it over HTTP on
`127.0.0.1`. **Consequences:** Clean presentation/application separation,
independent testability, remote-management path; requires background-thread
server management (WP6) and an HTTP client boundary (M1b).

### ADR-003 — Configuration Precedence & Secret Handling (D8)
**Status:** Accepted. **Decision:** Precedence defaults < YAML < environment;
secrets sourced only from the environment and modeled as `SecretStr`; corrupted
files raise a typed error; production forbids debug and weak/default secrets.
**Consequences:** Predictable, auditable configuration; no secrets in files or
logs (NFR §7).

### ADR-004 — Dependency Inversion as Import Direction (D13)
**Status:** Accepted. **Context:** The FSS Module Communication Rules describe
Core↔Infrastructure logical/runtime access. Decisions #1–#4 (WP4) require Core to
own all shared contracts. **Decision:** Source-code imports point inward:
Infrastructure and AI depend on Core; Core depends on nothing internal. The FSS
dependency diagram is clarified as describing runtime/logical access, realized in
source via DIP. **Consequences:** Core is the stable center; adapters implement
Core ports; Import Linter enforces the direction. **Supersedes:** the literal
`core → infrastructure` import reading.

### ADR-005 — Domain Purity (D15)
**Status:** Accepted. **Decision:** Core must not import infrastructure
frameworks (Loguru, SQLAlchemy, FastAPI, Pydantic, PySide6, …). Enforced by an
Import Linter `forbidden` contract. **Consequences:** Core remains portable and
independently testable.

### ADR-006 — Centralized Logging on Loguru (D10)
**Status:** Accepted. **Decision:** One logging subsystem: console + rotating app
file + structured JSON audit sinks; stdlib logging bridged via `InterceptHandler`;
secret redaction patcher; `diagnose` disabled outside development. Application
code uses `get_logger`; the stdlib `logging` module is prohibited for app logging.
**Consequences:** Uniform, secret-safe, centralized logging including third-party
output.

### ADR-007 — Alembic as Sole Migration Mechanism (D18, D22)
**Status:** Accepted. **Decision:** Alembic migrations are the only authoritative
schema-evolution mechanism; `create_all` is restricted to controlled dev/test.
Deployment applies `alembic upgrade head`. **Consequences:** Reproducible schema
evolution; `alembic check` guards model↔migration parity.

### ADR-008 — Repository + Unit of Work (D18)
**Status:** Accepted. **Decision:** A generic `SqlAlchemyRepository` implements
the Core `IRepository` port with domain-oriented operations; a capability-based
`IUnitOfWork` coordinates atomic multi-repository transactions. Entity↔row mapping
is isolated in infrastructure mappers. **Consequences:** SQLAlchemy stays an
infrastructure concern; the domain is persistence-agnostic.

### ADR-009 — Audit Persistence via Dependency Injection (D18)
**Status:** Accepted. **Decision:** `AuditLogger` persists records through an
injected Unit-of-Work factory, in its own transaction, best-effort (failures
logged, never raised). Logging call sites are unchanged. **Consequences:** Audit
survives business-transaction rollback; persistence is transparent to callers.

### ADR-010 — DP-DB-08 Interpretation (D17)
**Status:** Accepted. **Decision:** DP-DB-08 audit fields (`created_at`,
`updated_at`, `created_by`, `updated_by`, `version`) are carried on persisted
rows via an ORM `AuditColumns` mixin; Core entities carry the domain lifecycle
subset (`created_at`/`updated_at`). **Consequences:** DP-DB-08 satisfied at the
persistence layer without coupling the domain to ORM concerns.

---

## Part B — Document-specific updates

### `Folder_Structure.md`
- **File naming (D1):** Python modules use `snake_case` (Development Standards
  §13 is authoritative). Update entity examples: `ThreatReport.py` → `threat_report.py`.
- **Interface naming (D2):** interfaces use the `I` prefix (`IRepository`,
  `ILogger`, `IConfigurationProvider`, `IAIService`), superseding suffix-style
  examples.
- **Dependency rules / Module Communication Rules (D13):** annotate that the
  table describes runtime/logical access; import direction follows DIP (ADR-004).
- **Config package (D7):** `config/` is a Python package (schemas, loader,
  validation, paths, environments, defaults, settings, exceptions) alongside YAML.
- **Infrastructure (D14, D19):** add `infrastructure/configuration/` (config→Core
  port adapter); record `infrastructure/database/` (base, engine, models,
  mappers, unit_of_work) and `infrastructure/repositories/` (base_repository,
  registry).

### `Development_Standards.md`
- **Standards (D11, D15):** record centralized-logging-only, exception
  consolidation into Core, dependency-injection / no-hidden-global-state,
  Core-owned contracts, and Domain Purity.
- **Tooling (D20):** `PLE1205` disabled (Loguru brace-style), `max-args=10` for
  data-carrying entities, generated migrations exempt from import-order/whitespace
  lint.

### `Database_Architecture.md`
- **DP-DB-08 (D17):** clarify per ADR-010.
- **Persistence architecture (D18):** record ADR-007/008/009; deferred
  optimistic-lock enforcement (version column present).

### `Non_functional_requirements.md`
- **§14 (D9):** `incident_response` configurable settings deferred to the AIR
  milestone.

### `Testing_and_Quality_Assurance_Strategy.md`
- **(D12, D21):** record the security/persistence test baseline: secret-redaction
  and audit-channel coverage; repository CRUD, UoW atomicity, audit
  persistence/redaction, and a live Alembic-upgrade integration test.

### `Deployment___Operations_Architecture.md`
- **(D22):** schema deployment step is `alembic upgrade head`; `create_all` is
  dev/test only.

### `AI_Model_Specification.md` / interface docs
- **(D16):** `IAIService` base defines `name`/`is_ready`; analysis methods added
  additively in the AI milestone.

---

## Part C — Traceability (D1–D22)

| D | Target | Resolved by |
|---|--------|-------------|
| D1 | Folder_Structure | Part B — file naming |
| D2 | Folder_Structure / Dev Standards | Part B — interface naming |
| D3 | ADR_Catalogue | ADR-001 |
| D4 | ADR_Catalogue | ADR-002 |
| D5 | Folder_Structure | ADR-002 / Part B |
| D6 | ADR_Catalogue | ADR-007 |
| D7 | Folder_Structure | Part B — config package |
| D8 | ADR_Catalogue | ADR-003 |
| D9 | NFR §14 | Part B |
| D10 | ADR_Catalogue | ADR-006 |
| D11 | Dev Standards | Part B — standards |
| D12 | QA Strategy | Part B |
| D13 | Folder_Structure / ADR | ADR-004 |
| D14 | Folder_Structure | Part B — infrastructure |
| D15 | Dev Standards / ADR | ADR-005 |
| D16 | AI Model Spec | Part B |
| D17 | Database_Architecture | ADR-010 |
| D18 | Database_Architecture / ADR | ADR-007/008/009 |
| D19 | Folder_Structure | Part B — infrastructure |
| D20 | Dev Standards | Part B — tooling |
| D21 | QA Strategy | Part B |
| D22 | Deployment/Ops | Part B / ADR-007 |

All 22 items resolved. After applying, mark the Documentation Impact Log entries
🟢 applied.
