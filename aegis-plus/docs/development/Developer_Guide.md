# Developer Guide

**Status:** Current (M9 Phase 3-C)

This guide covers building, testing, and extending AEGIS+, with emphasis on the
Intelligence Graph Explorer.

## 1. Environment

- Python 3.12, PySide6 6.11, FastAPI, SQLAlchemy 2.0 + Alembic, SQLite, LightGBM,
  Loguru, Pydantic.
- Create a virtualenv and install: `pip install -r requirements.txt -r requirements-dev.txt`.

## 2. Running

- App entry point: `python main.py`.
- The backend runs embedded on localhost; the PySide6 UI reaches it over HTTP via
  `BackendClient`.

## 3. Quality gates (all must pass)

```bash
black --check .
ruff check .
mypy .                       # strict
lint-imports                 # 7/7 contracts
pytest --ignore=tests/ui     # non-UI
QT_QPA_PLATFORM=offscreen pytest tests/ui   # UI (run split from non-UI)
```

Alembic no-drift:
```bash
export AEGIS_DATABASE_URL="sqlite:///./_d.db"
alembic upgrade head
alembic revision --autogenerate -m d   # newest file must have empty upgrade()
```

> **UI tests run split** from non-UI tests. UI tests must not spawn real worker
> threads that outlive their objects — inject a synchronous runner (see below).

## 4. Architecture rules (enforced)

- **Core** depends on nothing internal and is framework-independent.
- **Services** depend inward only (Core), never on delivery/adapters.
- **UI** depends on **Core only** and reaches services **over HTTP** via
  `BackendClient` — never importing `services` or domain graph objects.
- **Infrastructure/AI** implement Core ports and stay isolated from delivery.

## 5. Extending the Graph Explorer

- **New analytics field:** add it to `GraphAnalyticsSummary`
  (`core/domain/graph_view.py`), populate it in `GraphExplorerService.analytics`,
  extend `AnalyticsModel` + `_analytics_model` (API), `_parse_analytics`
  (client), and the `AnalyticsSummaryPanel`. Keep fields additive with defaults.
- **New graph query:** add it to `GraphQueryService` (delegating to the
  repository port), expose it via `GraphExplorerService`, add an endpoint +
  `BackendClient` method, then a view-model method.
- **New panel/interaction:** add a component under `ui/components/graph/`, wire it
  in `GraphExplorerPage._wire`, and route intents through the view-model.

### View-model testing pattern

Inject the synchronous runner so backend calls run inline:

```python
from tests.ui._async import SyncRunner
vm = GraphExplorerViewModel(fake_client, runner_factory=SyncRunner)
```

`GraphExplorerPage(context, runner_factory=SyncRunner)` does the same for page
tests. The production default is the threaded `AsyncRunner`.

## 6. Observability

- Backend: `GraphExplorerService.metrics()` → surfaced as the `graph-explorer`
  health component.
- UI: the view-model emits `metrics_ready` with layout/render/query/expand/
  search/timeline durations and node/edge/visible/hidden/expansion counts; the
  Analytics panel renders them.

## 7. Session state

`ExplorerSessionState`/`ViewportState` (`ui/viewmodels/explorer_session.py`) are
in-memory only. `page.session_state()` captures; `page.restore_session(state)`
restores. Do **not** add persistence here — that is milestone M10.

## 8. Constraints for the current milestone

No PostgreSQL/SQLite/Neo4j persistence, no repository-interface changes, and no
event-publisher wiring. Keep the in-memory adapters intact.
