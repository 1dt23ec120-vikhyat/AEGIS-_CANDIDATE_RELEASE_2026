# AEGIS+

**AI-Based Integrated Multi-Layer Identity Attack and Phishing Detection System with Automated Incident Response**

AEGIS+ is an enterprise-grade cybersecurity desktop application that detects,
analyzes, explains, and responds to phishing and identity-based attacks using a
multi-layer AI framework with Explainable AI (XAI) and Automated Incident
Response (AIR).


---

## Architecture

AEGIS+ follows **Clean Architecture + MVVM** (SADD, IEEE 1016 / ISO 42010).
Dependencies point inward toward the most stable layers:

```
UI  →  Services  →  Core  →  Infrastructure  →  Database
                     │
                     └→  AI  (isolated; reached only through Core interfaces)
```

The desktop UI (PySide6) communicates with an embedded local backend
(FastAPI over `127.0.0.1`) to keep presentation and application concerns
cleanly separated and to enable independent testing and future extensibility.

### Repository layout

| Directory         | Responsibility                                            |
|-------------------|-----------------------------------------------------------|
| `application/`    | Composition root: bootstrap, lifecycle, dependency wiring |
| `core/`           | Business rules: entities, use cases, contracts            |
| `ai/`             | Machine-learning subsystem (isolated from UI)             |
| `services/`       | Application services coordinating UI and core             |
| `infrastructure/` | External integrations: persistence, logging, networking   |
| `ui/`             | MVVM presentation layer (PySide6)                         |
| `data/`           | Data-processing utilities                                 |
| `config/`         | Configuration files (YAML)                                |
| `database/`       | Schema, migrations, and local SQLite storage              |
| `models/`         | AI model artifacts (binaries not committed)               |
| `tests/`          | Automated test suite                                      |
| `docs/`           | Project documentation                                     |

Directory ownership and dependency rules are fixed by
`Folder_Structure.md` and must not change without an approved ADR.

---

## Getting started

Requires **Python 3.12+**.

```bash
# 1. Create and activate a virtual environment
python3 -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate

# 2. Install runtime and developer dependencies
pip install -r requirements.txt -r requirements-dev.txt

# 3. Install git hooks
pre-commit install

# 4. Configure environment
cp .env.example .env               # then edit .env for your machine
```

---

## Developer tooling

Coding standards (`Development_Standards.md`) and architectural boundaries are
enforced automatically. All tools are configured in `pyproject.toml`.

| Command                         | Purpose                                    |
|---------------------------------|--------------------------------------------|
| `black .`                       | Format code (line length 100)              |
| `ruff check .`                  | Lint and sort imports                      |
| `mypy`                          | Static type checking                       |
| `lint-imports`                  | Verify Clean Architecture dependency rules |
| `pytest`                        | Run the test suite                         |
| `pre-commit run --all-files`    | Run every check across the repository      |

All of the above run automatically on `git commit` via pre-commit.

---

## License

Proprietary — Internal use. See `LICENSE`. Final licensing is subject to
project governance.
