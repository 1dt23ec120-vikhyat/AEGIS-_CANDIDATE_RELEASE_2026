"""Integration tests for the Authentication API (M13).

Wires the real ``AuthenticationService`` over an in-memory SQLite database with
the real scrypt hasher, mounts the auth router plus a protected probe router, and
drives the full flow: registration (success + validation + duplicate), login
(success + wrong password + unknown account + generic errors), the ``/me``
session endpoint, logout and invalidation, protected-route enforcement, and the
guarantees that password hashes are never returned and errors never enumerate
accounts.
"""

from __future__ import annotations

from collections.abc import Callable, Iterator
from typing import Any

import pytest
from fastapi import APIRouter, Depends, FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

import infrastructure.database.models  # noqa: F401 - registers ORM tables
from application.api import auth
from application.api.auth import require_session
from core.domain.auth import AuthenticatedUser
from infrastructure.database.base import Base
from infrastructure.repositories.auth_repository import (
    SqlAlchemyAuthSessionRepository,
    SqlAlchemyUserRepository,
)
from infrastructure.security import ScryptPasswordHasher
from services.auth import AuthenticationService, AuthRepositories

_PASSWORD = "Str0ng!Passw0rd"


class _FakeLogger:
    def debug(self, *a: object, **k: object) -> None: ...
    def info(self, *a: object, **k: object) -> None: ...
    def warning(self, *a: object, **k: object) -> None: ...
    def error(self, *a: object, **k: object) -> None: ...
    def critical(self, *a: object, **k: object) -> None: ...
    def exception(self, *a: object, **k: object) -> None: ...
    def bind(self, **k: object) -> _FakeLogger:
        return self


def _service(session_ttl_minutes: int = 720) -> AuthenticationService:
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    factory = sessionmaker(engine)

    def run_in_uow(operation: Callable[[AuthRepositories], object]) -> object:
        session = factory()
        try:
            repos = AuthRepositories(
                users=SqlAlchemyUserRepository(session),
                sessions=SqlAlchemyAuthSessionRepository(session),
            )
            result = operation(repos)
            session.commit()
            return result
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()

    return AuthenticationService(
        run_in_uow,
        ScryptPasswordHasher(),
        _FakeLogger(),
        session_ttl_minutes=session_ttl_minutes,
    )


@pytest.fixture
def client() -> Iterator[TestClient]:
    service = _service()
    app = FastAPI()
    app.state.auth_service = service
    app.include_router(auth.build_router())

    probe = APIRouter(prefix="/api/probe", tags=["probe"])

    @probe.get("/secret")
    def secret(user: AuthenticatedUser = Depends(require_session)) -> dict[str, str]:  # noqa: B008
        return {"username": user.username}

    app.include_router(probe, dependencies=[Depends(require_session)])
    with TestClient(app) as test_client:
        yield test_client


def _register(client: TestClient, **overrides: str) -> Any:
    body = {
        "full_name": "Jane Analyst",
        "username": "jane",
        "email": "jane@aegis.local",
        "password": _PASSWORD,
        "confirm_password": _PASSWORD,
    }
    body.update(overrides)
    return client.post("/api/auth/register", json=body)


def _login(client: TestClient, identifier: str = "jane", password: str = _PASSWORD) -> Any:
    return client.post("/api/auth/login", json={"identifier": identifier, "password": password})


# --- status / first launch ----------------------------------------------


def test_status_reports_no_account_on_first_launch(client: TestClient) -> None:
    body = client.get("/api/auth/status").json()
    assert body["account_exists"] is False


def test_status_reports_account_after_registration(client: TestClient) -> None:
    _register(client)
    assert client.get("/api/auth/status").json()["account_exists"] is True


# --- registration --------------------------------------------------------


def test_registration_success_returns_user_without_hash(client: TestClient) -> None:
    response = _register(client)
    assert response.status_code == 201
    body = response.json()
    assert body["user"]["username"] == "jane"
    assert "password" not in body["user"]
    assert "password_hash" not in str(body)


def test_registration_rejects_weak_password(client: TestClient) -> None:
    response = _register(client, password="weak", confirm_password="weak")
    assert response.status_code == 422
    assert "password" in response.json()["detail"]["fields"]


def test_registration_rejects_mismatched_password(client: TestClient) -> None:
    response = _register(client, confirm_password="Different!Pass99")
    assert response.status_code == 422
    assert "confirm_password" in response.json()["detail"]["fields"]


def test_registration_rejects_invalid_email(client: TestClient) -> None:
    response = _register(client, email="not-an-email")
    assert response.status_code == 422
    assert "email" in response.json()["detail"]["fields"]


def test_registration_rejects_bad_username(client: TestClient) -> None:
    response = _register(client, username="a")
    assert response.status_code == 422
    assert "username" in response.json()["detail"]["fields"]


def test_second_registration_is_conflict(client: TestClient) -> None:
    _register(client)
    response = _register(client, username="other", email="other@aegis.local")
    assert response.status_code == 409


# --- login ---------------------------------------------------------------


def test_login_success_returns_token(client: TestClient) -> None:
    _register(client)
    response = _login(client)
    assert response.status_code == 200
    body = response.json()
    assert body["token"]
    assert body["user"]["username"] == "jane"
    assert "password_hash" not in str(body)


def test_login_by_email_is_case_insensitive(client: TestClient) -> None:
    _register(client)
    response = _login(client, identifier="JANE@AEGIS.LOCAL")
    assert response.status_code == 200


def test_login_wrong_password_is_generic_401(client: TestClient) -> None:
    _register(client)
    response = _login(client, password="WrongPassw0rd!")
    assert response.status_code == 401
    assert response.json()["detail"] == "Invalid username or password."


def test_login_unknown_account_is_generic_401(client: TestClient) -> None:
    _register(client)
    response = _login(client, identifier="ghost")
    assert response.status_code == 401
    assert response.json()["detail"] == "Invalid username or password."


# --- session / me / protected --------------------------------------------


def test_me_requires_authentication(client: TestClient) -> None:
    assert client.get("/api/auth/me").status_code == 401


def test_me_returns_current_user_with_token(client: TestClient) -> None:
    _register(client)
    token = _login(client).json()["token"]
    response = client.get("/api/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 200
    assert response.json()["username"] == "jane"


def test_protected_route_rejects_without_token(client: TestClient) -> None:
    _register(client)
    assert client.get("/api/probe/secret").status_code == 401


def test_protected_route_allows_with_token(client: TestClient) -> None:
    _register(client)
    token = _login(client).json()["token"]
    response = client.get("/api/probe/secret", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 200
    assert response.json()["username"] == "jane"


def test_protected_route_rejects_bogus_token(client: TestClient) -> None:
    _register(client)
    response = client.get("/api/probe/secret", headers={"Authorization": "Bearer not-a-real-token"})
    assert response.status_code == 401


# --- logout --------------------------------------------------------------


def test_logout_invalidates_session(client: TestClient) -> None:
    _register(client)
    token = _login(client).json()["token"]
    headers = {"Authorization": f"Bearer {token}"}
    assert client.get("/api/probe/secret", headers=headers).status_code == 200
    assert client.post("/api/auth/logout", headers=headers).status_code == 204
    assert client.get("/api/probe/secret", headers=headers).status_code == 401


def test_session_expiry_returns_401(client: TestClient) -> None:
    # A zero-TTL service issues sessions that are already expired.
    service = _service(session_ttl_minutes=0)
    app = FastAPI()
    app.state.auth_service = service
    app.include_router(auth.build_router())
    probe = APIRouter()

    @probe.get("/api/probe/secret")
    def secret(user: AuthenticatedUser = Depends(require_session)) -> dict[str, str]:  # noqa: B008
        return {"username": user.username}

    app.include_router(probe, dependencies=[Depends(require_session)])
    local = TestClient(app)
    _register(local)
    token = _login(local).json()["token"]
    response = local.get("/api/probe/secret", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 401
