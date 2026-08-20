"""Authentication API (M13).

The HTTP surface for the single-user local account: register, login, current
session (``/me``), and logout. Sessions are opaque bearer tokens; a FastAPI
dependency (:func:`require_session`) validates the token and guards protected
routers. Responses never include the password hash or any internal detail, and
authentication failures are generic to avoid account enumeration.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, Header, HTTPException, Request, status
from pydantic import BaseModel, Field

from core.domain.auth import AuthenticatedUser
from services.auth import AuthenticationService

_GENERIC_INVALID = "Invalid username or password."
_BEARER_PARTS = 2


class RegisterRequest(BaseModel):
    """Registration request body."""

    full_name: str = Field(min_length=1, max_length=120)
    username: str = Field(min_length=1, max_length=64)
    email: str = Field(min_length=1, max_length=320)
    password: str = Field(min_length=1, max_length=256)
    confirm_password: str = Field(min_length=1, max_length=256)


class LoginRequest(BaseModel):
    """Login request body."""

    identifier: str = Field(min_length=1, max_length=320)
    password: str = Field(min_length=1, max_length=256)


class UserModel(BaseModel):
    """The safe, hash-free representation of the account."""

    id: str
    full_name: str
    username: str
    email: str


class LoginResponse(BaseModel):
    """Successful login response."""

    token: str
    expires_at: str
    user: UserModel


class RegisterResponse(BaseModel):
    """Successful registration response."""

    user: UserModel


class AuthStatusModel(BaseModel):
    """First-launch/status hint for the UI."""

    account_exists: bool


def _user_model(user: AuthenticatedUser) -> UserModel:
    return UserModel(id=user.id, full_name=user.full_name, username=user.username, email=user.email)


def _service(request: Request) -> AuthenticationService:
    service: AuthenticationService = request.app.state.auth_service
    return service


def _token_from_header(authorization: str | None) -> str:
    if not authorization:
        return ""
    parts = authorization.split(" ", 1)
    if len(parts) == _BEARER_PARTS and parts[0].lower() == "bearer":
        return parts[1].strip()
    return authorization.strip()


def require_session(
    request: Request, authorization: str | None = Header(default=None)
) -> AuthenticatedUser:
    """Resolve and require a valid session; raise 401 otherwise.

    Used as a dependency on every protected router. The 401 carries a generic
    message and a ``WWW-Authenticate`` hint so the client can return to login.
    """
    token = _token_from_header(authorization)
    user = _service(request).current_user(token)
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Your session has expired. Please sign in again.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return user


def build_router() -> APIRouter:
    """Build the authentication API router."""
    router = APIRouter(prefix="/api/auth", tags=["auth"])

    @router.get("/status", response_model=AuthStatusModel)
    def status_(request: Request) -> AuthStatusModel:
        return AuthStatusModel(account_exists=_service(request).account_exists())

    @router.post("/register", response_model=RegisterResponse, status_code=status.HTTP_201_CREATED)
    def register(request: Request, payload: RegisterRequest) -> RegisterResponse:
        result = _service(request).register(
            full_name=payload.full_name,
            username=payload.username,
            email=payload.email,
            password=payload.password,
            confirm_password=payload.confirm_password,
        )
        if result.ok and result.user is not None:
            return RegisterResponse(user=_user_model(result.user))
        if result.error_code == "ACCOUNT_EXISTS":
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail={
                    "message": "An account already exists for this installation.",
                    "fields": result.field_errors or {},
                },
            )
        # Validation failure. Use the numeric status to stay stable across the
        # Starlette rename of the 422 constant.
        raise HTTPException(
            status_code=422,
            detail={
                "message": "Please correct the highlighted fields.",
                "fields": result.field_errors or {},
            },
        )

    @router.post("/login", response_model=LoginResponse)
    def login(request: Request, payload: LoginRequest) -> LoginResponse:
        result = _service(request).login(identifier=payload.identifier, password=payload.password)
        if not result.ok or result.user is None or result.expires_at is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=_GENERIC_INVALID,
                headers={"WWW-Authenticate": "Bearer"},
            )
        return LoginResponse(
            token=result.token,
            expires_at=result.expires_at.isoformat(),
            user=_user_model(result.user),
        )

    @router.get("/me", response_model=UserModel)
    def me(user: AuthenticatedUser = Depends(require_session)) -> UserModel:  # noqa: B008
        return _user_model(user)

    @router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
    def logout(request: Request, authorization: str | None = Header(default=None)) -> None:
        token = _token_from_header(authorization)
        if token:
            _service(request).logout(token)

    return router
