"""Shared authentication helper for backend integration tests (M13).

The protected API routers require a valid session. Feature-vertical integration
tests (URL, email, file, threats, incidents, SOC) are not about authentication,
so they use this helper to register and log in once against the running backend
and obtain a bearer-token header to attach to their requests.
"""

from __future__ import annotations

from typing import Any

import httpx
import pytest

_PASSWORD = "Str0ng!Passw0rd"


def auth_header(base_url: str) -> dict[str, str]:
    """Register (idempotently) and log in; return a bearer ``Authorization`` header.

    Registration is attempted once; if an account already exists (409) the login
    still proceeds. Returns a header dict suitable for ``httpx`` requests.
    """
    httpx.post(
        f"{base_url}/api/auth/register",
        json={
            "full_name": "Integration Analyst",
            "username": "integration",
            "email": "integration@aegis.local",
            "password": _PASSWORD,
            "confirm_password": _PASSWORD,
        },
        timeout=10.0,
    )
    login = httpx.post(
        f"{base_url}/api/auth/login",
        json={"identifier": "integration", "password": _PASSWORD},
        timeout=10.0,
    )
    token = login.json()["token"]
    return {"Authorization": f"Bearer {token}"}


def install_auth(monkeypatch: pytest.MonkeyPatch, base_url: str) -> None:
    """Authenticate and auto-attach the bearer header to all ``httpx`` calls.

    Feature-vertical integration tests issue bare ``httpx.get``/``httpx.post``
    calls against the protected backend. This wraps those module functions for
    the duration of the test so every request carries a valid session, without
    editing each call site. Auth endpoints are exempt so login/register still
    work unauthenticated.
    """
    header = auth_header(base_url)
    real_get = httpx.get
    real_post = httpx.post
    real_put = httpx.put
    real_patch = httpx.patch
    real_delete = httpx.delete
    real_stream = httpx.stream

    def _merge(kwargs: dict[str, Any], url: str) -> dict[str, Any]:
        if "/api/auth/" in url:
            return kwargs
        headers = dict(kwargs.get("headers") or {})
        headers.setdefault("Authorization", header["Authorization"])
        kwargs["headers"] = headers
        return kwargs

    def patched_get(url: str, **kwargs: Any) -> httpx.Response:
        return real_get(url, **_merge(kwargs, url))

    def patched_post(url: str, **kwargs: Any) -> httpx.Response:
        return real_post(url, **_merge(kwargs, url))

    def patched_put(url: str, **kwargs: Any) -> httpx.Response:
        return real_put(url, **_merge(kwargs, url))

    def patched_patch(url: str, **kwargs: Any) -> httpx.Response:
        return real_patch(url, **_merge(kwargs, url))

    def patched_delete(url: str, **kwargs: Any) -> httpx.Response:
        return real_delete(url, **_merge(kwargs, url))

    def patched_stream(method: str, url: str, **kwargs: Any) -> Any:
        return real_stream(method, url, **_merge(kwargs, url))

    monkeypatch.setattr(httpx, "get", patched_get)
    monkeypatch.setattr(httpx, "post", patched_post)
    monkeypatch.setattr(httpx, "put", patched_put)
    monkeypatch.setattr(httpx, "patch", patched_patch)
    monkeypatch.setattr(httpx, "delete", patched_delete)
    monkeypatch.setattr(httpx, "stream", patched_stream)


__all__ = ["auth_header", "install_auth"]
