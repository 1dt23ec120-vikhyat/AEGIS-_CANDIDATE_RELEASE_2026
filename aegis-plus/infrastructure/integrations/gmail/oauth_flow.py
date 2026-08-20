"""Gmail loopback OAuth 2.0 flow (M14).

Implements the installed-app loopback authorization flow over ``httpx`` and the
standard library — no Google SDK. The flow:

1. Binds a temporary HTTP listener to ``127.0.0.1`` on an ephemeral port.
2. Opens the system browser to Google's consent page, with a ``state`` nonce and
   the loopback ``redirect_uri``.
3. Waits for Google to redirect back to the loopback with an authorization code,
   validating the ``state`` nonce (CSRF protection).
4. Exchanges the code for tokens at the token endpoint.
5. Shuts the listener down cleanly — on success, denial, timeout, or error.

Lifecycle safety is a first-class concern: the listener binds only to loopback on
an ephemeral port, lives only for one authorization, and is always torn down in a
``finally`` block (and on process exit via ``atexit``). Tokens and the client
secret are never logged.

This is the read-only Gmail scope only; the connector never requests write
access. Gmail OAuth is a separate boundary from AEGIS+ authentication.
"""

from __future__ import annotations

import atexit
import secrets
import threading
import urllib.parse
import webbrowser
from collections.abc import Callable
from contextlib import suppress
from datetime import UTC, datetime, timedelta
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any

import httpx

from core.domain.gmail import GmailCredentials
from core.interfaces.gmail import GmailAuthError, IGmailAuthFlow

BrowserOpener = Callable[[str], bool]

_SUCCESS_HTML = (
    b"<html><body style='font-family:sans-serif;background:#0B0E14;color:#E7EBF3;"
    b"text-align:center;padding-top:80px'><h2>AEGIS+ is now connected to Gmail.</h2>"
    b"<p>You can close this tab and return to AEGIS+.</p></body></html>"
)
_FAILURE_HTML = (
    b"<html><body style='font-family:sans-serif;background:#0B0E14;color:#E7EBF3;"
    b"text-align:center;padding-top:80px'><h2>Authorization was not completed.</h2>"
    b"<p>You can close this tab and return to AEGIS+.</p></body></html>"
)


class _CallbackResult:
    """Shared, thread-safe holder for the loopback callback outcome."""

    def __init__(self) -> None:
        self.code: str = ""
        self.error: str = ""
        self.state: str = ""
        self.received = threading.Event()


def _make_handler(result: _CallbackResult) -> type[BaseHTTPRequestHandler]:
    class _Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802 - required name
            parsed = urllib.parse.urlparse(self.path)
            params = urllib.parse.parse_qs(parsed.query)
            result.state = params.get("state", [""])[0]
            error = params.get("error", [""])[0]
            code = params.get("code", [""])[0]
            ok = bool(code) and not error
            result.code = code
            result.error = error
            body = _SUCCESS_HTML if ok else _FAILURE_HTML
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            result.received.set()

        def log_message(self, *_args: object) -> None:
            # Never write request lines (which contain the auth code) to stderr.
            return

    return _Handler


class LoopbackGmailAuthFlow(IGmailAuthFlow):
    """Installed-app loopback OAuth 2.0 flow for the read-only Gmail scope."""

    def __init__(
        self,
        *,
        client_id: str,
        client_secret: str,
        auth_uri: str,
        token_uri: str,
        scope: str,
        loopback_host: str = "127.0.0.1",
        timeout_seconds: float = 180.0,
        request_timeout_seconds: float = 30.0,
        browser_opener: BrowserOpener | None = None,
    ) -> None:
        """Initialize the flow.

        Args:
            client_id: OAuth client id (not secret).
            client_secret: OAuth client secret (secret; never logged).
            auth_uri: Google authorization endpoint.
            token_uri: Google token endpoint.
            scope: The read-only Gmail scope.
            loopback_host: Loopback bind host (``127.0.0.1``).
            timeout_seconds: How long to wait for the user to complete consent.
            request_timeout_seconds: Per-HTTP-request timeout for token calls.
            browser_opener: Injectable browser opener (defaults to
                :func:`webbrowser.open`); tests supply a fake.
        """
        self._client_id = client_id
        self._client_secret = client_secret
        self._auth_uri = auth_uri
        self._token_uri = token_uri
        self._scope = scope
        self._host = loopback_host
        self._timeout = timeout_seconds
        self._request_timeout = request_timeout_seconds
        self._open_browser: BrowserOpener = browser_opener or webbrowser.open

    def authorize(self) -> GmailCredentials:
        """Run the loopback flow and return fresh credentials."""
        if not self._client_id or not self._client_secret:
            raise GmailAuthError(
                "Gmail OAuth client is not configured. Set the client id and the "
                "client-secret environment variable."
            )
        result = _CallbackResult()
        state = secrets.token_urlsafe(24)
        server = HTTPServer((self._host, 0), _make_handler(result))
        # Ensure the listener is torn down even if the process exits abnormally.
        atexit.register(server.server_close)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        try:
            port = server.server_address[1]
            redirect_uri = f"http://{self._host}:{port}/"
            thread.start()
            self._open_browser(self._build_auth_url(redirect_uri, state))
            if not result.received.wait(timeout=self._timeout):
                raise GmailAuthError("Timed out waiting for Gmail authorization.")
            if result.error:
                raise GmailAuthError("Gmail authorization was denied.")
            if not secrets.compare_digest(result.state, state):
                raise GmailAuthError("Authorization state mismatch; aborting.")
            return self._exchange_code(result.code, redirect_uri)
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5.0)
            _safe_unregister(server.server_close)

    def refresh(self, credentials: GmailCredentials) -> GmailCredentials:
        """Return refreshed credentials using the stored refresh token."""
        if not credentials.refresh_token:
            raise GmailAuthError("No refresh token available; reconnect Gmail.")
        payload = {
            "client_id": self._client_id,
            "client_secret": self._client_secret,
            "refresh_token": credentials.refresh_token,
            "grant_type": "refresh_token",
        }
        data = self._token_request(payload)
        # A refresh response usually omits the refresh token; keep the old one.
        return self._credentials_from_token_response(
            data, fallback_refresh=credentials.refresh_token
        )

    # --- internals -------------------------------------------------------

    def _build_auth_url(self, redirect_uri: str, state: str) -> str:
        query = urllib.parse.urlencode(
            {
                "client_id": self._client_id,
                "redirect_uri": redirect_uri,
                "response_type": "code",
                "scope": self._scope,
                "state": state,
                "access_type": "offline",
                "prompt": "consent",
            }
        )
        return f"{self._auth_uri}?{query}"

    def _exchange_code(self, code: str, redirect_uri: str) -> GmailCredentials:
        payload = {
            "client_id": self._client_id,
            "client_secret": self._client_secret,
            "code": code,
            "grant_type": "authorization_code",
            "redirect_uri": redirect_uri,
        }
        data = self._token_request(payload)
        return self._credentials_from_token_response(data, fallback_refresh="")

    def _token_request(self, payload: dict[str, str]) -> dict[str, Any]:
        try:
            response = httpx.post(self._token_uri, data=payload, timeout=self._request_timeout)
        except httpx.HTTPError as exc:
            raise GmailAuthError("Could not reach the Google token endpoint.") from exc
        if response.status_code != httpx.codes.OK:
            # Do not include the response body — it may echo request parameters.
            raise GmailAuthError(f"Token endpoint returned HTTP {response.status_code}.")
        body = response.json()
        if not isinstance(body, dict):
            raise GmailAuthError("Unexpected token endpoint response.")
        return body

    def _credentials_from_token_response(
        self, data: dict[str, Any], *, fallback_refresh: str
    ) -> GmailCredentials:
        access_token = str(data.get("access_token", ""))
        if not access_token:
            raise GmailAuthError("Token response did not include an access token.")
        expires_in = int(data.get("expires_in", 0) or 0)
        expires_at = datetime.now(UTC) + timedelta(seconds=expires_in)
        return GmailCredentials(
            access_token=access_token,
            refresh_token=str(data.get("refresh_token", "") or fallback_refresh),
            token_type=str(data.get("token_type", "Bearer")),
            scope=str(data.get("scope", self._scope)),
            expires_at=expires_at,
        )


def _safe_unregister(func: Callable[[], object]) -> None:
    with suppress(Exception):
        atexit.unregister(func)
