"""Gmail read-only connector adapters (M14).

Concrete infrastructure for the Gmail input connector: the OAuth loopback flow,
the token store, and the REST gateway — all over ``httpx`` and the standard
library, with no Google SDK dependency.
"""

from infrastructure.integrations.gmail.gateway import HttpxGmailGateway
from infrastructure.integrations.gmail.oauth_flow import LoopbackGmailAuthFlow
from infrastructure.integrations.gmail.token_store import FileGmailTokenStore

__all__ = [
    "FileGmailTokenStore",
    "HttpxGmailGateway",
    "LoopbackGmailAuthFlow",
]
