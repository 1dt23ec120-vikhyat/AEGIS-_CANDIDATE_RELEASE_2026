"""Password hasher port (M13).

Abstracts password hashing and verification so the domain and application layers
never depend on a concrete algorithm. The hash string is opaque and
self-describing (it embeds the algorithm parameters and salt), so verification
needs only the stored hash and the candidate password. The concrete
implementation lives in infrastructure.
"""

from __future__ import annotations

from abc import ABC, abstractmethod


class IPasswordHasher(ABC):
    """Contract for hashing and verifying passwords."""

    @abstractmethod
    def hash(self, password: str) -> str:
        """Return an opaque, self-describing hash for ``password``."""

    @abstractmethod
    def verify(self, password: str, password_hash: str) -> bool:
        """Return whether ``password`` matches ``password_hash``.

        Implementations must use a constant-time comparison and must never raise
        for a malformed stored hash — they return ``False`` instead.
        """
