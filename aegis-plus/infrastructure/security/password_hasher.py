"""Scrypt password hasher (M13).

A concrete :class:`~core.interfaces.password_hasher.IPasswordHasher` backed by the
standard library's memory-hard ``hashlib.scrypt``. No third-party dependency is
introduced: scrypt is a professionally accepted password-hashing function and is
part of the frozen Python stdlib (ADR-0003).

The stored hash is a single opaque, self-describing string:

    scrypt$<n>$<r>$<p>$<salt_b64>$<hash_b64>

so verification needs only the stored value and the candidate password. A fresh
16-byte random salt is generated per password. Verification is constant-time and
never raises for a malformed stored hash — it returns ``False``.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets

from core.interfaces.password_hasher import IPasswordHasher

# Cost parameters. n must be a power of two; these give strong protection while
# keeping login latency acceptable for a local desktop application.
_N = 2**14
_R = 8
_P = 1
_SALT_BYTES = 16
_DKLEN = 32
# scrypt requires maxmem large enough for the chosen parameters.
_MAXMEM = 128 * _N * _R * _P + (1 << 20)


class ScryptPasswordHasher(IPasswordHasher):
    """Hashes and verifies passwords using stdlib scrypt."""

    def hash(self, password: str) -> str:
        """Return a self-describing scrypt hash string for ``password``."""
        salt = secrets.token_bytes(_SALT_BYTES)
        derived = self._derive(password, salt, _N, _R, _P)
        return "$".join(
            (
                "scrypt",
                str(_N),
                str(_R),
                str(_P),
                _b64(salt),
                _b64(derived),
            )
        )

    def verify(self, password: str, password_hash: str) -> bool:
        """Return whether ``password`` matches ``password_hash`` (constant-time)."""
        try:
            scheme, n_s, r_s, p_s, salt_b64, hash_b64 = password_hash.split("$")
            if scheme != "scrypt":
                return False
            n, r, p = int(n_s), int(r_s), int(p_s)
            salt = _unb64(salt_b64)
            expected = _unb64(hash_b64)
        except (ValueError, TypeError):
            return False
        try:
            candidate = self._derive(password, salt, n, r, p, dklen=len(expected))
        except (ValueError, MemoryError):
            return False
        return hmac.compare_digest(candidate, expected)

    @staticmethod
    def _derive(
        password: str, salt: bytes, n: int, r: int, p: int, *, dklen: int = _DKLEN
    ) -> bytes:
        return hashlib.scrypt(
            password.encode("utf-8"),
            salt=salt,
            n=n,
            r=r,
            p=p,
            dklen=dklen,
            maxmem=_MAXMEM,
        )


def _b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def _unb64(encoded: str) -> bytes:
    return base64.b64decode(encoded.encode("ascii"))
