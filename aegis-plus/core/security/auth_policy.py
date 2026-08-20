"""Authentication validation policy (M13).

Framework-free rules for validating and normalizing registration and login
input. Centralizing them here keeps the same rules enforceable at the API
boundary and reusable for UI-side pre-validation hints, without duplicating
logic. Password *hashing* is separate (the hasher port); this module only decides
whether input is well-formed.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

_USERNAME_RE = re.compile(r"^[A-Za-z0-9._-]{3,32}$")
# A pragmatic, non-exhaustive email shape check (full RFC 5322 is intentionally
# out of scope). Rejects whitespace and obvious malformations.
_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")

MIN_PASSWORD_LENGTH = 10
MAX_PASSWORD_LENGTH = 128
MAX_NAME_LENGTH = 120
_MIN_CHAR_CLASSES = 3


@dataclass(frozen=True, slots=True)
class RegistrationInput:
    """Normalized registration fields."""

    full_name: str
    username: str
    email: str
    password: str


@dataclass(frozen=True, slots=True)
class ValidationOutcome:
    """The result of validating registration input.

    ``errors`` maps a field name to a human-readable message. The input is valid
    when ``errors`` is empty.
    """

    errors: dict[str, str] = field(default_factory=dict)

    @property
    def ok(self) -> bool:
        """Whether the input passed validation."""
        return not self.errors


def normalize_identifier(identifier: str) -> str:
    """Normalize a login identifier (trim; case-fold for comparison)."""
    return identifier.strip().casefold()


def normalize_registration(
    *, full_name: str, username: str, email: str, password: str
) -> RegistrationInput:
    """Trim and normalize registration fields (password is left verbatim)."""
    return RegistrationInput(
        full_name=full_name.strip(),
        username=username.strip(),
        email=email.strip(),
        password=password,
    )


def password_strength_issue(password: str) -> str | None:
    """Return a message describing why a password is weak, or ``None`` if fine.

    Requires a reasonable length and a mix of character classes. Whitespace-only
    or overly long passwords are rejected.
    """
    if len(password) < MIN_PASSWORD_LENGTH:
        return f"Password must be at least {MIN_PASSWORD_LENGTH} characters."
    if len(password) > MAX_PASSWORD_LENGTH:
        return f"Password must be at most {MAX_PASSWORD_LENGTH} characters."
    classes = (
        any(c.islower() for c in password),
        any(c.isupper() for c in password),
        any(c.isdigit() for c in password),
        any(not c.isalnum() for c in password),
    )
    if sum(classes) < _MIN_CHAR_CLASSES:
        return "Use a mix of uppercase, lowercase, digits, and symbols."
    return None


def validate_registration(data: RegistrationInput, *, confirm_password: str) -> ValidationOutcome:
    """Validate normalized registration input plus the confirmation field."""
    errors: dict[str, str] = {}

    if not data.full_name:
        errors["full_name"] = "Full name is required."
    elif len(data.full_name) > MAX_NAME_LENGTH:
        errors["full_name"] = f"Full name must be at most {MAX_NAME_LENGTH} characters."

    if not data.username:
        errors["username"] = "Username is required."
    elif not _USERNAME_RE.match(data.username):
        errors["username"] = (
            "Username must be 3-32 characters using letters, digits, dot, " "underscore, or hyphen."
        )

    if not data.email:
        errors["email"] = "Email is required."
    elif not _EMAIL_RE.match(data.email):
        errors["email"] = "Enter a valid email address."

    if not data.password:
        errors["password"] = "Password is required."
    else:
        issue = password_strength_issue(data.password)
        if issue is not None:
            errors["password"] = issue

    if data.password != confirm_password:
        errors["confirm_password"] = "Passwords do not match."

    return ValidationOutcome(errors=errors)
