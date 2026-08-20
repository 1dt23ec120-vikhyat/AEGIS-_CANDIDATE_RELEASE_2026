"""Value objects.

Value objects are immutable and compared by value. :class:`EntityId` is the
shared identity value object used by all entities. Everything here is pure
Python, keeping the domain framework-independent.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass

from core.exceptions import ValidationError


@dataclass(frozen=True, slots=True)
class ValueObject:
    """Base class for value objects: immutable and compared by value."""


@dataclass(frozen=True, slots=True)
class EntityId(ValueObject):
    """A unique identifier backed by a UUID."""

    value: uuid.UUID

    @classmethod
    def generate(cls) -> EntityId:
        """Create a new, random identifier."""
        return cls(uuid.uuid4())

    @classmethod
    def from_string(cls, raw: str) -> EntityId:
        """Parse an identifier from its string form.

        Args:
            raw: The UUID string.

        Returns:
            The parsed :class:`EntityId`.

        Raises:
            ValidationError: If ``raw`` is not a valid UUID.
        """
        try:
            return cls(uuid.UUID(raw))
        except (ValueError, AttributeError, TypeError) as exc:
            raise ValidationError(f"Invalid entity id: {raw!r}") from exc

    def __str__(self) -> str:
        """Return the canonical string form of the identifier."""
        return str(self.value)
