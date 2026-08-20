"""Unit tests for Core entities and value objects."""

from __future__ import annotations

import uuid

import pytest

from core.domain import EntityId
from core.entities import AggregateRoot, BaseEntity
from core.exceptions import ValidationError

pytestmark = pytest.mark.unit


class _Product(BaseEntity):
    """Concrete entity used for testing identity semantics."""


class _Order(AggregateRoot):
    """Concrete aggregate root used for testing."""


def test_entity_id_generate_is_unique() -> None:
    a = EntityId.generate()
    b = EntityId.generate()
    assert a != b
    assert isinstance(a.value, uuid.UUID)


def test_entity_id_round_trips_through_string() -> None:
    original = EntityId.generate()
    assert EntityId.from_string(str(original)) == original


def test_entity_id_from_invalid_string_raises() -> None:
    with pytest.raises(ValidationError):
        EntityId.from_string("not-a-uuid")


def test_entity_id_is_immutable() -> None:
    entity_id = EntityId.generate()
    with pytest.raises(AttributeError):
        entity_id.value = uuid.uuid4()  # type: ignore[misc]


def test_entity_assigns_id_and_timestamps() -> None:
    entity = _Product()
    assert isinstance(entity.id, EntityId)
    assert entity.created_at is not None
    assert entity.updated_at is not None


def test_entity_equality_is_by_identity_and_type() -> None:
    shared = EntityId.generate()
    assert _Product(entity_id=shared) == _Product(entity_id=shared)
    assert _Product(entity_id=shared) != _Product()
    # Same id, different concrete type -> not equal.
    assert _Product(entity_id=shared) != _Order(entity_id=shared)


def test_entity_is_hashable_by_identity() -> None:
    shared = EntityId.generate()
    assert hash(_Product(entity_id=shared)) == hash(_Product(entity_id=shared))
    assert len({_Product(entity_id=shared), _Product(entity_id=shared)}) == 1


def test_touch_advances_updated_at() -> None:
    entity = _Product()
    before = entity.updated_at
    entity.touch()
    assert entity.updated_at >= before


def test_aggregate_root_is_an_entity() -> None:
    assert isinstance(_Order(), BaseEntity)
