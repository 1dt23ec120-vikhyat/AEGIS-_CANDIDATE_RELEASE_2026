"""Unit tests for the centralized Core exception hierarchy."""

from __future__ import annotations

import pytest

from core.exceptions import (
    AegisError,
    ConfigurationError,
    ConfigurationFileError,
    ConfigurationValidationError,
    DomainError,
    InfrastructureError,
    NotFoundError,
    ValidationError,
)

pytestmark = pytest.mark.unit


def test_all_errors_derive_from_root() -> None:
    for error_type in (
        DomainError,
        ValidationError,
        NotFoundError,
        InfrastructureError,
        ConfigurationError,
    ):
        assert issubclass(error_type, AegisError)


def test_domain_error_specialization() -> None:
    assert issubclass(ValidationError, DomainError)
    assert issubclass(NotFoundError, DomainError)


def test_configuration_errors_specialize_infrastructure() -> None:
    assert issubclass(ConfigurationError, InfrastructureError)
    assert issubclass(ConfigurationFileError, ConfigurationError)
    assert issubclass(ConfigurationValidationError, ConfigurationError)


def test_error_carries_message_and_context() -> None:
    error = ValidationError("bad value", context={"field": "url"})
    assert error.message == "bad value"
    assert error.context == {"field": "url"}
    assert str(error) == "bad value"


def test_error_is_catchable_as_root() -> None:
    with pytest.raises(AegisError):
        raise NotFoundError("missing")
