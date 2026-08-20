"""Tests for the Url value object."""

from __future__ import annotations

import pytest

from core.domain import Url
from core.exceptions import ValidationError

pytestmark = pytest.mark.unit


def test_parses_https_url() -> None:
    url = Url.create("https://www.example.com/path?q=1#frag")
    assert url.scheme == "https"
    assert url.host == "www.example.com"
    assert url.path == "/path"
    assert url.query == "q=1"
    assert url.fragment == "frag"
    assert url.uses_https is True


def test_bare_host_defaults_to_http() -> None:
    url = Url.create("example.com/login")
    assert url.scheme == "http"
    assert url.host == "example.com"
    assert url.uses_https is False


def test_detects_ip_host() -> None:
    assert Url.create("http://192.168.0.1/login").is_ip_host is True
    assert Url.create("https://example.com").is_ip_host is False


@pytest.mark.parametrize("value", ["", "   ", "ftp://example.com", "http://", "x" * 3000])
def test_invalid_urls_raise(value: str) -> None:
    with pytest.raises(ValidationError):
        Url.create(value)
