"""Structural tests guarding the AEGIS+ architectural package tree.

These tests fail loudly if a top-level architectural package is removed or
renamed, protecting the Clean Architecture layout defined in
``Folder_Structure.md`` from accidental drift.
"""

import importlib

import pytest

# Top-level architectural packages that must always exist and be importable.
ARCHITECTURAL_PACKAGES = [
    "application",
    "core",
    "ai",
    "data",
    "services",
    "infrastructure",
    "ui",
]


@pytest.mark.unit
@pytest.mark.parametrize("package_name", ARCHITECTURAL_PACKAGES)
def test_architectural_package_is_importable(package_name: str) -> None:
    """Each architectural layer is importable as a Python package."""
    module = importlib.import_module(package_name)
    assert module.__doc__, f"Package '{package_name}' must declare a module docstring."
