"""Provider Registry.

A runtime registry of all evidence providers with their metadata. This is the
single place platform diagnostics queries to learn which providers are active,
their versions, supported artifact types, and configuration — supporting future
VirusTotal, YARA, Sandbox, Sigma, and Cloud Intelligence providers without
contract change.

The registry is additive: providers register themselves and the registry is
read-only from there. It does not manage provider lifecycle.
"""

from __future__ import annotations

from core.domain.fusion import ProviderInfo


class ProviderRegistry:
    """Runtime registry of all evidence providers."""

    def __init__(self) -> None:
        """Initialize an empty registry."""
        self._providers: dict[str, ProviderInfo] = {}

    def register(self, info: ProviderInfo) -> None:
        """Register a provider.

        Args:
            info: The provider metadata.
        """
        self._providers[info.name] = info

    def get(self, name: str) -> ProviderInfo | None:
        """Return the provider info for ``name``, or ``None`` if absent."""
        return self._providers.get(name)

    def all(self) -> tuple[ProviderInfo, ...]:
        """Return all registered providers, in registration order."""
        return tuple(self._providers.values())

    @property
    def count(self) -> int:
        """The number of registered providers."""
        return len(self._providers)

    def enabled(self) -> tuple[ProviderInfo, ...]:
        """Return only the enabled providers."""
        return tuple(p for p in self._providers.values() if p.enabled)

    def summary(self) -> dict[str, str]:
        """Return a compact name → version+status mapping for SOC display."""
        return {
            info.name: f"{info.version} ({'enabled' if info.enabled else 'disabled'})"
            for info in self._providers.values()
        }
