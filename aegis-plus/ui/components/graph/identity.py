"""Node visual identities.

Distinct, clean identities (fill colour + short glyph + display label) for each
knowledge-graph node type, giving analysts an at-a-glance read of what each node
is. Uses a fixed categorical palette (independent of the light/dark theme) so
node types stay distinguishable on any background; the surrounding chrome still
follows the theme. Framework-free for testability.
"""

from __future__ import annotations

from dataclasses import dataclass

from ui.theme.tokens import Palette

_CATEGORICAL: dict[str, tuple[str, str, str]] = {
    # node_type: (fill hex, glyph, display label)
    "file": ("#6C7BFF", "F", "File"),
    "url": ("#4C8DFF", "U", "URL"),
    "domain": ("#22B8CF", "D", "Domain"),
    "email": ("#9B7BFF", "@", "Email"),
    "hash": ("#7A8699", "#", "Hash"),
    "ioc": ("#F5A524", "!", "IOC"),
    "threat": ("#F0506E", "T", "Threat"),
    "incident": ("#FF7A45", "IN", "Incident"),
    "campaign": ("#E64980", "CP", "Campaign"),
    "investigation": ("#2FBF71", "IV", "Investigation"),
    "provider": ("#868E96", "PR", "Provider"),
    "ip_address": ("#15AABF", "IP", "IP Address"),
    "artifact": ("#5C6BC0", "A", "Artifact"),
}
_FALLBACK = ("#5F6B82", "?", "Node")

# The ordered set of types that carry a distinct identity (for legends/filters).
NODE_TYPE_ORDER: tuple[str, ...] = (
    "file",
    "url",
    "domain",
    "email",
    "hash",
    "ioc",
    "threat",
    "incident",
    "campaign",
    "investigation",
    "provider",
    "ip_address",
)


@dataclass(frozen=True, slots=True)
class NodeIdentity:
    """The visual identity for a node type."""

    node_type: str
    fill: str
    glyph: str
    label: str
    border: str
    text: str


def node_identity(node_type: str, palette: Palette) -> NodeIdentity:
    """Return the visual identity for a node type.

    Args:
        node_type: The graph node type (e.g. ``"url"``).
        palette: The active theme palette (for border/text chrome).

    Returns:
        A :class:`NodeIdentity` with a fill colour, glyph, and label.
    """
    fill, glyph, label = _CATEGORICAL.get(node_type, _FALLBACK)
    return NodeIdentity(
        node_type=node_type,
        fill=fill,
        glyph=glyph,
        label=label,
        border=palette.border_strong,
        text="#FFFFFF",
    )


def type_label(node_type: str) -> str:
    """Return the human-readable label for a node type."""
    return _CATEGORICAL.get(node_type, _FALLBACK)[2]
