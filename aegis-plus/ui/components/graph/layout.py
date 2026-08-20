"""Force-directed graph layout (pure, deterministic).

A compact Fruchterman-Reingold spring layout used by the graph canvas. It is
deterministic (seeded initial placement, fixed iteration count) so the same graph
always lays out the same way, and framework-free so it can be unit-tested without
Qt. Positions are returned in an abstract coordinate box; the canvas maps them to
scene coordinates.
"""

from __future__ import annotations

import math
from collections.abc import Sequence
from random import Random

_DEFAULT_ITERATIONS = 60
_DEFAULT_SEED = 42
_MIN_DISTANCE = 0.01


def spring_layout(
    node_ids: Sequence[str],
    edges: Sequence[tuple[str, str]],
    *,
    width: float = 1000.0,
    height: float = 700.0,
    iterations: int = _DEFAULT_ITERATIONS,
    seed: int = _DEFAULT_SEED,
) -> dict[str, tuple[float, float]]:
    """Compute 2-D positions for nodes using a spring model.

    Args:
        node_ids: The nodes to place.
        edges: Undirected connections as ``(source_id, target_id)`` pairs.
        width: Layout box width.
        height: Layout box height.
        iterations: Number of relaxation passes.
        seed: RNG seed for deterministic initial placement.

    Returns:
        A mapping of node id to ``(x, y)`` within the box.
    """
    ids = list(dict.fromkeys(node_ids))
    if not ids:
        return {}
    if len(ids) == 1:
        return {ids[0]: (width / 2, height / 2)}

    rng = Random(seed)
    area = width * height
    k = math.sqrt(area / len(ids))  # ideal edge length
    positions: dict[str, list[float]] = {}
    for nid in ids:
        positions[nid] = [rng.uniform(0.0, width), rng.uniform(0.0, height)]

    adjacency = [(s, t) for s, t in edges if s in positions and t in positions]
    temperature = width / 10.0
    cooling = temperature / (iterations + 1)

    for _ in range(iterations):
        displacement: dict[str, list[float]] = {nid: [0.0, 0.0] for nid in ids}
        _apply_repulsion(ids, positions, displacement, k)
        _apply_attraction(adjacency, positions, displacement, k)
        _apply_displacement(ids, positions, displacement, temperature, width, height)
        temperature = max(temperature - cooling, 0.0)

    return {nid: (pos[0], pos[1]) for nid, pos in positions.items()}


def _apply_repulsion(
    ids: list[str],
    positions: dict[str, list[float]],
    displacement: dict[str, list[float]],
    k: float,
) -> None:
    for i, a in enumerate(ids):
        for b in ids[i + 1 :]:
            dx = positions[a][0] - positions[b][0]
            dy = positions[a][1] - positions[b][1]
            dist = max(math.hypot(dx, dy), _MIN_DISTANCE)
            force = (k * k) / dist
            ux, uy = dx / dist, dy / dist
            displacement[a][0] += ux * force
            displacement[a][1] += uy * force
            displacement[b][0] -= ux * force
            displacement[b][1] -= uy * force


def _apply_attraction(
    adjacency: list[tuple[str, str]],
    positions: dict[str, list[float]],
    displacement: dict[str, list[float]],
    k: float,
) -> None:
    for s, t in adjacency:
        dx = positions[s][0] - positions[t][0]
        dy = positions[s][1] - positions[t][1]
        dist = max(math.hypot(dx, dy), _MIN_DISTANCE)
        force = (dist * dist) / k
        ux, uy = dx / dist, dy / dist
        displacement[s][0] -= ux * force
        displacement[s][1] -= uy * force
        displacement[t][0] += ux * force
        displacement[t][1] += uy * force


def _apply_displacement(
    ids: list[str],
    positions: dict[str, list[float]],
    displacement: dict[str, list[float]],
    temperature: float,
    width: float,
    height: float,
) -> None:
    for nid in ids:
        dx, dy = displacement[nid]
        dist = max(math.hypot(dx, dy), _MIN_DISTANCE)
        step = min(dist, temperature)
        positions[nid][0] = _clamp(positions[nid][0] + (dx / dist) * step, 0.0, width)
        positions[nid][1] = _clamp(positions[nid][1] + (dy / dist) * step, 0.0, height)


def _clamp(value: float, low: float, high: float) -> float:
    return max(low, min(high, value))
