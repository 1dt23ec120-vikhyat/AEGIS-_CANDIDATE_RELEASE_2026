# Intelligence Graph Explorer — User Guide

**Audience:** SOC analysts · **Status:** Current (M9 Phase 3-C)

The Intelligence Graph Explorer (Operations → **Graph Explorer**) shows how
entities in your intelligence graph relate — artifacts, threats, incidents,
campaigns, IOCs, and more — so you can pivot, trace attack paths, and review
analytics.

## Getting there

- From the sidebar: **Operations → Graph Explorer**.
- From an investigation: in the **File Investigation** workspace, choose
  **Open in Graph Explorer** to jump straight to that artifact. Use **Back to
  investigation** to return.

> If the canvas is empty, search for an artifact or open the Explorer from an
> investigation to begin. The graph populates automatically as artifacts are
> analysed across the platform.

## The canvas

- **Pan:** drag an empty area of the canvas.
- **Zoom:** mouse wheel, or the toolbar **+ / −**, or keyboard **+ / −**.
- **Fit to view:** toolbar **Fit**, or keyboard **F** / **Home**.
- **Move a node:** drag it.
- **Focus/select a node:** click it — details appear in the **Node Details** panel.
- **Expand a node:** double-click it (or use **Expand** in Node Details) to pull
  in its neighbours; the graph grows in place.
- **Inspect a relationship:** click an edge — details appear in **Relationship
  Details**.
- **Hover** a node to highlight it, its neighbours, and their connections.
- **Keyboard:** arrow keys pan; **+ / −** zoom; **F** fits.

Each node type has a distinct colour and glyph (see the **Legend** below the
canvas): File, URL, Domain, Email, Hash, IOC, Threat, Incident, Campaign,
Investigation, Provider, IP.

## Panels

- **Search** — find nodes by identifier, label, or metadata. Results focus the
  graph and highlight matches; recent searches are kept for quick reuse.
- **Filters** — show/hide by node type and relationship type, and set a minimum
  confidence. Filtered-out elements are dimmed, not removed.
- **Timeline** — slide to a point in time to focus on relationships observed up to
  that moment; **Show all** clears the cutoff.
- **Node Details** — the selected node's type, connections, and metadata, with
  **Expand**, **Focus**, and **Open Investigation** actions.
- **Relationship Details** — the selected edge's endpoints, type, confidence,
  provenance, and observation time.
- **Analytics** — graph size, entity and relationship distribution, most-connected
  entities, component count, largest component, density, blast radius, and live
  **Observability** timings (query, layout, render, expansion, search, timeline).

## Pivoting to an investigation

From **Node Details**, **Open Investigation** takes you to the relevant workspace
(Incidents for incident/campaign nodes; File Investigation otherwise) so you can
continue the analysis there.

## Tips

- Use **Fit** after expanding several nodes to re-frame the whole graph.
- Combine **Filters** and **Timeline** to isolate how a campaign developed.
- The **Analytics → Most connected** list is a fast way to find pivot points.
