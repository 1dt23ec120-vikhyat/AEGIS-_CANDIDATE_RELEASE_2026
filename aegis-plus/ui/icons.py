"""Icon system.

Crisp, theme-tinted line icons drawn with :class:`~PySide6.QtGui.QPainter` on a
24x24 canvas - no binary assets. Icons are rendered to a pixmap at the requested
size and colour, so they scale cleanly and recolour with the theme.
"""

from __future__ import annotations

from collections.abc import Callable

from PySide6.QtCore import QPointF, QRectF, Qt
from PySide6.QtGui import QColor, QIcon, QPainter, QPainterPath, QPen, QPixmap

_VIEWBOX = 24.0


def _dot(painter: QPainter, x: float, y: float, r: float, color: str) -> None:
    painter.save()
    painter.setBrush(QColor(color))
    painter.setPen(Qt.PenStyle.NoPen)
    painter.drawEllipse(QPointF(x, y), r, r)
    painter.restore()


def _shield(p: QPainter, color: str) -> None:
    path = QPainterPath()
    path.moveTo(12, 2)
    path.lineTo(20, 5)
    path.lineTo(20, 11)
    path.cubicTo(20, 16.5, 16.2, 20.2, 12, 22)
    path.cubicTo(7.8, 20.2, 4, 16.5, 4, 11)
    path.lineTo(4, 5)
    path.closeSubpath()
    p.drawPath(path)


def _dashboard(p: QPainter, color: str) -> None:
    p.drawRoundedRect(QRectF(3, 3, 7.5, 7.5), 1.5, 1.5)
    p.drawRoundedRect(QRectF(13.5, 3, 7.5, 5), 1.5, 1.5)
    p.drawRoundedRect(QRectF(13.5, 11, 7.5, 10), 1.5, 1.5)
    p.drawRoundedRect(QRectF(3, 13.5, 7.5, 7.5), 1.5, 1.5)


def _globe(p: QPainter, color: str) -> None:
    p.drawEllipse(QRectF(3, 3, 18, 18))
    p.drawEllipse(QRectF(8, 3, 8, 18))
    p.drawLine(QPointF(3, 12), QPointF(21, 12))


def _mail(p: QPainter, color: str) -> None:
    p.drawRoundedRect(QRectF(3, 5, 18, 14), 2, 2)
    path = QPainterPath()
    path.moveTo(4, 6.5)
    path.lineTo(12, 12.5)
    path.lineTo(20, 6.5)
    p.drawPath(path)


def _file(p: QPainter, color: str) -> None:
    path = QPainterPath()
    path.moveTo(6, 3)
    path.lineTo(14, 3)
    path.lineTo(19, 8)
    path.lineTo(19, 21)
    path.lineTo(6, 21)
    path.closeSubpath()
    p.drawPath(path)
    path2 = QPainterPath()
    path2.moveTo(14, 3)
    path2.lineTo(14, 8)
    path2.lineTo(19, 8)
    p.drawPath(path2)


def _alert(p: QPainter, color: str) -> None:
    path = QPainterPath()
    path.moveTo(12, 3.5)
    path.lineTo(21, 20)
    path.lineTo(3, 20)
    path.closeSubpath()
    p.drawPath(path)
    p.drawLine(QPointF(12, 10), QPointF(12, 15))
    _dot(p, 12, 17.5, 1.0, color)


def _report(p: QPainter, color: str) -> None:
    p.drawLine(QPointF(5, 3), QPointF(5, 21))
    p.drawLine(QPointF(5, 21), QPointF(21, 21))
    p.drawLine(QPointF(9, 21), QPointF(9, 14))
    p.drawLine(QPointF(13.5, 21), QPointF(13.5, 9))
    p.drawLine(QPointF(18, 21), QPointF(18, 12))


def _chip(p: QPainter, color: str) -> None:
    p.drawRoundedRect(QRectF(6, 6, 12, 12), 2, 2)
    p.drawRoundedRect(QRectF(9.5, 9.5, 5, 5), 1, 1)
    for x in (9.5, 14.5):
        p.drawLine(QPointF(x, 3), QPointF(x, 6))
        p.drawLine(QPointF(x, 18), QPointF(x, 21))
    for y in (9.5, 14.5):
        p.drawLine(QPointF(3, y), QPointF(6, y))
        p.drawLine(QPointF(18, y), QPointF(21, y))


def _settings(p: QPainter, color: str) -> None:
    for y in (6, 12, 18):
        p.drawLine(QPointF(3, y), QPointF(21, y))
    _dot(p, 8, 6, 2.4, color)
    _dot(p, 16, 12, 2.4, color)
    _dot(p, 10, 18, 2.4, color)


def _copilot(p: QPainter, color: str) -> None:
    # A speech bubble (conversation) with an inner spark (AI assistance).
    path = QPainterPath()
    path.moveTo(4, 6)
    path.lineTo(20, 6)
    path.cubicTo(21, 6, 21, 7, 21, 8)
    path.lineTo(21, 15)
    path.cubicTo(21, 16, 21, 17, 20, 17)
    path.lineTo(10, 17)
    path.lineTo(6, 21)
    path.lineTo(6, 17)
    path.lineTo(4, 17)
    path.cubicTo(3, 17, 3, 16, 3, 15)
    path.lineTo(3, 8)
    path.cubicTo(3, 7, 3, 6, 4, 6)
    p.drawPath(path)
    # spark
    p.drawLine(QPointF(12, 8.5), QPointF(12, 14.5))
    p.drawLine(QPointF(9, 11.5), QPointF(15, 11.5))


def _search(p: QPainter, color: str) -> None:
    p.drawEllipse(QRectF(4, 4, 12, 12))
    p.drawLine(QPointF(15, 15), QPointF(20, 20))


def _sun(p: QPainter, color: str) -> None:
    p.drawEllipse(QRectF(8, 8, 8, 8))
    for x1, y1, x2, y2 in (
        (12, 2, 12, 4.5),
        (12, 19.5, 12, 22),
        (2, 12, 4.5, 12),
        (19.5, 12, 22, 12),
        (5, 5, 6.8, 6.8),
        (17.2, 17.2, 19, 19),
        (17.2, 6.8, 19, 5),
        (5, 19, 6.8, 17.2),
    ):
        p.drawLine(QPointF(x1, y1), QPointF(x2, y2))


def _moon(p: QPainter, color: str) -> None:
    path = QPainterPath()
    path.moveTo(20, 14.5)
    path.cubicTo(18.5, 15.3, 16.8, 15.6, 15, 15.2)
    path.cubicTo(10.6, 14.2, 8.4, 9.4, 10.2, 5.2)
    path.cubicTo(6.2, 6.2, 3.6, 10.2, 4.4, 14.4)
    path.cubicTo(5.3, 19, 9.8, 22, 14.4, 21)
    path.cubicTo(17, 20.4, 19, 18.7, 20, 14.5)
    p.drawPath(path)


def _bell(p: QPainter, color: str) -> None:
    path = QPainterPath()
    path.moveTo(6, 17)
    path.lineTo(18, 17)
    path.cubicTo(16.5, 15.5, 16.5, 14, 16.5, 11)
    path.cubicTo(16.5, 7.5, 14.5, 5.5, 12, 5.5)
    path.cubicTo(9.5, 5.5, 7.5, 7.5, 7.5, 11)
    path.cubicTo(7.5, 14, 7.5, 15.5, 6, 17)
    p.drawPath(path)
    path2 = QPainterPath()
    path2.moveTo(10.5, 20)
    path2.cubicTo(11, 21, 13, 21, 13.5, 20)
    p.drawPath(path2)


def _lock(p: QPainter, color: str) -> None:
    p.drawRoundedRect(QRectF(4.5, 10.5, 15, 10), 2, 2)
    arc = QPainterPath()
    arc.moveTo(7.5, 10.5)
    arc.lineTo(7.5, 7.5)
    arc.cubicTo(7.5, 3, 16.5, 3, 16.5, 7.5)
    arc.lineTo(16.5, 10.5)
    p.drawPath(arc)
    _dot(p, 12, 15, 1.4, color)


def _user(p: QPainter, color: str) -> None:
    p.drawEllipse(QPointF(12, 8.5), 3.6, 3.6)
    arc = QPainterPath()
    arc.moveTo(5, 20)
    arc.cubicTo(5, 14.5, 19, 14.5, 19, 20)
    p.drawPath(arc)


def _eye(p: QPainter, color: str) -> None:
    path = QPainterPath()
    path.moveTo(2.5, 12)
    path.cubicTo(6, 6.5, 18, 6.5, 21.5, 12)
    path.cubicTo(18, 17.5, 6, 17.5, 2.5, 12)
    p.drawPath(path)
    p.drawEllipse(QPointF(12, 12), 3, 3)


def _eye_off(p: QPainter, color: str) -> None:
    path = QPainterPath()
    path.moveTo(2.5, 12)
    path.cubicTo(6, 6.5, 18, 6.5, 21.5, 12)
    path.cubicTo(18, 17.5, 6, 17.5, 2.5, 12)
    p.drawPath(path)
    p.drawEllipse(QPointF(12, 12), 3, 3)
    p.drawLine(QPointF(4, 4), QPointF(20, 20))


def _log_out(p: QPainter, color: str) -> None:
    door = QPainterPath()
    door.moveTo(13, 4)
    door.lineTo(6, 4)
    door.lineTo(6, 20)
    door.lineTo(13, 20)
    p.drawPath(door)
    p.drawLine(QPointF(11, 12), QPointF(20, 12))
    arrow = QPainterPath()
    arrow.moveTo(16.5, 8.5)
    arrow.lineTo(20, 12)
    arrow.lineTo(16.5, 15.5)
    p.drawPath(arrow)


_DRAWERS: dict[str, Callable[[QPainter, str], None]] = {
    "shield": _shield,
    "dashboard": _dashboard,
    "globe": _globe,
    "mail": _mail,
    "file": _file,
    "alert": _alert,
    "report": _report,
    "chip": _chip,
    "settings": _settings,
    "copilot": _copilot,
    "search": _search,
    "sun": _sun,
    "moon": _moon,
    "bell": _bell,
    "lock": _lock,
    "user": _user,
    "eye": _eye,
    "eye-off": _eye_off,
    "log-out": _log_out,
}


def render_icon(
    name: str, *, size: int = 20, color: str = "#FFFFFF", width: float = 1.8
) -> QPixmap:
    """Render a named icon to a pixmap.

    Args:
        name: Icon name (see the registry).
        size: Pixel size of the square pixmap.
        color: Stroke/fill colour (hex).
        width: Stroke width in the 24-unit coordinate space.

    Returns:
        A transparent-background pixmap containing the icon.
    """
    pixmap = QPixmap(size, size)
    pixmap.fill(Qt.GlobalColor.transparent)
    painter = QPainter(pixmap)
    painter.setRenderHint(QPainter.RenderHint.Antialiasing, True)
    painter.scale(size / _VIEWBOX, size / _VIEWBOX)
    pen = QPen(QColor(color))
    pen.setWidthF(width)
    pen.setCapStyle(Qt.PenCapStyle.RoundCap)
    pen.setJoinStyle(Qt.PenJoinStyle.RoundJoin)
    painter.setPen(pen)
    painter.setBrush(Qt.BrushStyle.NoBrush)
    drawer = _DRAWERS.get(name, _dashboard)
    drawer(painter, color)
    painter.end()
    return pixmap


def icon(name: str, *, size: int = 20, color: str = "#FFFFFF") -> QIcon:
    """Return a named icon as a :class:`~PySide6.QtGui.QIcon`."""
    return QIcon(render_icon(name, size=size, color=color))


def available_icons() -> list[str]:
    """Return the list of registered icon names."""
    return sorted(_DRAWERS)
