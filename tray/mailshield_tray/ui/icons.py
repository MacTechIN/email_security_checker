"""상태별 트레이 아이콘을 PIL로 그린다. 외부 이미지 파일에 의존하지 않는다."""

from __future__ import annotations

from PIL import Image, ImageDraw

STATE_WATCHING = "watching"
STATE_ALERT = "alert"
STATE_CONNECTING = "connecting"
STATE_PAUSED = "paused"
STATE_ERROR = "error"
STATE_UNCONFIGURED = "unconfigured"

_COLORS = {
    STATE_WATCHING: ("#1E8E3E", "#FFFFFF"),
    STATE_ALERT: ("#D93025", "#FFFFFF"),
    STATE_CONNECTING: ("#F29900", "#FFFFFF"),
    STATE_PAUSED: ("#80868B", "#FFFFFF"),
    STATE_ERROR: ("#B3261E", "#FFFFFF"),
    STATE_UNCONFIGURED: ("#5F6368", "#FFFFFF"),
}

_LABELS = {
    STATE_WATCHING: "감시 중",
    STATE_ALERT: "위험 메일 감지",
    STATE_CONNECTING: "연결 중",
    STATE_PAUSED: "일시 중지",
    STATE_ERROR: "인증 필요",
    STATE_UNCONFIGURED: "계정 미설정",
}


def state_label(state: str) -> str:
    return _LABELS.get(state, state)


def _shield(draw: ImageDraw.ImageDraw, size: int, fill: str) -> None:
    s = size
    points = [
        (s * 0.50, s * 0.04),
        (s * 0.92, s * 0.20),
        (s * 0.88, s * 0.58),
        (s * 0.50, s * 0.96),
        (s * 0.12, s * 0.58),
        (s * 0.08, s * 0.20),
    ]
    draw.polygon(points, fill=fill)


def render(state: str, size: int = 64) -> Image.Image:
    fill, fg = _COLORS.get(state, _COLORS[STATE_UNCONFIGURED])
    image = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    draw = ImageDraw.Draw(image)
    _shield(draw, size, fill)
    s = size
    width = max(2, size // 12)
    if state == STATE_WATCHING:
        draw.line([(s * 0.30, s * 0.52), (s * 0.45, s * 0.67), (s * 0.72, s * 0.36)], fill=fg, width=width)
    elif state == STATE_ALERT:
        draw.line([(s * 0.50, s * 0.28), (s * 0.50, s * 0.58)], fill=fg, width=width)
        draw.ellipse([(s * 0.45, s * 0.66), (s * 0.55, s * 0.76)], fill=fg)
    elif state == STATE_CONNECTING:
        draw.arc([(s * 0.30, s * 0.30), (s * 0.70, s * 0.70)], start=30, end=300, fill=fg, width=width)
    elif state == STATE_PAUSED:
        draw.rectangle([(s * 0.36, s * 0.32), (s * 0.45, s * 0.68)], fill=fg)
        draw.rectangle([(s * 0.55, s * 0.32), (s * 0.64, s * 0.68)], fill=fg)
    elif state == STATE_ERROR:
        draw.line([(s * 0.34, s * 0.34), (s * 0.66, s * 0.66)], fill=fg, width=width)
        draw.line([(s * 0.66, s * 0.34), (s * 0.34, s * 0.66)], fill=fg, width=width)
    else:
        draw.ellipse([(s * 0.40, s * 0.40), (s * 0.60, s * 0.60)], outline=fg, width=width)
    return image


def save_ico(path: str, state: str = STATE_WATCHING) -> None:
    """설치기·exe용 .ico 파일 생성."""
    base = render(state, 256)
    base.save(path, format="ICO", sizes=[(16, 16), (24, 24), (32, 32), (48, 48), (64, 64), (128, 128), (256, 256)])
