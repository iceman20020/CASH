"""ASCII banner + startup splash. Rich-rendered with gradient."""

from __future__ import annotations

from rich.align import Align
from rich.console import Console
from rich.panel import Panel
from rich.text import Text

from vulnscan import __version__


BANNER_LINES = [
    "▄████▄   ▄▄▄        ██████  ██░ ██ ",
    "▒██▀ ▀█  ▒████▄    ▒██    ▒ ▓██░ ██▒",
    "▒▓█    ▄ ▒██  ▀█▄  ░ ▓██▄   ▒██▀▀██░",
    "▒▓▓▄ ▄██▒░██▄▄▄▄██   ▒   ██▒░▓█ ░██ ",
    "▒ ▓███▀ ░ ▓█   ▓██▒▒██████▒▒░▓█▒░██▓",
    "░ ░▒ ▒  ░ ▒▒   ▓▒█░▒ ▒▓▒ ▒ ░ ▒ ░░▒░▒",
    "  ░  ▒     ▒   ▒▒ ░░ ░▒  ░ ░ ▒ ░▒░ ░",
    "░          ░   ▒   ░  ░  ░   ░  ░░ ░",
    "░ ░            ░  ░      ░   ░  ░  ░",
    "░                                   ",
]

BANNER_PLAIN = "\n".join(BANNER_LINES)
TAGLINE = "aggregated recon · web + network + dns · owasp-tagged findings"

GRADIENT = [
    "#00e5ff",
    "#00b8ff",
    "#0088ff",
    "#5a5aff",
    "#8a3aff",
    "#b02bd0",
    "#d61f9e",
    "#ff1f7a",
    "#ff4f5a",
    "#ff7a3a",
]


def _lerp(a: str, b: str, t: float) -> str:
    a = a.lstrip("#")
    b = b.lstrip("#")
    ar, ag, ab = int(a[0:2], 16), int(a[2:4], 16), int(a[4:6], 16)
    br, bg, bb = int(b[0:2], 16), int(b[2:4], 16), int(b[4:6], 16)
    r = int(ar + (br - ar) * t)
    g = int(ag + (bg - ag) * t)
    bl = int(ab + (bb - ab) * t)
    return f"#{r:02x}{g:02x}{bl:02x}"


def _gradient_color(idx: int, total: int) -> str:
    if total <= 1:
        return GRADIENT[0]
    pos = idx / (total - 1)
    span = len(GRADIENT) - 1
    lo = int(pos * span)
    hi = min(lo + 1, span)
    t = (pos * span) - lo
    return _lerp(GRADIENT[lo], GRADIENT[hi], t)


def render_gradient_banner(console: Console) -> None:
    text = Text()
    for i, line in enumerate(BANNER_LINES):
        color = _gradient_color(i, len(BANNER_LINES))
        text.append(line + "\n", style=f"bold {color}")
    console.print(Align.center(text))


def render_splash(console: Console, *, target: str = "", subtitle: str = "") -> None:
    render_gradient_banner(console)
    footer = Text()
    footer.append("vulnscan ", style="bold white")
    footer.append(f"v{__version__}", style="bold cyan")
    footer.append("   ")
    footer.append(TAGLINE, style="dim")
    if target:
        footer.append("\n  target ", style="dim")
        footer.append(target, style="bold yellow")
    if subtitle:
        footer.append("\n  " + subtitle, style="dim italic")
    console.print(Align.center(footer))
    console.print()


def render_splash_panel(console: Console, *, target: str = "") -> None:
    inner = Text()
    for i, line in enumerate(BANNER_LINES):
        color = _gradient_color(i, len(BANNER_LINES))
        inner.append(line + "\n", style=f"bold {color}")
    inner.append("\n")
    inner.append("  " + TAGLINE, style="dim")
    if target:
        inner.append("\n  target  ", style="dim")
        inner.append(target, style="bold yellow")
    panel = Panel(
        Align.center(inner),
        border_style="magenta",
        padding=(0, 2),
        title="[bold cyan]vulnscan[/]",
        subtitle=f"[dim]v{__version__}[/]",
    )
    console.print(panel)


# ---------------- reports ----------------

def banner_html() -> str:
    rows = []
    for i, line in enumerate(BANNER_LINES):
        color = _gradient_color(i, len(BANNER_LINES))
        safe = line.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
        safe = safe.replace(" ", "&nbsp;")
        rows.append(f'<span style="color:{color};">{safe}</span>')
    body = "<br/>".join(rows)
    return f'<pre class="banner" aria-label="vulnscan">{body}</pre>'


def banner_md() -> str:
    return f"```\n{BANNER_PLAIN}\n```\n*vulnscan v{__version__} — {TAGLINE}*"


def banner_txt() -> str:
    return BANNER_PLAIN + f"\nvulnscan v{__version__}\n{TAGLINE}\n"
