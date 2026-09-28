"""Startup banner for Pandora.

The art is baked in as a static string (generated once with the 'ansi_shadow'
figlet font) so there is no runtime dependency. Colour is applied only when
writing to a real terminal, so redirected logs stay clean.
"""
from __future__ import annotations

import sys

from . import __version__

_ART = r"""
██████╗  █████╗ ███╗   ██╗██████╗  ██████╗ ██████╗  █████╗
██╔══██╗██╔══██╗████╗  ██║██╔══██╗██╔═══██╗██╔══██╗██╔══██╗
██████╔╝███████║██╔██╗ ██║██║  ██║██║   ██║██████╔╝███████║
██╔═══╝ ██╔══██║██║╚██╗██║██║  ██║██║   ██║██╔══██╗██╔══██║
██║     ██║  ██║██║ ╚████║██████╔╝╚██████╔╝██║  ██║██║  ██║
╚═╝     ╚═╝  ╚═╝╚═╝  ╚═══╝╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝
"""

_TAGLINE = "Everything in the box was meant to stay inside — Pandora finds what got out."

# ANSI colours
_MAGENTA = "\033[38;5;171m"
_CYAN = "\033[38;5;44m"
_DIM = "\033[2m"
_RESET = "\033[0m"


def render(color: bool | None = None) -> str:
    """Return the banner as a string. Colour auto-detects a TTY unless forced."""
    if color is None:
        color = sys.stdout.isatty()
    art = _ART.strip("\n")
    sub = f"  osint data-exposure monitor  ·  v{__version__}"
    if not color:
        return f"{art}\n{sub}\n  {_TAGLINE}\n"
    return (
        f"{_MAGENTA}{art}{_RESET}\n"
        f"{_CYAN}{sub}{_RESET}\n"
        f"{_DIM}  {_TAGLINE}{_RESET}\n"
    )


def print_banner() -> None:
    print(render())
