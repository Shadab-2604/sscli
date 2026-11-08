"""Professional terminal startup banner for systemscan."""

from __future__ import annotations

import sys

from rich.align import Align
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from systemscan.platform import current_platform, detect_installation_type
from systemscan.version import (
    APP_SHORT_NAME,
    APP_TAGLINE,
    __version__,
)


def get_banner_panel() -> Panel:
    """Construct dynamic Rich panel banner displaying platform and runtime information."""
    header_text = Text()
    header_text.append(f"{APP_SHORT_NAME}\n", style="bold cyan")
    header_text.append(f"{APP_TAGLINE}", style="bold white")

    # Metadata table
    table = Table.grid(padding=(0, 2))
    table.add_column("Key", style="dim cyan", justify="right")
    table.add_column("Separator", style="dim", justify="center")
    table.add_column("Value", style="bold white", justify="left")

    py_version = f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
    install_type = detect_installation_type()

    table.add_row("Version", ":", __version__)
    table.add_row("Platform", ":", current_platform.os_name)
    table.add_row("Architecture", ":", current_platform.architecture)
    table.add_row("Python", ":", py_version)
    table.add_row("Install Type", ":", install_type)

    content = Align.center(table)

    banner_panel = Panel(
        content,
        title=header_text,
        title_align="center",
        border_style="cyan",
        padding=(1, 2),
        expand=False,
    )
    return banner_panel


def render_banner(console: Console | None = None) -> None:
    """Print the startup banner to the specified console or stdout."""
    c = console or Console()
    c.print()
    c.print(get_banner_panel())
    c.print()
