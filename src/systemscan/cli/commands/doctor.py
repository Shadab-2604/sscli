"""Environment diagnostics and doctor command for systemscan."""

from __future__ import annotations

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from systemscan.core.application import app_instance
from systemscan.core.dependencies import EnvironmentDoctor

app = typer.Typer(
    name="doctor",
    help="Diagnose runtime environment, dependencies, tool availability, and permissions.",
    no_args_is_help=False,
)
console = Console()


@app.callback(invoke_without_command=True)
def doctor_default(
    ctx: typer.Context,
    verbose: bool = typer.Option(
        False, "--verbose", "-v", help="Show verbose diagnostic inspection details."
    ),
) -> None:
    """Run comprehensive system and environment health diagnosis."""
    if app_instance.lifecycle.state.value == "CREATED":
        app_instance.bootstrap()

    console.print("\n[bold cyan]SystemScan Environment Doctor[/bold cyan]")
    console.print("[dim]Analyzing runtime, virtual environment, dependencies, and tools...[/dim]\n")

    doctor = EnvironmentDoctor()
    diagnosis = doctor.diagnose()

    # 1. Runtime & Environment Overview Table
    env_table = Table(title="Runtime & Environment", show_header=True, header_style="bold magenta")
    env_table.add_column("Property", style="bold", width=25)
    env_table.add_column("Value")
    env_table.add_column("Status", width=12)

    py_status = "[green]PASS[/green]" if diagnosis.python_version_ok else "[red]FAIL[/red]"
    env_table.add_row(
        "Python Version",
        f"{diagnosis.python_version} ({'64-bit' if diagnosis.is_64bit else '32-bit'})",
        py_status,
    )
    env_table.add_row(
        "Virtual Environment",
        f"{'Active' if diagnosis.is_virtualenv else 'None (Global/System)'} - {diagnosis.virtualenv_path or 'N/A'}",
        "[green]OK[/green]" if diagnosis.is_virtualenv else "[yellow]WARN[/yellow]",
    )
    env_table.add_row("Executable Path", diagnosis.executable_path, "[green]OK[/green]")

    # Directory permissions
    all_dirs_ok = all(d.get("writable", False) for d in diagnosis.writable_dirs)
    dir_status = "[green]PASS[/green]" if all_dirs_ok else "[red]FAIL[/red]"
    env_table.add_row(
        "Storage Directories",
        f"{len(diagnosis.writable_dirs)} inspected, {'all writable' if all_dirs_ok else 'permissions issue'}",
        dir_status,
    )
    console.print(env_table)
    console.print()

    if verbose:
        dir_table = Table(
            title="App Storage Paths & Permissions", show_header=True, header_style="bold blue"
        )
        dir_table.add_column("Role", style="bold")
        dir_table.add_column("Path")
        dir_table.add_column("Writable", width=12)
        for d in diagnosis.writable_dirs:
            w_status = "[green]YES[/green]" if d["writable"] else "[red]NO[/red]"
            dir_table.add_row(d["name"], d["path"], w_status)
        console.print(dir_table)
        console.print()

    # 2. Dependencies Table
    deps_table = Table(title="Package Dependencies", show_header=True, header_style="bold cyan")
    deps_table.add_column("Package", style="bold", width=20)
    deps_table.add_column("Category", width=15)
    deps_table.add_column("Required", width=12)
    deps_table.add_column("Installed", width=12)
    deps_table.add_column("Status", width=12)

    for dep in diagnosis.dependencies:
        if dep.is_compatible:
            status = "[green]INSTALLED[/green]"
        elif not dep.installed:
            status = (
                "[red]MISSING[/red]"
                if dep.dependency_type.value == "CORE"
                else "[yellow]OPTIONAL[/yellow]"
            )
        else:
            status = "[yellow]INCOMPATIBLE[/yellow]"

        deps_table.add_row(
            dep.name,
            dep.dependency_type.value,
            dep.spec_version or "*",
            dep.installed_version or "None",
            status,
        )
    console.print(deps_table)
    console.print()

    # 3. External Tools Table
    tool_table = Table(
        title="External Security & System Tools", show_header=True, header_style="bold green"
    )
    tool_table.add_column("Tool", style="bold", width=15)
    tool_table.add_column("Category", width=15)
    tool_table.add_column("Found At")
    tool_table.add_column("Version", width=15)
    tool_table.add_column("Status", width=12)

    for tool in diagnosis.external_tools:
        status = "[green]AVAILABLE[/green]" if tool.available else "[dim]NOT FOUND[/dim]"
        tool_table.add_row(
            tool.name,
            tool.category,
            tool.executable_path or "N/A",
            tool.version or "N/A",
            status,
        )
    console.print(tool_table)
    console.print()

    # 4. Platform Capabilities & Permission Matrix
    cap_table = Table(
        title=f"Platform Capabilities & Security Matrix ({app_instance.platform.os_name})",
        show_header=True,
        header_style="bold cyan",
    )
    cap_table.add_column("Capability", style="bold", width=30)
    cap_table.add_column("Status", width=22)

    status_styles = {
        "AVAILABLE": "[green]AVAILABLE[/green]",
        "PARTIALLY_AVAILABLE": "[yellow]PARTIALLY_AVAILABLE[/yellow]",
        "PERMISSION_REQUIRED": "[magenta]PERMISSION_REQUIRED[/magenta]",
        "DEPENDENCY_MISSING": "[red]DEPENDENCY_MISSING[/red]",
        "UNSUPPORTED": "[dim]UNSUPPORTED[/dim]",
        "ERROR": "[bold red]ERROR[/bold red]",
    }

    try:
        cap_matrix = app_instance.platform.get_capabilities_matrix()
        for cap_name, cap_status in sorted(cap_matrix.items()):
            styled_status = status_styles.get(cap_status.value, cap_status.value)
            cap_table.add_row(cap_name, styled_status)
    except Exception as e:
        cap_table.add_row("Evaluation Error", f"[red]{e}[/red]")

    console.print(cap_table)
    console.print()

    # Health verdict panel
    if diagnosis.overall_health == "healthy":
        verdict_color = "green"
        verdict_title = "Environment Status: HEALTHY"
        verdict_text = (
            "All core dependencies, permissions, and runtime specifications are satisfied."
        )
    elif diagnosis.overall_health == "degraded":
        verdict_color = "yellow"
        verdict_title = "Environment Status: DEGRADED (Functional)"
        verdict_text = (
            "System is operational, but some optional packages or external tools are missing."
        )
    else:
        verdict_color = "red"
        verdict_title = "Environment Status: UNHEALTHY"
        verdict_text = "Critical issues detected. Core dependencies or permissions are missing."

    console.print(
        Panel(
            verdict_text,
            title=f"[{verdict_color}]{verdict_title}[/{verdict_color}]",
            border_style=verdict_color,
        )
    )

    if diagnosis.recommendations:
        console.print("\n[bold yellow]Doctor Recommendations:[/bold yellow]")
        for rec in diagnosis.recommendations:
            console.print(f"  • {rec}")
        console.print()

    if diagnosis.overall_health == "unhealthy":
        raise typer.Exit(code=1)
