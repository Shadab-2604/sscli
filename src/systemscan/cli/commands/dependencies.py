"""Dependency management CLI commands for systemscan."""

from __future__ import annotations

import typer
from rich.console import Console
from rich.table import Table

from systemscan.cli.display import print_error, print_info, print_success
from systemscan.core.application import app_instance
from systemscan.core.dependencies import (
    DependencyRegistry,
    DependencyType,
    SafeDependencyInstaller,
)

app = typer.Typer(
    name="dependencies",
    help="Inspect, check, verify, and safely install application dependencies.",
    no_args_is_help=False,
)
console = Console()


@app.callback(invoke_without_command=True)
def dependencies_default(ctx: typer.Context) -> None:
    """Default callback listing dependencies if no subcommand provided."""
    if ctx.invoked_subcommand is None:
        list_dependencies()


@app.command("list")
def list_dependencies(
    category: str | None = typer.Option(
        None,
        "--category",
        "-c",
        help="Filter by category (core, optional, development, tool).",
    ),
) -> None:
    """List all registered application dependencies and their installation status."""
    if app_instance.lifecycle.state.value == "CREATED":
        app_instance.bootstrap()

    deps = DependencyRegistry.get_all_specs()
    if category:
        cat_lower = category.lower()
        deps = [d for d in deps if cat_lower in d.dependency_type.value.lower()]

    table = Table(
        title="Application Dependency Registry", show_header=True, header_style="bold cyan"
    )
    table.add_column("Package Name", style="bold", width=22)
    table.add_column("Type", width=15)
    table.add_column("Required Spec", width=14)
    table.add_column("Installed Version", width=18)
    table.add_column("Status", width=14)

    for dep in deps:
        installed, installed_ver = DependencyRegistry.check_installed(dep.name)
        compatible = DependencyRegistry.is_compatible(dep.name) if installed else False

        if compatible:
            status = "[green]COMPATIBLE[/green]"
        elif not installed:
            status = (
                "[red]MISSING[/red]"
                if dep.dependency_type in (DependencyType.CORE, DependencyType.REQUIRED)
                else "[dim]NOT INSTALLED[/dim]"
            )
        else:
            status = "[yellow]INCOMPATIBLE[/yellow]"

        table.add_row(
            dep.name,
            dep.dependency_type.value,
            dep.spec_version or "*",
            installed_ver or "None",
            status,
        )

    console.print()
    console.print(table)
    console.print()


@app.command("check")
def check_dependencies() -> None:
    """Check all registered dependencies and verify host compatibility."""
    if app_instance.lifecycle.state.value == "CREATED":
        app_instance.bootstrap()

    console.print("\n[bold cyan]Checking Application Dependencies...[/bold cyan]")
    missing, incompatible = DependencyRegistry.verify_all()

    if not missing and not incompatible:
        print_success("All core and required dependencies are installed and compatible!")
        return

    if missing:
        console.print(f"[bold red]Missing dependencies ({len(missing)}):[/bold red]")
        for m in missing:
            console.print(f"  • {m.name} ({m.dependency_type.value}) - required: {m.spec_version}")

    if incompatible:
        console.print(
            f"[bold yellow]Incompatible dependency versions ({len(incompatible)}):[/bold yellow]"
        )
        for inc in incompatible:
            _, installed_ver = DependencyRegistry.check_installed(inc.name)
            console.print(f"  • {inc.name}: installed {installed_ver}, required {inc.spec_version}")

    console.print()
    core_missing = [
        m for m in missing if m.dependency_type in (DependencyType.CORE, DependencyType.REQUIRED)
    ]
    if core_missing:
        raise typer.Exit(code=1)


@app.command("missing")
def list_missing() -> None:
    """List only missing dependencies."""
    if app_instance.lifecycle.state.value == "CREATED":
        app_instance.bootstrap()

    missing, _ = DependencyRegistry.verify_all()
    if not missing:
        print_success("No missing dependencies detected.")
        return

    table = Table(title="Missing Dependencies", show_header=True, header_style="bold red")
    table.add_column("Package Name", style="bold")
    table.add_column("Type")
    table.add_column("Spec Version")
    table.add_column("Description")

    for dep in missing:
        table.add_row(dep.name, dep.dependency_type.value, dep.spec_version or "*", dep.description)

    console.print()
    console.print(table)
    console.print()


@app.command("verify")
def verify_dependencies() -> None:
    """Verify runtime integrity and importability of installed dependencies."""
    if app_instance.lifecycle.state.value == "CREATED":
        app_instance.bootstrap()

    console.print("\n[bold cyan]Verifying Installed Dependency Runtimes...[/bold cyan]")
    all_specs = DependencyRegistry.get_all_specs()

    passed = 0
    failed = 0
    for dep in all_specs:
        installed, ver = DependencyRegistry.check_installed(dep.name)
        if not installed:
            if dep.dependency_type in (DependencyType.CORE, DependencyType.REQUIRED):
                console.print(f"[red]FAIL[/red]: Core package '{dep.name}' is NOT installed.")
                failed += 1
            continue

        if not DependencyRegistry.is_compatible(dep.name):
            console.print(
                f"[yellow]WARN[/yellow]: Package '{dep.name}' v{ver} does not satisfy '{dep.spec_version}'."
            )
            failed += 1
        else:
            passed += 1

    console.print(
        f"\n[green]Verification complete:[/green] {passed} packages verified, {failed} issues found.\n"
    )
    if failed > 0:
        raise typer.Exit(code=1)


@app.command("install")
def install_dependency(
    package_name: str | None = typer.Argument(
        None, help="Name of registered package or spec to install."
    ),
    all_optional: bool = typer.Option(
        False, "--all-optional", help="Install all optional extensions into active virtualenv."
    ),
    dry_run: bool = typer.Option(
        False, "--dry-run", help="Simulate installation without making changes."
    ),
    allow_global: bool = typer.Option(
        False, "--allow-global", help="Explicitly allow installing into global Python environment."
    ),
) -> None:
    """Safely install missing or optional dependencies into the active virtual environment."""
    if app_instance.lifecycle.state.value == "CREATED":
        app_instance.bootstrap()

    installer = SafeDependencyInstaller()

    if all_optional:
        optional_deps = DependencyRegistry.get_optional_specs()
        to_install = [
            d.name for d in optional_deps if not DependencyRegistry.check_installed(d.name)[0]
        ]
        if not to_install:
            print_info("All optional dependencies are already installed.")
            return

        console.print(
            f"[cyan]Installing {len(to_install)} optional dependencies: {', '.join(to_install)}[/cyan]"
        )
        for pkg in to_install:
            ok, msg = installer.install_package(pkg, allow_global=allow_global, dry_run=dry_run)
            if ok:
                print_success(f"Installed {pkg}: {msg}")
            else:
                print_error(f"Failed to install {pkg}", msg)
        return

    if not package_name:
        print_error("Please specify a package name to install or use --all-optional.")
        raise typer.Exit(code=1)

    console.print(f"[cyan]Installing '{package_name}'...[/cyan]")
    ok, msg = installer.install_package(package_name, allow_global=allow_global, dry_run=dry_run)
    if ok:
        print_success(f"Installation succeeded: {msg}")
    else:
        print_error("Installation failed", msg)
        raise typer.Exit(code=1)
