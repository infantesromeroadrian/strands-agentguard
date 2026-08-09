"""Public command-line interface for Strands AgentGuard."""

from __future__ import annotations

import asyncio

import typer

from strands_agentguard.doctor import run_doctor
from strands_agentguard.inventory import (
    InventoryError,
    deterministic_inventory_json,
    discover_registered_inventory,
    repository_root,
    safe_inventory_summary,
)

app = typer.Typer(add_completion=False, help="Offline Strands AgentGuard utilities.")


@app.callback()
def main() -> None:
    """Run an explicitly selected AgentGuard utility."""


@app.command()
def doctor() -> None:
    """Validate the deterministic environment and checked-in fixture stack offline."""

    report = run_doctor()
    for check in report.checks:
        marker = "ok" if check.ok else "failed"
        typer.echo(f"[{marker}] {check.name}: {check.detail}")
    typer.echo("agentguard doctor: healthy" if report.ok else "agentguard doctor: unhealthy")
    if not report.ok:
        raise typer.Exit(code=report.exit_code)


@app.command("inventory")
def inventory_command(
    json_output: bool = typer.Option(
        False,
        "--json",
        help="Emit canonical versioned JSON instead of the safe human summary.",
    ),
) -> None:
    """Discover and normalize the registered local MCP tool inventory."""

    try:
        inventory = asyncio.run(discover_registered_inventory(repository_root()))
    except InventoryError:
        typer.echo("agentguard inventory: discovery failed", err=True)
        raise typer.Exit(code=1) from None

    output = (
        deterministic_inventory_json(inventory)
        if json_output
        else safe_inventory_summary(inventory)
    )
    typer.echo(output, nl=False)
    if inventory.rejected:
        raise typer.Exit(code=2)


__all__ = ["app", "doctor", "inventory_command", "main"]
