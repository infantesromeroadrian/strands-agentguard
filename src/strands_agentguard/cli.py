"""Public command-line interface for Strands AgentGuard."""

from __future__ import annotations

import typer

from strands_agentguard.doctor import run_doctor

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


__all__ = ["app", "doctor", "main"]
