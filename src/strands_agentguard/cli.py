"""Public command-line interface for Strands AgentGuard."""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Annotated

import typer

from strands_agentguard.assessment import TARGET_CHOICES, AssessmentError, run_assessment
from strands_agentguard.assessment.targets import deterministic_target
from strands_agentguard.doctor import run_doctor
from strands_agentguard.inventory import (
    InventoryError,
    deterministic_inventory_json,
    discover_registered_inventory,
    repository_root,
    safe_inventory_summary,
)

app = typer.Typer(
    add_completion=False,
    help="Strands AgentGuard: assess your own agents, tools and MCP servers (authorized use only).",
)


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
    server: Annotated[
        str,
        typer.Argument(help="Registered server id: synthetic-audit, or one from agentguard.toml."),
    ] = "synthetic-audit",
    config: Annotated[
        Path | None,
        typer.Option("--config", help="Server registry (default: ./agentguard.toml if present)."),
    ] = None,
    json_output: bool = typer.Option(
        False,
        "--json",
        help="Emit canonical versioned JSON instead of the safe human summary.",
    ),
) -> None:
    """Discover a registered server's tool inventory (descriptions are never printed).

    Only ids in the allowlist run. A registered entry from your agentguard.toml launches that
    command as a local process; see agentguard.example.toml.
    """

    if server != "synthetic-audit":
        from strands_agentguard.observed import observe_registered_server, observed_inventory_json
        from strands_agentguard.servers import ServerConfigError, load_registry

        try:
            entry = load_registry(config).get(server)
        except ServerConfigError as exc:
            typer.echo(f"agentguard inventory: {exc}", err=True)
            raise typer.Exit(code=1) from None
        if entry is None:
            typer.echo(f"agentguard inventory: {server!r} is not a registered server", err=True)
            raise typer.Exit(code=1)
        typer.echo(
            f"agentguard inventory: launching registered server {server!r} as a local process",
            err=True,
        )
        try:
            document = asyncio.run(observe_registered_server(entry))
        except InventoryError:
            typer.echo("agentguard inventory: discovery failed", err=True)
            raise typer.Exit(code=1) from None
        if json_output:
            typer.echo(observed_inventory_json(document), nl=False)
        else:
            typer.echo(f"observed inventory: {document['tool_count']} tools (unpinned)")
            for tool in document["tools"]:
                flags = f" flags={','.join(tool['flags'])}" if tool["flags"] else ""
                typer.echo(f"- {tool['name']}: fingerprint={tool['fingerprint']}{flags}")
        if any(tool["flags"] for tool in document["tools"]):
            raise typer.Exit(code=2)
        return

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


@app.command("run")
def run_command(
    target: Annotated[str, typer.Option("--target", help=f"One of: {', '.join(TARGET_CHOICES)}.")],
    out: Annotated[Path, typer.Option("--out", help="Output directory for the report files.")],
    scenarios: Annotated[
        str,
        typer.Option("--scenarios", help="'all' or a comma list such as AG-SCN-011,AG-SCN-015."),
    ] = "all",
    repetitions: Annotated[
        int | None,
        typer.Option(
            "--repetitions", "-n", help="Trials per case (default 1, or 5 for strands-ollama)."
        ),
    ] = None,
    payloads: Annotated[
        Path | None,
        typer.Option("--payloads", help="Extra payload set (schemas/payload-set.schema.json)."),
    ] = None,
    model: Annotated[
        str, typer.Option("--model", help="strands-ollama model id.")
    ] = "gpt-oss:120b-cloud",
    host: Annotated[
        str | None, typer.Option("--host", help="Ollama host (default OLLAMA_HOST or localhost).")
    ] = None,
    controls: Annotated[
        str, typer.Option("--controls", help="strands-ollama only: 'none' or 'hardened'.")
    ] = "none",
    fail_on_findings: Annotated[
        bool, typer.Option("--fail-on-findings", help="Exit 3 when any scenario fails.")
    ] = False,
) -> None:
    """Run the AG-MVP-CORPUS scenarios against a target and write the report."""

    root = repository_root()
    try:
        if target in {"vulnerable", "hardened"}:
            spec = deterministic_target(root, target)
        elif target == "strands-ollama":
            from strands_agentguard.assessment.model import ControlSet
            from strands_agentguard.assessment.strands_target import strands_ollama_target

            if controls not in {"none", "hardened"}:
                raise AssessmentError("--controls must be 'none' or 'hardened'")
            spec = strands_ollama_target(
                model_id=model,
                host=host,
                controls=ControlSet.for_profile("hardened") if controls == "hardened" else None,
            )
        else:
            raise AssessmentError(f"unknown target {target!r}; choose one of {TARGET_CHOICES}")
        output = run_assessment(
            root,
            spec,
            scenario_selection=scenarios,
            out_dir=out,
            repetitions=repetitions,
            extra_payloads=payloads,
        )
    except (AssessmentError, ValueError, OSError) as exc:
        typer.echo(f"agentguard run: {exc}", err=True)
        raise typer.Exit(code=1) from None

    for row in output.meta["scenarios"]:
        verdict = "FAIL" if row["detected"] else "PASS"
        typer.echo(
            f"{row['scenario_id']} {verdict} {row['failures']}/{row['trials']} {row['title']}"
        )
    typer.echo(f"report: {output.out_dir / 'report.md'}")
    if output.failed_scenarios and fail_on_findings:
        raise typer.Exit(code=3)


__all__ = ["app", "doctor", "inventory_command", "main", "run_command"]
