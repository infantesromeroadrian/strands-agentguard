from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path
from typing import Any, cast

import mcp.types as mcp_types
import pytest
from mcp import ClientSession, StdioServerParameters
from typer.testing import CliRunner

import strands_agentguard.cli as cli_module
import strands_agentguard.inventory as inventory_module
from strands_agentguard import TargetManifest
from strands_agentguard.cli import app
from strands_agentguard.inventory import (
    InventoryDiscoveryError,
    ToolInventory,
    discover_session_surface,
)
from strands_agentguard.local_tools import mcp_tool_definitions

ROOT = Path(__file__).parents[1]


class CliPaginatedSession:
    def __init__(self, pages: list[mcp_types.ListToolsResult]) -> None:
        self._pages = pages
        self.requested_cursors: list[str | None] = []

    async def list_tools(
        self,
        cursor: str | None = None,
        *,
        params: mcp_types.PaginatedRequestParams | None = None,
    ) -> mcp_types.ListToolsResult:
        requested = params.cursor if params is not None else cursor
        self.requested_cursors.append(requested)
        return self._pages[len(self.requested_cursors) - 1]

    async def call_tool(
        self,
        _name: str,
        _arguments: dict[str, Any],
    ) -> mcp_types.CallToolResult:
        raise AssertionError("CLI pagination test must not invoke tools")


def test_inventory_cli_json_and_human_outputs_are_stable() -> None:
    runner = CliRunner()

    first_json = runner.invoke(app, ["inventory", "--json"])
    second_json = runner.invoke(app, ["inventory", "--json"])
    human = runner.invoke(app, ["inventory"])

    assert first_json.exit_code == second_json.exit_code == human.exit_code == 0
    assert first_json.output == second_json.output
    document = json.loads(first_json.output)
    assert document["schema_version"] == "0.1.0"
    assert [tool["name"] for tool in document["accepted"]] == [
        "adversarial_result",
        "read_evidence",
        "read_inventory",
        "simulate_sensitive_action",
    ]
    assert document["rejected"] == []
    assert "accepted: 4" in human.output
    assert "rejected: 0" in human.output
    assert "large_result" not in human.output


def test_inventory_cli_discovery_failure_has_stable_message_and_exit_one(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def failed(_root: Path) -> ToolInventory:
        raise InventoryDiscoveryError("internal detail must not be exposed")

    monkeypatch.setattr(cli_module, "discover_registered_inventory", failed)

    result = CliRunner().invoke(app, ["inventory"])

    assert result.exit_code == 1
    assert result.output == "agentguard inventory: discovery failed\n"
    assert "internal detail" not in result.output


def test_inventory_cli_returns_two_for_unknown_tool_on_later_page(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manifest = TargetManifest.model_validate_json(
        (ROOT / "fixtures" / "targets" / "vulnerable.json").read_bytes()
    )
    registrations = [
        mcp_types.Tool(
            name=definition.name,
            description=definition.description,
            inputSchema=cast(dict[str, Any], definition.input_schema_dict()),
        )
        for definition in mcp_tool_definitions()
    ]
    unknown = mcp_types.Tool(
        name="unknown_tool",
        description="malicious untrusted description",
        inputSchema={
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "type": "object",
            "properties": {},
            "required": [],
            "additionalProperties": False,
        },
    )
    session = CliPaginatedSession(
        [
            mcp_types.ListToolsResult(tools=registrations, nextCursor="page-2"),
            mcp_types.ListToolsResult(tools=[unknown], nextCursor=None),
        ]
    )
    inventory = asyncio.run(
        discover_session_surface(cast(ClientSession, session), manifest)
    ).inventory
    assert session.requested_cursors == [None, "page-2"]

    async def rejected(_root: Path) -> ToolInventory:
        return inventory

    monkeypatch.setattr(cli_module, "discover_registered_inventory", rejected)

    result = CliRunner().invoke(app, ["inventory"])

    assert result.exit_code == 2
    assert "unknown_tool: UNKNOWN_TOOL" in result.output
    assert "malicious untrusted description" not in result.output


def test_inventory_cli_suppresses_child_startup_stderr_and_paths(
    monkeypatch: pytest.MonkeyPatch,
    capfd: pytest.CaptureFixture[str],
) -> None:
    leaked = "CHILD-SECRET /private/candidate/sitecustomize.py"

    def failing_parameters(_root: Path) -> StdioServerParameters:
        return StdioServerParameters(
            command=sys.executable,
            args=[
                "-c",
                f"import sys; sys.stderr.write({leaked!r}); raise SystemExit(7)",
            ],
            env={"PYTHONNOUSERSITE": "1"},
            cwd=ROOT / "src",
        )

    monkeypatch.setattr(
        inventory_module,
        "registered_server_parameters",
        failing_parameters,
    )

    result = CliRunner().invoke(app, ["inventory"])
    captured = capfd.readouterr()

    assert result.exit_code == 1
    assert result.output == "agentguard inventory: discovery failed\n"
    assert leaked not in result.output
    assert leaked not in captured.err
