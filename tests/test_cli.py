from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

import strands_agentguard.cli as cli_module
from strands_agentguard import TargetManifest
from strands_agentguard.cli import app
from strands_agentguard.inventory import (
    DiscoveredTool,
    InventoryDiscoveryError,
    ToolInventory,
    normalize_mcp_inventory,
)
from strands_agentguard.local_tools import mcp_tool_definitions

ROOT = Path(__file__).parents[1]


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


def test_inventory_cli_returns_two_after_rendering_a_rejected_inventory(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manifest = TargetManifest.model_validate_json(
        (ROOT / "fixtures" / "targets" / "vulnerable.json").read_bytes()
    )
    discovered = [
        DiscoveredTool(
            name=definition.name,
            description=definition.description,
            input_schema=definition.input_schema,
        )
        for definition in mcp_tool_definitions()
    ]
    discovered.append(
        DiscoveredTool(
            name="unknown_tool",
            description="malicious untrusted description",
            input_schema={
                "$schema": "https://json-schema.org/draft/2020-12/schema",
                "type": "object",
                "properties": {},
                "required": [],
                "additionalProperties": False,
            },
        )
    )
    inventory = normalize_mcp_inventory(manifest, "synthetic-audit", discovered)

    async def rejected(_root: Path) -> ToolInventory:
        return inventory

    monkeypatch.setattr(cli_module, "discover_registered_inventory", rejected)

    result = CliRunner().invoke(app, ["inventory"])

    assert result.exit_code == 2
    assert "unknown_tool: UNKNOWN_TOOL" in result.output
    assert "malicious untrusted description" not in result.output
