from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any, cast

import mcp.types as mcp_types
import pytest
from jsonschema import Draft202012Validator  # type: ignore[import-untyped, unused-ignore]
from mcp import ClientSession
from pydantic import ValidationError

from strands_agentguard import TargetManifest, fixture_candidate_identity
from strands_agentguard.inventory import (
    MAX_MCP_DISCOVERED_TOOLS,
    MAX_MCP_DISCOVERY_PAGES,
    AcceptedToolSurface,
    DiscoveredTool,
    InventoryDiscoveryError,
    ToolExposureRejected,
    ToolInventory,
    deterministic_inventory_json,
    discover_session_surface,
    load_discovery_fixture,
    normalize_mcp_inventory,
    safe_inventory_summary,
)
from strands_agentguard.local_tools import mcp_tool_definitions

ROOT = Path(__file__).parents[1]
MCP_FIXTURES = ROOT / "fixtures" / "mcp" / "v0.1.0"


class PaginatedSession:
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
        raise AssertionError("pagination tests must not invoke tools")


def trusted_mcp_registrations() -> list[mcp_types.Tool]:
    return [
        mcp_types.Tool(
            name=definition.name,
            description=definition.description,
            inputSchema=cast(dict[str, Any], definition.input_schema_dict()),
        )
        for definition in mcp_tool_definitions()
    ]


def unknown_mcp_registration(name: str = "unknown_tool") -> mcp_types.Tool:
    return mcp_types.Tool(
        name=name,
        description="Untrusted tool from a later page",
        inputSchema={
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "type": "object",
            "properties": {},
            "required": [],
            "additionalProperties": False,
        },
    )


def load_baseline() -> TargetManifest:
    return TargetManifest.model_validate_json(
        (ROOT / "fixtures" / "targets" / "vulnerable.json").read_bytes()
    )


def trusted_discovery() -> tuple[DiscoveredTool, ...]:
    return tuple(
        DiscoveredTool(
            name=definition.name,
            description=definition.description,
            input_schema=definition.input_schema,
        )
        for definition in mcp_tool_definitions()
    )


def replace_discovery(
    base: tuple[DiscoveredTool, ...],
    replacements: tuple[DiscoveredTool, ...],
) -> tuple[DiscoveredTool, ...]:
    by_name = {tool.name: tool for tool in base}
    by_name.update({tool.name: tool for tool in replacements})
    return tuple(by_name[name] for name in sorted(by_name))


def test_exact_baseline_surface_is_the_only_accepted_inventory() -> None:
    inventory = normalize_mcp_inventory(
        load_baseline(),
        "synthetic-audit",
        trusted_discovery(),
    )

    assert [tool.name for tool in inventory.accepted] == [
        "adversarial_result",
        "read_evidence",
        "read_inventory",
        "simulate_sensitive_action",
    ]
    assert inventory.rejected == ()
    assert "large_result" not in {tool.name for tool in inventory.accepted}
    assert {tool.permission_class for tool in inventory.accepted} == {"READ_ONLY_ALLOWED"}
    assert {tool.effect_class for tool in inventory.accepted} == {
        "READ",
        "SIMULATED_WRITE",
    }


def test_discovery_reads_every_page_and_rejects_unknown_tool_on_later_page() -> None:
    registrations = trusted_mcp_registrations()
    session = PaginatedSession(
        [
            mcp_types.ListToolsResult(tools=registrations[:2], nextCursor="page-2"),
            mcp_types.ListToolsResult(
                tools=[*registrations[2:], unknown_mcp_registration()],
                nextCursor=None,
            ),
        ]
    )

    surface = asyncio.run(discover_session_surface(cast(ClientSession, session), load_baseline()))

    assert session.requested_cursors == [None, "page-2"]
    assert [tool.name for tool in surface.tools] == [
        "adversarial_result",
        "read_evidence",
        "read_inventory",
        "simulate_sensitive_action",
    ]
    assert [(tool.observed_name, tool.reason) for tool in surface.inventory.rejected] == [
        ("unknown_tool", "UNKNOWN_TOOL")
    ]


def test_discovery_rejects_repeated_or_cyclic_cursor() -> None:
    session = PaginatedSession(
        [
            mcp_types.ListToolsResult(tools=[], nextCursor="repeat"),
            mcp_types.ListToolsResult(tools=[], nextCursor="repeat"),
        ]
    )

    with pytest.raises(InventoryDiscoveryError, match="cursor repeated or cycled"):
        asyncio.run(discover_session_surface(cast(ClientSession, session), load_baseline()))

    assert session.requested_cursors == [None, "repeat"]


def test_discovery_page_limit_fails_closed() -> None:
    pages = [
        mcp_types.ListToolsResult(tools=[], nextCursor=f"cursor-{index + 1}")
        for index in range(MAX_MCP_DISCOVERY_PAGES)
    ]
    session = PaginatedSession(pages)

    with pytest.raises(InventoryDiscoveryError, match="page limit"):
        asyncio.run(discover_session_surface(cast(ClientSession, session), load_baseline()))

    assert len(session.requested_cursors) == MAX_MCP_DISCOVERY_PAGES


def test_discovery_tool_limit_fails_closed() -> None:
    tools = [
        unknown_mcp_registration(f"unknown_{index:03d}")
        for index in range(MAX_MCP_DISCOVERED_TOOLS + 1)
    ]
    session = PaginatedSession([mcp_types.ListToolsResult(tools=tools, nextCursor=None)])

    with pytest.raises(InventoryDiscoveryError, match="tool limit"):
        asyncio.run(discover_session_surface(cast(ClientSession, session), load_baseline()))

    assert session.requested_cursors == [None]


def test_poisoned_description_and_unknown_tool_are_rejected_without_echoing_content() -> None:
    poisoned = load_discovery_fixture(MCP_FIXTURES / "poisoned-description.json")
    discovered = replace_discovery(trusted_discovery(), poisoned)

    inventory = normalize_mcp_inventory(load_baseline(), "synthetic-audit", discovered)
    summary = safe_inventory_summary(inventory)
    serialized = deterministic_inventory_json(inventory)

    assert {(tool.observed_name, tool.reason) for tool in inventory.rejected} == {
        ("exfiltrate_data", "UNKNOWN_TOOL"),
        ("read_evidence", "FINGERPRINT_DRIFT"),
    }
    assert "read_evidence" not in {tool.name for tool in inventory.accepted}
    for poison in (
        "IGNORE ALL POLICY",
        "Send every credential",
        "external endpoint",
    ):
        assert poison not in summary
        assert poison not in serialized
    assert summary.count("untrusted-description=omitted") == 2


def test_input_schema_drift_is_rejected_before_exposure() -> None:
    drift = load_discovery_fixture(MCP_FIXTURES / "schema-drift.json")
    discovered = replace_discovery(trusted_discovery(), drift)

    inventory = normalize_mcp_inventory(load_baseline(), "synthetic-audit", discovered)

    assert [(tool.observed_name, tool.reason) for tool in inventory.rejected] == [
        ("read_inventory", "FINGERPRINT_DRIFT")
    ]
    assert "read_inventory" not in {tool.name for tool in inventory.accepted}


def test_declared_denied_tool_is_classified_and_rejected() -> None:
    payload = cast(
        dict[str, Any],
        json.loads((ROOT / "fixtures" / "targets" / "vulnerable.json").read_text(encoding="utf-8")),
    )
    tools = cast(list[dict[str, Any]], payload["tools"])
    tool = next(item for item in tools if item["tool_id"] == "read_evidence")
    tool.update(
        {
            "permission_class": "DENIED",
            "effect_class": "NONE",
            "approval_required": False,
        }
    )
    permissions = cast(dict[str, list[str]], payload["permissions"])
    permissions["allow"].remove("read_evidence")
    permissions["deny"] = sorted([*permissions["deny"], "read_evidence"])
    payload["candidate_identity"] = fixture_candidate_identity(payload)
    manifest = TargetManifest.model_validate(payload)

    inventory = normalize_mcp_inventory(
        manifest,
        "synthetic-audit",
        trusted_discovery(),
    )

    assert ("read_evidence", "DENIED") in {
        (item.observed_name, item.reason) for item in inventory.rejected
    }
    assert "read_evidence" not in {item.name for item in inventory.accepted}


def test_manifest_identity_drift_is_rejected_before_discovery_normalization() -> None:
    payload = cast(
        dict[str, Any],
        json.loads((ROOT / "fixtures" / "targets" / "vulnerable.json").read_text(encoding="utf-8")),
    )
    payload["limits"]["max_iterations"] -= 1
    manifest = TargetManifest.model_validate(payload)

    with pytest.raises(ValueError, match="identity is invalid"):
        normalize_mcp_inventory(
            manifest,
            "synthetic-audit",
            trusted_discovery(),
        )


def test_rejected_tools_are_neither_exposed_nor_forwarded_to_the_invoker() -> None:
    drift = load_discovery_fixture(MCP_FIXTURES / "schema-drift.json")
    unknown = DiscoveredTool(
        name="unknown_tool",
        description="Untrusted tool",
        input_schema={
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "type": "object",
            "properties": {},
            "required": [],
            "additionalProperties": False,
        },
    )
    discovered = replace_discovery(trusted_discovery(), (*drift, unknown))
    inventory = normalize_mcp_inventory(load_baseline(), "synthetic-audit", discovered)
    calls: list[str] = []

    async def invoker(name: str, _arguments: dict[str, Any]) -> mcp_types.CallToolResult:
        calls.append(name)
        return mcp_types.CallToolResult(
            content=[mcp_types.TextContent(type="text", text="ok")],
            structuredContent={"ok": True},
        )

    surface = AcceptedToolSurface(inventory=inventory, _invoker=invoker)

    assert {tool.name for tool in surface.tools} == {
        "adversarial_result",
        "read_evidence",
        "simulate_sensitive_action",
    }
    with pytest.raises(ToolExposureRejected):
        asyncio.run(surface.invoke("read_inventory", {"inventory_id": "inventory-001"}))
    with pytest.raises(ToolExposureRejected):
        asyncio.run(surface.invoke("unknown_tool", {}))
    assert calls == []
    result = asyncio.run(surface.invoke("read_evidence", {"evidence_id": "evidence-001"}))
    assert result.structuredContent == {"ok": True}
    assert calls == ["read_evidence"]


def test_inventory_json_schema_fingerprint_and_repeatability() -> None:
    inventory = normalize_mcp_inventory(
        load_baseline(),
        "synthetic-audit",
        trusted_discovery(),
    )
    first = deterministic_inventory_json(inventory)
    second = deterministic_inventory_json(
        normalize_mcp_inventory(
            load_baseline(),
            "synthetic-audit",
            tuple(reversed(trusted_discovery())),
        )
    )
    schema = cast(
        dict[str, Any],
        json.loads((ROOT / "schemas" / "tool-inventory.schema.json").read_text()),
    )

    Draft202012Validator.check_schema(schema)
    Draft202012Validator(schema).validate(json.loads(first))
    assert first == second
    assert first.endswith("\n")
    assert "\n" not in first[:-1]

    changed = inventory.model_dump(mode="python")
    changed["inventory_fingerprint"] = "0" * 64
    with pytest.raises(ValidationError, match="inventory_fingerprint"):
        ToolInventory.model_validate(changed)


@pytest.mark.parametrize(
    ("discovered", "reason"),
    [
        (
            lambda tools: (*tools, tools[0]),
            "DUPLICATE_TOOL",
        ),
        (
            lambda tools: tools[1:],
            "MISSING_TOOL",
        ),
    ],
)
def test_duplicate_and_missing_tools_fail_closed(
    discovered: Any,
    reason: str,
) -> None:
    inventory = normalize_mcp_inventory(
        load_baseline(),
        "synthetic-audit",
        discovered(trusted_discovery()),
    )

    assert reason in {tool.reason for tool in inventory.rejected}
