"""Observed (unpinned) inventory of a user-supplied stdio MCP server.

Unlike the baseline-pinned inventory, this makes no trust decision: it records
what the server advertises, as stable fingerprints, so the owner can review the
surface and pin it. Raw descriptions are never copied into the output.
"""

from __future__ import annotations

import hashlib
import json
import shlex
from collections.abc import Mapping, Sequence
from typing import Any, TextIO, cast

import anyio
import mcp.types as mcp_types
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

from strands_agentguard.contracts import ToolDescriptor, canonical_json_bytes
from strands_agentguard.inventory import (
    MAX_DISCOVERED_DESCRIPTION_BYTES,
    MAX_MCP_DISCOVERED_TOOLS,
    MAX_MCP_DISCOVERY_PAGES,
    InventoryDiscoveryError,
)
from strands_agentguard.servers import ServerEntry


def _flags(name: str, description: str | None, duplicate: bool) -> list[str]:
    flags: list[str] = []
    if duplicate:
        flags.append("duplicate_name")
    if description is None or not description.strip():
        flags.append("missing_description")
    elif len(description.encode("utf-8")) > MAX_DISCOVERED_DESCRIPTION_BYTES:
        flags.append("oversized_description")
    if not name or not name.replace("_", "").replace("-", "").isalnum():
        flags.append("unusual_name")
    return flags


def observed_inventory_document(
    command: Sequence[str], tools: Sequence[mcp_types.Tool]
) -> dict[str, Any]:
    names = [tool.name for tool in tools]
    entries: list[dict[str, Any]] = []
    for tool in sorted(tools, key=lambda t: t.name):
        description = tool.description or ""
        schema = cast(Mapping[str, Any], tool.inputSchema)
        try:
            fingerprint: str | None = ToolDescriptor.fingerprint_for(
                name=tool.name, description=description, input_schema=schema
            )
        except (TypeError, ValueError):
            fingerprint = None
        entries.append(
            {
                "name": tool.name[:64],
                "fingerprint": fingerprint,
                "description_sha256": hashlib.sha256(description.encode()).hexdigest(),
                "input_schema_sha256": hashlib.sha256(
                    canonical_json_bytes(dict(schema))
                ).hexdigest(),
                "flags": _flags(tool.name, tool.description, names.count(tool.name) > 1),
            }
        )
    return {
        "schema_version": "0.1.0",
        "kind": "observed-inventory",
        "command_sha256": hashlib.sha256(shlex.join(command).encode()).hexdigest(),
        "tool_count": len(entries),
        "tools": entries,
    }


async def observe_registered_server(entry: ServerEntry) -> dict[str, Any]:
    """Launch one allowlisted stdio MCP server and list its tools (bounded)."""

    command = [entry.command, *entry.args]
    parameters = StdioServerParameters(
        command=entry.command, args=list(entry.args), env=entry.launch_env()
    )
    tools: list[mcp_types.Tool] = []
    try:
        with anyio.fail_after(entry.timeout_seconds):
            async with stdio_client(parameters, errlog=cast(TextIO, open("/dev/null", "w"))) as (
                read_stream,
                write_stream,
            ):
                async with ClientSession(read_stream, write_stream) as session:
                    await session.initialize()
                    cursor: str | None = None
                    for _ in range(MAX_MCP_DISCOVERY_PAGES):
                        listed = await session.list_tools(
                            params=mcp_types.PaginatedRequestParams(cursor=cursor)
                            if cursor
                            else None
                        )
                        tools.extend(listed.tools)
                        if len(tools) > MAX_MCP_DISCOVERED_TOOLS:
                            raise InventoryDiscoveryError("server exposes too many tools")
                        cursor = listed.nextCursor
                        if cursor is None:
                            break
    except InventoryDiscoveryError:
        raise
    except Exception:
        raise InventoryDiscoveryError("could not list tools from the supplied server") from None
    return observed_inventory_document(command, tools)


def observed_inventory_json(document: Mapping[str, Any]) -> str:
    return json.dumps(document, indent=2, sort_keys=True) + "\n"


__all__ = ["observe_registered_server", "observed_inventory_document", "observed_inventory_json"]
