from __future__ import annotations

import asyncio
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any, TextIO, cast

import anyio
import pytest
from mcp import ClientSession
from mcp.client.stdio import stdio_client

from strands_agentguard.inventory import (
    MCP_LIFECYCLE_TIMEOUT_SECONDS,
    InventoryDiscoveryError,
    discover_registered_inventory,
    registered_server_parameters,
)

ROOT = Path(__file__).parents[1]
EXPECTED_MCP_TOOLS = [
    "adversarial_result",
    "read_evidence",
    "read_inventory",
    "simulate_sensitive_action",
]


async def exercise_server() -> tuple[list[str], dict[str, Any], bool, bool, bool, bool]:
    parameters = registered_server_parameters(ROOT)
    errlog = cast(TextIO, subprocess.DEVNULL)
    with anyio.fail_after(MCP_LIFECYCLE_TIMEOUT_SECONDS):
        async with stdio_client(parameters, errlog=errlog) as (read_stream, write_stream):
            async with ClientSession(read_stream, write_stream) as session:
                await session.initialize()
                listed = await session.list_tools()
                evidence = await session.call_tool("read_evidence", {"evidence_id": "evidence-001"})
                first = await session.call_tool(
                    "simulate_sensitive_action",
                    {
                        "operation_id": "op-001",
                        "record_id": "record-001",
                        "value": "synthetic",
                    },
                )
                repeated = await session.call_tool(
                    "simulate_sensitive_action",
                    {
                        "operation_id": "op-001",
                        "record_id": "record-001",
                        "value": "synthetic",
                    },
                )
                conflict = await session.call_tool(
                    "simulate_sensitive_action",
                    {
                        "operation_id": "op-001",
                        "record_id": "record-001",
                        "value": "different",
                    },
                )
                invalid = await session.call_tool(
                    "read_inventory",
                    {"inventory_id": "inventory-001", "path": "/tmp"},
                )
                local_only = await session.call_tool("large_result", {"size_bytes": 16})
                return (
                    [tool.name for tool in listed.tools],
                    evidence.structuredContent or {},
                    first.structuredContent == repeated.structuredContent,
                    bool(conflict.isError),
                    bool(invalid.isError),
                    bool(local_only.isError),
                )


def test_stdio_server_discovery_calls_and_fail_closed_dispatch() -> None:
    (
        names,
        evidence,
        repeat_same,
        conflict_rejected,
        invalid_rejected,
        local_only_rejected,
    ) = asyncio.run(exercise_server())

    assert names == EXPECTED_MCP_TOOLS
    assert evidence["sanitized"] is True
    assert repeat_same
    assert conflict_rejected
    assert invalid_rejected
    assert local_only_rejected


def test_registered_server_environment_contains_no_credential_or_network_configuration() -> None:
    parameters = registered_server_parameters(ROOT)

    assert parameters.command == sys.executable
    assert parameters.args == ["-m", "strands_agentguard.synthetic_mcp"]
    assert parameters.cwd == ROOT / "src"
    assert parameters.env is not None
    assert set(parameters.env) == {"AGENTGUARD_EGRESS", "PYTHONNOUSERSITE", "PYTHONPATH"}
    assert parameters.env["AGENTGUARD_EGRESS"] == "deny"
    assert parameters.env["PYTHONPATH"].split(os.pathsep)[0] == str(ROOT / "src")
    assert not any(
        token in key.upper()
        for key in parameters.env
        for token in ("AWS", "CREDENTIAL", "KEY", "SECRET", "TOKEN")
    )


def test_stdio_client_cleanup_terminates_the_registered_server(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    original_open_process = anyio.open_process
    processes: list[anyio.abc.Process] = []

    async def tracked_open_process(*args: Any, **kwargs: Any) -> anyio.abc.Process:
        process = await original_open_process(*args, **kwargs)
        processes.append(process)
        return process

    monkeypatch.setattr(anyio, "open_process", tracked_open_process)

    asyncio.run(exercise_server())

    assert len(processes) == 1
    assert processes[0].returncode is not None


def test_caller_controlled_root_cannot_execute_sitecustomize_or_server_module(
    tmp_path: Path,
) -> None:
    candidate = tmp_path / "candidate"
    target_directory = candidate / "fixtures" / "targets"
    package_directory = candidate / "src" / "strands_agentguard"
    target_directory.mkdir(parents=True)
    package_directory.mkdir(parents=True)
    shutil.copy2(ROOT / "fixtures" / "targets" / "vulnerable.json", target_directory)
    site_marker = tmp_path / "sitecustomize-executed"
    module_marker = tmp_path / "synthetic-module-executed"
    (candidate / "src" / "sitecustomize.py").write_text(
        "from pathlib import Path\n"
        f"Path({str(site_marker)!r}).write_text('executed', encoding='utf-8')\n",
        encoding="utf-8",
    )
    (package_directory / "__init__.py").write_text("", encoding="utf-8")
    (package_directory / "synthetic_mcp.py").write_text(
        "from pathlib import Path\n"
        f"Path({str(module_marker)!r}).write_text('executed', encoding='utf-8')\n",
        encoding="utf-8",
    )

    with pytest.raises(InventoryDiscoveryError, match="root is not trusted"):
        asyncio.run(discover_registered_inventory(candidate))

    assert not site_marker.exists()
    assert not module_marker.exists()
