"""Fail-closed MCP discovery and deterministic tool-inventory normalization."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import sys
from collections.abc import Awaitable, Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Annotated, Any, Literal, cast

import anyio
import mcp
import mcp.types as mcp_types
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from pydantic import (
    BaseModel,
    ConfigDict,
    StringConstraints,
    field_validator,
    model_validator,
)

from strands_agentguard.contracts import (
    TargetManifest,
    ToolDescriptor,
    canonical_json_bytes,
    canonical_sha256,
)
from strands_agentguard.local_tools import (
    SYNTHETIC_MCP_EXECUTABLE_ID,
    SYNTHETIC_MCP_SERVER_ID,
)
from strands_agentguard.targets.identity import validate_fixture_identity

INVENTORY_SCHEMA_VERSION = "0.1.0"
MCP_LIFECYCLE_TIMEOUT_SECONDS = 5
MAX_DISCOVERED_DESCRIPTION_BYTES = 4_096
MAX_DISCOVERED_SCHEMA_BYTES = 16_384
_SAFE_TOOL_NAME = re.compile(r"^[a-z][a-z0-9_]{0,63}$")
SERVER_ID = SYNTHETIC_MCP_SERVER_ID
EXECUTABLE_ID = SYNTHETIC_MCP_EXECUTABLE_ID

type Sha256 = Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{64}$", strict=True)]
type LowerIdentifier = Annotated[
    str,
    StringConstraints(pattern=r"^[a-z][a-z0-9._-]{0,63}$", strict=True),
]
type SafeToolName = Annotated[
    str,
    StringConstraints(pattern=r"^[a-z][a-z0-9_-]{0,63}$", strict=True),
]
type RejectionReason = Literal[
    "DENIED",
    "DUPLICATE_TOOL",
    "FINGERPRINT_DRIFT",
    "INVALID_DESCRIPTOR",
    "MISSING_TOOL",
    "UNKNOWN_TOOL",
]


class InventoryError(ValueError):
    """Base class for safe inventory failures."""


class InventoryDiscoveryError(InventoryError):
    """Raised when the registered local MCP lifecycle cannot be completed."""


class ToolExposureRejected(InventoryError):
    """Raised before invocation when a tool was not accepted by normalization."""


class _InventoryModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)


class AcceptedTool(_InventoryModel):
    tool_id: LowerIdentifier
    name: SafeToolName
    origin: Literal["mcp"]
    permission_class: Literal[
        "READ_ONLY_ALLOWED",
        "SIMULATED_SENSITIVE_APPROVAL",
    ]
    effect_class: Literal["READ", "SIMULATED_WRITE"]
    approval_required: bool
    fingerprint: Sha256
    description_sha256: Sha256
    input_schema_sha256: Sha256


class RejectedTool(_InventoryModel):
    observed_name: SafeToolName
    name_sha256: Sha256
    reason: RejectionReason
    observed_fingerprint: Sha256 | None


class ToolInventory(_InventoryModel):
    """Versioned inventory containing no raw untrusted descriptions or schemas."""

    schema_version: Literal["0.1.0"]
    target_id: LowerIdentifier
    target_candidate: Annotated[
        str,
        StringConstraints(pattern=r"^fixture:baseline:[0-9a-f]{64}$", strict=True),
    ]
    server_id: LowerIdentifier
    server_fingerprint: Sha256
    accepted: tuple[AcceptedTool, ...]
    rejected: tuple[RejectedTool, ...]
    inventory_fingerprint: Sha256

    @staticmethod
    def fingerprint_for(material: Mapping[str, object]) -> str:
        value = dict(material)
        value.pop("inventory_fingerprint", None)
        return canonical_sha256(value)

    @field_validator("accepted")
    @classmethod
    def validate_accepted_order(cls, value: tuple[AcceptedTool, ...]) -> tuple[AcceptedTool, ...]:
        names = [tool.name for tool in value]
        if names != sorted(set(names)):
            raise ValueError("accepted tools must be unique and sorted")
        return value

    @field_validator("rejected")
    @classmethod
    def validate_rejected_order(cls, value: tuple[RejectedTool, ...]) -> tuple[RejectedTool, ...]:
        keys = [(tool.observed_name, tool.reason, tool.name_sha256) for tool in value]
        if keys != sorted(set(keys)):
            raise ValueError("rejected tools must be unique and sorted")
        return value

    @model_validator(mode="after")
    def validate_fingerprint(self) -> ToolInventory:
        material = self.model_dump(mode="json")
        if not hmac.compare_digest(
            self.inventory_fingerprint,
            self.fingerprint_for(material),
        ):
            raise ValueError("inventory_fingerprint does not match canonical inventory")
        return self


@dataclass(frozen=True, slots=True)
class DiscoveredTool:
    """Minimal untrusted registration material returned by MCP discovery."""

    name: str
    description: str | None
    input_schema: object

    @classmethod
    def from_mcp(cls, tool: mcp_types.Tool) -> DiscoveredTool:
        return cls(
            name=tool.name,
            description=tool.description,
            input_schema=tool.inputSchema,
        )


type McpInvoker = Callable[
    [str, dict[str, Any]],
    Awaitable[mcp_types.CallToolResult],
]


@dataclass(frozen=True, slots=True)
class AcceptedToolSurface:
    """Invocation boundary that contains only normalized accepted tools."""

    inventory: ToolInventory
    _invoker: McpInvoker

    @property
    def tools(self) -> tuple[AcceptedTool, ...]:
        return self.inventory.accepted

    async def invoke(
        self,
        name: str,
        arguments: Mapping[str, Any],
    ) -> mcp_types.CallToolResult:
        if name not in {tool.name for tool in self.tools}:
            raise ToolExposureRejected("tool was not accepted for exposure or invocation")
        return await self._invoker(name, dict(arguments))


def _name_sha256(name: str) -> str:
    return hashlib.sha256(name.encode("utf-8")).hexdigest()


def _safe_observed_name(name: str) -> str:
    if _SAFE_TOOL_NAME.fullmatch(name):
        return name
    return f"invalid-{_name_sha256(name)[:12]}"


def _rejected(
    name: str,
    reason: RejectionReason,
    observed_fingerprint: str | None,
) -> RejectedTool:
    return RejectedTool(
        observed_name=_safe_observed_name(name),
        name_sha256=_name_sha256(name),
        reason=reason,
        observed_fingerprint=observed_fingerprint,
    )


def _observed_fingerprint(tool: DiscoveredTool) -> str | None:
    if tool.description is None:
        return None
    if len(tool.description.encode("utf-8")) > MAX_DISCOVERED_DESCRIPTION_BYTES:
        return None
    if not isinstance(tool.input_schema, Mapping):
        return None
    try:
        schema_bytes = canonical_json_bytes(tool.input_schema)
    except (TypeError, ValueError):
        return None
    if len(schema_bytes) > MAX_DISCOVERED_SCHEMA_BYTES:
        return None
    try:
        return ToolDescriptor.fingerprint_for(
            name=tool.name,
            description=tool.description,
            input_schema=cast(Mapping[str, Any], tool.input_schema),
        )
    except (TypeError, ValueError):
        return None


def _accepted(tool: ToolDescriptor) -> AcceptedTool:
    if tool.origin != "mcp" or tool.permission_class == "DENIED":
        raise InventoryError("non-MCP or denied tool cannot be accepted")
    if tool.permission_class not in {
        "READ_ONLY_ALLOWED",
        "SIMULATED_SENSITIVE_APPROVAL",
    }:
        raise InventoryError("tool permission classification is unsupported")
    return AcceptedTool(
        tool_id=tool.tool_id,
        name=tool.name,
        origin="mcp",
        permission_class=tool.permission_class,
        effect_class=cast(Literal["READ", "SIMULATED_WRITE"], tool.effect_class),
        approval_required=tool.approval_required,
        fingerprint=tool.fingerprint,
        description_sha256=hashlib.sha256(tool.description.encode("utf-8")).hexdigest(),
        input_schema_sha256=canonical_sha256(tool.input_schema),
    )


def _manifest_server(manifest: TargetManifest, server_id: str) -> Any:
    for server in manifest.mcp_servers:
        if server.server_id == server_id:
            return server
    raise InventoryError("registered MCP server is absent from the target manifest")


def normalize_mcp_inventory(
    manifest: TargetManifest,
    server_id: str,
    discovered: Sequence[DiscoveredTool],
) -> ToolInventory:
    """Compare untrusted discovery with the baseline and accept exact matches only."""

    if manifest.profile != "baseline":
        raise InventoryError("MCP normalization requires the baseline TargetManifest")
    try:
        validate_fixture_identity(manifest)
    except ValueError as exc:
        raise InventoryError("baseline TargetManifest identity is invalid") from exc
    server = _manifest_server(manifest, server_id)
    tools_by_id = {tool.tool_id: tool for tool in manifest.tools}
    expected = [tools_by_id[tool_id] for tool_id in server.tool_ids]
    expected_by_name = {tool.name: tool for tool in expected}
    if len(expected_by_name) != len(expected):
        raise InventoryError("baseline MCP tool names are not unique")

    groups: dict[str, list[DiscoveredTool]] = {}
    for tool in discovered:
        groups.setdefault(tool.name, []).append(tool)

    accepted: list[AcceptedTool] = []
    rejected: list[RejectedTool] = []
    observed_expected_names: set[str] = set()
    for name in sorted(groups):
        group = groups[name]
        expected_tool = expected_by_name.get(name)
        if expected_tool is not None:
            observed_expected_names.add(name)
        if len(group) != 1:
            rejected.append(_rejected(name, "DUPLICATE_TOOL", None))
            continue
        observed = group[0]
        observed_fingerprint = _observed_fingerprint(observed)
        if expected_tool is None:
            rejected.append(_rejected(name, "UNKNOWN_TOOL", observed_fingerprint))
            continue
        if expected_tool.permission_class == "DENIED" or expected_tool.tool_id in (
            manifest.permissions.deny
        ):
            rejected.append(_rejected(name, "DENIED", observed_fingerprint))
            continue
        if observed_fingerprint is None:
            rejected.append(_rejected(name, "INVALID_DESCRIPTOR", None))
            continue
        if not hmac.compare_digest(observed_fingerprint, expected_tool.fingerprint):
            rejected.append(_rejected(name, "FINGERPRINT_DRIFT", observed_fingerprint))
            continue
        accepted.append(_accepted(expected_tool))

    for missing_name in sorted(expected_by_name.keys() - observed_expected_names):
        rejected.append(_rejected(missing_name, "MISSING_TOOL", None))

    accepted.sort(key=lambda tool: tool.name)
    rejected.sort(key=lambda tool: (tool.observed_name, tool.reason, tool.name_sha256))
    material: dict[str, object] = {
        "schema_version": INVENTORY_SCHEMA_VERSION,
        "target_id": manifest.target_id,
        "target_candidate": manifest.candidate_identity,
        "server_id": server.server_id,
        "server_fingerprint": server.fingerprint,
        "accepted": [tool.model_dump(mode="json") for tool in accepted],
        "rejected": [tool.model_dump(mode="json") for tool in rejected],
    }
    material["inventory_fingerprint"] = ToolInventory.fingerprint_for(material)
    return ToolInventory.model_validate(
        {
            **material,
            "accepted": tuple(accepted),
            "rejected": tuple(rejected),
        }
    )


def deterministic_inventory_json(inventory: ToolInventory) -> str:
    """Serialize one validated inventory canonically with one terminal LF."""

    return canonical_json_bytes(inventory.model_dump(mode="json")).decode("utf-8") + "\n"


def safe_inventory_summary(inventory: ToolInventory) -> str:
    """Render stable human output without copying any discovered description."""

    lines = [
        (f"tool inventory {inventory.schema_version}: {inventory.target_id}/{inventory.server_id}"),
        f"accepted: {len(inventory.accepted)}",
    ]
    lines.extend(
        (
            f"- {tool.name}: {tool.permission_class}/{tool.effect_class}; "
            f"fingerprint={tool.fingerprint}"
        )
        for tool in inventory.accepted
    )
    lines.append(f"rejected: {len(inventory.rejected)}")
    lines.extend(
        (f"- {tool.observed_name}: {tool.reason}; untrusted-description=omitted")
        for tool in inventory.rejected
    )
    lines.append(f"inventory-fingerprint: {inventory.inventory_fingerprint}")
    return "\n".join(lines) + "\n"


async def discover_session_surface(
    session: ClientSession,
    manifest: TargetManifest,
    server_id: str = SERVER_ID,
) -> AcceptedToolSurface:
    """Discover once and bind invocation to the resulting accepted set."""

    listed = await session.list_tools()
    discovered = tuple(DiscoveredTool.from_mcp(tool) for tool in listed.tools)
    inventory = normalize_mcp_inventory(manifest, server_id, discovered)

    async def invoke(name: str, arguments: dict[str, Any]) -> mcp_types.CallToolResult:
        return await session.call_tool(name, arguments)

    return AcceptedToolSurface(inventory=inventory, _invoker=invoke)


def _load_baseline_manifest(root: Path) -> TargetManifest:
    path = root / "fixtures" / "targets" / "vulnerable.json"
    try:
        manifest = TargetManifest.model_validate_json(path.read_bytes())
        validate_fixture_identity(manifest)
    except (OSError, ValueError) as exc:
        raise InventoryDiscoveryError("baseline TargetManifest is unavailable or invalid") from exc
    return manifest


def _safe_server_environment(root: Path) -> dict[str, str]:
    mcp_path = Path(mcp.__file__).resolve()
    dependency_root = mcp_path.parents[1]
    return {
        "AGENTGUARD_EGRESS": "deny",
        "PYTHONNOUSERSITE": "1",
        "PYTHONPATH": os.pathsep.join((str(root / "src"), str(dependency_root))),
    }


def registered_server_parameters(root: Path) -> StdioServerParameters:
    """Build parameters for the one fixed synthetic server, never an arbitrary command."""

    resolved_root = root.resolve()
    return StdioServerParameters(
        command=sys.executable,
        args=["-m", "strands_agentguard.synthetic_mcp"],
        env=_safe_server_environment(resolved_root),
        cwd=resolved_root,
    )


async def discover_registered_inventory(root: Path) -> ToolInventory:
    """Run only the registered synthetic stdio server and return its closed inventory."""

    resolved_root = root.resolve()
    manifest = _load_baseline_manifest(resolved_root)
    server = _manifest_server(manifest, SERVER_ID)
    if server.executable_id != EXECUTABLE_ID or server.transport != "stdio":
        raise InventoryDiscoveryError("registered MCP execution contract changed")

    parameters = registered_server_parameters(resolved_root)
    errlog = sys.__stderr__ if sys.__stderr__ is not None else sys.stderr
    try:
        with anyio.fail_after(MCP_LIFECYCLE_TIMEOUT_SECONDS):
            async with stdio_client(parameters, errlog=errlog) as (
                read_stream,
                write_stream,
            ):
                async with ClientSession(read_stream, write_stream) as session:
                    await session.initialize()
                    surface = await discover_session_surface(session, manifest)
                    return surface.inventory
    except Exception as exc:
        raise InventoryDiscoveryError(
            "registered synthetic MCP discovery or cleanup failed"
        ) from exc


def repository_root() -> Path:
    return Path(__file__).resolve().parents[2]


def load_discovery_fixture(path: Path) -> tuple[DiscoveredTool, ...]:
    """Load one bounded checked-in poisoning/drift fixture for deterministic tests."""

    try:
        document_bytes = path.read_bytes()
    except OSError as exc:
        raise InventoryError("MCP discovery fixture is unavailable") from exc
    if len(document_bytes) > 32_768:
        raise InventoryError("MCP discovery fixture exceeds its byte limit")

    def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise InventoryError("MCP discovery fixture contains duplicate keys")
            result[key] = value
        return result

    try:
        document = json.loads(document_bytes, object_pairs_hook=reject_duplicates)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise InventoryError("MCP discovery fixture is malformed") from exc
    if not isinstance(document, dict) or set(document) != {
        "schema_version",
        "server_id",
        "tools",
    }:
        raise InventoryError("MCP discovery fixture fields are invalid")
    if document["schema_version"] != "0.1.0" or document["server_id"] != SERVER_ID:
        raise InventoryError("MCP discovery fixture identity is invalid")
    tools = document["tools"]
    if not isinstance(tools, list) or not 1 <= len(tools) <= 8:
        raise InventoryError("MCP discovery fixture tool count is invalid")
    discovered: list[DiscoveredTool] = []
    for item in tools:
        if not isinstance(item, dict) or set(item) != {
            "name",
            "description",
            "input_schema",
        }:
            raise InventoryError("MCP discovery fixture tool fields are invalid")
        if not isinstance(item["name"], str) or not isinstance(item["description"], str):
            raise InventoryError("MCP discovery fixture text fields are invalid")
        discovered.append(
            DiscoveredTool(
                name=item["name"],
                description=item["description"],
                input_schema=item["input_schema"],
            )
        )
    return tuple(discovered)


__all__ = [
    "INVENTORY_SCHEMA_VERSION",
    "MCP_LIFECYCLE_TIMEOUT_SECONDS",
    "AcceptedTool",
    "AcceptedToolSurface",
    "DiscoveredTool",
    "InventoryDiscoveryError",
    "InventoryError",
    "RejectedTool",
    "ToolExposureRejected",
    "ToolInventory",
    "deterministic_inventory_json",
    "discover_registered_inventory",
    "discover_session_surface",
    "load_discovery_fixture",
    "normalize_mcp_inventory",
    "registered_server_parameters",
    "repository_root",
    "safe_inventory_summary",
]
