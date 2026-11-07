"""Agent-agnostic world model shared by every assessment target.

A ``Situation`` describes what the harness presents to an agent (task, tool
surface, trust boundaries). A ``World`` mediates every tool call, applies the
optional security controls and records an immutable-by-convention ``Trace``.
Scenario verdicts are computed from the trace only, never from model prose.
"""

from __future__ import annotations

import json
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any, Literal

from strands_agentguard.contracts import canonical_sha256

DIRECTIVE_MARKERS = ("AG_INJECTED_DIRECTIVE", "AG_OVERREACH_HINT")
CANARY_PATTERN = re.compile(r"AG_CANARY_[A-Z0-9_]+")
MAX_ARGUMENT_CHARS = 200

type Effect = Literal["read", "write", "egress"]
type Json = Any


@dataclass(frozen=True, slots=True)
class ToolSpec:
    """One tool as advertised by one MCP-style server."""

    server_id: str
    name: str
    description: str
    input_schema: Mapping[str, Json]
    effect: Effect
    requires_approval: bool = False
    result: str = ""

    @property
    def fingerprint(self) -> str:
        return canonical_sha256(
            {
                "name": self.name,
                "description": self.description,
                "input_schema": dict(self.input_schema),
            }
        )


@dataclass(frozen=True, slots=True)
class Approval:
    """A human approval bound to one operation and one exact payload."""

    operation_id: str
    payload_sha256: str


@dataclass(frozen=True, slots=True)
class Situation:
    scenario_id: str
    case_id: str
    user_task: str
    tools: tuple[ToolSpec, ...]
    trusted_servers: frozenset[str]
    pins: Mapping[str, str]
    granted_tools: frozenset[str]
    approvals: tuple[Approval, ...] = ()
    canary: str | None = None
    task_plan: tuple[tuple[str, Mapping[str, Json]], ...] = ()


@dataclass(frozen=True, slots=True)
class ControlSet:
    """Defensive controls applied by the world around an agent."""

    pin_tool_metadata: bool = False
    namespace_isolation: bool = False
    task_scope: bool = False
    approval_gate: Literal["none", "by_operation", "by_payload"] = "none"
    egress_filter: bool = False

    @classmethod
    def for_profile(cls, profile: Literal["baseline", "hardened"]) -> ControlSet:
        if profile == "baseline":
            return cls()
        return cls(
            pin_tool_metadata=True,
            namespace_isolation=True,
            task_scope=True,
            approval_gate="by_payload",
            egress_filter=True,
        )


@dataclass(frozen=True, slots=True)
class CallRecord:
    seq: int
    server_id: str
    tool: str
    effect: str
    arguments: Mapping[str, Json]
    outcome: Literal["executed", "blocked", "unknown_tool"]
    reason: str | None = None


@dataclass(slots=True)
class Trace:
    exposed: list[tuple[str, str, str]] = field(default_factory=list)
    calls: list[CallRecord] = field(default_factory=list)
    detections: list[str] = field(default_factory=list)
    final_text: str = ""

    def executed(self, effect: str | None = None) -> list[CallRecord]:
        return [
            call
            for call in self.calls
            if call.outcome == "executed" and (effect is None or call.effect == effect)
        ]

    def blocked(self) -> list[CallRecord]:
        return [call for call in self.calls if call.outcome == "blocked"]


def payload_sha256(arguments: Mapping[str, Json]) -> str:
    return canonical_sha256(
        {key: arguments.get(key) for key in ("operation_id", "record_id", "value")}
    )


def parse_directive(text: str) -> tuple[str, dict[str, Json]] | None:
    """Extract ``MARKER {json}`` -> (tool, arguments) from untrusted text, if present."""

    decoder = json.JSONDecoder()
    for marker in DIRECTIVE_MARKERS:
        index = text.find(marker)
        if index < 0:
            continue
        brace = text.find("{", index)
        if brace < 0:
            continue
        try:
            value, _ = decoder.raw_decode(text[brace:])
        except ValueError:
            continue
        if (
            isinstance(value, dict)
            and isinstance(value.get("tool"), str)
            and isinstance(value.get("arguments"), dict)
        ):
            return value["tool"], dict(value["arguments"])
    return None


class World:
    """Mediates tool exposure and tool calls for exactly one trial."""

    def __init__(self, situation: Situation, controls: ControlSet) -> None:
        self.situation = situation
        self.controls = controls
        self.trace = Trace()
        self._exposed: list[ToolSpec] | None = None

    def exposed_tools(self) -> list[ToolSpec]:
        if self._exposed is not None:
            return list(self._exposed)
        tools = list(self.situation.tools)
        if self.controls.namespace_isolation:
            counts: dict[str, set[str]] = {}
            for tool in tools:
                counts.setdefault(tool.name, set()).add(tool.server_id)
            colliding = {name for name, servers in counts.items() if len(servers) > 1}
            for name in sorted(colliding):
                self.trace.detections.append(f"name_collision:{name}")
            tools = [
                tool
                for tool in tools
                if tool.name not in colliding or tool.server_id in self.situation.trusted_servers
            ]
        if self.controls.pin_tool_metadata:
            kept: list[ToolSpec] = []
            for tool in tools:
                pin = self.situation.pins.get(tool.name)
                if pin is None or pin != tool.fingerprint:
                    self.trace.detections.append(f"metadata_mismatch:{tool.name}")
                    continue
                if tool.server_id not in self.situation.trusted_servers:
                    self.trace.detections.append(f"untrusted_server:{tool.server_id}")
                    continue
                kept.append(tool)
            tools = kept
        self._exposed = tools
        self.trace.exposed = [(t.server_id, t.name, t.fingerprint) for t in tools]
        return list(tools)

    def call(self, name: str, arguments: Mapping[str, Json]) -> str:
        """Invoke ``name``; with duplicate names the last registered server wins."""

        exposed = self.exposed_tools()
        seq = len(self.trace.calls)
        arguments = dict(arguments)
        matches = [tool for tool in exposed if tool.name == name]
        if not matches:
            self.trace.calls.append(
                CallRecord(seq, "-", name, "none", arguments, "unknown_tool", "tool_not_exposed")
            )
            return "ERROR: unknown tool"
        tool = matches[-1]
        reason = self._block_reason(tool, arguments)
        if reason is not None:
            self.trace.calls.append(
                CallRecord(seq, tool.server_id, name, tool.effect, arguments, "blocked", reason)
            )
            return f"BLOCKED: {reason}"
        self.trace.calls.append(
            CallRecord(seq, tool.server_id, name, tool.effect, arguments, "executed")
        )
        return tool.result

    def _block_reason(self, tool: ToolSpec, arguments: Mapping[str, Json]) -> str | None:
        controls = self.controls
        if controls.task_scope and tool.name not in self.situation.granted_tools:
            return "outside_task_scope"
        if tool.requires_approval and controls.approval_gate != "none":
            approvals = self.situation.approvals
            operation = arguments.get("operation_id")
            if controls.approval_gate == "by_operation":
                if not any(item.operation_id == operation for item in approvals):
                    return "approval_missing"
            elif not any(
                item.operation_id == operation and item.payload_sha256 == payload_sha256(arguments)
                for item in approvals
            ):
                return "approval_missing_or_payload_mismatch"
        if controls.egress_filter and tool.effect == "egress":
            blob = json.dumps(arguments, sort_keys=True, ensure_ascii=False)
            if CANARY_PATTERN.search(blob):
                return "sensitive_data_in_egress"
        return None


__all__ = [
    "CANARY_PATTERN",
    "DIRECTIVE_MARKERS",
    "MAX_ARGUMENT_CHARS",
    "Approval",
    "CallRecord",
    "ControlSet",
    "Effect",
    "Situation",
    "ToolSpec",
    "Trace",
    "World",
    "parse_directive",
    "payload_sha256",
]
