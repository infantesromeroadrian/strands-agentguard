from __future__ import annotations

import json
import os
import socket
import subprocess
from pathlib import Path
from typing import Any, cast

import pytest

from strands_agentguard import (
    LOCAL_TOOL_DEFINITIONS,
    MAX_LARGE_RESULT_BYTES,
    IdempotencyConflict,
    LocalToolInputRejected,
    LocalToolNotAvailable,
    SyntheticToolRuntime,
    TargetManifest,
)

ROOT = Path(__file__).parents[1]


def test_five_definitions_are_bounded_and_match_both_target_manifests() -> None:
    expected_names = [
        "adversarial_result",
        "large_result",
        "read_evidence",
        "read_inventory",
        "simulate_sensitive_action",
    ]
    assert [definition.name for definition in LOCAL_TOOL_DEFINITIONS] == expected_names
    assert all(definition.max_input_bytes > 0 for definition in LOCAL_TOOL_DEFINITIONS)
    assert all(definition.max_output_bytes > 0 for definition in LOCAL_TOOL_DEFINITIONS)

    for fixture_name in ("vulnerable.json", "hardened.json"):
        manifest = TargetManifest.model_validate_json(
            (ROOT / "fixtures" / "targets" / fixture_name).read_bytes()
        )
        assert [tool.name for tool in manifest.tools] == expected_names
        assert [tool.fingerprint for tool in manifest.tools] == [
            definition.fingerprint for definition in LOCAL_TOOL_DEFINITIONS
        ]
        server_names = {
            tool.name for tool in manifest.tools if tool.tool_id in manifest.mcp_servers[0].tool_ids
        }
        assert server_names == set(expected_names) - {"large_result"}

    properties = cast(dict[str, Any], LOCAL_TOOL_DEFINITIONS[0].input_schema["properties"])
    with pytest.raises(TypeError):
        properties["new"] = {"type": "string"}


def test_sanitized_reads_and_controlled_adversarial_result_are_bounded() -> None:
    runtime = SyntheticToolRuntime()

    evidence = runtime.invoke("read_evidence", {"evidence_id": "evidence-001"})
    inventory = runtime.invoke("read_inventory", {"inventory_id": "inventory-001"})
    adversarial = runtime.invoke("adversarial_result", {"scenario_id": "AG-SCN-003"})

    assert evidence["sanitized"] is True
    assert "credential" in str(evidence["content"])
    assert inventory["normalized"] is True
    assert len(inventory["items"]) == 2  # type: ignore[arg-type]
    assert adversarial["trust"] == "untrusted"
    assert adversarial["policy_changed"] is False
    assert runtime.effect_count == 0


@pytest.mark.parametrize(
    ("name", "arguments"),
    [
        ("read_evidence", {"evidence_id": "evidence-001", "extra": True}),
        ("read_evidence", {"evidence_id": "not-allowlisted"}),
        ("read_inventory", {"inventory_id": "I" * 65}),
        ("adversarial_result", {"scenario_id": "AG-SCN-004"}),
        (
            "simulate_sensitive_action",
            {"operation_id": "op-001", "record_id": "record-001", "value": ""},
        ),
        (
            "simulate_sensitive_action",
            {"operation_id": "op-001", "record_id": "record-001", "value": "x" * 65},
        ),
        ("large_result", {"size_bytes": MAX_LARGE_RESULT_BYTES + 1}),
    ],
)
def test_invalid_or_oversized_inputs_fail_before_effects(
    name: str,
    arguments: dict[str, Any],
) -> None:
    runtime = SyntheticToolRuntime()

    with pytest.raises(LocalToolInputRejected):
        runtime.invoke(name, arguments)

    assert runtime.effect_count == 0


def test_unregistered_tool_fails_closed() -> None:
    runtime = SyntheticToolRuntime()

    with pytest.raises(LocalToolNotAvailable, match="not registered"):
        runtime.invoke("shell", {})


def test_operation_id_is_the_idempotency_key_and_conflicts_fail_closed() -> None:
    runtime = SyntheticToolRuntime()
    operation = {
        "operation_id": "op-001",
        "record_id": "record-001",
        "value": "synthetic",
    }

    first = runtime.invoke("simulate_sensitive_action", operation)
    repeated = runtime.invoke("simulate_sensitive_action", dict(reversed(operation.items())))

    assert first == repeated
    assert runtime.effect_count == 1
    assert len(runtime.effects) == 1
    with pytest.raises(IdempotencyConflict, match="already bound"):
        runtime.invoke(
            "simulate_sensitive_action",
            {**operation, "value": "different"},
        )
    assert runtime.effect_count == 1
    assert runtime.effects[0]["value"] == "synthetic"


@pytest.mark.parametrize("size_bytes", [1, 2, 257, MAX_LARGE_RESULT_BYTES])
def test_large_result_is_exact_and_repeatable(size_bytes: int) -> None:
    runtime = SyntheticToolRuntime()

    first = runtime.invoke("large_result", {"size_bytes": size_bytes})
    second = runtime.invoke("large_result", {"size_bytes": size_bytes})

    assert first == second
    assert first["size_bytes"] == size_bytes
    assert len(str(first["data"]).encode("ascii")) == size_bytes
    assert runtime.effect_count == 0


def test_every_tool_executes_without_filesystem_network_or_subprocess(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime = SyntheticToolRuntime()

    def forbidden(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("external effect attempted")

    monkeypatch.setattr(os, "open", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)

    assert runtime.invoke("read_evidence", {"evidence_id": "evidence-001"})
    assert runtime.invoke("read_inventory", {"inventory_id": "inventory-001"})
    assert runtime.invoke("adversarial_result", {"scenario_id": "AG-SCN-003"})
    assert runtime.invoke("large_result", {"size_bytes": 32})
    assert runtime.invoke(
        "simulate_sensitive_action",
        {"operation_id": "op-001", "record_id": "record-001", "value": "synthetic"},
    )
    assert runtime.effect_count == 1
    assert json.dumps(dict(runtime.effects[0]))
