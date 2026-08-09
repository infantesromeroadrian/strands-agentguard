from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path
from typing import Any, cast

import pytest

from strands_agentguard import (
    DeterministicTarget,
    TargetInputRejected,
    UnsupportedScenarioError,
    fixture_candidate_identity,
    fixture_identity_digest,
    validate_fixture_identity,
)

ROOT = Path(__file__).parents[1]


def load_target() -> DeterministicTarget:
    return DeterministicTarget.from_repository(ROOT)


def test_one_engine_reuses_one_corpus_and_one_declared_surface_for_both_profiles() -> None:
    target = load_target()
    baseline = target.manifests["baseline"]
    hardened = target.manifests["hardened"]

    assert target.engine_id == "agentguard-in-memory-v0.1.0"
    assert set(target.manifests) == {"baseline", "hardened"}
    assert len(target.corpus.scenarios) == 10
    assert [tool.tool_id for tool in target.tool_surface] == [
        tool.tool_id for tool in baseline.tools
    ]
    assert [tool.fingerprint for tool in target.tool_surface] == [
        tool.fingerprint for tool in hardened.tools
    ]
    assert baseline.provider == hardened.provider
    assert baseline.mcp_servers == hardened.mcp_servers


def test_profile_policy_is_the_only_sensitive_action_differential() -> None:
    target = load_target()
    payload = {"operation_id": "op-001", "record_id": "record-001", "value": "synthetic"}

    baseline = target.simulate_sensitive_action(
        profile="baseline", payload=payload, approval_granted=False
    )
    hardened = target.simulate_sensitive_action(
        profile="hardened", payload=payload, approval_granted=False
    )

    assert baseline.effect_count == 1
    assert baseline.policy_decision == "allowed_without_approval"
    assert hardened.effect_count == 0
    assert hardened.policy_decision == "approval_required"
    assert all(
        {"cloud", "filesystem_arbitrary", "network", "shell", "subprocess"}.issubset(
            manifest.permissions.deny
        )
        for manifest in target.manifests.values()
    )


def test_sensitive_action_validates_untrusted_input_before_any_effect() -> None:
    target = load_target()

    with pytest.raises(TargetInputRejected, match="does not match"):
        target.simulate_sensitive_action(
            profile="baseline",
            payload={"operation_id": "op-001", "record_id": "record-001", "path": "/tmp/x"},
            approval_granted=False,
        )


@pytest.mark.parametrize(
    ("scenario_id", "approval_granted", "expected_effects"),
    [
        ("AG-SCN-001", False, 0),
        ("AG-SCN-002", True, 1),
        ("AG-SCN-003", False, 0),
    ],
)
def test_existing_corpus_scenarios_have_executable_deterministic_coverage(
    scenario_id: str,
    approval_granted: bool,
    expected_effects: int,
) -> None:
    target = load_target()
    scenario = target.corpus.get(scenario_id)

    result = target.execute_scenario(
        scenario_id,
        profile="hardened",
        approval_granted=approval_granted,
    )

    assert result.effect_count == expected_effects
    assert result.trajectory == scenario.expected_trajectory.required_order
    for assertion in scenario.expected_outcome.assertions:
        assert assertion.operator == "equals"
        assert result.outcome[assertion.field] == assertion.value


def test_adversarial_result_is_data_and_cannot_change_policy() -> None:
    target = load_target()

    result = target.execute_scenario("AG-SCN-003", profile="hardened")

    assert result.outcome == {"effect_count": 0, "policy_changed": False}
    assert result.effects == ()
    assert result.policy_decision == "untrusted_content_ignored"


def test_unregistered_scenario_fails_closed_without_falling_through_corpus() -> None:
    target = load_target()

    with pytest.raises(UnsupportedScenarioError, match="no deterministic"):
        target.execute_scenario("AG-SCN-004", profile="hardened")


@pytest.mark.parametrize("fixture_name", ["vulnerable.json", "hardened.json"])
def test_fixture_identity_is_canonical_non_self_referential_and_material(fixture_name: str) -> None:
    path = ROOT / "fixtures" / "targets" / fixture_name
    document = cast(dict[str, Any], json.loads(path.read_text(encoding="utf-8")))
    validate_fixture_identity(document)

    original_digest = fixture_identity_digest(document)
    changed_identity = deepcopy(document)
    changed_identity["candidate_identity"] = "fixture:probe:" + "0" * 64
    material_change = deepcopy(document)
    material_change["limits"]["max_iterations"] -= 1

    assert fixture_identity_digest(changed_identity) == original_digest
    assert fixture_candidate_identity(document) == document["candidate_identity"]
    assert fixture_candidate_identity(material_change) != document["candidate_identity"]
