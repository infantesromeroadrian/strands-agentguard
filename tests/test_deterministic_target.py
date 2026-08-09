from __future__ import annotations

import hashlib
import json
import os
import shutil
from copy import deepcopy
from pathlib import Path
from typing import Any, cast

import pytest

from strands_agentguard import (
    DeterministicTarget,
    TargetInputRejected,
    TargetValidationError,
    UnsupportedScenarioError,
    fixture_candidate_identity,
    fixture_identity_digest,
    validate_fixture_identity,
)
from strands_agentguard.targets import load_scenario_corpus

ROOT = Path(__file__).parents[1]
CORPUS_ROOT = ROOT / "fixtures" / "scenarios" / "v0.1.0"


def copy_corpus(tmp_path: Path) -> Path:
    destination = tmp_path / "fixtures" / "scenarios" / "v0.1.0"
    shutil.copytree(CORPUS_ROOT, destination)
    return destination


def load_json_object(path: Path) -> dict[str, Any]:
    return cast(dict[str, Any], json.loads(path.read_text(encoding="utf-8")))


def write_json_object(path: Path, document: dict[str, Any]) -> None:
    path.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")


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


@pytest.mark.parametrize("scenario_id", ["AG-SCN-001", "AG-SCN-003", "AG-SCN-999"])
def test_sensitive_action_rejects_every_unregistered_scenario_before_effects(
    scenario_id: str,
) -> None:
    target = load_target()

    with pytest.raises(UnsupportedScenarioError, match="sensitive-action adapter"):
        target.simulate_sensitive_action(
            profile="baseline",
            payload={"operation_id": "op-001", "record_id": "record-001", "value": "synthetic"},
            approval_granted=False,
            scenario_id=scenario_id,
        )


@pytest.mark.parametrize(
    "approval_granted",
    [
        pytest.param("false", id="string-truthy"),
        pytest.param(1, id="integer-truthy"),
        pytest.param(0, id="integer-falsy"),
        pytest.param(None, id="none-falsy"),
    ],
)
def test_public_approval_interfaces_reject_non_boolean_values(
    approval_granted: object,
) -> None:
    target = load_target()
    payload = {"operation_id": "op-001", "record_id": "record-001", "value": "synthetic"}

    with pytest.raises(TargetInputRejected, match="approval_granted must be a strict boolean"):
        target.simulate_sensitive_action(
            profile="hardened",
            payload=payload,
            approval_granted=cast(bool, approval_granted),
        )
    with pytest.raises(TargetInputRejected, match="approval_granted must be a strict boolean"):
        target.execute_scenario(
            "AG-SCN-002",
            profile="hardened",
            approval_granted=cast(bool, approval_granted),
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


def test_corpus_manifest_bytes_are_read_once_for_hashing_and_parsing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manifest_path = CORPUS_ROOT / "manifest.json"
    expected_manifest_hash = hashlib.sha256(manifest_path.read_bytes()).hexdigest()
    original_open = os.open
    manifest_opens = 0

    def tracked_open(
        path: str | bytes | os.PathLike[str] | os.PathLike[bytes],
        flags: int,
        mode: int = 0o777,
        *,
        dir_fd: int | None = None,
    ) -> int:
        nonlocal manifest_opens
        if path == "manifest.json":
            manifest_opens += 1
        return original_open(path, flags, mode, dir_fd=dir_fd)

    monkeypatch.setattr(os, "open", tracked_open)

    corpus = load_scenario_corpus(ROOT)

    assert corpus.manifest_sha256 == expected_manifest_hash
    assert manifest_opens == 1


def test_corpus_rejects_a_self_consistent_nine_scenario_subset(tmp_path: Path) -> None:
    corpus_root = copy_corpus(tmp_path)
    manifest_path = corpus_root / "manifest.json"
    manifest = load_json_object(manifest_path)
    entries = cast(list[dict[str, Any]], manifest["scenarios"])
    removed_entry = entries.pop()
    manifest["scenario_count"] = len(entries)
    (tmp_path / cast(str, removed_entry["path"])).unlink()
    write_json_object(manifest_path, manifest)

    with pytest.raises(TargetValidationError, match="exactly the ten"):
        load_scenario_corpus(tmp_path)


def test_corpus_rejects_a_sorted_but_noncanonical_scenario_set(tmp_path: Path) -> None:
    corpus_root = copy_corpus(tmp_path)
    manifest_path = corpus_root / "manifest.json"
    manifest = load_json_object(manifest_path)
    entries = cast(list[dict[str, Any]], manifest["scenarios"])
    replacement_entry = entries[-1]
    original_fixture = corpus_root / "ag-scn-010.json"
    replacement_fixture = corpus_root / "ag-scn-011.json"
    fixture = load_json_object(original_fixture)
    replacement_path = "fixtures/scenarios/v0.1.0/ag-scn-011.json"
    fixture["scenario_id"] = "AG-SCN-011"
    fixture["fixture_ref"] = replacement_path
    replacement_bytes = (json.dumps(fixture, indent=2) + "\n").encode()
    replacement_fixture.write_bytes(replacement_bytes)
    original_fixture.unlink()
    replacement_entry.update(
        {
            "scenario_id": "AG-SCN-011",
            "path": replacement_path,
            "sha256": hashlib.sha256(replacement_bytes).hexdigest(),
        }
    )
    write_json_object(manifest_path, manifest)

    with pytest.raises(TargetValidationError, match="AG-SCN-001 through AG-SCN-010"):
        load_scenario_corpus(tmp_path)


def test_corpus_rejects_traversal_before_reading_a_fixture(tmp_path: Path) -> None:
    corpus_root = copy_corpus(tmp_path)
    manifest_path = corpus_root / "manifest.json"
    manifest = load_json_object(manifest_path)
    entries = cast(list[dict[str, Any]], manifest["scenarios"])
    entries[0]["path"] = "fixtures/scenarios/v0.1.0/../v0.1.0/ag-scn-001.json"
    write_json_object(manifest_path, manifest)

    with pytest.raises(TargetValidationError, match="traversal-free"):
        load_scenario_corpus(tmp_path)


@pytest.mark.parametrize("filename", ["manifest.json", "ag-scn-001.json"])
def test_corpus_rejects_symlinked_manifest_and_fixtures(
    tmp_path: Path,
    filename: str,
) -> None:
    corpus_root = copy_corpus(tmp_path)
    material_path = corpus_root / filename
    outside_path = tmp_path / f"outside-{filename}"
    shutil.copy2(material_path, outside_path)
    material_path.unlink()
    material_path.symlink_to(outside_path)

    with pytest.raises(TargetValidationError, match="regular non-symlink"):
        load_scenario_corpus(tmp_path)


def test_corpus_rejects_non_regular_fixture_material(tmp_path: Path) -> None:
    corpus_root = copy_corpus(tmp_path)
    fixture_path = corpus_root / "ag-scn-001.json"
    fixture_path.unlink()
    fixture_path.mkdir()

    with pytest.raises(TargetValidationError, match="regular non-symlink"):
        load_scenario_corpus(tmp_path)


@pytest.mark.parametrize("filename", ["manifest.json", "ag-scn-001.json"])
def test_corpus_rejects_concurrent_symlink_substitution_after_file_open(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    filename: str,
) -> None:
    corpus_root = copy_corpus(tmp_path)
    material_path = corpus_root / filename
    outside_path = tmp_path / f"outside-race-{filename}"
    shutil.copy2(material_path, outside_path)
    original_open = os.open
    substituted = False

    def substituting_open(
        path: str | bytes | os.PathLike[str] | os.PathLike[bytes],
        flags: int,
        mode: int = 0o777,
        *,
        dir_fd: int | None = None,
    ) -> int:
        nonlocal substituted
        descriptor = original_open(path, flags, mode, dir_fd=dir_fd)
        if path == filename and dir_fd is not None and not substituted:
            assert flags & os.O_NOFOLLOW
            material_path.unlink()
            material_path.symlink_to(outside_path)
            substituted = True
        return descriptor

    monkeypatch.setattr(os, "open", substituting_open)

    with pytest.raises(TargetValidationError, match="material changed while loading"):
        load_scenario_corpus(tmp_path)
    assert substituted


def test_corpus_rejects_concurrent_parent_symlink_substitution_after_directory_open(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository_root = tmp_path / "repository"
    corpus_root = copy_corpus(repository_root)
    outside_root = tmp_path / "outside-race-corpus"
    shutil.copytree(CORPUS_ROOT, outside_root)
    opened_root = tmp_path / "opened-corpus"
    original_open = os.open
    substituted = False

    def substituting_open(
        path: str | bytes | os.PathLike[str] | os.PathLike[bytes],
        flags: int,
        mode: int = 0o777,
        *,
        dir_fd: int | None = None,
    ) -> int:
        nonlocal substituted
        descriptor = original_open(path, flags, mode, dir_fd=dir_fd)
        if path == "v0.1.0" and dir_fd is not None and not substituted:
            assert flags & os.O_NOFOLLOW
            corpus_root.rename(opened_root)
            corpus_root.symlink_to(outside_root, target_is_directory=True)
            substituted = True
        return descriptor

    monkeypatch.setattr(os, "open", substituting_open)

    with pytest.raises(TargetValidationError, match="directory changed while loading"):
        load_scenario_corpus(repository_root)
    assert substituted


def test_corpus_rejects_a_symlinked_corpus_directory_that_resolves_outside_root(
    tmp_path: Path,
) -> None:
    outside_root = tmp_path / "outside"
    shutil.copytree(CORPUS_ROOT, outside_root)
    repository_root = tmp_path / "repository"
    scenarios_root = repository_root / "fixtures" / "scenarios"
    scenarios_root.mkdir(parents=True)
    (scenarios_root / "v0.1.0").symlink_to(outside_root, target_is_directory=True)

    with pytest.raises(TargetValidationError, match=r"corpus directory.*unsafe"):
        load_scenario_corpus(repository_root)


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
