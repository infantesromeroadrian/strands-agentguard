from __future__ import annotations

import hashlib
import json
from copy import deepcopy
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, cast

import pytest

# jsonschema in the locked environment does not publish a typing marker or stubs.
from jsonschema import Draft202012Validator  # type: ignore[import-untyped, unused-ignore]
from pydantic import BaseModel, ValidationError
from referencing import Registry, Resource

from strands_agentguard import (
    AssessmentResult,
    AssessmentSummary,
    AssessmentTimestamps,
    Finding,
    RunIdentity,
    Scenario,
    ScenarioResult,
    TargetManifest,
    ToolDescriptor,
    canonical_json_bytes,
    canonical_sha256,
)

ROOT = Path(__file__).parents[1]
TARGET_FIXTURES = sorted((ROOT / "fixtures" / "targets").glob("*.json"))
SCENARIO_FIXTURES = sorted((ROOT / "fixtures" / "scenarios" / "v0.1.0").glob("ag-scn-*.json"))


def load_json(path: Path) -> dict[str, Any]:
    return cast(dict[str, Any], json.loads(path.read_text(encoding="utf-8")))


def valid_finding_payload() -> dict[str, Any]:
    return {
        "finding_id": "finding-001",
        "rule_id": "AG-RULE-007",
        "requirement_ids": ["AG-FR-001", "AG-SEC-001"],
        "scenario_id": "AG-SCN-004",
        "severity": "HIGH",
        "confidence": "CONFIRMED",
        "status": "OPEN",
        "disposition": None,
        "title": "Changed tool contract was rejected",
        "evidence_refs": ["artifacts/evidence.json#/events/0"],
        "reproduction": ["Present a changed description under the same tool identifier."],
        "limitations": [],
        "run_id": "run-001",
    }


def valid_run_identity_payload() -> dict[str, Any]:
    ignored_oid = "b" * 64
    payload: dict[str, Any] = {
        "schema_version": "0.1.0",
        "run_id": "run-001",
        "agentguard_candidate": f"commit:{'a' * 40}:{ignored_oid}",
        "target_candidate": f"fixture:hardened:{'c' * 64}",
        "ignored_oid": ignored_oid,
        "manifest_sha256": "d" * 64,
        "threat_catalog_version": "0.1.0",
        "threat_catalog_sha256": "e" * 64,
        "config_sha256": "f" * 64,
        "lock_sha256": "1" * 64,
        "python": "3.12.8",
        "os": "Darwin-24.6.0",
        "architecture": "arm64",
    }
    payload["identity_digest"] = RunIdentity.digest_for(payload)
    return payload


def valid_assessment() -> AssessmentResult:
    run_identity = RunIdentity.model_validate(valid_run_identity_payload())
    finding = Finding.model_validate(valid_finding_payload())
    scenario_result = ScenarioResult(
        scenario_id="AG-SCN-004",
        completed=True,
        passed=False,
        incomplete_reason=None,
        evidence_refs=["artifacts/evidence.json#/events/0"],
        finding_ids=["finding-001"],
    )
    started_at = datetime(2026, 8, 7, 8, 0, tzinfo=UTC)
    return AssessmentResult(
        schema_version="0.1.0",
        run_identity=run_identity,
        target_id="synthetic-agentguard",
        timestamps=AssessmentTimestamps(
            started_at=started_at,
            completed_at=started_at + timedelta(seconds=2),
        ),
        stop_reason="assessment completed",
        scenario_results=[scenario_result],
        findings=[finding],
        metrics={"duration_seconds": 2.0, "scenario_count": 1},
        artifact_hashes={"artifacts/evidence.json": "2" * 64},
        summary=AssessmentSummary(completed=True, incomplete_reason=None),
    )


@pytest.mark.parametrize("fixture_path", TARGET_FIXTURES, ids=lambda path: path.stem)
def test_target_fixtures_satisfy_strict_model(fixture_path: Path) -> None:
    manifest = TargetManifest.model_validate_json(fixture_path.read_text(encoding="utf-8"))

    assert manifest.schema_version == "0.1.0"
    assert manifest.synthetic is True
    assert manifest.real_data is False


@pytest.mark.parametrize("fixture_path", SCENARIO_FIXTURES, ids=lambda path: path.stem)
def test_scenario_fixtures_satisfy_strict_model(fixture_path: Path) -> None:
    scenario = Scenario.model_validate_json(fixture_path.read_text(encoding="utf-8"))

    assert scenario.fixture_ref.endswith(f"{scenario.scenario_id.lower()}.json")
    assert scenario.cleanup.verify is True


def test_tool_fingerprint_has_known_vector_and_terminal_lf() -> None:
    payload = load_json(ROOT / "fixtures" / "targets" / "hardened.json")["tools"][0]
    descriptor = ToolDescriptor.model_validate(payload)
    material = {
        "name": payload["name"],
        "description": payload["description"],
        "input_schema": payload["input_schema"],
    }

    assert descriptor.fingerprint == (
        "ae09a48de73c4eef665de7882dcf3c159a47867929b89171be1f1a9c2d870d77"
    )
    assert descriptor.fingerprint == canonical_sha256_bytes_with_lf(material)
    assert descriptor.fingerprint != canonical_sha256(material)


def canonical_sha256_bytes_with_lf(value: Any) -> str:
    return hashlib.sha256(canonical_json_bytes(value) + b"\n").hexdigest()


@pytest.mark.parametrize("changed_field", ["description", "input_schema"])
def test_tool_fingerprint_is_sensitive_to_registered_surface(changed_field: str) -> None:
    payload = load_json(ROOT / "fixtures" / "targets" / "hardened.json")["tools"][0]
    changed = deepcopy(payload)
    if changed_field == "description":
        changed["description"] = f"{changed['description']} Changed."
    else:
        changed["input_schema"]["properties"]["extra"] = {"type": "string"}

    with pytest.raises(ValidationError, match="fingerprint"):
        ToolDescriptor.model_validate(changed)


def test_tool_fingerprint_excludes_policy_metadata() -> None:
    payload = load_json(ROOT / "fixtures" / "targets" / "hardened.json")["tools"][0]

    assert ToolDescriptor.fingerprint_for(
        name=payload["name"],
        description=payload["description"],
        input_schema=payload["input_schema"],
    ) == ToolDescriptor.fingerprint_for(
        name=payload["name"],
        description=payload["description"],
        input_schema=deepcopy(payload["input_schema"]),
    )


@pytest.mark.parametrize(
    ("mutation", "error"),
    [
        (lambda data: data.update({"unknown": True}), "extra_forbidden"),
        (lambda data: data.update({"candidate_identity": "0313c66"}), "candidate_identity"),
        (lambda data: data.update({"contract_files": ["../private.json"]}), "contract_files"),
        (
            lambda data: data.update({"capabilities": list(reversed(data["capabilities"]))}),
            "manifest list",
        ),
    ],
)
def test_target_manifest_rejects_unsafe_or_ambiguous_data(
    mutation: Any,
    error: str,
) -> None:
    payload = load_json(ROOT / "fixtures" / "targets" / "hardened.json")
    mutation(payload)

    with pytest.raises(ValidationError, match=error):
        TargetManifest.model_validate(payload)


def test_target_manifest_rejects_secret_shaped_provider_extension() -> None:
    payload = load_json(ROOT / "fixtures" / "targets" / "hardened.json")
    payload["provider"]["api_key"] = "private-value"

    with pytest.raises(ValidationError, match="extra_forbidden"):
        TargetManifest.model_validate(payload)


def test_target_manifest_rejects_permission_reference_mismatch() -> None:
    payload = load_json(ROOT / "fixtures" / "targets" / "hardened.json")
    payload["permissions"]["approval"] = []

    with pytest.raises(ValidationError, match="permission lists"):
        TargetManifest.model_validate(payload)


@pytest.mark.parametrize(
    "mutation",
    [
        lambda data: data.update({"unexpected": "value"}),
        lambda data: data.update({"fixture_ref": "../ag-scn-001.json"}),
        lambda data: data.update({"fixture_ref": "fixtures/scenarios/v0.1.0/ag-scn-999.json"}),
        lambda data: data["cleanup"].update({"verify": False}),
        lambda data: data["expected_trajectory"]["forbidden_events"].append(
            data["expected_trajectory"]["required_order"][0]
        ),
    ],
)
def test_scenario_rejects_unknown_fields_unsafe_paths_and_incoherent_trajectory(
    mutation: Any,
) -> None:
    payload = load_json(SCENARIO_FIXTURES[0])
    mutation(payload)

    with pytest.raises(ValidationError):
        Scenario.model_validate(payload)


def test_finding_accepts_explicit_nullable_or_classified_disposition() -> None:
    open_finding = Finding.model_validate(valid_finding_payload())
    classified_payload = valid_finding_payload()
    classified_payload["disposition"] = "ACCEPTED_RISK"
    classified = Finding.model_validate(classified_payload)

    assert open_finding.status == classified.status == "OPEN"
    assert open_finding.disposition is None
    assert classified.disposition == "ACCEPTED_RISK"
    assert classified.severity == "HIGH"


@pytest.mark.parametrize(
    "mutation",
    [
        lambda data: data.pop("disposition"),
        lambda data: data.update({"status": "CLOSED"}),
        lambda data: data.update({"requirement_ids": ["REQ-1"]}),
        lambda data: data.update({"evidence_refs": ["../../private"]}),
        lambda data: data.update({"unknown": True}),
    ],
)
def test_finding_rejects_incomplete_or_unsafe_data(mutation: Any) -> None:
    payload = valid_finding_payload()
    mutation(payload)

    with pytest.raises(ValidationError):
        Finding.model_validate(payload)


def test_run_identity_digest_is_canonical_and_order_independent() -> None:
    payload = valid_run_identity_payload()
    identity = RunIdentity.model_validate(payload)
    reversed_payload = dict(reversed(list(payload.items())))

    assert identity.identity_digest == RunIdentity.digest_for(reversed_payload)
    assert identity.expected_identity_digest() == identity.identity_digest


def test_run_identity_rejects_changed_material_and_invalid_oids() -> None:
    changed = valid_run_identity_payload()
    changed["config_sha256"] = "2" * 64
    with pytest.raises(ValidationError, match="identity_digest"):
        RunIdentity.model_validate(changed)

    abbreviated = valid_run_identity_payload()
    abbreviated["agentguard_candidate"] = "a" * 7
    abbreviated["identity_digest"] = RunIdentity.digest_for(abbreviated)
    with pytest.raises(ValidationError, match="agentguard_candidate"):
        RunIdentity.model_validate(abbreviated)

    mismatched_ignored = valid_run_identity_payload()
    mismatched_ignored["ignored_oid"] = "3" * 64
    mismatched_ignored["identity_digest"] = RunIdentity.digest_for(mismatched_ignored)
    with pytest.raises(ValidationError, match="embedded ignored_oid"):
        RunIdentity.model_validate(mismatched_ignored)


def test_assessment_result_round_trips_as_source_json() -> None:
    result = valid_assessment()

    assert AssessmentResult.model_validate_json(result.model_dump_json()) == result
    assert result.summary.completed is True
    assert result.findings[0].run_id == result.run_identity.run_id


def test_assessment_result_represents_incomplete_scenario_explicitly() -> None:
    run_identity = RunIdentity.model_validate(valid_run_identity_payload())
    started_at = datetime(2026, 8, 7, 8, 0, tzinfo=UTC)

    result = AssessmentResult(
        schema_version="0.1.0",
        run_identity=run_identity,
        target_id="synthetic-agentguard",
        timestamps=AssessmentTimestamps(
            started_at=started_at,
            completed_at=started_at + timedelta(seconds=1),
        ),
        stop_reason="configured limit reached",
        scenario_results=[
            ScenarioResult(
                scenario_id="AG-SCN-004",
                completed=False,
                passed=None,
                incomplete_reason="Tool timeout reached",
                evidence_refs=[],
                finding_ids=[],
            )
        ],
        findings=[],
        metrics={"duration_seconds": 1},
        artifact_hashes={},
        summary=AssessmentSummary(
            completed=False,
            incomplete_reason="At least one scenario did not complete",
        ),
    )

    assert result.summary.incomplete_reason is not None
    assert result.scenario_results[0].passed is None


def test_assessment_result_rejects_cross_contract_inconsistency() -> None:
    result = valid_assessment().model_dump(mode="python")
    result["findings"][0]["run_id"] = "different-run"

    with pytest.raises(ValidationError, match="run_id"):
        AssessmentResult.model_validate(result)


def test_assessment_result_rejects_invalid_time_metric_and_path() -> None:
    result = valid_assessment().model_dump(mode="python")
    result["timestamps"]["completed_at"] = result["timestamps"]["started_at"] - timedelta(seconds=1)
    with pytest.raises(ValidationError, match="completed_at"):
        AssessmentResult.model_validate(result)

    result = valid_assessment().model_dump(mode="python")
    result["metrics"]["duration_seconds"] = -1
    with pytest.raises(ValidationError, match="greater than or equal"):
        AssessmentResult.model_validate(result)

    result = valid_assessment().model_dump(mode="python")
    result["artifact_hashes"] = {"../evidence.json": "2" * 64}
    with pytest.raises(ValidationError, match="artifact_hashes"):
        AssessmentResult.model_validate(result)


def schema_registry() -> tuple[dict[str, dict[str, Any]], Registry[Any]]:
    schemas = {
        path.name: load_json(path) for path in sorted((ROOT / "schemas").glob("*.schema.json"))
    }
    registry = Registry().with_resources(
        (uri, Resource.from_contents(schema))
        for name, schema in schemas.items()
        for uri in (schema["$id"], f"schemas/{name}")
    )
    return schemas, registry


@pytest.mark.parametrize(
    ("schema_name", "model"),
    [
        ("tool-descriptor.schema.json", ToolDescriptor),
        ("target-manifest.schema.json", TargetManifest),
        ("scenario.schema.json", Scenario),
        ("finding.schema.json", Finding),
        ("run-identity.schema.json", RunIdentity),
        ("assessment-result.schema.json", AssessmentResult),
    ],
)
def test_json_schema_top_level_matches_model_contract(
    schema_name: str,
    model: type[BaseModel],
) -> None:
    schemas, _ = schema_registry()
    schema = schemas[schema_name]

    assert schema["additionalProperties"] is False
    assert set(schema["required"]) == set(model.model_fields)


def test_json_schemas_accept_representative_contracts_and_fixtures() -> None:
    schemas, registry = schema_registry()
    target = load_json(ROOT / "fixtures" / "targets" / "hardened.json")
    scenario = load_json(SCENARIO_FIXTURES[0])
    run_identity = RunIdentity.model_validate(valid_run_identity_payload())
    finding = Finding.model_validate(valid_finding_payload())
    assessment = valid_assessment()
    examples = {
        "tool-descriptor.schema.json": target["tools"][0],
        "target-manifest.schema.json": target,
        "scenario.schema.json": scenario,
        "finding.schema.json": finding.model_dump(mode="json"),
        "run-identity.schema.json": run_identity.model_dump(mode="json"),
        "assessment-result.schema.json": assessment.model_dump(mode="json"),
    }

    for schema_name, instance in examples.items():
        Draft202012Validator(schemas[schema_name], registry=registry).validate(instance)

    target_validator = Draft202012Validator(
        schemas["target-manifest.schema.json"], registry=registry
    )
    scenario_validator = Draft202012Validator(schemas["scenario.schema.json"], registry=registry)
    for fixture_path in TARGET_FIXTURES:
        target_validator.validate(load_json(fixture_path))
    for fixture_path in SCENARIO_FIXTURES:
        scenario_validator.validate(load_json(fixture_path))

    Draft202012Validator(schemas["corpus-manifest.schema.json"], registry=registry).validate(
        load_json(ROOT / "fixtures" / "scenarios" / "v0.1.0" / "manifest.json")
    )


def test_every_schema_is_valid_draft_2020_12() -> None:
    schemas, _ = schema_registry()

    for schema in schemas.values():
        Draft202012Validator.check_schema(schema)
