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
from jsonschema.exceptions import (  # type: ignore[import-untyped, unused-ignore]
    ValidationError as JsonSchemaValidationError,
)
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
from strands_agentguard.contracts import (
    DRAFT_2020_12_SCHEMA,
    MAX_SAFE_INTEGER,
    MIN_SAFE_INTEGER,
    validate_contract_document,
)

ROOT = Path(__file__).parents[1]
TARGET_FIXTURES = sorted((ROOT / "fixtures" / "targets").glob("*.json"))
SCENARIO_FIXTURES = sorted((ROOT / "fixtures" / "scenarios" / "v0.1.0").glob("ag-scn-*.json"))


def load_json(path: Path) -> dict[str, Any]:
    return cast(dict[str, Any], json.loads(path.read_text(encoding="utf-8")))


def add_explicit_dialect(tool_payload: dict[str, Any]) -> dict[str, Any]:
    payload = deepcopy(tool_payload)
    payload["input_schema"]["$schema"] = DRAFT_2020_12_SCHEMA
    payload["fingerprint"] = ToolDescriptor.fingerprint_for(
        name=payload["name"],
        description=payload["description"],
        input_schema=payload["input_schema"],
    )
    return payload


def valid_tool_payload(index: int = 0) -> dict[str, Any]:
    target = load_json(ROOT / "fixtures" / "targets" / "hardened.json")
    return add_explicit_dialect(cast(dict[str, Any], target["tools"][index]))


def valid_target_payload(fixture_path: Path | None = None) -> dict[str, Any]:
    path = fixture_path or ROOT / "fixtures" / "targets" / "hardened.json"
    payload = load_json(path)
    payload["tools"] = [add_explicit_dialect(tool) for tool in payload["tools"]]
    return payload


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


def valid_run_identity_payload(oid_length: int = 40) -> dict[str, Any]:
    ignored_oid = "b" * oid_length
    payload: dict[str, Any] = {
        "schema_version": "0.1.0",
        "run_id": "run-001",
        "agentguard_candidate": f"commit:{'a' * oid_length}:{ignored_oid}",
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
        evidence_refs=("artifacts/evidence.json#/events/0",),
        finding_ids=("finding-001",),
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
        scenario_results=(scenario_result,),
        findings=(finding,),
        metrics={"duration_seconds": 2.0, "scenario_count": 1},
        artifact_hashes={"artifacts/evidence.json": "2" * 64},
        summary=AssessmentSummary(completed=True, incomplete_reason=None),
    )


@pytest.mark.parametrize("fixture_path", TARGET_FIXTURES, ids=lambda path: path.stem)
def test_migrated_target_fixtures_satisfy_strict_model(fixture_path: Path) -> None:
    manifest = TargetManifest.model_validate_json(fixture_path.read_text(encoding="utf-8"))

    assert manifest.schema_version == "0.1.0"
    assert manifest.synthetic is True
    assert manifest.real_data is False


@pytest.mark.parametrize("fixture_path", SCENARIO_FIXTURES, ids=lambda path: path.stem)
def test_scenario_fixtures_satisfy_strict_model(fixture_path: Path) -> None:
    scenario = Scenario.model_validate_json(fixture_path.read_text(encoding="utf-8"))

    assert scenario.fixture_ref.endswith(f"{scenario.scenario_id.lower()}.json")
    assert scenario.cleanup.verify is True


def test_scenario_manifest_entries_match_all_frozen_fixtures() -> None:
    manifest = load_json(ROOT / "fixtures" / "scenarios" / "v0.1.0" / "manifest.json")
    entries = cast(list[dict[str, Any]], manifest["scenarios"])

    assert len(SCENARIO_FIXTURES) == 10
    assert manifest["scenario_count"] == len(entries) == len(SCENARIO_FIXTURES)

    for entry, fixture_path in zip(entries, SCENARIO_FIXTURES, strict=True):
        scenario = load_json(fixture_path)

        assert entry["scenario_id"] == scenario["scenario_id"]
        assert entry["path"] == fixture_path.relative_to(ROOT).as_posix()
        assert entry["sha256"] == hashlib.sha256(fixture_path.read_bytes()).hexdigest()


def test_tool_fingerprint_has_known_vector_and_terminal_lf() -> None:
    payload = valid_tool_payload()
    descriptor = ToolDescriptor.model_validate(payload)
    material = {
        "name": payload["name"],
        "description": payload["description"],
        "input_schema": payload["input_schema"],
    }

    assert descriptor.fingerprint == (
        "b742eaadeab321b08386311af91590c3d35acc11f6f590a1201ab0aae709231c"
    )
    assert descriptor.fingerprint == canonical_sha256_bytes_with_lf(material)
    assert descriptor.fingerprint != canonical_sha256(material)


def canonical_sha256_bytes_with_lf(value: Any) -> str:
    return hashlib.sha256(canonical_json_bytes(value) + b"\n").hexdigest()


@pytest.mark.parametrize("changed_field", ["description", "input_schema"])
def test_tool_fingerprint_is_sensitive_to_registered_surface(changed_field: str) -> None:
    payload = valid_tool_payload()
    changed = deepcopy(payload)
    if changed_field == "description":
        changed["description"] = f"{changed['description']} Changed."
    else:
        changed["input_schema"]["properties"]["extra"] = {"type": "string"}

    with pytest.raises(ValidationError, match="fingerprint"):
        ToolDescriptor.model_validate(changed)


def test_tool_fingerprint_excludes_policy_metadata() -> None:
    payload = valid_tool_payload()

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
    payload = valid_target_payload()
    mutation(payload)

    with pytest.raises(ValidationError, match=error):
        TargetManifest.model_validate(payload)


def test_target_manifest_rejects_secret_shaped_provider_extension() -> None:
    payload = valid_target_payload()
    payload["provider"]["api_key"] = "private-value"

    with pytest.raises(ValidationError, match="extra_forbidden"):
        TargetManifest.model_validate(payload)


def test_target_manifest_rejects_permission_reference_mismatch() -> None:
    payload = valid_target_payload()
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


@pytest.mark.parametrize("candidate_field", ["agentguard_candidate", "target_candidate"])
def test_run_identity_rejects_embedded_ignored_oid_mismatch_with_canonical_parity(
    candidate_field: str,
) -> None:
    payload = valid_run_identity_payload()
    payload[candidate_field] = f"commit:{'a' * 40}:{'c' * 40}"
    payload["identity_digest"] = RunIdentity.digest_for(payload)

    with pytest.raises(ValidationError, match="embedded ignored_oid"):
        RunIdentity.model_validate(payload)
    # Cross-field equality is not expressible in standard Draft 2020-12.
    validate_schema("run-identity.schema.json", payload)
    with pytest.raises(ValidationError, match="embedded ignored_oid"):
        validate_contract("run-identity.schema.json", payload)


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
        scenario_results=(
            ScenarioResult(
                scenario_id="AG-SCN-004",
                completed=False,
                passed=None,
                incomplete_reason="Tool timeout reached",
                evidence_refs=(),
                finding_ids=(),
            ),
        ),
        findings=(),
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
        (schema["$id"], Resource.from_contents(schema)) for schema in schemas.values()
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
    target = valid_target_payload()
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
        validator = Draft202012Validator(schemas[schema_name], registry=registry)
        validator.validate(instance)
        validate_contract_document(schema_name, instance, schema_validator=validator)

    target_validator = Draft202012Validator(
        schemas["target-manifest.schema.json"], registry=registry
    )
    scenario_validator = Draft202012Validator(schemas["scenario.schema.json"], registry=registry)
    for fixture_path in TARGET_FIXTURES:
        target_validator.validate(valid_target_payload(fixture_path))
    for fixture_path in SCENARIO_FIXTURES:
        scenario_validator.validate(load_json(fixture_path))

    Draft202012Validator(schemas["corpus-manifest.schema.json"], registry=registry).validate(
        load_json(ROOT / "fixtures" / "scenarios" / "v0.1.0" / "manifest.json")
    )


def test_every_schema_is_valid_draft_2020_12() -> None:
    schemas, _ = schema_registry()

    for schema in schemas.values():
        assert schema["$schema"] == DRAFT_2020_12_SCHEMA
        Draft202012Validator.check_schema(schema)


def validate_schema(schema_name: str, instance: Any) -> None:
    schemas, registry = schema_registry()
    Draft202012Validator(schemas[schema_name], registry=registry).validate(instance)


def validate_contract(schema_name: str, instance: Any) -> BaseModel:
    schemas, registry = schema_registry()
    validator = Draft202012Validator(schemas[schema_name], registry=registry)
    return validate_contract_document(schema_name, instance, schema_validator=validator)


@pytest.mark.parametrize("oid_length", [40, 64])
def test_run_identity_supports_sha1_and_sha256_git_oids(oid_length: int) -> None:
    payload = valid_run_identity_payload(oid_length)

    identity = RunIdentity.model_validate(payload)
    validate_schema("run-identity.schema.json", payload)

    assert len(identity.ignored_oid) == oid_length


@pytest.mark.parametrize("candidate", ["a" * 40, "a" * 64])
def test_candidate_identities_must_be_tagged(candidate: str) -> None:
    run_payload = valid_run_identity_payload()
    run_payload["agentguard_candidate"] = candidate
    run_payload["identity_digest"] = RunIdentity.digest_for(run_payload)
    with pytest.raises(ValidationError, match="agentguard_candidate"):
        RunIdentity.model_validate(run_payload)
    with pytest.raises(JsonSchemaValidationError):
        validate_schema("run-identity.schema.json", run_payload)

    target_payload = valid_target_payload()
    target_payload["candidate_identity"] = candidate
    with pytest.raises(ValidationError, match="candidate_identity"):
        TargetManifest.model_validate(target_payload)
    with pytest.raises(JsonSchemaValidationError):
        validate_schema("target-manifest.schema.json", target_payload)


def test_candidate_git_oid_widths_must_match() -> None:
    payload = valid_run_identity_payload()
    payload["agentguard_candidate"] = f"commit:{'a' * 40}:{'b' * 64}"
    payload["ignored_oid"] = "b" * 64
    payload["identity_digest"] = RunIdentity.digest_for(payload)

    with pytest.raises(ValidationError, match="agentguard_candidate"):
        RunIdentity.model_validate(payload)
    with pytest.raises(JsonSchemaValidationError):
        validate_schema("run-identity.schema.json", payload)


@pytest.mark.parametrize("permission_list", ["allow", "approval"])
def test_permissive_lists_reject_undeclared_tool_ids(permission_list: str) -> None:
    payload = valid_target_payload()
    payload["permissions"][permission_list].append("undeclared_tool")
    payload["permissions"][permission_list].sort()

    with pytest.raises(ValidationError, match="undeclared tools"):
        TargetManifest.model_validate(payload)
    # Cross-array membership is not expressible in standard Draft 2020-12.
    validate_schema("target-manifest.schema.json", payload)
    with pytest.raises(ValidationError, match="undeclared tools"):
        validate_contract("target-manifest.schema.json", payload)


def test_deny_may_retain_disjoint_ambient_capabilities() -> None:
    payload = valid_target_payload()

    manifest = TargetManifest.model_validate(payload)

    assert "network" in manifest.permissions.deny
    assert "network" not in {tool.tool_id for tool in manifest.tools}


@pytest.mark.parametrize(
    ("permission_class", "effect_class", "approval_required"),
    [
        ("READ_ONLY_ALLOWED", "READ", False),
        ("READ_ONLY_ALLOWED", "SIMULATED_WRITE", False),
        ("SIMULATED_SENSITIVE_APPROVAL", "SIMULATED_WRITE", True),
        ("DENIED", "NONE", False),
    ],
)
def test_tool_policy_matrix_accepts_only_declared_states(
    permission_class: str,
    effect_class: str,
    approval_required: bool,
) -> None:
    payload = valid_tool_payload()
    payload.update(
        permission_class=permission_class,
        effect_class=effect_class,
        approval_required=approval_required,
    )

    ToolDescriptor.model_validate(payload)
    validate_schema("tool-descriptor.schema.json", payload)


@pytest.mark.parametrize(
    ("permission_class", "effect_class", "approval_required"),
    [
        ("READ_ONLY_ALLOWED", "NONE", False),
        ("READ_ONLY_ALLOWED", "READ", True),
        ("SIMULATED_SENSITIVE_APPROVAL", "READ", True),
        ("SIMULATED_SENSITIVE_APPROVAL", "SIMULATED_WRITE", False),
        ("DENIED", "READ", False),
        ("DENIED", "NONE", True),
    ],
)
def test_tool_policy_matrix_rejects_all_other_states(
    permission_class: str,
    effect_class: str,
    approval_required: bool,
) -> None:
    payload = valid_tool_payload()
    payload.update(
        permission_class=permission_class,
        effect_class=effect_class,
        approval_required=approval_required,
    )

    with pytest.raises(ValidationError, match="incoherent"):
        ToolDescriptor.model_validate(payload)
    with pytest.raises(JsonSchemaValidationError):
        validate_schema("tool-descriptor.schema.json", payload)


def test_model_validate_json_rejects_duplicate_keys_at_nested_depth() -> None:
    payload = valid_tool_payload()
    raw = json.dumps(payload).replace(
        '"type": "object"',
        '"type": "object", "type": "array"',
        1,
    )

    with pytest.raises(ValidationError, match="duplicate JSON key: 'type'"):
        ToolDescriptor.model_validate_json(raw)


def test_models_deep_freeze_nested_contract_data() -> None:
    target_payload = valid_target_payload()
    manifest = TargetManifest.model_validate(target_payload)
    descriptor = manifest.tools[0]
    assessment = valid_assessment()
    scenario_payload = load_json(SCENARIO_FIXTURES[0])
    scenario_payload["expected_outcome"]["assertions"][0]["value"] = {"nested": ["immutable"]}
    scenario = Scenario.model_validate(scenario_payload)

    with pytest.raises(TypeError):
        cast(dict[str, Any], descriptor.input_schema)["properties"] = {}
    properties = cast(dict[str, Any], descriptor.input_schema["properties"])
    with pytest.raises(TypeError):
        properties["new"] = {"type": "string"}
    with pytest.raises(AttributeError):
        cast(list[str], manifest.permissions.allow).append("new_tool")
    with pytest.raises(TypeError):
        cast(dict[str, Any], assessment.metrics)["new_metric"] = 1
    assertion_value = cast(dict[str, Any], scenario.expected_outcome.assertions[0].value)
    with pytest.raises(TypeError):
        assertion_value["nested"] = []
    with pytest.raises(AttributeError):
        cast(list[str], assertion_value["nested"]).append("changed")


def test_input_schema_must_be_valid_draft_2020_12() -> None:
    payload = valid_tool_payload()
    payload["input_schema"]["required"] = "scenario_id"
    payload["fingerprint"] = ToolDescriptor.fingerprint_for(
        name=payload["name"],
        description=payload["description"],
        input_schema=payload["input_schema"],
    )

    with pytest.raises(ValidationError, match="valid Draft 2020-12"):
        ToolDescriptor.model_validate(payload)
    with pytest.raises(JsonSchemaValidationError):
        validate_schema("tool-descriptor.schema.json", payload)


@pytest.mark.parametrize(
    "dialect",
    [
        None,
        "http://json-schema.org/draft-07/schema#",
        "https://example.invalid/unknown-schema",
    ],
)
def test_input_schema_must_declare_exact_draft_2020_12_dialect(
    dialect: str | None,
) -> None:
    payload = valid_tool_payload()
    if dialect is None:
        payload["input_schema"].pop("$schema")
    else:
        payload["input_schema"]["$schema"] = dialect
    payload["fingerprint"] = ToolDescriptor.fingerprint_for(
        name=payload["name"],
        description=payload["description"],
        input_schema=payload["input_schema"],
    )

    if dialect is not None:
        # jsonschema's check_schema validates under the selected validator; it
        # does not require the document's own declaration to match that draft.
        Draft202012Validator.check_schema(payload["input_schema"])
    with pytest.raises(ValidationError, match=r"input_schema\.\$schema"):
        ToolDescriptor.model_validate(payload)
    with pytest.raises(JsonSchemaValidationError):
        validate_schema("tool-descriptor.schema.json", payload)


def test_input_schema_accepts_exact_draft_2020_12_dialect() -> None:
    payload = valid_tool_payload()

    descriptor = ToolDescriptor.model_validate(payload)
    validated = validate_contract("tool-descriptor.schema.json", payload)

    assert descriptor.input_schema["$schema"] == DRAFT_2020_12_SCHEMA
    assert isinstance(validated, ToolDescriptor)


def test_local_evidence_requires_matching_artifact_hash() -> None:
    payload = json.loads(valid_assessment().model_dump_json())
    payload["artifact_hashes"] = {}

    with pytest.raises(ValidationError, match="lack artifact hashes"):
        AssessmentResult.model_validate_json(json.dumps(payload))
    # Membership between evidence refs and object keys is semantic.
    validate_schema("assessment-result.schema.json", payload)
    with pytest.raises(ValidationError, match="lack artifact hashes"):
        validate_contract("assessment-result.schema.json", payload)


def test_external_evidence_does_not_require_local_artifact_hash() -> None:
    payload = json.loads(valid_assessment().model_dump_json())
    external_ref = "https://evidence.invalid/runs/run-001/events/0"
    payload["scenario_results"][0]["evidence_refs"] = [external_ref]
    payload["findings"][0]["evidence_refs"] = [external_ref]
    payload["artifact_hashes"] = {}

    result = AssessmentResult.model_validate_json(json.dumps(payload))
    validate_schema("assessment-result.schema.json", payload)
    validated = validate_contract("assessment-result.schema.json", payload)

    assert result.artifact_hashes == {}
    assert isinstance(validated, AssessmentResult)


@pytest.mark.parametrize("reference", ["file:///etc/passwd", "FILE:///etc/passwd", "FiLe:x"])
def test_file_uri_is_rejected_case_insensitively(reference: str) -> None:
    payload = valid_finding_payload()
    payload["evidence_refs"] = [reference]

    with pytest.raises(ValidationError, match="non-file reference"):
        Finding.model_validate(payload)
    with pytest.raises(JsonSchemaValidationError):
        validate_schema("finding.schema.json", payload)


@pytest.mark.parametrize("reference", ["C:/private/evidence.json", "C:\\private\\evidence.json"])
def test_windows_drive_evidence_is_local_and_cannot_bypass_hash_policy(reference: str) -> None:
    finding_payload = valid_finding_payload()
    finding_payload["evidence_refs"] = [reference]

    with pytest.raises(ValidationError, match="Windows drive paths are local evidence"):
        Finding.model_validate(finding_payload)
    with pytest.raises(JsonSchemaValidationError):
        validate_schema("finding.schema.json", finding_payload)

    assessment_payload = json.loads(valid_assessment().model_dump_json())
    assessment_payload["scenario_results"][0]["evidence_refs"] = [reference]
    assessment_payload["findings"][0]["evidence_refs"] = [reference]
    assessment_payload["artifact_hashes"] = {}
    with pytest.raises(ValidationError, match="Windows drive paths are local evidence"):
        AssessmentResult.model_validate(assessment_payload)
    with pytest.raises(JsonSchemaValidationError):
        validate_schema("assessment-result.schema.json", assessment_payload)


def test_huge_integer_metric_is_a_stable_validation_error() -> None:
    payload = json.loads(valid_assessment().model_dump_json())
    payload["metrics"]["huge"] = 10**1000

    with pytest.raises(ValidationError, match="less than or equal"):
        AssessmentResult.model_validate_json(json.dumps(payload))
    with pytest.raises(JsonSchemaValidationError):
        validate_schema("assessment-result.schema.json", payload)


@pytest.mark.parametrize(
    "value",
    [MAX_SAFE_INTEGER + 1, MIN_SAFE_INTEGER - 1, float(MAX_SAFE_INTEGER + 1)],
)
def test_canonical_json_rejects_integers_outside_interoperable_range(value: int | float) -> None:
    with pytest.raises(ValueError, match="JSON integers must be between"):
        canonical_json_bytes({"nested": [value]})


def test_canonical_json_accepts_safe_integer_boundaries() -> None:
    assert canonical_json_bytes({"maximum": MAX_SAFE_INTEGER, "minimum": MIN_SAFE_INTEGER}) == (
        b'{"maximum":9007199254740991,"minimum":-9007199254740991}'
    )


@pytest.mark.parametrize("location", ["action", "assertion"])
def test_scenario_free_json_rejects_unsafe_nested_integers(location: str) -> None:
    payload = load_json(SCENARIO_FIXTURES[0])
    unsafe = {"nested": [MAX_SAFE_INTEGER + 1]}
    if location == "action":
        payload["action"]["input"] = unsafe
    else:
        payload["expected_outcome"]["assertions"][0]["value"] = unsafe

    with pytest.raises(ValidationError, match="JSON integers must be between"):
        Scenario.model_validate(payload)
    with pytest.raises(JsonSchemaValidationError):
        validate_schema("scenario.schema.json", payload)


def test_tool_input_schema_rejects_unsafe_integer_keywords() -> None:
    payload = valid_tool_payload()
    payload["input_schema"]["x-agentguard-test-integer"] = MAX_SAFE_INTEGER + 1
    with pytest.raises(ValueError, match="JSON integers must be between"):
        ToolDescriptor.fingerprint_for(
            name=payload["name"],
            description=payload["description"],
            input_schema=payload["input_schema"],
        )
    payload["fingerprint"] = "0" * 64

    with pytest.raises(ValidationError, match="JSON integers must be between"):
        ToolDescriptor.model_validate(payload)
    with pytest.raises(JsonSchemaValidationError):
        validate_schema("tool-descriptor.schema.json", payload)


def test_scenario_normalized_set_like_collections_preserve_existing_behavior() -> None:
    payload = load_json(SCENARIO_FIXTURES[0])
    payload["threat_ids"] = ["AG-THR-999", payload["threat_ids"][0]]
    payload["forbidden_effects"] = ["z_event", "a_event"]
    payload["evidence_required"] = ["a_evidence", "z_evidence"]

    scenario = Scenario.model_validate(payload)
    validate_schema("scenario.schema.json", payload)
    validated = validate_contract("scenario.schema.json", payload)

    assert scenario.threat_ids == tuple(sorted(payload["threat_ids"]))
    assert scenario.forbidden_effects == tuple(sorted(payload["forbidden_effects"]))
    assert scenario.evidence_required == tuple(payload["evidence_required"])
    assert isinstance(validated, Scenario)
    persisted = validated.model_dump(mode="json")
    assert persisted["threat_ids"] == sorted(payload["threat_ids"])
    assert persisted["forbidden_effects"] == sorted(payload["forbidden_effects"])
    assert persisted["evidence_required"] == payload["evidence_required"]


def test_scenario_evidence_required_rejects_noncanonical_order() -> None:
    payload = load_json(SCENARIO_FIXTURES[0])
    payload["evidence_required"] = ["z_evidence", "a_evidence"]

    with pytest.raises(ValidationError, match="evidence_required must be sorted lexicographically"):
        Scenario.model_validate(payload)
    # Standard Draft 2020-12 treats the ordering extension as an annotation.
    validate_schema("scenario.schema.json", payload)
    with pytest.raises(ValidationError, match="evidence_required must be sorted lexicographically"):
        validate_contract("scenario.schema.json", payload)


def test_scenario_evidence_required_rejects_duplicates() -> None:
    payload = load_json(SCENARIO_FIXTURES[0])

    payload["evidence_required"] = ["duplicate", "duplicate"]
    with pytest.raises(ValidationError, match="duplicates"):
        Scenario.model_validate(payload)
    with pytest.raises(JsonSchemaValidationError):
        validate_schema("scenario.schema.json", payload)
    with pytest.raises(JsonSchemaValidationError):
        validate_contract("scenario.schema.json", payload)


def test_permission_and_finding_sets_reject_noncanonical_order() -> None:
    target_payload = valid_target_payload()
    target_payload["permissions"]["allow"].reverse()
    with pytest.raises(ValidationError, match="sorted lexicographically"):
        TargetManifest.model_validate(target_payload)
    validate_schema("target-manifest.schema.json", target_payload)
    with pytest.raises(ValidationError, match="sorted lexicographically"):
        validate_contract("target-manifest.schema.json", target_payload)

    finding_payload = valid_finding_payload()
    finding_payload["requirement_ids"].reverse()
    with pytest.raises(ValidationError, match="sorted lexicographically"):
        Finding.model_validate(finding_payload)
    validate_schema("finding.schema.json", finding_payload)
    with pytest.raises(ValidationError, match="sorted lexicographically"):
        validate_contract("finding.schema.json", finding_payload)


def test_assessment_finding_references_reject_noncanonical_order() -> None:
    payload = json.loads(valid_assessment().model_dump_json())
    second_finding = deepcopy(payload["findings"][0])
    second_finding["finding_id"] = "finding-002"
    payload["findings"].append(second_finding)
    payload["scenario_results"][0]["finding_ids"] = ["finding-002", "finding-001"]

    with pytest.raises(ValidationError, match="sorted lexicographically"):
        AssessmentResult.model_validate(payload)
    validate_schema("assessment-result.schema.json", payload)
    with pytest.raises(ValidationError, match="sorted lexicographically"):
        validate_contract("assessment-result.schema.json", payload)


@pytest.mark.parametrize(
    "model",
    [ToolDescriptor, TargetManifest, Scenario, Finding, RunIdentity, AssessmentResult],
)
@pytest.mark.parametrize("malformed", ["{", b'{"unterminated":', b"\xff"])
def test_model_validate_json_wraps_malformed_json_as_pydantic_validation_error(
    model: type[BaseModel],
    malformed: str | bytes,
) -> None:
    with pytest.raises(ValidationError):
        model.model_validate_json(malformed)


def incomplete_assessment_payload() -> dict[str, Any]:
    payload = cast(dict[str, Any], json.loads(valid_assessment().model_dump_json()))
    payload["scenario_results"][0].update(
        completed=False,
        passed=None,
        incomplete_reason="Tool timeout reached",
    )
    payload["summary"] = {
        "completed": False,
        "incomplete_reason": "At least one scenario did not complete",
    }
    payload["stop_reason"] = "configured limit reached"
    return payload


def test_assessment_global_completion_state_is_coherent() -> None:
    incomplete = incomplete_assessment_payload()
    AssessmentResult.model_validate_json(json.dumps(incomplete))
    validate_schema("assessment-result.schema.json", incomplete)

    completed_scenarios_with_incomplete_summary = json.loads(valid_assessment().model_dump_json())
    completed_scenarios_with_incomplete_summary["summary"] = {
        "completed": False,
        "incomplete_reason": "Unexpected stop",
    }
    completed_scenarios_with_incomplete_summary["stop_reason"] = "configured limit reached"
    with pytest.raises(ValidationError, match=r"summary\.completed"):
        AssessmentResult.model_validate_json(
            json.dumps(completed_scenarios_with_incomplete_summary)
        )
    with pytest.raises(JsonSchemaValidationError):
        validate_schema(
            "assessment-result.schema.json",
            completed_scenarios_with_incomplete_summary,
        )

    incomplete["stop_reason"] = "assessment completed"
    with pytest.raises(ValidationError, match="completed stop_reason"):
        AssessmentResult.model_validate_json(json.dumps(incomplete))
    with pytest.raises(JsonSchemaValidationError):
        validate_schema("assessment-result.schema.json", incomplete)
