"""Strict, versioned data contracts for Strands AgentGuard.

The contracts in this module are intentionally independent from any agent,
tool, MCP, network, or cloud runtime.  They validate persisted JSON at the
boundary and reject ambiguous or internally inconsistent representations.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import math
from collections.abc import Mapping, Sequence
from pathlib import PurePosixPath
from typing import Annotated, Literal, Self

from pydantic import (
    AfterValidator,
    AwareDatetime,
    BaseModel,
    ConfigDict,
    Field,
    JsonValue,
    StringConstraints,
    field_validator,
    model_validator,
)

SCHEMA_VERSION = "0.1.0"

type JsonObject = dict[str, JsonValue]
type Sha256Hex = Annotated[
    str,
    StringConstraints(pattern=r"^[0-9a-f]{64}$", strict=True),
]
type SemanticVersion = Annotated[
    str,
    StringConstraints(pattern=r"^[0-9]+\.[0-9]+\.[0-9]+$", strict=True),
]
type LowerIdentifier = Annotated[
    str,
    StringConstraints(pattern=r"^[a-z][a-z0-9._-]{0,63}$", strict=True),
]
type SafeOpaqueIdentifier = Annotated[
    str,
    StringConstraints(
        min_length=1,
        max_length=128,
        pattern=r"^[^\s\x00-\x1f\x7f]+$",
        strict=True,
    ),
]


def _validate_non_blank_text(value: str) -> str:
    if not value.strip() or value != value.strip():
        raise ValueError("must be non-blank and have no surrounding whitespace")
    return value


type NonEmptyText = Annotated[
    str,
    StringConstraints(min_length=1, max_length=1024, strip_whitespace=False, strict=True),
    AfterValidator(_validate_non_blank_text),
]
type SafeReason = Annotated[
    str,
    StringConstraints(
        min_length=1,
        max_length=256,
        pattern=r"^[^\x00-\x1f\x7f]+$",
        strip_whitespace=False,
        strict=True,
    ),
    AfterValidator(_validate_non_blank_text),
]
type ScenarioId = Annotated[
    str,
    StringConstraints(pattern=r"^AG-SCN-[0-9]{3}$", strict=True),
]
type RuleId = Annotated[
    str,
    StringConstraints(pattern=r"^AG-RULE-[0-9]{3}$", strict=True),
]
type RequirementId = Annotated[
    str,
    StringConstraints(pattern=r"^AG-(?:FR|SEC|NFR|DAT)-[0-9]{3}$", strict=True),
]
type EventId = Annotated[
    str,
    StringConstraints(pattern=r"^[a-z][a-z0-9._-]{0,63}$", strict=True),
]

_SAFE_PATH_PATTERN = r"^[A-Za-z0-9._-]+(?:/[A-Za-z0-9._-]+)*$"
_CANDIDATE_PATTERN = (
    r"^(?:"
    r"(?:[0-9a-f]{40}|[0-9a-f]{64})|"
    r"commit:(?:[0-9a-f]{40}|[0-9a-f]{64}):[0-9a-f]{64}|"
    r"(?:staged|diff):(?:[0-9a-f]{40}|[0-9a-f]{64}):[0-9a-f]{64}:[0-9a-f]{64}|"
    r"fixture:[a-z0-9][a-z0-9._-]{0,63}:[0-9a-f]{64}"
    r")$"
)


def _validate_safe_relative_path(value: str) -> str:
    path = PurePosixPath(value)
    if (
        path.is_absolute()
        or value != path.as_posix()
        or any(part in {"", ".", ".."} for part in path.parts)
    ):
        raise ValueError("must be a normalized relative POSIX path without traversal")
    return value


type SafeRelativePath = Annotated[
    str,
    StringConstraints(
        min_length=1,
        max_length=256,
        pattern=_SAFE_PATH_PATTERN,
        strict=True,
    ),
    AfterValidator(_validate_safe_relative_path),
]


def _validate_evidence_reference(value: str) -> str:
    normalized = value.replace("#", "/")
    if (
        value.startswith(("/", "\\", "file:"))
        or "\\" in value
        or any(part == ".." for part in normalized.split("/"))
    ):
        raise ValueError("must be an addressable non-file reference without traversal")
    return value


type EvidenceReference = Annotated[
    str,
    StringConstraints(
        min_length=1,
        max_length=512,
        pattern=r"^[^\s\x00-\x1f\x7f]+$",
        strict=True,
    ),
    AfterValidator(_validate_evidence_reference),
]


def canonical_json_bytes(value: JsonValue) -> bytes:
    """Serialize a JSON value deterministically for hashing.

    Version 0.1.0 uses sorted object keys, compact separators, UTF-8, and no
    non-finite numeric extensions.
    """

    try:
        serialized = json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )
    except (TypeError, ValueError) as exc:
        raise ValueError("value is not canonical JSON") from exc
    return serialized.encode("utf-8")


def canonical_sha256(value: JsonValue) -> str:
    """Return the lowercase SHA-256 digest of canonical JSON bytes."""

    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def _require_unique(values: Sequence[str], field_name: str) -> None:
    if len(values) != len(set(values)):
        raise ValueError(f"{field_name} must not contain duplicates")


def _require_sorted_unique(values: Sequence[str], field_name: str) -> None:
    _require_unique(values, field_name)
    if list(values) != sorted(values):
        raise ValueError(f"{field_name} must be sorted lexicographically")


class ContractModel(BaseModel):
    """Shared fail-closed Pydantic configuration."""

    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)


class ToolDescriptor(ContractModel):
    """Closed description of one exposed tool."""

    tool_id: LowerIdentifier
    name: Annotated[
        str,
        StringConstraints(pattern=r"^[a-z][a-z0-9_]{0,63}$", strict=True),
    ]
    description: Annotated[str, StringConstraints(min_length=1, max_length=512, strict=True)]
    input_schema: JsonObject
    origin: Literal["custom", "mcp", "vended"]
    permission_class: Literal[
        "READ_ONLY_ALLOWED",
        "SIMULATED_SENSITIVE_APPROVAL",
        "DENIED",
    ]
    effect_class: Literal["NONE", "READ", "SIMULATED_WRITE"]
    approval_required: bool
    fingerprint: Sha256Hex

    @staticmethod
    def fingerprint_for(
        *,
        name: str,
        description: str,
        input_schema: JsonObject,
    ) -> str:
        """Fingerprint the v0.1.0 registration surface of a tool."""

        material: JsonValue = {
            "name": name,
            "description": description,
            "input_schema": input_schema,
        }
        # The frozen v0.1.0 fixtures use a single terminal LF as part of the
        # fingerprinted byte representation.
        return hashlib.sha256(canonical_json_bytes(material) + b"\n").hexdigest()

    def expected_fingerprint(self) -> str:
        """Calculate the fingerprint implied by this descriptor."""

        return self.fingerprint_for(
            name=self.name,
            description=self.description,
            input_schema=self.input_schema,
        )

    @field_validator("input_schema")
    @classmethod
    def validate_input_schema(cls, value: JsonObject) -> JsonObject:
        canonical_json_bytes(value)
        if value.get("type") != "object":
            raise ValueError("input_schema.type must be 'object'")
        if value.get("additionalProperties") is not False:
            raise ValueError("input_schema must explicitly deny additional properties")
        return value

    @model_validator(mode="after")
    def validate_coherence(self) -> Self:
        if self.permission_class == "SIMULATED_SENSITIVE_APPROVAL" and (
            not self.approval_required or self.effect_class != "SIMULATED_WRITE"
        ):
            raise ValueError("SIMULATED_SENSITIVE_APPROVAL requires approval and SIMULATED_WRITE")
        if self.permission_class == "DENIED" and (
            self.approval_required or self.effect_class != "NONE"
        ):
            raise ValueError("DENIED tools must require no approval and have no effect")
        if not hmac.compare_digest(self.fingerprint, self.expected_fingerprint()):
            raise ValueError("fingerprint does not match canonical tool registration material")
        return self


class DeterministicProvider(ContractModel):
    kind: Literal["deterministic"]
    model_id: Literal["agentguard-deterministic-v0.1.0"]
    egress: Literal[False]


class McpServerDescriptor(ContractModel):
    server_id: LowerIdentifier
    transport: Literal["stdio"]
    executable_id: Annotated[
        str,
        StringConstraints(pattern=r"^[a-z][a-z0-9._-]{0,127}$", strict=True),
    ]
    tool_ids: Annotated[list[LowerIdentifier], Field(min_length=1)]
    fingerprint: Sha256Hex

    @field_validator("tool_ids")
    @classmethod
    def validate_tool_ids(cls, value: list[str]) -> list[str]:
        _require_sorted_unique(value, "tool_ids")
        return value


class PermissionSet(ContractModel):
    allow: list[LowerIdentifier]
    approval: list[LowerIdentifier]
    deny: list[LowerIdentifier]

    @field_validator("allow", "approval", "deny")
    @classmethod
    def validate_lists(cls, value: list[str]) -> list[str]:
        _require_sorted_unique(value, "permission list")
        return value

    @model_validator(mode="after")
    def validate_disjoint(self) -> Self:
        allow = set(self.allow)
        approval = set(self.approval)
        deny = set(self.deny)
        if allow & approval or allow & deny or approval & deny:
            raise ValueError("allow, approval, and deny must be disjoint")
        return self


class ExecutionLimits(ContractModel):
    assessment_timeout_seconds: Annotated[int, Field(ge=1, le=120)]
    node_timeout_seconds: Annotated[int, Field(ge=1, le=30)]
    tool_timeout_seconds: Annotated[int, Field(ge=1, le=5)]
    max_node_executions: Annotated[int, Field(ge=1, le=8)]
    max_iterations: Annotated[int, Field(ge=1, le=12)]
    max_total_tool_calls: Annotated[int, Field(ge=1, le=32)]
    max_calls_per_tool: Annotated[int, Field(ge=1, le=12)]
    max_specialist_invocations: Annotated[int, Field(ge=0, le=2)]
    max_handoffs: Literal[0]
    max_effects_per_operation: Literal[1]

    @model_validator(mode="after")
    def validate_timeouts(self) -> Self:
        if self.tool_timeout_seconds > self.node_timeout_seconds:
            raise ValueError("tool timeout cannot exceed node timeout")
        if self.node_timeout_seconds > self.assessment_timeout_seconds:
            raise ValueError("node timeout cannot exceed assessment timeout")
        if self.max_calls_per_tool > self.max_total_tool_calls:
            raise ValueError("per-tool call limit cannot exceed total tool call limit")
        return self


class TargetManifest(ContractModel):
    """Versioned, closed inventory for one assessment target."""

    schema_version: Literal["0.1.0"]
    target_id: LowerIdentifier
    target_version: SemanticVersion
    profile: Literal["baseline", "hardened"]
    candidate_identity: Annotated[
        str,
        StringConstraints(pattern=_CANDIDATE_PATTERN, strict=True),
    ]
    provenance: Literal["authored_for_strands_agentguard"]
    confidence: Literal["designed_not_executed"]
    synthetic: Literal[True]
    real_data: Literal[False]
    provider: DeterministicProvider
    tools: Annotated[list[ToolDescriptor], Field(min_length=1)]
    mcp_servers: list[McpServerDescriptor]
    permissions: PermissionSet
    limits: ExecutionLimits
    capabilities: Annotated[list[LowerIdentifier], Field(min_length=1)]
    contract_files: Annotated[list[SafeRelativePath], Field(min_length=1, max_length=16)]

    @field_validator("capabilities", "contract_files")
    @classmethod
    def validate_sorted_strings(cls, value: list[str]) -> list[str]:
        _require_sorted_unique(value, "manifest list")
        return value

    @field_validator("tools")
    @classmethod
    def validate_tools(cls, value: list[ToolDescriptor]) -> list[ToolDescriptor]:
        ids = [tool.tool_id for tool in value]
        _require_sorted_unique(ids, "tools")
        return value

    @field_validator("mcp_servers")
    @classmethod
    def validate_mcp_servers(cls, value: list[McpServerDescriptor]) -> list[McpServerDescriptor]:
        ids = [server.server_id for server in value]
        _require_sorted_unique(ids, "mcp_servers")
        return value

    @model_validator(mode="after")
    def validate_references(self) -> Self:
        tools = {tool.tool_id: tool for tool in self.tools}
        mcp_tool_ids: list[str] = []
        for server in self.mcp_servers:
            unknown = set(server.tool_ids) - tools.keys()
            if unknown:
                raise ValueError(f"MCP server references unknown tools: {sorted(unknown)}")
            for tool_id in server.tool_ids:
                if tools[tool_id].origin != "mcp":
                    raise ValueError("MCP servers may only reference tools with origin 'mcp'")
            mcp_tool_ids.extend(server.tool_ids)

        _require_unique(mcp_tool_ids, "MCP tool assignments")
        declared_mcp_tools = {tool.tool_id for tool in self.tools if tool.origin == "mcp"}
        if set(mcp_tool_ids) != declared_mcp_tools:
            raise ValueError("every MCP-origin tool must belong to exactly one declared server")

        for tool in self.tools:
            if tool.permission_class == "DENIED":
                expected_list = self.permissions.deny
            elif tool.approval_required:
                expected_list = self.permissions.approval
            else:
                expected_list = self.permissions.allow
            if tool.tool_id not in expected_list:
                raise ValueError(f"permission lists do not classify tool {tool.tool_id!r}")
        return self


class ScenarioAction(ContractModel):
    operation: LowerIdentifier
    input: JsonObject

    @field_validator("input")
    @classmethod
    def validate_input(cls, value: JsonObject) -> JsonObject:
        canonical_json_bytes(value)
        return value


class ExpectedTrajectory(ContractModel):
    required_order: Annotated[list[EventId], Field(min_length=1)]
    forbidden_events: list[EventId]

    @field_validator("required_order", "forbidden_events")
    @classmethod
    def validate_unique_events(cls, value: list[str]) -> list[str]:
        _require_unique(value, "trajectory events")
        return value

    @model_validator(mode="after")
    def validate_disjoint(self) -> Self:
        if set(self.required_order) & set(self.forbidden_events):
            raise ValueError("required and forbidden trajectory events must be disjoint")
        return self


class OutcomeAssertion(ContractModel):
    field: Annotated[
        str,
        StringConstraints(pattern=r"^[a-z][a-z0-9._-]{0,127}$", strict=True),
    ]
    operator: Literal["absent", "contains", "equals", "less_than_or_equal", "present"]
    value: JsonValue

    @field_validator("value")
    @classmethod
    def validate_value(cls, value: JsonValue) -> JsonValue:
        canonical_json_bytes(value)
        return value


class ExpectedOutcome(ContractModel):
    summary: Annotated[str, StringConstraints(min_length=1, max_length=512, strict=True)]
    assertions: Annotated[list[OutcomeAssertion], Field(min_length=1)]

    @field_validator("assertions")
    @classmethod
    def validate_assertions(cls, value: list[OutcomeAssertion]) -> list[OutcomeAssertion]:
        identities = [f"{item.field}:{item.operator}" for item in value]
        _require_unique(identities, "outcome assertions")
        return value


class ScenarioCleanup(ContractModel):
    mode: Literal["none", "sandbox"]
    verify: Literal[True]


class ScenarioEvaluator(ContractModel):
    deterministic_rules: Annotated[list[RuleId], Field(min_length=1)]
    semantic: Literal[False]

    @field_validator("deterministic_rules")
    @classmethod
    def validate_rules(cls, value: list[str]) -> list[str]:
        _require_sorted_unique(value, "deterministic_rules")
        return value


class Scenario(ContractModel):
    """Closed synthetic scenario with a predeclared expected trajectory."""

    schema_version: Literal["0.1.0"]
    scenario_id: ScenarioId
    version: Literal["0.1.0"]
    kind: Literal["benign", "adversarial", "chaos"]
    threat_ids: Annotated[
        list[
            Annotated[
                str,
                StringConstraints(pattern=r"^AG-THR-[0-9]{3}$", strict=True),
            ]
        ],
        Field(min_length=1),
    ]
    fixture_ref: SafeRelativePath
    provenance: Literal["authored_for_strands_agentguard"]
    confidence: Literal["designed_not_executed"]
    synthetic: Literal[True]
    real_data: Literal[False]
    preconditions: Annotated[list[NonEmptyText], Field(min_length=1)]
    action: ScenarioAction
    expected_trajectory: ExpectedTrajectory
    expected_outcome: ExpectedOutcome
    forbidden_effects: list[EventId]
    evidence_required: Annotated[list[EventId], Field(min_length=1)]
    cleanup: ScenarioCleanup
    evaluator: ScenarioEvaluator

    @field_validator("threat_ids", "forbidden_effects", "evidence_required")
    @classmethod
    def validate_sorted_identifiers(cls, value: list[str]) -> list[str]:
        _require_unique(value, "scenario identifier list")
        return value

    @field_validator("preconditions")
    @classmethod
    def validate_preconditions(cls, value: list[str]) -> list[str]:
        _require_unique(value, "preconditions")
        return value

    @model_validator(mode="after")
    def validate_fixture_reference(self) -> Self:
        expected_name = f"{self.scenario_id.lower()}.json"
        if PurePosixPath(self.fixture_ref).name != expected_name:
            raise ValueError("fixture_ref filename must match scenario_id")
        return self


class Finding(ContractModel):
    """Evidence-backed finding emitted by one assessment run."""

    finding_id: SafeOpaqueIdentifier
    rule_id: RuleId
    requirement_ids: Annotated[list[RequirementId], Field(min_length=1)]
    scenario_id: ScenarioId
    severity: Literal["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    confidence: Literal["CONFIRMED", "PROBABLE", "POSSIBLE"]
    status: Literal["OPEN"]
    disposition: (
        Literal[
            "MITIGATED",
            "ACCEPTED_RISK",
            "FALSE_POSITIVE",
            "DUPLICATE",
            "OUT_OF_SCOPE",
            "NOT_REPRODUCIBLE",
        ]
        | None
    )
    title: Annotated[str, StringConstraints(min_length=1, max_length=200, strict=True)]
    evidence_refs: Annotated[list[EvidenceReference], Field(min_length=1)]
    reproduction: Annotated[list[NonEmptyText], Field(min_length=1)]
    limitations: list[NonEmptyText]
    run_id: SafeOpaqueIdentifier

    @field_validator("requirement_ids", "evidence_refs")
    @classmethod
    def validate_sorted_references(cls, value: list[str]) -> list[str]:
        _require_sorted_unique(value, "finding reference list")
        return value

    @field_validator("reproduction", "limitations")
    @classmethod
    def validate_unique_text(cls, value: list[str]) -> list[str]:
        _require_unique(value, "finding text list")
        return value


class RunIdentity(ContractModel):
    """Reproducible identity of inputs used by one assessment run."""

    schema_version: Literal["0.1.0"]
    run_id: SafeOpaqueIdentifier
    agentguard_candidate: Annotated[
        str,
        StringConstraints(pattern=_CANDIDATE_PATTERN, strict=True),
    ]
    target_candidate: Annotated[
        str,
        StringConstraints(pattern=_CANDIDATE_PATTERN, strict=True),
    ]
    ignored_oid: Sha256Hex
    manifest_sha256: Sha256Hex
    threat_catalog_version: SemanticVersion
    threat_catalog_sha256: Sha256Hex
    config_sha256: Sha256Hex
    lock_sha256: Sha256Hex
    python: Annotated[
        str,
        StringConstraints(pattern=r"^[0-9]+\.[0-9]+\.[0-9]+(?:[A-Za-z0-9.+-]*)?$", strict=True),
    ]
    os: SafeOpaqueIdentifier
    architecture: Annotated[
        str,
        StringConstraints(pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$", strict=True),
    ]
    identity_digest: Sha256Hex

    @staticmethod
    def digest_for(identity: Mapping[str, JsonValue]) -> str:
        """Calculate the v0.1.0 digest, excluding only identity_digest."""

        material = dict(identity)
        material.pop("identity_digest", None)
        return canonical_sha256(material)

    def expected_identity_digest(self) -> str:
        material: dict[str, JsonValue] = self.model_dump(mode="json")
        return self.digest_for(material)

    @model_validator(mode="after")
    def validate_identity(self) -> Self:
        for candidate in (self.agentguard_candidate, self.target_candidate):
            parts = candidate.split(":")
            if parts[0] in {"commit", "staged", "diff"} and parts[-1] != self.ignored_oid:
                raise ValueError("candidate embedded ignored_oid does not match ignored_oid")
        if not hmac.compare_digest(self.identity_digest, self.expected_identity_digest()):
            raise ValueError("identity_digest does not match canonical run identity")
        return self


class AssessmentTimestamps(ContractModel):
    started_at: AwareDatetime
    completed_at: AwareDatetime

    @model_validator(mode="after")
    def validate_order(self) -> Self:
        if self.completed_at < self.started_at:
            raise ValueError("completed_at must not precede started_at")
        return self


class ScenarioResult(ContractModel):
    scenario_id: ScenarioId
    completed: bool
    passed: bool | None
    incomplete_reason: NonEmptyText | None
    evidence_refs: list[EvidenceReference]
    finding_ids: list[SafeOpaqueIdentifier]

    @field_validator("evidence_refs", "finding_ids")
    @classmethod
    def validate_sorted_lists(cls, value: list[str]) -> list[str]:
        _require_sorted_unique(value, "scenario result reference list")
        return value

    @model_validator(mode="after")
    def validate_completion(self) -> Self:
        if self.completed:
            if self.passed is None or self.incomplete_reason is not None:
                raise ValueError("completed scenario requires passed and no incomplete_reason")
        elif self.passed is not None or self.incomplete_reason is None:
            raise ValueError("incomplete scenario requires null passed and an incomplete_reason")
        return self


type MetricName = Annotated[
    str,
    StringConstraints(pattern=r"^[a-z][a-z0-9._-]{0,63}$", strict=True),
]
type MetricValue = Annotated[int | float, Field(ge=0)]


class AssessmentSummary(ContractModel):
    completed: bool
    incomplete_reason: NonEmptyText | None

    @model_validator(mode="after")
    def validate_completion(self) -> Self:
        if self.completed and self.incomplete_reason is not None:
            raise ValueError("completed assessment must have null incomplete_reason")
        if not self.completed and self.incomplete_reason is None:
            raise ValueError("incomplete assessment requires an incomplete_reason")
        return self


class AssessmentResult(ContractModel):
    """Source JSON result for one bounded assessment."""

    schema_version: Literal["0.1.0"]
    run_identity: RunIdentity
    target_id: LowerIdentifier
    timestamps: AssessmentTimestamps
    stop_reason: SafeReason
    scenario_results: list[ScenarioResult]
    findings: list[Finding]
    metrics: dict[MetricName, MetricValue]
    artifact_hashes: dict[SafeRelativePath, Sha256Hex]
    summary: AssessmentSummary

    @field_validator("metrics")
    @classmethod
    def validate_metrics(cls, value: dict[str, int | float]) -> dict[str, int | float]:
        for metric in value.values():
            if isinstance(metric, bool) or not math.isfinite(metric):
                raise ValueError("metrics must be finite non-negative numbers")
        return value

    @field_validator("scenario_results")
    @classmethod
    def validate_scenario_results(cls, value: list[ScenarioResult]) -> list[ScenarioResult]:
        ids = [result.scenario_id for result in value]
        _require_sorted_unique(ids, "scenario_results")
        return value

    @field_validator("findings")
    @classmethod
    def validate_findings(cls, value: list[Finding]) -> list[Finding]:
        ids = [finding.finding_id for finding in value]
        _require_sorted_unique(ids, "findings")
        return value

    @model_validator(mode="after")
    def validate_references(self) -> Self:
        scenario_results = {result.scenario_id: result for result in self.scenario_results}
        findings = {finding.finding_id: finding for finding in self.findings}

        for finding in self.findings:
            if finding.run_id != self.run_identity.run_id:
                raise ValueError("finding run_id must match run_identity.run_id")
            if finding.scenario_id not in scenario_results:
                raise ValueError("finding references a scenario absent from scenario_results")

        referenced_findings: set[str] = set()
        for result in self.scenario_results:
            for finding_id in result.finding_ids:
                referenced_finding = findings.get(finding_id)
                if referenced_finding is None:
                    raise ValueError("scenario result references an unknown finding")
                if referenced_finding.scenario_id != result.scenario_id:
                    raise ValueError("finding is attached to a different scenario result")
                referenced_findings.add(finding_id)
        if referenced_findings != findings.keys():
            raise ValueError("every finding must be referenced by its scenario result")

        if self.summary.completed and any(not result.completed for result in self.scenario_results):
            raise ValueError("completed assessment contains an incomplete scenario")
        return self


__all__ = [
    "SCHEMA_VERSION",
    "AssessmentResult",
    "AssessmentSummary",
    "AssessmentTimestamps",
    "ExecutionLimits",
    "ExpectedOutcome",
    "ExpectedTrajectory",
    "Finding",
    "McpServerDescriptor",
    "OutcomeAssertion",
    "PermissionSet",
    "RunIdentity",
    "Scenario",
    "ScenarioAction",
    "ScenarioCleanup",
    "ScenarioEvaluator",
    "ScenarioResult",
    "TargetManifest",
    "ToolDescriptor",
    "canonical_json_bytes",
    "canonical_sha256",
]
