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
from types import MappingProxyType
from typing import Annotated, Any, Literal, Self, cast
from urllib.parse import urlsplit

# jsonschema is present in the locked quality environment.  Importing the
# validator here keeps tool schemas on the same Draft 2020-12 boundary as the
# persisted contract schemas.
from jsonschema import Draft202012Validator  # type: ignore[import-untyped, unused-ignore]
from jsonschema.exceptions import SchemaError  # type: ignore[import-untyped, unused-ignore]
from pydantic import (
    AfterValidator,
    AwareDatetime,
    BaseModel,
    BeforeValidator,
    ConfigDict,
    Field,
    JsonValue,
    PlainSerializer,
    StringConstraints,
    ValidationError,
    field_validator,
    model_validator,
)
from pydantic.config import ExtraValues
from pydantic_core import InitErrorDetails, PydanticCustomError

SCHEMA_VERSION = "0.1.0"
DRAFT_2020_12_SCHEMA = "https://json-schema.org/draft/2020-12/schema"
MIN_SAFE_INTEGER = -9_007_199_254_740_991
MAX_SAFE_INTEGER = 9_007_199_254_740_991


def _to_tuple(value: object) -> object:
    if isinstance(value, list):
        return tuple(value)
    return value


type FrozenSequence[Item] = Annotated[
    tuple[Item, ...],
    BeforeValidator(_to_tuple),
]


def _freeze_mapping[Key, Value](value: Mapping[Key, Value]) -> Mapping[Key, Value]:
    return MappingProxyType(dict(value))


def _serialize_mapping[Key, Value](value: Mapping[Key, Value]) -> dict[Key, Value]:
    return dict(value)


type FrozenMapping[Key, Value] = Annotated[
    Mapping[Key, Value],
    AfterValidator(_freeze_mapping),
    PlainSerializer(_serialize_mapping, return_type=dict[Key, Value]),
]


def _deep_freeze_json(value: JsonValue) -> object:
    if isinstance(value, dict):
        return MappingProxyType({key: _deep_freeze_json(item) for key, item in value.items()})
    if isinstance(value, list):
        return tuple(_deep_freeze_json(item) for item in value)
    return value


def _thaw_json(value: object) -> JsonValue:
    if value is None or isinstance(value, (bool, int, float, str)):
        return value
    if isinstance(value, Mapping):
        if not all(isinstance(key, str) for key in value):
            raise TypeError("JSON object keys must be strings")
        return {str(key): _thaw_json(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_thaw_json(item) for item in value]
    raise TypeError(f"unsupported JSON value: {type(value).__name__}")


def _freeze_json_object(value: Mapping[str, JsonValue]) -> Mapping[str, JsonValue]:
    return cast(Mapping[str, JsonValue], _deep_freeze_json(dict(value)))


def _serialize_json_object(value: Mapping[str, JsonValue]) -> dict[str, JsonValue]:
    thawed = _thaw_json(value)
    if not isinstance(thawed, dict):
        raise TypeError("expected a JSON object")
    return thawed


type JsonObject = Annotated[
    Mapping[str, JsonValue],
    AfterValidator(_freeze_json_object),
    PlainSerializer(_serialize_json_object, return_type=dict[str, JsonValue]),
]
type ImmutableJsonValue = Annotated[
    JsonValue,
    AfterValidator(_deep_freeze_json),
    PlainSerializer(_thaw_json, return_type=JsonValue),
]
type Sha256Hex = Annotated[
    str,
    StringConstraints(pattern=r"^[0-9a-f]{64}$", strict=True),
]
type GitOid = Annotated[
    str,
    StringConstraints(pattern=r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$", strict=True),
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
    r"commit:(?:[0-9a-f]{40}:[0-9a-f]{40}|[0-9a-f]{64}:[0-9a-f]{64})|"
    r"(?:staged|diff):(?:"
    r"[0-9a-f]{40}:[0-9a-f]{40}:[0-9a-f]{40}|"
    r"[0-9a-f]{64}:[0-9a-f]{64}:[0-9a-f]{64})|"
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
    if _is_windows_drive_reference(value):
        raise ValueError(
            "Windows drive paths are local evidence and must use normalized relative POSIX paths"
        )
    parsed = urlsplit(value)
    if (
        value.startswith(("/", "\\"))
        or parsed.scheme.lower() == "file"
        or "\\" in value
        or any(part == ".." for part in normalized.split("/"))
    ):
        raise ValueError("must be an addressable non-file reference without traversal")
    if not parsed.scheme:
        local_path = value.partition("#")[0]
        _validate_safe_relative_path(local_path)
    return value


def _local_evidence_path(value: str) -> str | None:
    if _is_windows_drive_reference(value):
        return value.partition("#")[0]
    if urlsplit(value).scheme:
        return None
    return value.partition("#")[0]


def _is_windows_drive_reference(value: str) -> bool:
    reference = value.partition("#")[0]
    return (
        len(reference) >= 3
        and reference[0].isalpha()
        and reference[1] == ":"
        and reference[2] in {"/", "\\"}
    )


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


def canonical_json_bytes(value: object) -> bytes:
    """Serialize a JSON value deterministically for hashing.

    Version 0.1.0 uses sorted object keys, compact separators, UTF-8, and no
    non-finite numeric extensions.
    """

    try:
        thawed = _thaw_json(value)
    except (TypeError, ValueError) as exc:
        raise ValueError("value is not canonical JSON") from exc

    _validate_safe_json_numbers(thawed)
    try:
        serialized = json.dumps(
            thawed,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )
    except (TypeError, ValueError) as exc:
        raise ValueError("value is not canonical JSON") from exc
    return serialized.encode("utf-8")


def _validate_safe_json_numbers(value: object) -> None:
    if isinstance(value, bool) or value is None or isinstance(value, str):
        return
    if isinstance(value, int):
        if not MIN_SAFE_INTEGER <= value <= MAX_SAFE_INTEGER:
            raise ValueError(
                f"JSON integers must be between {MIN_SAFE_INTEGER} and {MAX_SAFE_INTEGER}"
            )
        return
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError("JSON numbers must be finite")
        if value.is_integer() and not MIN_SAFE_INTEGER <= value <= MAX_SAFE_INTEGER:
            raise ValueError(
                f"JSON integers must be between {MIN_SAFE_INTEGER} and {MAX_SAFE_INTEGER}"
            )
        return
    if isinstance(value, Mapping):
        for item in value.values():
            _validate_safe_json_numbers(item)
        return
    if isinstance(value, (list, tuple)):
        for item in value:
            _validate_safe_json_numbers(item)
        return
    raise TypeError(f"unsupported JSON value: {type(value).__name__}")


def canonical_sha256(value: object) -> str:
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

    @classmethod
    def model_validate_json(
        cls,
        json_data: str | bytes | bytearray,
        *,
        strict: bool | None = None,
        extra: ExtraValues | None = None,
        context: Any | None = None,
        by_alias: bool | None = None,
        by_name: bool | None = None,
    ) -> Self:
        """Parse JSON while rejecting duplicate keys at every object depth."""

        def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
            result: dict[str, Any] = {}
            for key, value in pairs:
                if key in result:
                    error = InitErrorDetails(
                        type=PydanticCustomError(
                            "json_duplicate_key",
                            "duplicate JSON key: {key}",
                            {"key": repr(key)},
                        ),
                        loc=(),
                        input=json_data,
                    )
                    raise ValidationError.from_exception_data(cls.__name__, [error])
                result[key] = value
            return result

        try:
            json.loads(json_data, object_pairs_hook=reject_duplicates)
        except (json.JSONDecodeError, UnicodeDecodeError):
            # Pydantic owns the public error contract for malformed JSON.
            # Reparse through pydantic-core so callers consistently receive
            # pydantic.ValidationError rather than stdlib parser exceptions.
            return super().model_validate_json(
                json_data,
                strict=strict,
                extra=extra,
                context=context,
                by_alias=by_alias,
                by_name=by_name,
            )
        return super().model_validate_json(
            json_data,
            strict=strict,
            extra=extra,
            context=context,
            by_alias=by_alias,
            by_name=by_name,
        )


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
        input_schema: Mapping[str, JsonValue],
    ) -> str:
        """Fingerprint the v0.1.0 registration surface of a tool."""

        material: dict[str, object] = {
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
        if value.get("$schema") != DRAFT_2020_12_SCHEMA:
            raise ValueError(f"input_schema.$schema must be exactly {DRAFT_2020_12_SCHEMA!r}")
        if value.get("type") != "object":
            raise ValueError("input_schema.type must be 'object'")
        if value.get("additionalProperties") is not False:
            raise ValueError("input_schema must explicitly deny additional properties")
        try:
            Draft202012Validator.check_schema(_serialize_json_object(value))
        except SchemaError as exc:
            raise ValueError("input_schema must be a valid Draft 2020-12 JSON Schema") from exc
        return value

    @model_validator(mode="after")
    def validate_coherence(self) -> Self:
        # READ_ONLY_ALLOWED + SIMULATED_WRITE intentionally represents the
        # vulnerable baseline; every other accepted state is enumerated.
        allowed_policy_states = {
            ("READ_ONLY_ALLOWED", "READ", False),
            ("READ_ONLY_ALLOWED", "SIMULATED_WRITE", False),
            ("SIMULATED_SENSITIVE_APPROVAL", "SIMULATED_WRITE", True),
            ("DENIED", "NONE", False),
        }
        policy_state = (self.permission_class, self.effect_class, self.approval_required)
        if policy_state not in allowed_policy_states:
            raise ValueError("permission_class, effect_class, and approval_required are incoherent")
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
    tool_ids: Annotated[FrozenSequence[LowerIdentifier], Field(min_length=1)]
    fingerprint: Sha256Hex

    @field_validator("tool_ids")
    @classmethod
    def validate_tool_ids(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        _require_sorted_unique(value, "tool_ids")
        return value


class PermissionSet(ContractModel):
    allow: FrozenSequence[LowerIdentifier]
    approval: FrozenSequence[LowerIdentifier]
    deny: FrozenSequence[LowerIdentifier]

    @field_validator("allow", "approval", "deny")
    @classmethod
    def validate_lists(cls, value: tuple[str, ...]) -> tuple[str, ...]:
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
    tools: Annotated[FrozenSequence[ToolDescriptor], Field(min_length=1)]
    mcp_servers: FrozenSequence[McpServerDescriptor]
    permissions: PermissionSet
    limits: ExecutionLimits
    capabilities: Annotated[FrozenSequence[LowerIdentifier], Field(min_length=1)]
    contract_files: Annotated[FrozenSequence[SafeRelativePath], Field(min_length=1, max_length=16)]

    @field_validator("capabilities", "contract_files")
    @classmethod
    def validate_sorted_strings(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        _require_sorted_unique(value, "manifest list")
        return value

    @field_validator("tools")
    @classmethod
    def validate_tools(cls, value: tuple[ToolDescriptor, ...]) -> tuple[ToolDescriptor, ...]:
        ids = [tool.tool_id for tool in value]
        _require_sorted_unique(ids, "tools")
        return value

    @field_validator("mcp_servers")
    @classmethod
    def validate_mcp_servers(
        cls, value: tuple[McpServerDescriptor, ...]
    ) -> tuple[McpServerDescriptor, ...]:
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

        declared_tool_ids = set(tools)
        unknown_permitted = (set(self.permissions.allow) | set(self.permissions.approval)) - (
            declared_tool_ids
        )
        if unknown_permitted:
            raise ValueError(
                f"permission lists reference undeclared tools: {sorted(unknown_permitted)}"
            )

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
    required_order: Annotated[FrozenSequence[EventId], Field(min_length=1)]
    forbidden_events: FrozenSequence[EventId]

    @field_validator("required_order", "forbidden_events")
    @classmethod
    def validate_unique_events(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        _require_unique(value, "trajectory events")
        return value

    @field_validator("forbidden_events")
    @classmethod
    def validate_forbidden_event_order(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        _require_unique(value, "forbidden trajectory events")
        return tuple(sorted(value))

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
    value: ImmutableJsonValue

    @field_validator("value")
    @classmethod
    def validate_value(cls, value: JsonValue) -> JsonValue:
        canonical_json_bytes(value)
        return value


class ExpectedOutcome(ContractModel):
    summary: Annotated[str, StringConstraints(min_length=1, max_length=512, strict=True)]
    assertions: Annotated[FrozenSequence[OutcomeAssertion], Field(min_length=1)]

    @field_validator("assertions")
    @classmethod
    def validate_assertions(
        cls, value: tuple[OutcomeAssertion, ...]
    ) -> tuple[OutcomeAssertion, ...]:
        identities = [f"{item.field}:{item.operator}" for item in value]
        _require_unique(identities, "outcome assertions")
        return value


class ScenarioCleanup(ContractModel):
    mode: Literal["none", "sandbox"]
    verify: Literal[True]


class ScenarioEvaluator(ContractModel):
    deterministic_rules: Annotated[FrozenSequence[RuleId], Field(min_length=1)]
    semantic: Literal[False]

    @field_validator("deterministic_rules")
    @classmethod
    def validate_rules(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        _require_sorted_unique(value, "deterministic_rules")
        return value


class Scenario(ContractModel):
    """Closed synthetic scenario with a predeclared expected trajectory."""

    schema_version: Literal["0.1.0"]
    scenario_id: ScenarioId
    version: Literal["0.1.0"]
    kind: Literal["benign", "adversarial", "chaos"]
    threat_ids: Annotated[
        FrozenSequence[
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
    preconditions: Annotated[FrozenSequence[NonEmptyText], Field(min_length=1)]
    action: ScenarioAction
    expected_trajectory: ExpectedTrajectory
    expected_outcome: ExpectedOutcome
    forbidden_effects: FrozenSequence[EventId]
    evidence_required: Annotated[FrozenSequence[EventId], Field(min_length=1)]
    cleanup: ScenarioCleanup
    evaluator: ScenarioEvaluator

    @field_validator("threat_ids", "forbidden_effects", "evidence_required")
    @classmethod
    def validate_sorted_identifiers(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        _require_unique(value, "scenario identifier list")
        return tuple(sorted(value))

    @field_validator("preconditions")
    @classmethod
    def validate_preconditions(cls, value: tuple[str, ...]) -> tuple[str, ...]:
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
    requirement_ids: Annotated[FrozenSequence[RequirementId], Field(min_length=1)]
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
    evidence_refs: Annotated[FrozenSequence[EvidenceReference], Field(min_length=1)]
    reproduction: Annotated[FrozenSequence[NonEmptyText], Field(min_length=1)]
    limitations: FrozenSequence[NonEmptyText]
    run_id: SafeOpaqueIdentifier

    @field_validator("requirement_ids", "evidence_refs")
    @classmethod
    def validate_sorted_references(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        _require_sorted_unique(value, "finding reference list")
        return value

    @field_validator("reproduction", "limitations")
    @classmethod
    def validate_unique_text(cls, value: tuple[str, ...]) -> tuple[str, ...]:
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
    ignored_oid: GitOid
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
    evidence_refs: FrozenSequence[EvidenceReference]
    finding_ids: FrozenSequence[SafeOpaqueIdentifier]

    @field_validator("evidence_refs", "finding_ids")
    @classmethod
    def validate_sorted_lists(cls, value: tuple[str, ...]) -> tuple[str, ...]:
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
type MetricValue = Annotated[int | float, Field(ge=0, le=9_007_199_254_740_991)]


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
    scenario_results: Annotated[FrozenSequence[ScenarioResult], Field(min_length=1)]
    findings: FrozenSequence[Finding]
    metrics: FrozenMapping[MetricName, MetricValue]
    artifact_hashes: FrozenMapping[SafeRelativePath, Sha256Hex]
    summary: AssessmentSummary

    @field_validator("metrics")
    @classmethod
    def validate_metrics(cls, value: Mapping[str, int | float]) -> Mapping[str, int | float]:
        for metric in value.values():
            if isinstance(metric, bool) or (
                isinstance(metric, float) and not math.isfinite(metric)
            ):
                raise ValueError("metrics must be finite non-negative numbers")
        return value

    @field_validator("scenario_results")
    @classmethod
    def validate_scenario_results(
        cls, value: tuple[ScenarioResult, ...]
    ) -> tuple[ScenarioResult, ...]:
        ids = [result.scenario_id for result in value]
        _require_sorted_unique(ids, "scenario_results")
        return value

    @field_validator("findings")
    @classmethod
    def validate_findings(cls, value: tuple[Finding, ...]) -> tuple[Finding, ...]:
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

        local_evidence_paths = {
            local_path
            for evidence_ref in (
                ref for result in self.scenario_results for ref in result.evidence_refs
            )
            if (local_path := _local_evidence_path(evidence_ref)) is not None
        }
        local_evidence_paths.update(
            local_path
            for evidence_ref in (ref for finding in self.findings for ref in finding.evidence_refs)
            if (local_path := _local_evidence_path(evidence_ref)) is not None
        )
        missing_hashes = local_evidence_paths - self.artifact_hashes.keys()
        if missing_hashes:
            raise ValueError(
                f"local evidence references lack artifact hashes: {sorted(missing_hashes)}"
            )

        all_scenarios_completed = all(result.completed for result in self.scenario_results)
        if self.summary.completed != all_scenarios_completed:
            raise ValueError("summary.completed must match completion of every scenario result")
        if self.summary.completed and self.stop_reason != "assessment completed":
            raise ValueError("completed assessment requires stop_reason 'assessment completed'")
        if not self.summary.completed and self.stop_reason == "assessment completed":
            raise ValueError("incomplete assessment cannot use completed stop_reason")
        return self


_CONTRACT_MODELS_BY_SCHEMA_ID: Mapping[str, type[ContractModel]] = MappingProxyType(
    {
        "assessment-result.schema.json": AssessmentResult,
        "finding.schema.json": Finding,
        "run-identity.schema.json": RunIdentity,
        "scenario.schema.json": Scenario,
        "target-manifest.schema.json": TargetManifest,
        "tool-descriptor.schema.json": ToolDescriptor,
    }
)


def validate_contract_document(
    schema_id: str,
    document: object,
    *,
    schema_validator: Draft202012Validator,
) -> ContractModel:
    """Validate one persisted document against schema and semantic invariants.

    Standard Draft 2020-12 cannot express this contract's cross-field equality,
    referential integrity, lexicographic set ordering, digest, fingerprint, or
    local-evidence-to-artifact-hash membership rules.  This is the canonical
    validation surface when those invariants matter: it first applies the
    caller's configured checked-in schema (including its reference registry),
    then the corresponding immutable Pydantic model.
    """

    model = _CONTRACT_MODELS_BY_SCHEMA_ID.get(schema_id)
    if model is None:
        raise ValueError(f"unknown contract schema: {schema_id!r}")

    schema = schema_validator.schema
    if not isinstance(schema, Mapping):
        raise ValueError("contract schema must be a JSON object")
    if schema.get("$schema") != DRAFT_2020_12_SCHEMA:
        raise ValueError(f"contract schema must declare exactly {DRAFT_2020_12_SCHEMA!r}")
    if schema.get("$id") != schema_id:
        raise ValueError("schema validator does not match the requested contract schema")

    Draft202012Validator.check_schema(schema)
    schema_validator.validate(document)
    return model.model_validate_json(canonical_json_bytes(document))


__all__ = [
    "DRAFT_2020_12_SCHEMA",
    "MAX_SAFE_INTEGER",
    "MIN_SAFE_INTEGER",
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
    "validate_contract_document",
]
