"""Offline health checks for the deterministic AgentGuard fixture stack."""

from __future__ import annotations

import asyncio
import copy
import json
import sys
import tomllib
from collections.abc import Callable
from dataclasses import dataclass
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path
from typing import Any, cast

# jsonschema and referencing are already locked transitive contract dependencies.
from jsonschema import Draft202012Validator  # type: ignore[import-untyped, unused-ignore]
from referencing import Registry, Resource  # type: ignore[import-untyped, unused-ignore]
from strands import Agent
from strands.models import Model
from strands.types.content import Messages

from strands_agentguard.contracts import (
    DRAFT_2020_12_SCHEMA,
    TargetManifest,
    validate_contract_document,
)
from strands_agentguard.models import DeterministicModel, UnregisteredModelInput
from strands_agentguard.targets import (
    DeterministicTarget,
    fixture_candidate_identity,
    fixture_identity_digest,
    validate_fixture_identity,
)

_SCHEMA_NAMES = frozenset(
    {
        "assessment-result.schema.json",
        "corpus-manifest.schema.json",
        "finding.schema.json",
        "run-identity.schema.json",
        "scenario.schema.json",
        "target-manifest.schema.json",
        "tool-descriptor.schema.json",
    }
)
_CONTRACT_SCHEMA_NAMES = frozenset(
    {
        "assessment-result.schema.json",
        "finding.schema.json",
        "run-identity.schema.json",
        "scenario.schema.json",
        "target-manifest.schema.json",
        "tool-descriptor.schema.json",
    }
)
_TARGET_PATHS = (
    "fixtures/targets/vulnerable.json",
    "fixtures/targets/hardened.json",
)
_PROBE_PROMPT = "agentguard offline doctor probe"
_PROBE_RESPONSE = "agentguard-offline-ok"
_PROBE_SYSTEM_PROMPT = "Use only the registered offline transcript."


class DoctorValidationError(ValueError):
    """Safe, non-secret-bearing doctor failure."""


@dataclass(frozen=True, slots=True)
class DoctorCheck:
    name: str
    ok: bool
    detail: str


@dataclass(frozen=True, slots=True)
class DoctorReport:
    checks: tuple[DoctorCheck, ...]

    @property
    def ok(self) -> bool:
        return all(check.ok for check in self.checks)

    @property
    def exit_code(self) -> int:
        return 0 if self.ok else 1


@dataclass(slots=True)
class _DoctorContext:
    root: Path
    schemas: dict[str, dict[str, Any]] | None = None
    registry: Registry[Any] | None = None
    target: DeterministicTarget | None = None


def repository_root() -> Path:
    """Return the source checkout root containing fixtures and schemas."""

    return Path(__file__).resolve().parents[2]


def _read_json_object(path: Path) -> dict[str, Any]:
    def reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise DoctorValidationError("JSON document contains duplicate keys")
            result[key] = value
        return result

    try:
        document = json.loads(path.read_bytes(), object_pairs_hook=reject_duplicate_keys)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise DoctorValidationError("required JSON document is unavailable or malformed") from exc
    if not isinstance(document, dict):
        raise DoctorValidationError("required JSON document is not an object")
    return cast(dict[str, Any], document)


def _load_schemas(context: _DoctorContext) -> tuple[dict[str, dict[str, Any]], Registry[Any]]:
    if context.schemas is not None and context.registry is not None:
        return context.schemas, context.registry
    schema_paths = sorted((context.root / "schemas").glob("*.schema.json"))
    if {path.name for path in schema_paths} != _SCHEMA_NAMES:
        raise DoctorValidationError("checked-in schema inventory is incomplete or unexpected")
    schemas = {path.name: _read_json_object(path) for path in schema_paths}
    for name, schema in schemas.items():
        if schema.get("$schema") != DRAFT_2020_12_SCHEMA or schema.get("$id") != name:
            raise DoctorValidationError("schema identity or dialect is invalid")
        try:
            Draft202012Validator.check_schema(schema)
        except Exception as exc:
            raise DoctorValidationError("checked-in JSON Schema is invalid") from exc
    registry = Registry().with_resources(
        (schema["$id"], Resource.from_contents(schema)) for schema in schemas.values()
    )
    context.schemas = schemas
    context.registry = registry
    return schemas, registry


def _check_environment(_context: _DoctorContext) -> str:
    if sys.version_info[:2] != (3, 12):
        raise DoctorValidationError("Python 3.12 is required")
    try:
        strands_version = version("strands-agents")
    except PackageNotFoundError as exc:
        raise DoctorValidationError("strands-agents is not installed") from exc
    if strands_version != "1.50.2":
        raise DoctorValidationError("the locked Strands 1.50.2 environment is required")
    if not issubclass(DeterministicModel, Model):
        raise DoctorValidationError(
            "deterministic model does not implement the Strands model interface"
        )
    return "Python 3.12 and Strands 1.50.2"


def _check_configuration(context: _DoctorContext) -> str:
    try:
        project = tomllib.loads((context.root / "pyproject.toml").read_text(encoding="utf-8"))
        lock = tomllib.loads((context.root / "uv.lock").read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
        raise DoctorValidationError(
            "project or lock configuration is unavailable or malformed"
        ) from exc

    project_table = project.get("project")
    uv_table = project.get("tool", {}).get("uv")
    if not isinstance(project_table, dict) or not isinstance(uv_table, dict):
        raise DoctorValidationError("project or uv configuration is absent")
    if (
        project_table.get("requires-python") != ">=3.12,<3.13"
        or uv_table.get("required-version") != ">=0.12.2,<0.13"
        or project_table.get("scripts", {}).get("agentguard") != "strands_agentguard.cli:app"
    ):
        raise DoctorValidationError("supported Python, uv, or CLI configuration changed")
    dependencies = project_table.get("dependencies")
    if not isinstance(dependencies, list) or "strands-agents>=1.50.2,<2" not in dependencies:
        raise DoctorValidationError("Strands dependency constraint changed")
    if (
        lock.get("version") != 1
        or lock.get("revision") != 3
        or lock.get("requires-python") != "==3.12.*"
    ):
        raise DoctorValidationError("uv lock format or Python resolution changed")
    packages = lock.get("package")
    if not isinstance(packages, list):
        raise DoctorValidationError("uv lock package inventory is absent")
    locked_strands = [item for item in packages if item.get("name") == "strands-agents"]
    local_package = [item for item in packages if item.get("name") == "strands-agentguard"]
    if len(locked_strands) != 1 or locked_strands[0].get("version") != "1.50.2":
        raise DoctorValidationError("uv lock does not contain exactly Strands 1.50.2")
    if len(local_package) != 1 or local_package[0].get("version") != project_table.get("version"):
        raise DoctorValidationError("local package metadata differs from the uv lock")

    try:
        environment = dict(
            line.split("=", maxsplit=1)
            for line in (context.root / ".env.example").read_text(encoding="utf-8").splitlines()
        )
    except (OSError, UnicodeDecodeError, ValueError) as exc:
        raise DoctorValidationError(
            "offline environment example is unavailable or malformed"
        ) from exc
    if (
        environment.get("AGENTGUARD_MODEL_PROVIDER") != "deterministic"
        or environment.get("AGENTGUARD_EGRESS") != "deny"
        or environment.get("OLLAMA_HOST") != ""
        or environment.get("OLLAMA_API_KEY") != ""
    ):
        raise DoctorValidationError("offline environment configuration changed")
    return "pyproject, uv.lock, and offline configuration"


def _check_schemas(context: _DoctorContext) -> str:
    schemas, _ = _load_schemas(context)
    if not _CONTRACT_SCHEMA_NAMES.issubset(schemas):
        raise DoctorValidationError("six canonical contract schemas are not available")
    return "7 Draft 2020-12 schemas, including 6 semantic contracts"


def _check_targets(context: _DoctorContext) -> str:
    schemas, registry = _load_schemas(context)
    schema = schemas["target-manifest.schema.json"]
    validator = Draft202012Validator(schema, registry=registry)
    profiles: set[str] = set()
    for relative_path in _TARGET_PATHS:
        document = _read_json_object(context.root / relative_path)
        try:
            model = validate_contract_document(
                "target-manifest.schema.json", document, schema_validator=validator
            )
            if not isinstance(model, TargetManifest):
                raise TypeError
            validate_fixture_identity(model)
        except (TypeError, ValueError) as exc:
            raise DoctorValidationError(
                "target fixture violates schema, semantics, or identity"
            ) from exc
        profiles.add(model.profile)
    if profiles != {"baseline", "hardened"}:
        raise DoctorValidationError("target profiles are incomplete")
    context.target = DeterministicTarget.from_repository(context.root)
    return "one shared in-memory target, two policy profiles, one declared tool surface"


def _check_corpus(context: _DoctorContext) -> str:
    schemas, registry = _load_schemas(context)
    target = context.target or DeterministicTarget.from_repository(context.root)
    manifest = _read_json_object(
        context.root / "fixtures" / "scenarios" / "v0.1.0" / "manifest.json"
    )
    try:
        Draft202012Validator(schemas["corpus-manifest.schema.json"], registry=registry).validate(
            manifest
        )
        scenario_validator = Draft202012Validator(
            schemas["scenario.schema.json"], registry=registry
        )
        for scenario in target.corpus.scenarios.values():
            validate_contract_document(
                "scenario.schema.json",
                scenario.model_dump(mode="json"),
                schema_validator=scenario_validator,
            )
        target.execute_scenario("AG-SCN-001", profile="hardened")
        target.execute_scenario("AG-SCN-002", profile="hardened", approval_granted=True)
        target.execute_scenario("AG-SCN-003", profile="hardened")
    except ValueError as exc:
        raise DoctorValidationError(
            "frozen corpus or executable F1.M3 coverage is invalid"
        ) from exc
    context.target = target
    return "10 frozen scenarios validated; AG-SCN-001..003 executed"


async def _collect_model_events(
    model: DeterministicModel, messages: Messages
) -> tuple[object, ...]:
    events = [
        event
        async for event in model.stream(
            messages,
            system_prompt=_PROBE_SYSTEM_PROMPT,
            system_prompt_content=[{"text": _PROBE_SYSTEM_PROMPT}],
        )
    ]
    return tuple(events)


def _check_model(_context: _DoctorContext) -> str:
    model = DeterministicModel({_PROBE_PROMPT: _PROBE_RESPONSE}, system_prompt=_PROBE_SYSTEM_PROMPT)
    messages: Messages = [{"role": "user", "content": [{"text": _PROBE_PROMPT}]}]
    first = asyncio.run(_collect_model_events(model, messages))
    second = asyncio.run(_collect_model_events(model, messages))
    if first != second:
        raise DoctorValidationError(
            "deterministic model event sequence changed across identical inputs"
        )
    first_result = Agent(
        model=model,
        tools=[],
        system_prompt=_PROBE_SYSTEM_PROMPT,
        callback_handler=None,
    )(_PROBE_PROMPT)
    second_result = Agent(
        model=model,
        tools=[],
        system_prompt=_PROBE_SYSTEM_PROMPT,
        callback_handler=None,
    )(_PROBE_PROMPT)
    if (
        str(first_result).strip() != _PROBE_RESPONSE
        or str(second_result).strip() != _PROBE_RESPONSE
    ):
        raise DoctorValidationError(
            "Strands invocation did not return the registered offline result"
        )

    unknown: Messages = [{"role": "user", "content": [{"text": "unregistered"}]}]
    try:
        asyncio.run(_collect_model_events(model, unknown))
    except UnregisteredModelInput:
        pass
    else:
        raise DoctorValidationError("deterministic model did not fail closed")
    return "real Strands Model invocation is repeatable and fail-closed"


def _check_identities(context: _DoctorContext) -> str:
    target = context.target or DeterministicTarget.from_repository(context.root)
    for manifest in target.manifests.values():
        validate_fixture_identity(manifest)
        material = manifest.model_dump(mode="json")
        original_digest = fixture_identity_digest(material)
        self_reference_probe = copy.deepcopy(material)
        self_reference_probe["candidate_identity"] = "fixture:probe:" + "0" * 64
        if fixture_identity_digest(self_reference_probe) != original_digest:
            raise DoctorValidationError("fixture identity is self-referential")
        changed = copy.deepcopy(material)
        changed["limits"]["max_iterations"] = cast(int, changed["limits"]["max_iterations"]) - 1
        if fixture_candidate_identity(changed) == manifest.candidate_identity:
            raise DoctorValidationError("material target change did not alter fixture identity")
    return "canonical non-self-referential identities match both manifests"


def _run_check(
    name: str, checker: Callable[[_DoctorContext], str], context: _DoctorContext
) -> DoctorCheck:
    try:
        detail = checker(context)
    except DoctorValidationError as exc:
        return DoctorCheck(name=name, ok=False, detail=str(exc))
    except Exception as exc:
        return DoctorCheck(name=name, ok=False, detail=f"unexpected {type(exc).__name__}")
    return DoctorCheck(name=name, ok=True, detail=detail)


def run_doctor(root: Path | None = None) -> DoctorReport:
    """Run every offline check and return a structured, non-throwing report."""

    context = _DoctorContext(root=(root or repository_root()).resolve())
    checks = (
        ("environment", _check_environment),
        ("configuration", _check_configuration),
        ("schemas", _check_schemas),
        ("targets", _check_targets),
        ("corpus", _check_corpus),
        ("model", _check_model),
        ("identities", _check_identities),
    )
    return DoctorReport(
        checks=tuple(_run_check(name, checker, context) for name, checker in checks)
    )


__all__ = [
    "DoctorCheck",
    "DoctorReport",
    "DoctorValidationError",
    "repository_root",
    "run_doctor",
]
