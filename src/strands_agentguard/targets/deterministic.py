"""One bounded, deterministic synthetic target shared by both policy profiles."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import stat
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import Any, Literal, cast

# jsonschema is installed by Strands and already anchors the checked-in contracts.
from jsonschema import Draft202012Validator  # type: ignore[import-untyped, unused-ignore]
from jsonschema.exceptions import (  # type: ignore[import-untyped, unused-ignore]
    ValidationError as JsonSchemaValidationError,
)
from pydantic import JsonValue

from strands_agentguard.contracts import (
    Scenario,
    TargetManifest,
    ToolDescriptor,
    canonical_json_bytes,
)
from strands_agentguard.targets.identity import validate_fixture_identity

type TargetProfile = Literal["baseline", "hardened"]

SUPPORTED_SCENARIO_IDS = ("AG-SCN-001", "AG-SCN-002", "AG-SCN-003")
_EXPECTED_CORPUS_SCENARIO_IDS = tuple(f"AG-SCN-{index:03d}" for index in range(1, 11))
_SENSITIVE_ACTION_SCENARIO_ID = "AG-SCN-002"
_TARGET_PATHS: Mapping[TargetProfile, str] = MappingProxyType(
    {
        "baseline": "fixtures/targets/vulnerable.json",
        "hardened": "fixtures/targets/hardened.json",
    }
)
_CORPUS_RELATIVE_ROOT = Path("fixtures/scenarios/v0.1.0")
_DIRECTORY_OPEN_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
_FILE_OPEN_FLAGS = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
_DENIED_AMBIENT_CAPABILITIES = frozenset(
    {"cloud", "filesystem_arbitrary", "network", "shell", "subprocess"}
)


class TargetValidationError(ValueError):
    """Raised when bounded target or corpus material is invalid."""


class TargetInputRejected(ValueError):
    """Raised when untrusted synthetic operation input is not allowlisted."""


class UnsupportedScenarioError(LookupError):
    """Raised when no deterministic handler is registered for a scenario."""


@dataclass(frozen=True, slots=True)
class DeclaredTool:
    """Policy-neutral tool registration surface shared by both profiles."""

    tool_id: str
    name: str
    description: str
    input_schema_sha256: str
    origin: str
    effect_class: str
    fingerprint: str


@dataclass(frozen=True, slots=True)
class ScenarioCorpus:
    """Validated frozen scenario corpus held entirely in memory."""

    corpus_id: str
    version: str
    manifest_sha256: str
    scenarios: Mapping[str, Scenario]

    def get(self, scenario_id: str) -> Scenario:
        try:
            return self.scenarios[scenario_id]
        except KeyError:
            raise UnsupportedScenarioError("scenario is absent from the frozen corpus") from None


@dataclass(frozen=True, slots=True)
class TargetExecution:
    """Immutable observable result of one synthetic in-memory operation."""

    scenario_id: str
    profile: TargetProfile
    trajectory: tuple[str, ...]
    outcome: Mapping[str, JsonValue]
    effects: tuple[Mapping[str, JsonValue], ...]
    policy_decision: str

    @property
    def effect_count(self) -> int:
        return len(self.effects)


def _parse_json_object(document_bytes: bytes) -> dict[str, Any]:
    def reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise TargetValidationError("duplicate JSON key in fixture material")
            result[key] = value
        return result

    try:
        value = json.loads(document_bytes, object_pairs_hook=reject_duplicate_keys)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise TargetValidationError("fixture material is unavailable or malformed") from exc
    if not isinstance(value, dict):
        raise TargetValidationError("fixture document must be a JSON object")
    canonical_json_bytes(value)
    return cast(dict[str, Any], value)


def _open_directory(path: str | Path, *, dir_fd: int | None = None) -> int:
    try:
        descriptor = os.open(path, _DIRECTORY_OPEN_FLAGS, dir_fd=dir_fd)
    except OSError as exc:
        raise TargetValidationError("corpus directory is unavailable or unsafe") from exc
    try:
        metadata = os.fstat(descriptor)
    except OSError as exc:
        os.close(descriptor)
        raise TargetValidationError("corpus directory is unavailable or unsafe") from exc
    if not stat.S_ISDIR(metadata.st_mode):
        os.close(descriptor)
        raise TargetValidationError("corpus directory is unavailable or unsafe")
    return descriptor


def _directory_identity(metadata: os.stat_result) -> tuple[int, int, int]:
    return metadata.st_dev, metadata.st_ino, metadata.st_mode


def _file_identity(metadata: os.stat_result) -> tuple[int, int, int, int, int, int]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


@contextmanager
def _opened_corpus_directory(root: Path) -> Iterator[int]:
    """Anchor every corpus path component to a non-symlink directory descriptor."""

    descriptors = [_open_directory(root)]
    directory_links: list[tuple[int, str, os.stat_result]] = []
    try:
        for component in _CORPUS_RELATIVE_ROOT.parts:
            parent_descriptor = descriptors[-1]
            child_descriptor = _open_directory(component, dir_fd=parent_descriptor)
            descriptors.append(child_descriptor)
            try:
                child_metadata = os.fstat(child_descriptor)
            except OSError as exc:
                raise TargetValidationError("corpus directory is unavailable or unsafe") from exc
            directory_links.append((parent_descriptor, component, child_metadata))
        yield descriptors[-1]
        for parent_descriptor, component, opened_metadata in directory_links:
            try:
                current_metadata = os.stat(
                    component,
                    dir_fd=parent_descriptor,
                    follow_symlinks=False,
                )
            except OSError as exc:
                raise TargetValidationError("corpus directory changed while loading") from exc
            if not stat.S_ISDIR(current_metadata.st_mode) or _directory_identity(
                current_metadata
            ) != _directory_identity(opened_metadata):
                raise TargetValidationError("corpus directory changed while loading")
    finally:
        for descriptor in reversed(descriptors):
            os.close(descriptor)


def _validate_corpus_filename(filename: str) -> None:
    """Accept only one direct POSIX child name within the anchored corpus directory."""

    parts = filename.split("/")
    if len(parts) != 1 or parts[0] in {"", ".", ".."} or "\\" in filename:
        raise TargetValidationError("corpus material path contains traversal")


def _read_regular_corpus_file(
    corpus_descriptor: int,
    filename: str,
) -> tuple[bytes, os.stat_result]:
    """Validate and read one file through the same non-following descriptor."""

    _validate_corpus_filename(filename)
    try:
        descriptor = os.open(filename, _FILE_OPEN_FLAGS, dir_fd=corpus_descriptor)
    except OSError as exc:
        raise TargetValidationError(
            "corpus material must be a regular non-symlink file within v0.1.0"
        ) from exc
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise TargetValidationError(
                "corpus material must be a regular non-symlink file within v0.1.0"
            )
        with os.fdopen(descriptor, "rb", closefd=False) as source:
            document_bytes = source.read()
        after = os.fstat(descriptor)
    except OSError as exc:
        raise TargetValidationError("corpus material became unavailable while reading") from exc
    finally:
        os.close(descriptor)
    if _file_identity(before) != _file_identity(after):
        raise TargetValidationError("corpus material changed while reading")
    return document_bytes, after


def _verify_opened_corpus_files(
    corpus_descriptor: int,
    opened_files: Mapping[str, os.stat_result],
) -> None:
    """Reject path replacement after a safe descriptor was acquired and read."""

    for filename, opened_metadata in opened_files.items():
        try:
            current_metadata = os.stat(
                filename,
                dir_fd=corpus_descriptor,
                follow_symlinks=False,
            )
        except OSError as exc:
            raise TargetValidationError("corpus material changed while loading") from exc
        if not stat.S_ISREG(current_metadata.st_mode) or _file_identity(
            current_metadata
        ) != _file_identity(opened_metadata):
            raise TargetValidationError("corpus material changed while loading")


def load_scenario_corpus(root: Path) -> ScenarioCorpus:
    """Load and hash-check the one existing frozen corpus hierarchy."""

    with _opened_corpus_directory(root) as corpus_descriptor:
        opened_files: dict[str, os.stat_result] = {}
        manifest_bytes, manifest_metadata = _read_regular_corpus_file(
            corpus_descriptor, "manifest.json"
        )
        opened_files["manifest.json"] = manifest_metadata
        manifest = _parse_json_object(manifest_bytes)
        expected_keys = {
            "schema_version",
            "corpus_id",
            "version",
            "frozen",
            "frozen_at",
            "provenance",
            "confidence",
            "synthetic",
            "real_data",
            "scenario_schema",
            "scenario_count",
            "scenarios",
        }
        if set(manifest) != expected_keys:
            raise TargetValidationError("corpus manifest fields do not match v0.1.0")
        if (
            manifest["schema_version"] != "0.1.0"
            or manifest["corpus_id"] != "AG-THREAT-CORPUS"
            or manifest["version"] != "0.1.0"
            or manifest["frozen"] is not True
            or manifest["provenance"] != "authored_for_strands_agentguard"
            or manifest["confidence"] != "designed_not_executed"
            or manifest["synthetic"] is not True
            or manifest["real_data"] is not False
            or manifest["scenario_schema"] != "schemas/scenario.schema.json"
        ):
            raise TargetValidationError(
                "corpus manifest metadata is not the frozen v0.1.0 contract"
            )

        entries = manifest["scenarios"]
        count = manifest["scenario_count"]
        if isinstance(count, bool) or not isinstance(count, int) or not isinstance(entries, list):
            raise TargetValidationError("corpus manifest count or entries are invalid")
        if count != len(_EXPECTED_CORPUS_SCENARIO_IDS) or len(entries) != count:
            raise TargetValidationError(
                "corpus manifest must contain exactly the ten frozen v0.1.0 scenarios"
            )

        validated_entries: list[tuple[str, str, str, str]] = []
        expected_paths: set[str] = set()
        for entry, expected_scenario_id in zip(entries, _EXPECTED_CORPUS_SCENARIO_IDS, strict=True):
            if not isinstance(entry, dict) or set(entry) != {"scenario_id", "path", "sha256"}:
                raise TargetValidationError("corpus entry fields do not match v0.1.0")
            scenario_id = entry["scenario_id"]
            path_value = entry["path"]
            expected_hash = entry["sha256"]
            if not all(
                isinstance(value, str) for value in (scenario_id, path_value, expected_hash)
            ):
                raise TargetValidationError("corpus entry values must be strings")
            if scenario_id != expected_scenario_id:
                raise TargetValidationError(
                    "corpus scenarios must be exactly AG-SCN-001 through AG-SCN-010 in order"
                )
            expected_path = f"fixtures/scenarios/v0.1.0/{scenario_id.lower()}.json"
            path_parts = path_value.split("/")
            if (
                path_value.startswith("/")
                or any(part in {"", ".", ".."} for part in path_parts)
                or "\\" in path_value
                or path_value != expected_path
                or path_value in expected_paths
            ):
                raise TargetValidationError(
                    "corpus entry path is not canonical, unique, and traversal-free"
                )
            filename = f"{scenario_id.lower()}.json"
            _validate_corpus_filename(filename)
            validated_entries.append((scenario_id, path_value, expected_hash, filename))
            expected_paths.add(path_value)

        scenarios: dict[str, Scenario] = {}
        for scenario_id, path_value, expected_hash, filename in validated_entries:
            fixture_bytes, fixture_metadata = _read_regular_corpus_file(corpus_descriptor, filename)
            opened_files[filename] = fixture_metadata
            actual_hash = hashlib.sha256(fixture_bytes).hexdigest()
            if not hmac.compare_digest(expected_hash, actual_hash):
                raise TargetValidationError(
                    "scenario fixture hash does not match the frozen manifest"
                )
            try:
                scenario = Scenario.model_validate_json(fixture_bytes)
            except ValueError as exc:
                raise TargetValidationError(
                    "scenario fixture violates its semantic contract"
                ) from exc
            if scenario.scenario_id != scenario_id or scenario.fixture_ref != path_value:
                raise TargetValidationError("scenario fixture does not match its manifest entry")
            if scenario_id in scenarios:
                raise TargetValidationError("corpus contains a duplicate scenario identifier")
            scenarios[scenario_id] = scenario

        try:
            materialized_names = {
                name
                for name in os.listdir(corpus_descriptor)
                if name.startswith("ag-scn-") and name.endswith(".json")
            }
        except OSError as exc:
            raise TargetValidationError("corpus directory changed while loading") from exc
        expected_names = {entry[3] for entry in validated_entries}
        if materialized_names != expected_names:
            raise TargetValidationError(
                "frozen corpus manifest does not enumerate exactly its fixtures"
            )
        _verify_opened_corpus_files(corpus_descriptor, opened_files)

    return ScenarioCorpus(
        corpus_id=cast(str, manifest["corpus_id"]),
        version=cast(str, manifest["version"]),
        manifest_sha256=hashlib.sha256(manifest_bytes).hexdigest(),
        scenarios=MappingProxyType(scenarios),
    )


class DeterministicTarget:
    """Single in-memory engine whose only variable is the selected profile policy."""

    engine_id = "agentguard-in-memory-v0.1.0"

    def __init__(
        self,
        *,
        corpus: ScenarioCorpus,
        manifests: Mapping[TargetProfile, TargetManifest],
    ) -> None:
        if set(manifests) != {"baseline", "hardened"}:
            raise TargetValidationError("exactly baseline and hardened manifests are required")
        baseline = manifests["baseline"]
        hardened = manifests["hardened"]
        if baseline.profile != "baseline" or hardened.profile != "hardened":
            raise TargetValidationError("target manifest is assigned to the wrong profile")
        if (
            baseline.target_id != hardened.target_id
            or baseline.target_version != hardened.target_version
            or baseline.provider != hardened.provider
            or baseline.mcp_servers != hardened.mcp_servers
            or baseline.capabilities != hardened.capabilities
        ):
            raise TargetValidationError("profiles do not describe one shared target engine")

        baseline_surface = self._surface_for(baseline)
        hardened_surface = self._surface_for(hardened)
        if baseline_surface != hardened_surface:
            raise TargetValidationError("profiles do not share the same declared tool surface")
        for manifest in (baseline, hardened):
            if not _DENIED_AMBIENT_CAPABILITIES.issubset(manifest.permissions.deny):
                raise TargetValidationError("target profile does not deny every ambient capability")

        sensitive_baseline = self._tool_for(baseline, "simulate_sensitive_action")
        sensitive_hardened = self._tool_for(hardened, "simulate_sensitive_action")
        if (
            sensitive_baseline.approval_required
            or sensitive_baseline.tool_id not in baseline.permissions.allow
            or not sensitive_hardened.approval_required
            or sensitive_hardened.tool_id not in hardened.permissions.approval
        ):
            raise TargetValidationError("profile policies do not encode the approval differential")

        self._corpus = corpus
        self._manifests = MappingProxyType(dict(manifests))
        self._tool_surface = baseline_surface

    @classmethod
    def from_repository(cls, root: Path) -> DeterministicTarget:
        """Load the fixed target fixtures and corpus before entering in-memory execution."""

        manifests: dict[TargetProfile, TargetManifest] = {}
        for profile, relative_path in _TARGET_PATHS.items():
            try:
                manifest = TargetManifest.model_validate_json((root / relative_path).read_bytes())
                validate_fixture_identity(manifest)
            except (OSError, ValueError) as exc:
                raise TargetValidationError("target manifest is unavailable or invalid") from exc
            manifests[profile] = manifest
        return cls(corpus=load_scenario_corpus(root), manifests=manifests)

    @property
    def corpus(self) -> ScenarioCorpus:
        return self._corpus

    @property
    def manifests(self) -> Mapping[TargetProfile, TargetManifest]:
        return self._manifests

    @property
    def tool_surface(self) -> tuple[DeclaredTool, ...]:
        return self._tool_surface

    @staticmethod
    def _tool_for(manifest: TargetManifest, tool_id: str) -> ToolDescriptor:
        for tool in manifest.tools:
            if tool.tool_id == tool_id:
                return tool
        raise TargetValidationError("required synthetic tool declaration is absent")

    @classmethod
    def _surface_for(cls, manifest: TargetManifest) -> tuple[DeclaredTool, ...]:
        return tuple(
            DeclaredTool(
                tool_id=tool.tool_id,
                name=tool.name,
                description=tool.description,
                input_schema_sha256=hashlib.sha256(
                    canonical_json_bytes(tool.input_schema)
                ).hexdigest(),
                origin=tool.origin,
                effect_class=tool.effect_class,
                fingerprint=tool.fingerprint,
            )
            for tool in manifest.tools
        )

    def manifest_for(self, profile: TargetProfile) -> TargetManifest:
        try:
            return self._manifests[profile]
        except KeyError:
            raise TargetInputRejected("target profile is not supported") from None

    def simulate_sensitive_action(
        self,
        *,
        profile: TargetProfile,
        payload: Mapping[str, JsonValue],
        approval_granted: bool,
        scenario_id: str = "AG-SCN-002",
    ) -> TargetExecution:
        """Apply at most one synthetic effect to an invocation-local in-memory tuple."""

        if not isinstance(approval_granted, bool):
            raise TargetInputRejected("approval_granted must be a strict boolean")
        if scenario_id != _SENSITIVE_ACTION_SCENARIO_ID:
            raise UnsupportedScenarioError("scenario has no deterministic sensitive-action adapter")
        manifest = self.manifest_for(profile)
        descriptor = self._tool_for(manifest, "simulate_sensitive_action")
        try:
            validated_payload = json.loads(canonical_json_bytes(payload))
            Draft202012Validator(dict(descriptor.input_schema)).validate(validated_payload)
        except (TypeError, ValueError, JsonSchemaValidationError) as exc:
            raise TargetInputRejected(
                "sensitive action input does not match its declaration"
            ) from exc

        if descriptor.approval_required and not approval_granted:
            return TargetExecution(
                scenario_id=scenario_id,
                profile=profile,
                trajectory=("propose", "policy_check", "deny", "verify_zero_effect", "audit"),
                outcome=MappingProxyType({"effect_count": 0, "idempotent": True}),
                effects=(),
                policy_decision="approval_required",
            )

        decision = "approved" if descriptor.approval_required else "allowed_without_approval"
        trajectory = (
            (
                "propose",
                "policy_check",
                "interrupt",
                "bind_decision",
                "execute_once",
                "verify_effect",
                "audit",
            )
            if descriptor.approval_required
            else ("propose", "policy_check", "execute_once", "verify_effect", "audit")
        )
        effect = MappingProxyType(cast(dict[str, JsonValue], validated_payload))
        return TargetExecution(
            scenario_id=scenario_id,
            profile=profile,
            trajectory=trajectory,
            outcome=MappingProxyType({"effect_count": 1, "idempotent": True}),
            effects=(effect,),
            policy_decision=decision,
        )

    def execute_scenario(
        self,
        scenario_id: str,
        *,
        profile: TargetProfile,
        approval_granted: bool = False,
    ) -> TargetExecution:
        """Execute only the three explicitly registered F1.M3 scenario adapters."""

        if not isinstance(approval_granted, bool):
            raise TargetInputRejected("approval_granted must be a strict boolean")
        if scenario_id not in SUPPORTED_SCENARIO_IDS:
            raise UnsupportedScenarioError("scenario has no deterministic F1.M3 adapter")
        scenario = self._corpus.get(scenario_id)

        if scenario_id == "AG-SCN-001":
            requested_profile = scenario.action.input.get("target_profile")
            if profile != "hardened" or requested_profile != profile:
                raise TargetInputRejected("inspection scenario requires the hardened profile")
            manifest = self.manifest_for(profile)
            execution = TargetExecution(
                scenario_id=scenario_id,
                profile=profile,
                trajectory=(
                    "validate_identity",
                    "read_allowlisted_contract",
                    "build_manifest",
                    "fingerprint_tools",
                    "persist_inventory",
                ),
                outcome=MappingProxyType({"manifest_valid": True, "effect_count": 0}),
                effects=(),
                policy_decision=f"inspected:{manifest.candidate_identity}",
            )
        elif scenario_id == "AG-SCN-002":
            if profile != "hardened" or not approval_granted:
                raise TargetInputRejected("corpus scenario requires its declared one-use approval")
            execution = self.simulate_sensitive_action(
                profile=profile,
                payload=scenario.action.input,
                approval_granted=True,
                scenario_id=scenario_id,
            )
        else:
            if profile != "hardened":
                raise TargetInputRejected(
                    "adversarial corpus scenario requires the hardened profile"
                )
            execution = TargetExecution(
                scenario_id=scenario_id,
                profile=profile,
                trajectory=(
                    "receive_untrusted_result",
                    "label_untrusted",
                    "policy_check",
                    "guide_or_cancel",
                    "verify_zero_effect",
                    "record",
                ),
                outcome=MappingProxyType({"effect_count": 0, "policy_changed": False}),
                effects=(),
                policy_decision="untrusted_content_ignored",
            )

        self._validate_expected_result(scenario, execution)
        return execution

    @staticmethod
    def _validate_expected_result(scenario: Scenario, execution: TargetExecution) -> None:
        if execution.trajectory != scenario.expected_trajectory.required_order:
            raise TargetValidationError("scenario trajectory does not match the frozen corpus")
        for assertion in scenario.expected_outcome.assertions:
            if (
                assertion.operator != "equals"
                or execution.outcome.get(assertion.field) != assertion.value
            ):
                raise TargetValidationError("scenario outcome does not match the frozen corpus")


__all__ = [
    "SUPPORTED_SCENARIO_IDS",
    "DeclaredTool",
    "DeterministicTarget",
    "ScenarioCorpus",
    "TargetExecution",
    "TargetInputRejected",
    "TargetProfile",
    "TargetValidationError",
    "UnsupportedScenarioError",
    "load_scenario_corpus",
]
