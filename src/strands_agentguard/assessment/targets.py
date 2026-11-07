"""Construct assessment targets: the deterministic reference profiles."""

from __future__ import annotations

from pathlib import Path
from typing import Literal

from strands_agentguard.assessment.agents import ObedientReferenceAgent
from strands_agentguard.assessment.model import ControlSet
from strands_agentguard.assessment.runner import AssessmentError, TargetSpec
from strands_agentguard.contracts import TargetManifest, canonical_sha256
from strands_agentguard.targets import validate_fixture_identity

DETERMINISTIC_TARGETS: dict[str, tuple[Literal["baseline", "hardened"], str]] = {
    "vulnerable": ("baseline", "fixtures/targets/vulnerable.json"),
    "hardened": ("hardened", "fixtures/targets/hardened.json"),
}
TARGET_CHOICES = ("vulnerable", "hardened", "strands-ollama")


def deterministic_target(root: Path, name: str) -> TargetSpec:
    try:
        profile, relative = DETERMINISTIC_TARGETS[name]
    except KeyError:
        raise AssessmentError(f"unknown deterministic target: {name!r}") from None
    try:
        manifest = TargetManifest.model_validate_json((root / relative).read_bytes())
        validate_fixture_identity(manifest)
    except (OSError, ValueError) as exc:
        raise AssessmentError("target fixture is unavailable or invalid") from exc
    return TargetSpec(
        kind="deterministic",
        name=name,
        target_id=manifest.target_id,
        profile=profile,
        controls=ControlSet.for_profile(profile),
        agent_factory=ObedientReferenceAgent,
        target_candidate=manifest.candidate_identity,
        manifest_sha256=canonical_sha256(manifest.model_dump(mode="json")),
        default_repetitions=1,
    )


__all__ = ["DETERMINISTIC_TARGETS", "TARGET_CHOICES", "deterministic_target"]
