"""Bounded synthetic targets for offline AgentGuard checks."""

from .deterministic import (
    FROZEN_CORPUS,
    MVP_CORPUS,
    CorpusSpec,
    DeclaredTool,
    DeterministicTarget,
    ScenarioCorpus,
    TargetExecution,
    TargetInputRejected,
    TargetProfile,
    TargetValidationError,
    UnsupportedScenarioError,
    load_scenario_corpus,
)
from .identity import (
    FixtureIdentityError,
    fixture_candidate_identity,
    fixture_identity_digest,
    validate_fixture_identity,
)

__all__ = [
    "FROZEN_CORPUS",
    "MVP_CORPUS",
    "CorpusSpec",
    "DeclaredTool",
    "DeterministicTarget",
    "FixtureIdentityError",
    "ScenarioCorpus",
    "TargetExecution",
    "TargetInputRejected",
    "TargetProfile",
    "TargetValidationError",
    "UnsupportedScenarioError",
    "fixture_candidate_identity",
    "fixture_identity_digest",
    "load_scenario_corpus",
    "validate_fixture_identity",
]
