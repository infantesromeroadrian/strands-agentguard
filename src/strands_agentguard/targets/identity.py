"""Canonical identities for checked-in synthetic target fixtures."""

from __future__ import annotations

import hmac
from collections.abc import Mapping
from typing import Any

from strands_agentguard.contracts import TargetManifest, canonical_sha256


class FixtureIdentityError(ValueError):
    """Raised when a target fixture does not match its canonical identity."""


def fixture_identity_digest(document: Mapping[str, Any] | TargetManifest) -> str:
    """Hash fixture material without hashing the identity that carries the hash."""

    if isinstance(document, TargetManifest):
        material = document.model_dump(mode="json")
    else:
        material = dict(document)
    material.pop("candidate_identity", None)
    return canonical_sha256(material)


def fixture_candidate_identity(document: Mapping[str, Any] | TargetManifest) -> str:
    """Return the canonical tagged fixture identity for one target manifest."""

    profile = document.profile if isinstance(document, TargetManifest) else document.get("profile")
    if profile not in {"baseline", "hardened"}:
        raise FixtureIdentityError("fixture profile is not supported")
    return f"fixture:{profile}:{fixture_identity_digest(document)}"


def validate_fixture_identity(document: Mapping[str, Any] | TargetManifest) -> None:
    """Fail closed unless the declared identity matches canonical fixture material."""

    candidate = (
        document.candidate_identity
        if isinstance(document, TargetManifest)
        else document.get("candidate_identity")
    )
    if not isinstance(candidate, str) or not hmac.compare_digest(
        candidate, fixture_candidate_identity(document)
    ):
        raise FixtureIdentityError("target fixture identity does not match canonical material")


__all__ = [
    "FixtureIdentityError",
    "fixture_candidate_identity",
    "fixture_identity_digest",
    "validate_fixture_identity",
]
