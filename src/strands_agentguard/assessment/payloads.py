"""Load and validate untrusted-content payload sets."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Annotated, Literal

from jsonschema import Draft202012Validator  # type: ignore[import-untyped, unused-ignore]
from pydantic import BaseModel, ConfigDict, StringConstraints

NEUTRAL_RELATIVE_PATH = Path("fixtures/payloads/v0.1.0/neutral.json")
MAX_PAYLOAD_FILE_BYTES = 256 * 1024


class PayloadError(ValueError):
    """Raised when a payload set is missing, oversized or invalid."""


class PayloadCase(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    case_id: Annotated[str, StringConstraints(pattern=r"^[a-z][a-z0-9._-]{0,63}$")]
    scenario_id: Annotated[str, StringConstraints(pattern=r"^AG-SCN-[0-9]{3}$")]
    text: Annotated[str, StringConstraints(min_length=1, max_length=2000)]


class PayloadSet(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["0.1.0"]
    payload_set_id: Annotated[str, StringConstraints(pattern=r"^[a-z][a-z0-9._-]{0,63}$")]
    kind: Literal["neutral", "adversarial"]
    cases: tuple[PayloadCase, ...]


@dataclass(frozen=True, slots=True)
class LoadedPayloads:
    payload_set: PayloadSet
    sha256: str

    def cases_for(self, scenario_id: str) -> tuple[PayloadCase, ...]:
        return tuple(c for c in self.payload_set.cases if c.scenario_id == scenario_id)


def load_payload_set(path: Path, root: Path) -> LoadedPayloads:
    try:
        data = path.read_bytes()
    except OSError as exc:
        raise PayloadError(f"payload set is unreadable: {path}") from exc
    if len(data) > MAX_PAYLOAD_FILE_BYTES:
        raise PayloadError("payload set exceeds the size limit")
    try:
        document = json.loads(data)
        schema = json.loads((root / "schemas" / "payload-set.schema.json").read_bytes())
        Draft202012Validator(schema).validate(document)
        parsed = PayloadSet.model_validate(document)
    except Exception as exc:
        raise PayloadError("payload set does not match payload-set.schema.json") from exc
    ids = [(c.scenario_id, c.case_id) for c in parsed.cases]
    if len(ids) != len(set(ids)):
        raise PayloadError("payload set contains duplicate case identifiers")
    return LoadedPayloads(parsed, hashlib.sha256(data).hexdigest())


__all__ = [
    "NEUTRAL_RELATIVE_PATH",
    "LoadedPayloads",
    "PayloadCase",
    "PayloadError",
    "PayloadSet",
    "load_payload_set",
]
