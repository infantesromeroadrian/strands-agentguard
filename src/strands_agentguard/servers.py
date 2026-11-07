"""Allowlist of user-registered stdio MCP servers (agentguard.toml)."""

from __future__ import annotations

import os
import tomllib
from collections.abc import Mapping
from pathlib import Path
from typing import Annotated

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, ValidationError

DEFAULT_CONFIG_NAME = "agentguard.toml"
MAX_CONFIG_BYTES = 16 * 1024
MAX_SERVERS = 16
BUILTIN_SERVER_ID = "synthetic-audit"


class ServerConfigError(ValueError):
    """Raised when the server registry is missing, oversized or invalid."""


class ServerEntry(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    id: Annotated[str, StringConstraints(pattern=r"^[a-z][a-z0-9._-]{0,63}$")]
    command: Annotated[str, StringConstraints(min_length=1, max_length=512)]
    args: tuple[Annotated[str, StringConstraints(max_length=512)], ...] = ()
    env: Mapping[str, str] = {}
    env_passthrough: tuple[
        Annotated[str, StringConstraints(pattern=r"^[A-Z_][A-Z0-9_]*$")], ...
    ] = ()
    timeout_seconds: Annotated[int, Field(ge=1, le=60)] = 15

    def launch_env(self) -> dict[str, str]:
        """Explicit variables only; the MCP SDK adds its small safe default set."""

        env = dict(self.env)
        for name in self.env_passthrough:
            if name in os.environ:
                env[name] = os.environ[name]
        return env


class ServerRegistry(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    servers: tuple[ServerEntry, ...] = ()

    def get(self, server_id: str) -> ServerEntry | None:
        return next((entry for entry in self.servers if entry.id == server_id), None)


def load_registry(path: Path | None) -> ServerRegistry:
    """Load ``path`` (or ./agentguard.toml when it exists); no file means no extra servers."""

    if path is None:
        default = Path.cwd() / DEFAULT_CONFIG_NAME
        if not default.is_file():
            return ServerRegistry()
        path = default
    try:
        data = path.read_bytes()
    except OSError as exc:
        raise ServerConfigError(f"server config is unreadable: {path}") from exc
    if len(data) > MAX_CONFIG_BYTES:
        raise ServerConfigError("server config exceeds the size limit")
    try:
        registry = ServerRegistry.model_validate(tomllib.loads(data.decode("utf-8")))
    except (tomllib.TOMLDecodeError, UnicodeDecodeError, ValidationError) as exc:
        raise ServerConfigError("server config is not valid (see agentguard.example.toml)") from exc
    ids = [entry.id for entry in registry.servers]
    if len(ids) != len(set(ids)) or BUILTIN_SERVER_ID in ids or len(ids) > MAX_SERVERS:
        raise ServerConfigError(
            "server ids must be unique, at most 16, and must not reuse the built-in id"
        )
    return registry


__all__ = [
    "BUILTIN_SERVER_ID",
    "DEFAULT_CONFIG_NAME",
    "ServerConfigError",
    "ServerEntry",
    "ServerRegistry",
    "load_registry",
]
