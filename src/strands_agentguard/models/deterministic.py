"""Deterministic, transcript-backed Strands model for fully offline checks."""

from __future__ import annotations

import json
import math
from collections.abc import AsyncGenerator, Mapping
from types import MappingProxyType
from typing import Any, TypeVar, cast, override

from pydantic import BaseModel
from strands.models import Model
from strands.types.content import Messages, SystemContentBlock
from strands.types.streaming import StreamEvent
from strands.types.tools import ToolChoice, ToolSpec

T = TypeVar("T", bound=BaseModel)

MODEL_ID = "agentguard-deterministic-v0.1.0"


class UnregisteredModelInput(ValueError):
    """Raised when an invocation is outside the exact offline transcript."""


class DeterministicModel(Model):
    """A real Strands model provider that only answers predeclared text prompts.

    Runtime invocation state is deliberately ignored: it may contain opaque SDK
    objects and never has authority to select or alter a registered response.
    Messages, system prompt, tool surface, and model kwargs are checked exactly.
    """

    def __init__(
        self,
        responses: Mapping[str, str],
        *,
        system_prompt: str | None = None,
    ) -> None:
        if not responses:
            raise ValueError("at least one deterministic response is required")
        copied: dict[str, str] = {}
        for prompt, response in responses.items():
            if (
                not isinstance(prompt, str)
                or not prompt
                or not isinstance(response, str)
                or not response
            ):
                raise ValueError("deterministic prompts and responses must be non-empty strings")
            copied[prompt] = response
        if system_prompt is not None and (not isinstance(system_prompt, str) or not system_prompt):
            raise ValueError("system_prompt must be a non-empty string or None")
        self._responses = MappingProxyType(copied)
        self._system_prompt = system_prompt
        self._context_window_limit: int | None = None

    @override
    def get_config(self) -> dict[str, Any]:
        return {
            "model_id": MODEL_ID,
            "context_window_limit": self._context_window_limit,
            "egress": False,
        }

    @override
    def update_config(self, **model_config: Any) -> None:
        unknown = set(model_config) - {"model_id", "context_window_limit", "egress"}
        if unknown:
            raise ValueError("deterministic model configuration contains unsupported fields")
        if model_config.get("model_id", MODEL_ID) != MODEL_ID:
            raise ValueError("deterministic model_id is immutable")
        if model_config.get("egress", False) is not False:
            raise ValueError("deterministic model cannot enable egress")
        if "context_window_limit" in model_config:
            limit = model_config["context_window_limit"]
            if limit is not None and (
                isinstance(limit, bool) or not isinstance(limit, int) or limit < 1
            ):
                raise ValueError("context_window_limit must be a positive integer or None")
            self._context_window_limit = limit

    @override
    async def stream(
        self,
        messages: Messages,
        tool_specs: list[ToolSpec] | None = None,
        system_prompt: str | None = None,
        *,
        tool_choice: ToolChoice | None = None,
        system_prompt_content: list[SystemContentBlock] | None = None,
        invocation_state: dict[str, Any] | None = None,
        **kwargs: Any,
    ) -> AsyncGenerator[StreamEvent, None]:
        response = self._response_for(
            messages,
            tool_specs=tool_specs,
            system_prompt=system_prompt,
            tool_choice=tool_choice,
            system_prompt_content=system_prompt_content,
            invocation_state=invocation_state,
            kwargs=kwargs,
        )
        for event in self._events(response, messages):
            yield event

    @override
    async def structured_output(
        self,
        output_model: type[T],
        prompt: Messages,
        system_prompt: str | None = None,
        **kwargs: Any,
    ) -> AsyncGenerator[dict[str, T | Any], None]:
        invocation_state = kwargs.pop("invocation_state", None)
        response = self._response_for(
            prompt,
            tool_specs=None,
            system_prompt=system_prompt,
            tool_choice=None,
            system_prompt_content=None,
            invocation_state=invocation_state,
            kwargs=kwargs,
        )

        def reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
            value: dict[str, Any] = {}
            for key, item in pairs:
                if key in value:
                    raise UnregisteredModelInput("structured response contains duplicate keys")
                value[key] = item
            return value

        try:
            document = json.loads(response, object_pairs_hook=reject_duplicate_keys)
            if not isinstance(document, dict):
                raise ValueError
            output = output_model.model_validate(document, strict=True)
        except (json.JSONDecodeError, ValueError) as exc:
            raise UnregisteredModelInput("registered structured response is invalid") from exc
        yield {"output": output}

    def _response_for(
        self,
        messages: Messages,
        *,
        tool_specs: list[ToolSpec] | None,
        system_prompt: str | None,
        tool_choice: ToolChoice | None,
        system_prompt_content: list[SystemContentBlock] | None,
        invocation_state: dict[str, Any] | None,
        kwargs: Mapping[str, Any],
    ) -> str:
        if tool_specs:
            raise UnregisteredModelInput("no executable tool surface is registered")
        if tool_choice is not None:
            raise UnregisteredModelInput("tool choice is not registered")
        if invocation_state is not None and not isinstance(invocation_state, dict):
            raise UnregisteredModelInput("invocation state must be an SDK mapping")
        if set(kwargs) - {"model_state"} or kwargs.get("model_state", {}) not in ({}, None):
            raise UnregisteredModelInput("model kwargs are not registered")
        if system_prompt != self._system_prompt:
            raise UnregisteredModelInput("system prompt is not registered")

        expected_content: list[SystemContentBlock] | None = None
        if self._system_prompt is not None:
            expected_content = [{"text": self._system_prompt}]
        if system_prompt_content not in (None, [], expected_content):
            raise UnregisteredModelInput("structured system prompt is not registered")

        if len(messages) != 1 or messages[0].get("role") != "user":
            raise UnregisteredModelInput("conversation shape is not registered")
        content = messages[0].get("content")
        if not isinstance(content, list) or len(content) != 1 or set(content[0]) != {"text"}:
            raise UnregisteredModelInput("message content is not registered")
        prompt = content[0].get("text")
        if not isinstance(prompt, str):
            raise UnregisteredModelInput("message text is not registered")
        try:
            return self._responses[prompt]
        except KeyError:
            raise UnregisteredModelInput("prompt is not registered") from None

    @staticmethod
    def _events(response: str, messages: Messages) -> tuple[StreamEvent, ...]:
        input_chars = 0
        for message in messages:
            for block in message["content"]:
                text = block.get("text")
                if isinstance(text, str):
                    input_chars += len(text)
        input_tokens = max(1, math.ceil(input_chars / 4))
        output_tokens = max(1, math.ceil(len(response) / 4))
        return (
            cast(StreamEvent, {"messageStart": {"role": "assistant"}}),
            cast(StreamEvent, {"contentBlockDelta": {"delta": {"text": response}}}),
            cast(StreamEvent, {"contentBlockStop": {}}),
            cast(StreamEvent, {"messageStop": {"stopReason": "end_turn"}}),
            cast(
                StreamEvent,
                {
                    "metadata": {
                        "usage": {
                            "inputTokens": input_tokens,
                            "outputTokens": output_tokens,
                            "totalTokens": input_tokens + output_tokens,
                        },
                        "metrics": {"latencyMs": 0},
                    }
                },
            ),
        )


__all__ = ["MODEL_ID", "DeterministicModel", "UnregisteredModelInput"]
