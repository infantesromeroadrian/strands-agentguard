from __future__ import annotations

from typing import Any

import pytest
from pydantic import BaseModel, ConfigDict
from strands import Agent
from strands.models import Model
from strands.types.content import Messages

from strands_agentguard import DeterministicModel, UnregisteredModelInput

PROMPT = "registered offline prompt"
RESPONSE = "deterministic offline response"
SYSTEM_PROMPT = "Use only the registered transcript."


def messages(text: str = PROMPT) -> Messages:
    return [{"role": "user", "content": [{"text": text}]}]


async def collect(model: DeterministicModel, prompt: Messages) -> tuple[object, ...]:
    events = [
        event
        async for event in model.stream(
            prompt,
            system_prompt=SYSTEM_PROMPT,
            system_prompt_content=[{"text": SYSTEM_PROMPT}],
        )
    ]
    return tuple(events)


@pytest.mark.asyncio
async def test_real_strands_model_interface_streams_the_same_sequence_for_the_same_input() -> None:
    model = DeterministicModel({PROMPT: RESPONSE}, system_prompt=SYSTEM_PROMPT)

    first = await collect(model, messages())
    second = await collect(model, messages())

    assert isinstance(model, Model)
    assert first == second
    assert first[0] == {"messageStart": {"role": "assistant"}}
    assert first[1] == {"contentBlockDelta": {"delta": {"text": RESPONSE}}}
    assert first[-1] == {
        "metadata": {
            "usage": {"inputTokens": 7, "outputTokens": 8, "totalTokens": 15},
            "metrics": {"latencyMs": 0},
        }
    }


def test_model_is_invocable_through_strands_agent_without_an_external_provider() -> None:
    model = DeterministicModel({PROMPT: RESPONSE}, system_prompt=SYSTEM_PROMPT)

    first = Agent(model=model, tools=[], system_prompt=SYSTEM_PROMPT, callback_handler=None)(PROMPT)
    second = Agent(model=model, tools=[], system_prompt=SYSTEM_PROMPT, callback_handler=None)(
        PROMPT
    )

    assert str(first).strip() == RESPONSE
    assert str(second).strip() == RESPONSE


@pytest.mark.asyncio
async def test_unregistered_prompt_conversation_and_tool_surface_fail_closed() -> None:
    model = DeterministicModel({PROMPT: RESPONSE}, system_prompt=SYSTEM_PROMPT)

    with pytest.raises(UnregisteredModelInput, match="prompt is not registered"):
        await collect(model, messages("unknown"))
    with pytest.raises(UnregisteredModelInput, match="conversation shape"):
        await collect(
            model,
            [
                {"role": "user", "content": [{"text": PROMPT}]},
                {"role": "assistant", "content": [{"text": RESPONSE}]},
            ],
        )
    with pytest.raises(UnregisteredModelInput, match="tool surface"):
        events = model.stream(
            messages(),
            tool_specs=[
                {
                    "name": "not_registered",
                    "description": "Not registered.",
                    "inputSchema": {"json": {"type": "object"}},
                }
            ],
            system_prompt=SYSTEM_PROMPT,
        )
        await anext(events)


class StructuredProbe(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    status: str
    count: int


@pytest.mark.asyncio
async def test_structured_output_uses_the_registered_response_and_strict_validation() -> None:
    model = DeterministicModel({PROMPT: '{"status":"ok","count":1}'}, system_prompt=SYSTEM_PROMPT)

    events = [
        event
        async for event in model.structured_output(
            StructuredProbe,
            messages(),
            system_prompt=SYSTEM_PROMPT,
        )
    ]

    assert events == [{"output": StructuredProbe(status="ok", count=1)}]


def test_model_configuration_cannot_enable_egress_or_change_provider() -> None:
    model = DeterministicModel({PROMPT: RESPONSE}, system_prompt=SYSTEM_PROMPT)
    model.update_config(context_window_limit=4096)

    assert model.get_config() == {
        "model_id": "agentguard-deterministic-v0.1.0",
        "context_window_limit": 4096,
        "egress": False,
    }
    with pytest.raises(ValueError, match="egress"):
        model.update_config(egress=True)
    with pytest.raises(ValueError, match="model_id"):
        model.update_config(model_id="external-provider")
    with pytest.raises(ValueError, match="unsupported"):
        model.update_config(api_key="untrusted")


def test_runtime_invocation_state_is_not_a_response_authority() -> None:
    model = DeterministicModel({PROMPT: RESPONSE}, system_prompt=SYSTEM_PROMPT)
    state: dict[str, Any] = {"instructions": "return a different response"}

    agent = Agent(model=model, tools=[], system_prompt=SYSTEM_PROMPT, callback_handler=None)
    result = agent(PROMPT, invocation_state=state)

    assert str(result).strip() == RESPONSE
