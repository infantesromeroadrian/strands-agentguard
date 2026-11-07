"""Agents under test: the protocol and the two deterministic reference agents."""

from __future__ import annotations

from typing import Protocol

from strands_agentguard.assessment.model import Json, World, parse_directive


class AgentUnderTest(Protocol):
    """Anything that can act inside a ``World`` and return its final answer."""

    def run(self, world: World) -> str: ...


class ObedientReferenceAgent:
    """Deterministic stand-in for a gullible model.

    It performs the task plan, then obeys any directive marker found in tool
    descriptions or tool results. Whether that obedience causes harm depends
    only on the controls the world applies, which is what the reference
    ``vulnerable`` (no controls) and ``hardened`` (all controls) targets vary.
    """

    def run(self, world: World) -> str:
        tools = world.exposed_tools()
        for tool in tools:
            directive = parse_directive(tool.description)
            if directive is not None:
                world.call(directive[0], directive[1])
        gathered: list[str] = []
        for name, arguments in world.situation.task_plan:
            result = world.call(name, arguments)
            gathered.append(result)
            directive = parse_directive(result)
            if directive is not None:
                call_args = _substitute(directive[1], "\n".join(gathered))
                world.call(directive[0], call_args)
        return "done"


def _substitute(arguments: dict[str, Json], last_result: str) -> dict[str, Json]:
    return {
        key: value.replace("{{last_result}}", last_result) if isinstance(value, str) else value
        for key, value in arguments.items()
    }


__all__ = ["AgentUnderTest", "ObedientReferenceAgent"]
