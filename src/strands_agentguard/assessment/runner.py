"""Run scenarios against a target and write report.json, report.meta.json and report.md."""

from __future__ import annotations

import hashlib
import json
import platform
from collections import Counter
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal

from jsonschema import Draft202012Validator  # type: ignore[import-untyped, unused-ignore]
from referencing import Registry, Resource

import strands_agentguard
from strands_agentguard.assessment.agents import AgentUnderTest
from strands_agentguard.assessment.catalog import (
    CATALOG_BY_ID,
    OWASP_AGENTIC_2026_NAMES,
    OWASP_LLM_2025_NAMES,
)
from strands_agentguard.assessment.evaluate import (
    Verdict,
    evaluate,
    outcome_for,
    trace_evidence,
)
from strands_agentguard.assessment.model import ControlSet, Json, World
from strands_agentguard.assessment.payloads import (
    NEUTRAL_RELATIVE_PATH,
    LoadedPayloads,
    load_payload_set,
)
from strands_agentguard.assessment.worlds import build_situation
from strands_agentguard.contracts import (
    AssessmentResult,
    Scenario,
    canonical_sha256,
    validate_contract_document,
)
from strands_agentguard.targets import MVP_CORPUS, load_scenario_corpus

# Git's well-known empty-blob object id: this run has no ignored-state material to bind.
EMPTY_BLOB_OID = "e69de29bb2d1d6434b8b29ae775ad8e2e48c5391"
EMPTY_SHA256 = hashlib.sha256(b"").hexdigest()


class AssessmentError(RuntimeError):
    """Raised when a run cannot be set up or its output fails validation."""


@dataclass(frozen=True, slots=True)
class TargetSpec:
    kind: Literal["deterministic", "strands-ollama"]
    name: str
    target_id: str
    profile: Literal["baseline", "hardened"] | None
    controls: ControlSet
    agent_factory: Callable[[], AgentUnderTest]
    target_candidate: str
    manifest_sha256: str
    default_repetitions: int
    model: Mapping[str, Json] | None = None
    notes: tuple[str, ...] = ()


@dataclass(slots=True)
class _Trial:
    case_id: str
    verdict: Verdict
    evidence: dict[str, Json]
    error: str | None = None


@dataclass(slots=True)
class _ScenarioOutcome:
    scenario_id: str
    trials: list[_Trial] = field(default_factory=list)

    @property
    def errors(self) -> int:
        return sum(1 for t in self.trials if t.error is not None)

    @property
    def failures(self) -> int:
        return sum(1 for t in self.trials if t.error is None and not t.verdict.passed)

    @property
    def modes(self) -> Counter[str]:
        counter: Counter[str] = Counter()
        for trial in self.trials:
            counter.update(trial.verdict.failure_modes)
        return counter


@dataclass(frozen=True, slots=True)
class RunOutput:
    out_dir: Path
    result: AssessmentResult
    meta: dict[str, Any]
    failed_scenarios: tuple[str, ...]


def _write_json(path: Path, document: Mapping[str, Any]) -> bytes:
    data = (json.dumps(document, indent=2, sort_keys=True, ensure_ascii=False) + "\n").encode()
    path.write_bytes(data)
    return data


def _source_candidate() -> str:
    package_root = Path(strands_agentguard.__file__).parent
    digest = hashlib.sha256()
    for path in sorted(package_root.rglob("*.py")):
        digest.update(path.relative_to(package_root).as_posix().encode() + b"\0")
        digest.update(path.read_bytes() + b"\0")
    return f"fixture:agentguard:{digest.hexdigest()}"


def _schema_validator(root: Path, name: str) -> Draft202012Validator:
    schemas = {
        p.name: json.loads(p.read_bytes()) for p in sorted((root / "schemas").glob("*.schema.json"))
    }
    registry: Registry[Any] = Registry().with_resources(
        (schema["$id"], Resource.from_contents(schema)) for schema in schemas.values()
    )
    return Draft202012Validator(schemas[name], registry=registry)


def parse_scenario_selection(selection: str, available: Sequence[str]) -> list[str]:
    if selection == "all":
        return sorted(available)
    chosen = [part.strip().upper() for part in selection.split(",") if part.strip()]
    unknown = sorted(set(chosen) - set(available))
    if unknown or not chosen:
        raise AssessmentError(
            f"unknown scenarios: {unknown or selection!r}; known: {sorted(available)}"
        )
    return sorted(set(chosen))


def _assertions_hold(scenario: Scenario, outcome: Mapping[str, Json]) -> list[str]:
    broken: list[str] = []
    for assertion in scenario.expected_outcome.assertions:
        if assertion.operator == "equals" and outcome.get(assertion.field) != assertion.value:
            broken.append(assertion.field)
    return broken


def run_assessment(
    root: Path,
    target: TargetSpec,
    *,
    scenario_selection: str,
    out_dir: Path,
    repetitions: int | None = None,
    extra_payloads: Path | None = None,
    now: Callable[[], datetime] = lambda: datetime.now(UTC),
) -> RunOutput:
    reps = repetitions if repetitions is not None else target.default_repetitions
    if reps < 1 or reps > 100:
        raise AssessmentError("repetitions must be between 1 and 100")
    corpus = load_scenario_corpus(root, MVP_CORPUS)
    selected = parse_scenario_selection(scenario_selection, list(corpus.scenarios))
    neutral = load_payload_set(root / NEUTRAL_RELATIVE_PATH, root)
    adversarial: LoadedPayloads | None = (
        load_payload_set(extra_payloads, root) if extra_payloads is not None else None
    )
    started = now()

    outcomes: list[_ScenarioOutcome] = []
    for scenario_id in selected:
        scenario = corpus.get(scenario_id)
        cases = (adversarial.cases_for(scenario_id) if adversarial else ()) or neutral.cases_for(
            scenario_id
        )
        outcome = _ScenarioOutcome(scenario_id)
        for case in cases:
            for _ in range(reps):
                outcome.trials.append(
                    _run_trial(target, scenario, scenario_id, case.case_id, case.text)
                )
        outcomes.append(outcome)

    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "evidence").mkdir(exist_ok=True)
    artifact_hashes: dict[str, str] = {}
    for outcome in outcomes:
        relative = f"evidence/{outcome.scenario_id.lower()}.json"
        data = _write_json(
            out_dir / relative,
            {
                "scenario_id": outcome.scenario_id,
                "trials": [trial.evidence for trial in outcome.trials],
            },
        )
        artifact_hashes[relative] = hashlib.sha256(data).hexdigest()

    config = {
        "target": target.name,
        "target_candidate": target.target_candidate,
        "model": dict(target.model) if target.model else None,
        "scenarios": selected,
        "repetitions": reps,
        "payload_set_sha256": (adversarial or neutral).sha256,
        "fallback_payload_set_sha256": neutral.sha256,
    }
    config_sha = canonical_sha256(config)
    run_id = f"run-{config_sha[:16]}"
    lock = root / "uv.lock"
    identity: dict[str, Any] = {
        "schema_version": "0.1.0",
        "run_id": run_id,
        "agentguard_candidate": _source_candidate(),
        "target_candidate": target.target_candidate,
        "ignored_oid": EMPTY_BLOB_OID,
        "manifest_sha256": target.manifest_sha256,
        "threat_catalog_version": corpus.version,
        "threat_catalog_sha256": corpus.manifest_sha256,
        "config_sha256": config_sha,
        "lock_sha256": hashlib.sha256(lock.read_bytes()).hexdigest()
        if lock.is_file()
        else EMPTY_SHA256,
        "python": platform.python_version(),
        "os": platform.system().lower() or "unknown",
        "architecture": platform.machine() or "unknown",
    }
    identity["identity_digest"] = canonical_sha256(identity)

    findings: list[dict[str, Any]] = []
    scenario_results: list[dict[str, Any]] = []
    for outcome in outcomes:
        entry = CATALOG_BY_ID[outcome.scenario_id]
        evidence_ref = f"evidence/{outcome.scenario_id.lower()}.json"
        total = len(outcome.trials)
        if outcome.errors:
            scenario_results.append(
                {
                    "scenario_id": outcome.scenario_id,
                    "completed": False,
                    "passed": None,
                    "incomplete_reason": f"{outcome.errors} of {total} trials raised errors",
                    "evidence_refs": [evidence_ref],
                    "finding_ids": [],
                }
            )
            continue
        finding_ids: list[str] = []
        if outcome.failures:
            finding_id = f"AG-FND-{outcome.scenario_id[-3:]}"
            finding_ids.append(finding_id)
            findings.append(
                {
                    "finding_id": finding_id,
                    "rule_id": entry.rule_id,
                    "requirement_ids": [entry.requirement_id],
                    "scenario_id": outcome.scenario_id,
                    "severity": entry.severity,
                    "confidence": "CONFIRMED",
                    "status": "OPEN",
                    "disposition": None,
                    "title": entry.title,
                    "evidence_refs": [evidence_ref],
                    "reproduction": [
                        f"agentguard run --target {target.name} --scenarios {outcome.scenario_id} "
                        f"--repetitions {reps} --out <dir>"
                    ],
                    "limitations": [
                        f"Failed in {outcome.failures} of {total} trials "
                        f"(modes: {', '.join(sorted(outcome.modes)) or 'assertion'}).",
                        "Deterministic criterion over the recorded tool-call trace; "
                        "synthetic tools and data only.",
                    ],
                    "run_id": run_id,
                }
            )
        scenario_results.append(
            {
                "scenario_id": outcome.scenario_id,
                "completed": True,
                "passed": outcome.failures == 0,
                "incomplete_reason": None,
                "evidence_refs": [evidence_ref],
                "finding_ids": finding_ids,
            }
        )

    all_complete = all(item["completed"] for item in scenario_results)
    trials_total = sum(len(o.trials) for o in outcomes)
    document: dict[str, Any] = {
        "schema_version": "0.1.0",
        "run_identity": identity,
        "target_id": target.target_id,
        "timestamps": {
            "started_at": started.isoformat(),
            "completed_at": max(now(), started).isoformat(),
        },
        "stop_reason": "assessment completed"
        if all_complete
        else "trial errors prevented completion",
        "scenario_results": scenario_results,
        "findings": sorted(findings, key=lambda f: f["finding_id"]),
        "metrics": {
            "scenarios_total": len(outcomes),
            "scenarios_failed": sum(1 for o in outcomes if o.failures),
            "trials_total": trials_total,
            "trials_failed": sum(o.failures for o in outcomes),
        },
        "artifact_hashes": dict(sorted(artifact_hashes.items())),
        "summary": {
            "completed": all_complete,
            "incomplete_reason": None if all_complete else "one or more scenarios did not complete",
        },
    }
    try:
        validator = _schema_validator(root, "assessment-result.schema.json")
        validated = validate_contract_document(
            "assessment-result.schema.json", document, schema_validator=validator
        )
        if not isinstance(validated, AssessmentResult):
            raise TypeError("unexpected contract model")
        result = validated
    except Exception as exc:
        raise AssessmentError(f"generated report failed contract validation: {exc}") from exc
    report_bytes = _write_json(out_dir / "report.json", document)

    meta = _build_meta(
        target, corpus.corpus_id, corpus, neutral, adversarial, reps, outcomes, report_bytes, run_id
    )
    try:
        _schema_validator(root, "report-meta.schema.json").validate(meta)
    except Exception as exc:
        raise AssessmentError(f"generated metadata failed schema validation: {exc}") from exc
    _write_json(out_dir / "report.meta.json", meta)
    (out_dir / "report.md").write_text(render_markdown(meta, outcomes, target), encoding="utf-8")
    failed = tuple(o.scenario_id for o in outcomes if o.failures and o.scenario_id != "AG-SCN-018")
    return RunOutput(out_dir, result, meta, failed)


def _run_trial(
    target: TargetSpec, scenario: Scenario, scenario_id: str, case_id: str, text: str
) -> _Trial:
    situation = build_situation(scenario_id, case_id, text)
    world = World(situation, target.controls)
    try:
        world.trace.final_text = target.agent_factory().run(world)
        world.exposed_tools()  # make sure the exposed surface is always recorded
        verdict = evaluate(situation, world.trace)
        broken = _assertions_hold(scenario, outcome_for(situation, world.trace))
    except Exception as exc:  # a crashed trial is an incomplete result, never a pass
        message = type(exc).__name__
        empty = Verdict(False, ("trial_error",))
        return _Trial(
            case_id,
            empty,
            {"scenario_id": scenario_id, "case_id": case_id, "error": message},
            message,
        )
    if broken and verdict.passed:
        verdict = Verdict(False, tuple(f"assertion_failed:{f}" for f in broken), verdict.details)
    return _Trial(case_id, verdict, trace_evidence(situation, world.trace, verdict))


def _build_meta(
    target: TargetSpec,
    corpus_id: str,
    corpus: Any,
    neutral: LoadedPayloads,
    adversarial: LoadedPayloads | None,
    reps: int,
    outcomes: list[_ScenarioOutcome],
    report_bytes: bytes,
    run_id: str,
) -> dict[str, Any]:
    used = adversarial or neutral
    scenarios: list[dict[str, Any]] = []
    for outcome in outcomes:
        entry = CATALOG_BY_ID[outcome.scenario_id]
        total = len(outcome.trials)
        scenarios.append(
            {
                "scenario_id": outcome.scenario_id,
                "title": entry.title,
                "kind": entry.kind,
                "severity": entry.severity,
                "trials": total,
                "failures": outcome.failures,
                "detected": outcome.failures > 0,
                "failure_rate": round(outcome.failures / total, 4) if total else 0.0,
                "failure_modes": dict(sorted(outcome.modes.items())),
                "owasp_llm_2025": list(entry.owasp_llm_2025),
                "owasp_agentic_2026": list(entry.owasp_agentic_2026),
            }
        )
    benign = next((o for o in outcomes if o.scenario_id == "AG-SCN-018"), None)
    blocked = (
        sum(1 for t in benign.trials if "legitimate_call_blocked" in t.verdict.failure_modes)
        if benign
        else 0
    )
    false_positives: dict[str, Any] = {
        "scenario_id": "AG-SCN-018" if benign else None,
        "trials": len(benign.trials) if benign else 0,
        "blocked": blocked,
        "rate": round(blocked / len(benign.trials), 4) if benign and benign.trials else None,
    }
    tgt: dict[str, Any] = {"kind": target.kind, "target_id": target.target_id}
    if target.profile:
        tgt["profile"] = target.profile
    tgt["controls"] = {
        "pin_tool_metadata": target.controls.pin_tool_metadata,
        "namespace_isolation": target.controls.namespace_isolation,
        "task_scope": target.controls.task_scope,
        "approval_gate": target.controls.approval_gate,
        "egress_filter": target.controls.egress_filter,
    }
    if target.model:
        tgt["model"] = dict(target.model)
    limitations = [
        "MVP, not audited. A passing scenario shows the control worked for these cases, not that the agent is secure.",
        "Synthetic tools and data; every verdict is a deterministic function of the recorded tool-call trace.",
        "Coverage is limited to the eight catalogued scenarios and the payload cases of the selected payload set.",
        *target.notes,
    ]
    if target.kind == "deterministic":
        limitations.append(
            "The reference agent is an obedient stand-in, not a language model: results show the "
            "controls, not model behaviour."
        )
    else:
        limitations.append(
            f"With n={reps} repetitions per case there is no useful confidence interval; "
            "read k/n as an observation, not a rate estimate."
        )
    return {
        "schema_version": "0.1.0",
        "agentguard_version": strands_agentguard.__version__,
        "run_id": run_id,
        "report_sha256": hashlib.sha256(report_bytes).hexdigest(),
        "target": tgt,
        "corpus": {
            "corpus_id": corpus_id,
            "version": corpus.version,
            "manifest_sha256": corpus.manifest_sha256,
        },
        "payload_set": {
            "payload_set_id": used.payload_set.payload_set_id,
            "kind": used.payload_set.kind,
            "sha256": used.sha256,
            "fallback_payload_set_id": neutral.payload_set.payload_set_id if adversarial else None,
        },
        "repetitions": reps,
        "scenarios": scenarios,
        "false_positives": false_positives,
        "limitations": limitations,
    }


def render_markdown(
    meta: Mapping[str, Any], outcomes: list[_ScenarioOutcome], target: TargetSpec
) -> str:
    lines = [
        "# AgentGuard assessment report",
        "",
        f"- Run: `{meta['run_id']}` (AgentGuard {meta['agentguard_version']}, MVP, not audited)",
        f"- Target: `{target.name}` ({target.kind})",
        f"- Corpus: `{meta['corpus']['corpus_id']}` {meta['corpus']['version']}; "
        f"payload set `{meta['payload_set']['payload_set_id']}` ({meta['payload_set']['kind']})",
        f"- Repetitions per case: {meta['repetitions']}",
    ]
    model = meta["target"].get("model")
    if model:
        lines.append(
            f"- Model: `{model['model_id']}` digest `{model['digest']}` "
            f"(temperature {model['temperature']}, seed {model['seed']}, "
            f"Ollama {model['ollama_version']}, Strands {model['strands_version']})"
        )
    lines += [
        f"- `report.json` SHA-256: `{meta['report_sha256']}`",
        "",
        "## Summary",
        "",
        "| Scenario | Title | Result | k/n | OWASP LLM 2025 | OWASP Agentic 2026 |",
        "|---|---|---|---|---|---|",
    ]
    for row in meta["scenarios"]:
        verdict = "FAIL" if row["detected"] else "PASS"
        llm = ", ".join(row["owasp_llm_2025"]) or "-"
        agentic = ", ".join(row["owasp_agentic_2026"]) or "-"
        lines.append(
            f"| {row['scenario_id']} | {row['title']} | {verdict} | "
            f"{row['failures']}/{row['trials']} | {llm} | {agentic} |"
        )
    lines += [
        "",
        "`FAIL` means the weakness was observed in at least one trial; k/n is failures over trials.",
    ]
    fp = meta["false_positives"]
    if fp["scenario_id"]:
        lines += [
            "",
            f"False positives (benign control {fp['scenario_id']}): {fp['blocked']}/{fp['trials']} trials blocked.",
        ]
    failing = [o for o in outcomes if o.failures and o.errors == 0]
    if failing:
        lines += ["", "## Findings", ""]
    for outcome in failing:
        entry = CATALOG_BY_ID[outcome.scenario_id]
        first = next(t for t in outcome.trials if not t.verdict.passed)
        lines += [
            f"### {outcome.scenario_id} {entry.title} ({entry.severity})",
            "",
            f"- What happened: {entry.failure_summary}",
            f"- Failure modes: {', '.join(f'`{m}` x{n}' for m, n in sorted(outcome.modes.items()))}",
            f"- Evidence: `evidence/{outcome.scenario_id.lower()}.json` (first failing case `{first.case_id}`)",
        ]
        calls = first.evidence.get("calls")
        if isinstance(calls, list) and calls:
            lines.append("- Trace of the first failing trial:")
            for call in calls:
                lines.append(
                    f"  - #{call['seq']} `{call['server']}/{call['tool']}` {call['outcome']}"
                    + (f" ({call['reason']})" if call.get("reason") else "")
                )
        lines += [f"- Fix: {entry.remediation}", ""]
    errored = [o for o in outcomes if o.errors]
    if errored:
        lines += ["## Incomplete scenarios", ""]
        lines += [f"- {o.scenario_id}: {o.errors} trials raised errors" for o in errored]
        lines.append("")
    lines += ["## OWASP references", ""]
    lines += [f"- {key} {name}" for key, name in OWASP_LLM_2025_NAMES.items()]
    lines += [f"- {key} {name}" for key, name in OWASP_AGENTIC_2026_NAMES.items()]
    lines += ["", "## Limitations", ""]
    lines += [f"- {text}" for text in meta["limitations"]]
    lines.append("")
    return "\n".join(lines)


__all__ = [
    "AssessmentError",
    "RunOutput",
    "TargetSpec",
    "parse_scenario_selection",
    "render_markdown",
    "run_assessment",
]
