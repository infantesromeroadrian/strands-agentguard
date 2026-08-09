from __future__ import annotations

import json
import shutil
from pathlib import Path
from typing import Any, cast

from typer.testing import CliRunner

from strands_agentguard.cli import app
from strands_agentguard.doctor import run_doctor

ROOT = Path(__file__).parents[1]


def test_doctor_validates_the_complete_offline_stack() -> None:
    report = run_doctor(ROOT)

    assert report.ok
    assert report.exit_code == 0
    assert [check.name for check in report.checks] == [
        "environment",
        "configuration",
        "schemas",
        "targets",
        "inventory",
        "corpus",
        "model",
        "identities",
    ]
    assert all(check.ok for check in report.checks)
    corpus_check = next(check for check in report.checks if check.name == "corpus")
    assert corpus_check.detail == "10 frozen scenarios validated; AG-SCN-001..003 executed"
    inventory_check = next(check for check in report.checks if check.name == "inventory")
    assert inventory_check.detail == (
        "4 MCP tools accepted, local-only large result excluded, JSON repeatable"
    )


def test_public_agentguard_doctor_command_returns_zero_when_healthy() -> None:
    result = CliRunner().invoke(app, ["doctor"])

    assert result.exit_code == 0, result.output
    assert "[ok] model" in result.output
    assert "agentguard doctor: healthy" in result.output


def test_doctor_returns_nonzero_report_when_target_fixture_is_tampered(tmp_path: Path) -> None:
    for name in ("pyproject.toml", "uv.lock", ".env.example"):
        shutil.copy2(ROOT / name, tmp_path / name)
    shutil.copytree(ROOT / "schemas", tmp_path / "schemas")
    shutil.copytree(ROOT / "fixtures", tmp_path / "fixtures")

    fixture_path = tmp_path / "fixtures" / "targets" / "hardened.json"
    document = cast(dict[str, Any], json.loads(fixture_path.read_text(encoding="utf-8")))
    document["limits"]["max_iterations"] -= 1
    fixture_path.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")

    report = run_doctor(tmp_path)

    assert not report.ok
    assert report.exit_code != 0
    target_check = next(check for check in report.checks if check.name == "targets")
    assert not target_check.ok
    assert "identity" in target_check.detail
