import tomllib
from pathlib import Path

import strands_agentguard

ROOT = Path(__file__).parents[1]


def test_package_version_matches_project_metadata() -> None:
    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))

    assert strands_agentguard.__version__ == project["project"]["version"]


def test_environment_example_is_offline_and_contains_no_secret_values() -> None:
    entries = dict(
        line.split("=", maxsplit=1)
        for line in (ROOT / ".env.example").read_text(encoding="utf-8").splitlines()
    )

    assert entries["AGENTGUARD_MODEL_PROVIDER"] == "deterministic"
    assert entries["AGENTGUARD_EGRESS"] == "deny"
    assert entries["OLLAMA_HOST"] == ""
    assert entries["OLLAMA_API_KEY"] == ""
