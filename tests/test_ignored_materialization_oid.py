from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).parents[1]
SCRIPT = ROOT / "scripts" / "ignored-materialization-oid.py"
IGNORED_PATHS = """\
.env
.env.*
.venv/
artifacts/
offloaded/
sandboxes/
sessions/
build/
private.bin
"""


def initialized_repo(tmp_path: Path) -> Path:
    repo = tmp_path / "repo"
    repo.mkdir()
    subprocess.run(
        ["git", "init", "--quiet", repo],
        check=True,
        capture_output=True,
        text=True,
    )
    (repo / ".gitignore").write_text(IGNORED_PATHS, encoding="utf-8")
    return repo


def published_oid(repo: Path) -> str:
    result = subprocess.run(
        [sys.executable, SCRIPT, "--repo", repo],
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip()


@pytest.mark.parametrize(
    "relative_path",
    [
        ".env",
        ".env.local",
        ".venv/credentials.json",
        "artifacts/evidence.json",
        "offloaded/payload.json",
        "sandboxes/state.json",
        "sessions/transcript.json",
        "private.bin",
    ],
)
def test_sensitive_or_unclassified_content_is_redacted(
    tmp_path: Path,
    relative_path: str,
) -> None:
    repo = initialized_repo(tmp_path)
    ignored = repo / relative_path
    ignored.parent.mkdir(parents=True, exist_ok=True)
    ignored.write_bytes(b"synthetic-value-one")
    original_oid = published_oid(repo)

    ignored.write_bytes(b"synthetic-value-two-with-a-different-size")

    assert published_oid(repo) == original_oid


def test_redacted_file_presence_remains_identity_material(tmp_path: Path) -> None:
    repo = initialized_repo(tmp_path)
    without_env_oid = published_oid(repo)

    (repo / ".env").write_text("SYNTHETIC_TOKEN=present\n", encoding="utf-8")

    assert published_oid(repo) != without_env_oid


def test_allowlisted_generated_content_remains_identity_material(tmp_path: Path) -> None:
    repo = initialized_repo(tmp_path)
    generated = repo / "build" / "generated.bin"
    generated.parent.mkdir()
    generated.write_bytes(b"generated-version-one")
    original_oid = published_oid(repo)

    generated.write_bytes(b"generated-version-two")

    assert published_oid(repo) != original_oid
