#!/usr/bin/env python3
"""Identify ignored, untracked materialization without exposing sensitive content."""

from __future__ import annotations

import argparse
import os
import stat
import subprocess
import sys
from pathlib import Path

_REDACTED_CONTENT_SENTINEL = b"harness-codex/ignored-materialization/redacted-content/v1\0"
_SENSITIVE_PATH_NAMES = frozenset({b".venv", b"artifacts", b"offloaded", b"sandboxes", b"sessions"})
_CONTENT_SAFE_DIRECTORY_NAMES = frozenset(
    {
        b".mypy_cache",
        b".pytest_cache",
        b".ruff_cache",
        b"__pycache__",
        b"build",
        b"dist",
        b"htmlcov",
    }
)
_CONTENT_SAFE_FILE_NAMES = frozenset({b".coverage", b"coverage.xml"})
_CONTENT_SAFE_FILE_SUFFIXES = (b".pyc", b".pyd", b".pyo")
_STABLE_STAT_FIELDS = ("st_dev", "st_ino", "st_mode", "st_size", "st_mtime_ns")


def git(
    repo: bytes,
    *arguments: str,
    input_bytes: bytes | None = None,
) -> bytes:
    environment = os.environ.copy()
    environment["GIT_OPTIONAL_LOCKS"] = "0"
    result = subprocess.run(
        ["git", *arguments],
        cwd=repo,
        env=environment,
        input=input_bytes,
        capture_output=True,
        check=False,
    )
    if result.returncode != 0:
        message = result.stderr.decode("utf-8", "replace").strip()
        raise RuntimeError(message or f"git {' '.join(arguments)} failed")
    return result.stdout


def _require_unchanged(
    before: os.stat_result,
    after: os.stat_result,
    *,
    display_path: str,
) -> None:
    if any(getattr(before, field) != getattr(after, field) for field in _STABLE_STAT_FIELDS):
        raise RuntimeError(f"ignored filesystem entry changed while hashing: {display_path}")


def _git_blob_oid(repo: bytes, content: bytes) -> bytes:
    output = git(repo, "hash-object", "--stdin", input_bytes=content)
    oid = output.strip()
    if not oid:
        raise RuntimeError("git hash-object returned an empty OID")
    return oid


def _regular_file_oid(
    repo: bytes,
    absolute_path: bytes,
    before: os.stat_result,
    *,
    display_path: str,
) -> bytes:
    descriptor = os.open(absolute_path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        opened = os.fstat(descriptor)
        _require_unchanged(before, opened, display_path=display_path)
        if not stat.S_ISREG(opened.st_mode):
            raise RuntimeError(f"ignored filesystem entry is no longer a file: {display_path}")

        environment = os.environ.copy()
        environment["GIT_OPTIONAL_LOCKS"] = "0"
        result = subprocess.run(
            ["git", "hash-object", "--stdin"],
            cwd=repo,
            env=environment,
            stdin=descriptor,
            capture_output=True,
            check=False,
        )
        after_read = os.fstat(descriptor)
    finally:
        os.close(descriptor)

    if result.returncode != 0:
        message = result.stderr.decode("utf-8", "replace").strip()
        raise RuntimeError(message or "git hash-object failed")
    _require_unchanged(before, after_read, display_path=display_path)

    oid = result.stdout.strip()
    if not oid:
        raise RuntimeError("git hash-object returned an empty OID")
    return oid


def _path_is_sensitive(path: bytes) -> bool:
    parts = path.split(b"/")
    return any(
        part in _SENSITIVE_PATH_NAMES or part == b".env" or part.startswith(b".env.")
        for part in parts
    )


def _content_is_allowlisted(path: bytes) -> bool:
    if _path_is_sensitive(path):
        return False

    parts = path.split(b"/")
    name = parts[-1]
    return (
        any(
            part in _CONTENT_SAFE_DIRECTORY_NAMES or part.endswith(b".egg-info")
            for part in parts[:-1]
        )
        or name in _CONTENT_SAFE_FILE_NAMES
        or name.endswith(_CONTENT_SAFE_FILE_SUFFIXES)
    )


def ignored_materialization_oid(repo: bytes) -> bytes:
    listed = git(
        repo,
        "ls-files",
        "--others",
        "--ignored",
        "--exclude-standard",
        "-z",
    )
    paths = sorted(path for path in listed.split(b"\0") if path)
    stream = bytearray(b"harness-codex/ignored-materialization/v1\0")
    redacted_oid: bytes | None = None

    for path in paths:
        absolute_path = os.path.join(repo, path)
        display_path = os.fsdecode(path)
        before = os.lstat(absolute_path)
        if stat.S_ISREG(before.st_mode):
            kind = b"file"
        elif stat.S_ISLNK(before.st_mode):
            kind = b"symlink"
        else:
            raise RuntimeError(f"unsupported ignored filesystem entry: {display_path}")

        if not _content_is_allowlisted(path):
            if redacted_oid is None:
                redacted_oid = _git_blob_oid(repo, _REDACTED_CONTENT_SENTINEL)
            oid = redacted_oid
        elif kind == b"symlink":
            target = os.fsencode(os.readlink(absolute_path))
            oid = _git_blob_oid(repo, target)
        else:
            oid = _regular_file_oid(
                repo,
                absolute_path,
                before,
                display_path=display_path,
            )

        after = os.lstat(absolute_path)
        _require_unchanged(before, after, display_path=display_path)

        mode = f"{stat.S_IMODE(before.st_mode):04o}".encode("ascii")
        stream.extend(kind)
        stream.extend(b"\0")
        stream.extend(mode)
        stream.extend(b"\0")
        stream.extend(str(len(path)).encode("ascii"))
        stream.extend(b"\0")
        stream.extend(path)
        stream.extend(b"\0")
        stream.extend(oid)
        stream.extend(b"\0")

    return git(repo, "hash-object", "--stdin", input_bytes=bytes(stream)).strip()


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Print a canonical Git OID for ignored, untracked materialization "
            "without reading non-allowlisted content."
        )
    )
    parser.add_argument(
        "--repo",
        default=".",
        help="path inside the target Git worktree (default: current directory)",
    )
    arguments = parser.parse_args()

    try:
        requested = Path(arguments.repo).expanduser()
        top_level = subprocess.run(
            ["git", "-C", os.fspath(requested), "rev-parse", "--show-toplevel"],
            capture_output=True,
            check=False,
            text=True,
        )
        if top_level.returncode != 0:
            raise RuntimeError(top_level.stderr.strip() or "target is not a Git worktree")
        repo = os.fsencode(top_level.stdout.strip())
        oid = ignored_materialization_oid(repo)
    except (OSError, RuntimeError) as exc:
        print(f"ignored-materialization-oid: {exc}", file=sys.stderr)
        return 1

    print(oid.decode("ascii"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
