#!/usr/bin/env python3
"""Hash ignored, untracked files without writing Git objects."""

from __future__ import annotations

import argparse
import os
import stat
import subprocess
import sys
from pathlib import Path


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


def blob_oid(repo: bytes, path: bytes, link_target: bytes | None) -> bytes:
    if link_target is not None:
        output = git(repo, "hash-object", "--stdin", input_bytes=link_target)
    else:
        absolute_path = os.path.join(repo, path)
        environment = os.environ.copy()
        environment["GIT_OPTIONAL_LOCKS"] = "0"
        with open(absolute_path, "rb") as source:
            result = subprocess.run(
                ["git", "hash-object", "--stdin"],
                cwd=repo,
                env=environment,
                stdin=source,
                capture_output=True,
                check=False,
            )
        if result.returncode != 0:
            message = result.stderr.decode("utf-8", "replace").strip()
            raise RuntimeError(message or "git hash-object failed")
        output = result.stdout
    oid = output.strip()
    if not oid:
        raise RuntimeError("git hash-object returned an empty OID")
    return oid


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

    for path in paths:
        absolute_path = os.path.join(repo, path)
        before = os.lstat(absolute_path)
        if stat.S_ISREG(before.st_mode):
            kind = b"file"
            target = None
        elif stat.S_ISLNK(before.st_mode):
            kind = b"symlink"
            target = os.fsencode(os.readlink(absolute_path))
        else:
            display_path = os.fsdecode(path)
            raise RuntimeError(f"unsupported ignored filesystem entry: {display_path}")

        oid = blob_oid(repo, path, target)
        after = os.lstat(absolute_path)
        stable_fields = ("st_mode", "st_size", "st_mtime_ns", "st_ino")
        if any(getattr(before, field) != getattr(after, field) for field in stable_fields):
            display_path = os.fsdecode(path)
            raise RuntimeError(f"ignored filesystem entry changed while hashing: {display_path}")

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
            "Print a canonical Git OID for every ignored, untracked regular "
            "file and symlink in a worktree."
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
