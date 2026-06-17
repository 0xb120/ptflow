"""Subprocess plumbing for external CLI tools — substrate for thin adapters."""

from __future__ import annotations

import shutil
import subprocess
from collections.abc import Iterable, Sequence
from pathlib import Path

Command = Sequence[str]


class ToolNotFoundError(RuntimeError):
    """A required external tool is not on PATH."""


def require(*tools: str) -> None:
    missing = [t for t in tools if shutil.which(t) is None]
    if missing:
        msg = f"missing required tool(s): {', '.join(missing)}"
        raise ToolNotFoundError(msg)


def run(
    cmd: Command,
    *,
    stdin: str | None = None,
    check: bool = False,
    timeout: int | None = None,
    cwd: Path | None = None,
) -> str:
    proc = subprocess.run(
        list(cmd),
        input=stdin,
        capture_output=True,
        text=True,
        check=check,
        timeout=timeout,
        cwd=cwd,
    )
    return proc.stdout


def pipe(stages: Sequence[Command], *, stdin: str | None = None) -> str:
    if not stages:
        return ""
    procs: list[subprocess.Popen[bytes]] = []
    first = subprocess.Popen(
        list(stages[0]),
        stdin=subprocess.PIPE if stdin is not None else None,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
    )
    procs.append(first)
    for stage in stages[1:]:
        prev = procs[-1]
        nxt = subprocess.Popen(
            list(stage),
            stdin=prev.stdout,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
        )
        if prev.stdout is not None:
            prev.stdout.close()
        procs.append(nxt)
    # Feed stdin to the FIRST process (works for single- AND multi-stage):
    # communicate(input=) can't target the last process because its stdin is
    # the prior stage's stdout, not a PIPE. Inputs here are small (host/scope
    # lists), so write+close before draining the tail is safe.
    if stdin is not None and first.stdin is not None:
        first.stdin.write(stdin.encode())
        first.stdin.close()
    out, _ = procs[-1].communicate()
    for p in procs[:-1]:
        p.wait()
    return out.decode(errors="replace")


def dedupe(lines: Iterable[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for raw in lines:
        line = raw.strip()
        if line and line not in seen:
            seen.add(line)
            out.append(line)
    return out


def read_lines(path: Path) -> list[str]:
    if not path.exists():
        return []
    return [ln.strip() for ln in path.read_text(encoding="utf-8").splitlines() if ln.strip()]


def write_lines(path: Path, lines: Iterable[str]) -> int:
    deduped = dedupe(lines)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(deduped) + ("\n" if deduped else ""), encoding="utf-8")
    return len(deduped)
