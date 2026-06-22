"""Subprocess plumbing for external CLI tools — substrate for thin adapters."""

from __future__ import annotations

import json
import shlex
import shutil
import subprocess
from collections.abc import Iterable, Sequence
from pathlib import Path

from pipt.core.log import get_logger

Command = Sequence[str]
log = get_logger()


class ToolNotFoundError(RuntimeError):
    """A required external tool is not on PATH."""


def require(*tools: str) -> None:
    missing = [t for t in tools if shutil.which(t) is None]
    if missing:
        msg = f"missing required tool(s): {', '.join(missing)}"
        raise ToolNotFoundError(msg)


def run(  # noqa: PLR0913
    cmd: Command,
    *,
    stdin: str | None = None,
    check: bool = False,
    timeout: int | None = None,
    cwd: Path | None = None,
    stream_stderr: bool = False,
) -> str:
    """Run a command, return stdout. When `stream_stderr` is set, the tool's
    stderr is inherited (printed live to the terminal) instead of suppressed —
    used by verbose mode to surface tool progress/logs."""
    log.debug("$ %s", shlex.join(list(cmd)))
    proc = subprocess.run(
        list(cmd),
        input=stdin,
        stdout=subprocess.PIPE,
        stderr=None if stream_stderr else subprocess.DEVNULL,
        text=True,
        check=check,
        timeout=timeout,
        cwd=cwd,
    )
    return proc.stdout


def pipe(stages: Sequence[Command], *, stdin: str | None = None) -> str:
    if not stages:
        return ""
    log.debug("$ %s", " | ".join(shlex.join(list(s)) for s in stages))
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


def read_jsonl(path: Path) -> list[dict]:
    """Read a JSONL file (one JSON object per line). Returns [] if missing."""
    if not path.exists():
        return []
    return [json.loads(ln) for ln in path.read_text(encoding="utf-8").splitlines() if ln.strip()]


def write_jsonl(path: Path, records: Iterable[dict]) -> int:
    """Write records as JSONL (one object per line); returns the count."""
    recs = list(records)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(json.dumps(r) + "\n" for r in recs), encoding="utf-8")
    return len(recs)
