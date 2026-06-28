"""Subprocess plumbing for external CLI tools — substrate for thin adapters."""

from __future__ import annotations

import contextlib
import json
import os
import shlex
import shutil
import signal
import subprocess
import threading
import time
from collections.abc import Iterable, Sequence
from pathlib import Path

from pipt.core.log import get_logger

Command = Sequence[str]
log = get_logger()

# Live-subprocess registry. Every tool we spawn runs in its OWN session/process group
# (start_new_session) and is tracked here while running, so terminate_all() can kill it —
# and its grandchildren (e.g. headless chromium) — at a flow teardown/abort. This imposes
# NO time limit on a healthy scan; it only lets an aborting run tear down promptly instead
# of blocking on a long-lived subprocess (the nuclei teardown-hang incident).
_live: set[subprocess.Popen] = set()
_live_lock = threading.Lock()

# Abort flag. Set on interrupt/teardown (signal_abort); while set, run()/pipe() refuse to spawn a NEW
# subprocess and raise AbortedError instead. Without this, after a Ctrl-C the worker threads Prefect drains
# keep launching fresh tools (feroxbuster round N+1, httpx downloads, trufflehog network-verify) for
# minutes — so the network never goes quiet. Cleared at the start of every run (same-process reruns).
_aborting = threading.Event()


class AbortedError(RuntimeError):
    """Raised by run()/pipe() when the run is aborting — the subprocess is NOT spawned."""


def signal_abort() -> None:
    _aborting.set()


def clear_abort() -> None:
    _aborting.clear()


def is_aborting() -> bool:
    return _aborting.is_set()


def _register(proc: subprocess.Popen) -> None:
    with _live_lock:
        _live.add(proc)


def _unregister(proc: subprocess.Popen) -> None:
    with _live_lock:
        _live.discard(proc)


def _kill_group(proc: subprocess.Popen, sig: int) -> None:
    """Signal the child's whole process GROUP (so grandchildren die too); fall back to the
    child alone if its group is already gone."""
    try:
        os.killpg(os.getpgid(proc.pid), sig)
    except (ProcessLookupError, PermissionError, OSError):
        with contextlib.suppress(ProcessLookupError, OSError):
            proc.send_signal(sig)


def terminate_all(*, grace: float = 3.0) -> int:
    """Kill every still-running tracked subprocess (SIGTERM, brief grace, then SIGKILL),
    by process group so headless-browser grandchildren are reaped too. Called at flow
    teardown so an aborting run never blocks on a long scan. Returns the count that were
    still alive. NO-OP on a clean run — every finished tool is already unregistered."""
    with _live_lock:
        procs = [p for p in _live if p.poll() is None]
    if not procs:
        return 0
    for p in procs:
        _kill_group(p, signal.SIGTERM)
    end = time.monotonic() + grace
    while time.monotonic() < end and any(p.poll() is None for p in procs):
        time.sleep(0.1)
    for p in procs:
        if p.poll() is None:
            _kill_group(p, signal.SIGKILL)
    return len(procs)


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
    reap_group: bool = False,
) -> str:
    """Run a command, return stdout. When `stream_stderr` is set, the tool's
    stderr is inherited (printed live to the terminal) instead of suppressed —
    used by verbose mode to surface tool progress/logs.

    The child runs in its own session/process group and is tracked while live, so
    terminate_all() can kill it (and its grandchildren) at a teardown/abort — see the
    module registry. `timeout` is opt-in (no default); on expiry the whole group is
    killed and TimeoutExpired re-raised. `reap_group` SIGKILLs the child's process group
    on return — even a clean exit — to sweep stragglers the tool leaves behind (e.g. a
    headless chromium from `httpx -ss`/EyeWitness); safe because start_new_session gives
    the child its own group (pgid == pid)."""
    cmd_str = shlex.join(list(cmd))
    if _aborting.is_set():  # run is tearing down → don't launch new network work
        msg = f"aborted before spawning: {cmd_str}"
        raise AbortedError(msg)
    log.debug("$ %s", cmd_str)
    proc = subprocess.Popen(
        list(cmd),
        stdin=subprocess.PIPE if stdin is not None else None,
        stdout=subprocess.PIPE,
        stderr=None if stream_stderr else subprocess.DEVNULL,
        text=True,
        errors="replace",  # a stray non-UTF-8 byte (e.g. a Windows-1252 quote in urlfinder/gau
                           # OSINT output) → U+FFFD, never a UnicodeDecodeError that kills the stage
        cwd=cwd,
        start_new_session=True,  # own process group → killpg reaches grandchildren
    )
    _register(proc)
    try:
        out, _ = proc.communicate(input=stdin, timeout=timeout)
    except subprocess.TimeoutExpired:
        _kill_group(proc, signal.SIGKILL)
        proc.communicate()  # reap the killed group
        raise
    finally:
        _unregister(proc)
        if reap_group:  # sweep stragglers (e.g. headless chrome) even on a clean exit; pgid == pid
            with contextlib.suppress(ProcessLookupError, OSError):
                os.killpg(proc.pid, signal.SIGKILL)
    rc = proc.returncode
    if check and rc != 0:
        raise subprocess.CalledProcessError(rc, list(cmd), output=out)
    if rc != 0:
        # surface non-zero exits so a broken tool (bad flag, crash) can't masquerade
        # as a clean empty result — WARNING reaches the console even without --verbose
        log.warning("⚠ command exited %d: %s", rc, cmd_str)
    return out or ""


def pipe(stages: Sequence[Command], *, stdin: str | None = None) -> str:
    if not stages:
        return ""
    if _aborting.is_set():  # run is tearing down → don't launch new network work
        msg = "aborted before spawning pipe"
        raise AbortedError(msg)
    log.debug("$ %s", " | ".join(shlex.join(list(s)) for s in stages))
    procs: list[subprocess.Popen[bytes]] = []
    first = subprocess.Popen(
        list(stages[0]),
        stdin=subprocess.PIPE if stdin is not None else None,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
    )
    procs.append(first)
    _register(first)
    for stage in stages[1:]:
        prev = procs[-1]
        nxt = subprocess.Popen(
            list(stage),
            stdin=prev.stdout,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
        if prev.stdout is not None:
            prev.stdout.close()
        procs.append(nxt)
        _register(nxt)
    try:
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
    finally:
        for p in procs:
            _unregister(p)
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
    return [ln.strip() for ln in path.read_text(encoding="utf-8", errors="replace").splitlines() if ln.strip()]


def write_lines(path: Path, lines: Iterable[str]) -> int:
    deduped = dedupe(lines)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(deduped) + ("\n" if deduped else ""), encoding="utf-8")
    return len(deduped)


def read_jsonl(path: Path) -> list[dict]:
    """Read a JSONL file (one JSON object per line), SKIPPING any unparseable line. Returns [] if
    missing. Tolerant by design: some of these files hold a tool's RAW stdout (nerva, nuclei), where a
    stray non-JSON line (a banner/progress note) must not crash the consuming stage — mirrors the
    stdout JSONL parser used elsewhere. A skipped line is logged at DEBUG."""
    if not path.exists():
        return []
    out: list[dict] = []
    skipped = 0
    for ln in path.read_text(encoding="utf-8", errors="replace").splitlines():
        if not ln.strip():
            continue
        try:
            out.append(json.loads(ln))
        except json.JSONDecodeError:
            skipped += 1
    if skipped:
        log.debug("read_jsonl: skipped %d unparseable line(s) in %s", skipped, path)
    return out


def write_jsonl(path: Path, records: Iterable[dict]) -> int:
    """Write records as JSONL (one object per line); returns the count."""
    recs = list(records)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(json.dumps(r) + "\n" for r in recs), encoding="utf-8")
    return len(recs)
