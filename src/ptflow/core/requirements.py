"""Requirement inventory + checker for ``ptflow doctor``.

Pure logic (dataclasses + a checker parameterized on injectable resolve/version callables) so the
policy — *fail iff a CORE requirement is unmet* — is unit-testable apart from the real filesystem /
subprocess probing. A pipeline declares its requirements via a duck-typed ``requirements()`` hook (the
same convention as ``preflight``/``consolidate``/``followups``), and BOTH ``ptflow doctor`` and the
run-time ``preflight`` render from that one manifest, so the two can't drift.
"""

from __future__ import annotations

import re
import shutil
import subprocess
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

_VERSION_RE = re.compile(r"v?(\d+\.\d+(?:\.\d+)?)")
_VERSION_TIMEOUT = 10  # s — a `--version` call must never hang doctor
_NAME_WIDTH = 22       # left-pad width for the tool name column in the rendered report


@dataclass(frozen=True)
class Requirement:
    """One thing a pipeline needs on the host.

    ``command`` is the path/name to resolve (a ``tool``) or the filesystem path to check (a
    ``dataset``). ``kind`` drives the exit code: an unmet CORE requirement fails doctor; an unmet
    OPTIONAL one is only a warning. ``min_version`` (+ ``version_args``) opts a tool into a
    version-floor check; ``note`` is a short install/purpose hint shown when it's missing.
    """

    name: str
    command: str
    kind: str                                    # "core" | "optional"
    category: str = "tool"                       # "tool" | "dataset"
    min_version: str | None = None
    version_args: tuple[str, ...] = ("--version",)
    note: str = ""


@dataclass(frozen=True)
class CheckResult:
    req: Requirement
    found: bool
    resolved: str | None
    version: str | None
    version_ok: bool | None                      # None = not checked/unparseable; False = below floor

    @property
    def ok(self) -> bool:
        """Present AND not known-outdated. An unparseable version is treated as ok (warn, not fail)."""
        return self.found and self.version_ok is not False


@dataclass(frozen=True)
class Report:
    results: tuple[CheckResult, ...]

    @property
    def core_missing(self) -> list[CheckResult]:
        return [r for r in self.results if r.req.kind == "core" and not r.ok]

    @property
    def ok(self) -> bool:
        return not self.core_missing

    @property
    def exit_code(self) -> int:
        return 0 if self.ok else 1


def parse_version(text: str) -> str | None:
    """First dotted-number (``X.Y[.Z]``) found in a tool's --version output, or None."""
    m = _VERSION_RE.search(text)
    return m.group(1) if m else None


def _as_tuple(version: str) -> tuple[int, ...]:
    return tuple(int(p) for p in version.split("."))


def version_satisfies(actual: str, minimum: str) -> bool:
    """True if ``actual`` >= ``minimum``, compared numerically component-wise (so 1.10 >= 1.3)."""
    a, b = _as_tuple(actual), _as_tuple(minimum)
    width = max(len(a), len(b))
    return a + (0,) * (width - len(a)) >= b + (0,) * (width - len(b))


def _resolve(req: Requirement) -> str | None:
    """Default resolver: a dataset is its path iff it exists; a tool is its absolute path (if present)
    else a PATH lookup by name."""
    target = str(Path(req.command).expanduser())
    if req.category == "dataset":
        return target if Path(target).exists() else None
    if Path(target).is_absolute():
        return target if Path(target).exists() else None
    return shutil.which(req.command)


def _version_of(req: Requirement, resolved: str) -> str | None:
    """Default version probe: run ``<resolved> <version_args>`` and parse stdout+stderr."""
    try:
        proc = subprocess.run(
            [resolved, *req.version_args],
            capture_output=True, text=True, timeout=_VERSION_TIMEOUT, check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    return parse_version(f"{proc.stdout}\n{proc.stderr}")


def check(
    requirements: list[Requirement],
    *,
    resolve: Callable[[Requirement], str | None] = _resolve,
    version_of: Callable[[Requirement, str], str | None] = _version_of,
) -> Report:
    """Resolve each requirement into a Report. Inject ``resolve``/``version_of`` in tests to stay pure."""
    results: list[CheckResult] = []
    for req in requirements:
        resolved = resolve(req)
        version: str | None = None
        version_ok: bool | None = None
        if resolved is not None and req.min_version:
            version = version_of(req, resolved)
            if version is not None:
                version_ok = version_satisfies(version, req.min_version)
        results.append(CheckResult(req, resolved is not None, resolved, version, version_ok))
    return Report(tuple(results))


_MARK_OK = "✓"    # ✓
_MARK_BAD = "✗"   # ✗


def _line(r: CheckResult) -> str:
    mark = _MARK_OK if r.ok else _MARK_BAD
    if not r.found:
        detail = "MISSING" + (f" — {r.req.note}" if r.req.note else "")
    elif r.version_ok is False:
        detail = f"{r.resolved}  (v{r.version} < {r.req.min_version})"
    elif r.version:
        detail = f"{r.resolved}  (v{r.version})"
    else:
        detail = r.resolved or ""
    return f"  {mark} {r.req.name:<{_NAME_WIDTH}} {detail}"


def render_report(report: Report, *, pipeline: str) -> str:
    """Human-readable, grouped report (CORE tools / OPTIONAL tools / Datasets) + a PASS/FAIL summary."""
    tools_core = [r for r in report.results if r.req.category == "tool" and r.req.kind == "core"]
    tools_opt = [r for r in report.results if r.req.category == "tool" and r.req.kind == "optional"]
    datasets = [r for r in report.results if r.req.category == "dataset"]

    lines: list[str] = [f"ptflow doctor — {pipeline}", ""]

    def _section(title: str, items: list[CheckResult]) -> None:
        if not items:
            return
        present = sum(1 for r in items if r.ok)
        lines.append(f"{title} ({present}/{len(items)}):")
        lines.extend(_line(r) for r in items)
        lines.append("")

    _section("CORE tools", tools_core)
    _section("OPTIONAL tools", tools_opt)
    _section("Datasets / DBs", datasets)

    if report.ok:
        lines.append("PASS — all core requirements present.")
    else:
        lines.append(f"FAIL — missing core: {', '.join(r.req.name for r in report.core_missing)}")
    return "\n".join(lines)
