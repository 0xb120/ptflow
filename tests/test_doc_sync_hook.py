import os
import subprocess
from pathlib import Path

_GITHOOKS = Path(__file__).resolve().parent.parent / ".githooks"


def _git(args, cwd, env=None):
    return subprocess.run(
        ["git", *args], cwd=cwd, env=env, text=True, capture_output=True, check=False
    )


def _stub(path: Path, body: str) -> None:
    path.write_text("#!/usr/bin/env bash\n" + body)
    path.chmod(0o755)


def _init_repo(tmp_path: Path) -> Path:
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(["init", "-q", "-b", "main"], repo)
    _git(["config", "user.email", "t@example.com"], repo)
    _git(["config", "user.name", "Test"], repo)
    hooks = repo / ".githooks"
    hooks.mkdir()
    for name in ("post-merge", "doc-sync.sh"):
        dst = hooks / name
        dst.write_text((_GITHOOKS / name).read_text())
        dst.chmod(0o755)
    _git(["config", "core.hooksPath", ".githooks"], repo)
    (repo / "src").mkdir()
    (repo / "src" / "app.py").write_text("x = 1\n")
    (repo / "CLAUDE.md").write_text("# CLAUDE\n\ninitial\n")
    (repo / "README.md").write_text("# readme\n")
    (repo / "ptflow.toml.example").write_text("# example\n")
    (repo / "docs").mkdir()
    (repo / "docs" / "example-pipeline-map.md").write_text("map v0\n")
    _git(["add", "-A"], repo)
    _git(["commit", "-qm", "init"], repo)
    return repo


def _env(repo: Path, **overrides) -> dict:
    # default seams: regen = a stub that mutates a generated doc; claude = a no-op stub
    regen = repo / ".githooks" / "stub-regen.sh"
    _stub(regen, 'printf "map v1\\n" > docs/example-pipeline-map.md\n')
    noop = repo / ".githooks" / "stub-claude-noop.sh"
    _stub(noop, "exit 0\n")
    env = {
        **os.environ,
        "PTFLOW_DOC_SYNC_REGEN": str(regen),
        "CLAUDE_BIN": str(noop),
    }
    env.update(overrides)
    return env


def _merge(repo: Path, env: dict, *, on_main: bool = True, touch_src: bool = True):
    _git(["checkout", "-q", "-b", "feat"], repo)
    if touch_src:
        (repo / "src" / "app.py").write_text("x = 2\n")
    else:
        (repo / "docs" / "notes.txt").write_text("doc only\n")
    _git(["add", "-A"], repo)
    _git(["commit", "-qm", "feat change"], repo)
    if on_main:
        _git(["checkout", "-q", "main"], repo)
        return _git(["merge", "--no-ff", "-m", "merge feat", "feat"], repo, env)
    # merge main INTO feat → HEAD stays on feat (non-main target)
    return _git(["merge", "--no-ff", "-m", "merge main", "main"], repo, env)


def _subjects(repo: Path):
    return _git(["log", "--format=%s"], repo).stdout.splitlines()


def test_merge_on_main_commits_regen(tmp_path):
    repo = _init_repo(tmp_path)
    _merge(repo, _env(repo))
    assert _subjects(repo)[0].startswith("docs: auto-sync after merge")
    assert (repo / "docs" / "example-pipeline-map.md").read_text() == "map v1\n"


def test_non_main_target_no_action(tmp_path):
    repo = _init_repo(tmp_path)
    _merge(repo, _env(repo), on_main=False)
    assert not any(s.startswith("docs: auto-sync") for s in _subjects(repo))


def test_env_escape_no_action(tmp_path):
    repo = _init_repo(tmp_path)
    _merge(repo, _env(repo, PTFLOW_NO_DOC_SYNC="1"))
    assert not any(s.startswith("docs: auto-sync") for s in _subjects(repo))


def test_no_src_change_no_action(tmp_path):
    repo = _init_repo(tmp_path)
    _merge(repo, _env(repo), touch_src=False)
    assert not any(s.startswith("docs: auto-sync") for s in _subjects(repo))
