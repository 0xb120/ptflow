from pathlib import Path

from pipt.core.paths import Activity
from pipt.pipelines.recon import wordlists


def test_search_dirs_prepends_env_and_filters_missing(tmp_path, monkeypatch):
    real = tmp_path / "lists"
    real.mkdir()
    monkeypatch.setenv("PIPT_WORDLISTS", f"{real}:/nonexistent/dir")
    dirs = wordlists.search_dirs()
    assert real in dirs                      # existing env dir included
    assert Path("/nonexistent/dir") not in dirs  # missing dir filtered out


def test_provision_resolves_role_from_search_dir(tmp_path, monkeypatch):
    # a collection with the content list at a known candidate path
    coll = tmp_path / "coll"
    (coll / "Discovery" / "Web-Content").mkdir(parents=True)
    (coll / "Discovery" / "Web-Content" / "common.txt").write_text("admin\nlogin\n")
    monkeypatch.setenv("PIPT_WORDLISTS", str(coll))

    act = Activity.named("demo", root=tmp_path).ensure()
    resolved = wordlists.provision(act)
    assert "content" in resolved
    # symlinked into wl_global/content.txt and readable by role
    rp = wordlists.role_path(act, "content")
    assert rp is not None
    assert rp.read_text(encoding="utf-8") == "admin\nlogin\n"


def test_provision_byo_wins_and_unresolved_degrades(tmp_path, monkeypatch):
    monkeypatch.setattr(wordlists, "_DEFAULT_DIRS", ())  # isolate from any system SecLists
    monkeypatch.setenv("PIPT_WORDLISTS", str(tmp_path / "empty"))  # nothing installed
    act = Activity.named("demo", root=tmp_path).ensure()
    # user drops their own content list → BYO must win, and unresolved roles stay None
    (act.wl_global / "content.txt").write_text("mine\n")
    wordlists.provision(act)
    assert wordlists.role_path(act, "content").read_text(encoding="utf-8") == "mine\n"
    assert wordlists.role_path(act, "wordpress") is None  # not installed, not BYO → degrade


def test_explicit_env_override_per_role(tmp_path, monkeypatch):
    custom = tmp_path / "my_content.txt"
    custom.write_text("x\n")
    monkeypatch.setenv("PIPT_WORDLISTS", str(tmp_path / "empty"))
    monkeypatch.setenv("PIPT_WL_CONTENT", str(custom))
    act = Activity.named("demo", root=tmp_path).ensure()
    wordlists.provision(act)
    assert wordlists.role_path(act, "content").read_text(encoding="utf-8") == "x\n"


def test_tech_role_paths_matches_detected_tech(tmp_path):
    act = Activity.named("demo", root=tmp_path).ensure()
    (act.wl_global / "wordpress.txt").write_text("wp-admin\n")
    # detected tech tag substring-matches the role; missing roles skipped
    assert wordlists.tech_role_paths(["WordPress 6.4", "Nginx"], act.wl_global) == [
        act.wl_global / "wordpress.txt"
    ]
    assert wordlists.tech_role_paths(["Apache"], act.wl_global) == []


def test_staged_roles_resolve_from_search_dir(tmp_path, monkeypatch):
    coll = tmp_path / "coll"
    coll.mkdir()
    (coll / "an_directories_1m.txt").write_text("/\n/admin\n")
    (coll / "an_php.txt").write_text("index.php\n")
    monkeypatch.setattr(wordlists, "_DEFAULT_DIRS", ())
    monkeypatch.setenv("PIPT_WORDLISTS", str(coll))
    act = Activity.named("demo", root=tmp_path).ensure()
    wordlists.provision(act)
    assert wordlists.role_path(act, "an_directories").read_text(encoding="utf-8") == "/\n/admin\n"
    assert wordlists.role_path(act, "an_php").read_text(encoding="utf-8") == "index.php\n"
    assert wordlists.role_path(act, "mn_php") is None  # not installed → degrade
