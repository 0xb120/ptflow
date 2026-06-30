# tests/core/test_runconfig.py
import pytest

from pipt.core import runconfig


def _envmap(resolved):
    return {r.env: r.value for r in resolved}


def test_resolve_precedence_set_over_env_over_config():
    config = {"profile": "wide", "oast": False, "net_limit": 5}
    env = {"PIPT_PROFILE": "home"}                       # env beats config
    out = _envmap(runconfig.resolve(config, env, ["oast=on"]))  # --set beats env+config
    assert out["PIPT_PROFILE"] == "home"                 # env wins over config
    assert out["PIPT_OAST"] == "on"                      # --set wins (bool coerced)
    assert out["PIPT_NET_LIMIT"] == "5"                  # from config (int → str)


def test_resolve_coerces_bool_list_and_path():
    config = {"oast": True, "http_header": ["Cookie: a", "X: b"], "tools": {"sqlmap": "~/x/sqlmap.py"}}
    out = _envmap(runconfig.resolve(config, {}, None))
    assert out["PIPT_OAST"] == "on"
    assert out["PIPT_HTTP_HEADER"] == "Cookie: a;;X: b"  # list → ;;-joined
    assert out["PIPT_SQLMAP"].endswith("/x/sqlmap.py")   # path expanduser
    assert "~" not in out["PIPT_SQLMAP"]


def test_resolve_dynamic_wordlist_roles():
    config = {"wordlists": {"roles": {"content": "olfa.txt", "params": "p.txt"}}}
    out = _envmap(runconfig.resolve(config, {}, ["wordlists.roles.php=php.txt"]))
    assert out["PIPT_WL_CONTENT"].endswith("olfa.txt")
    assert out["PIPT_WL_PARAMS"].endswith("p.txt")
    assert out["PIPT_WL_PHP"].endswith("php.txt")        # added via --set


def test_resolve_validates_enums_and_set_syntax():
    with pytest.raises(runconfig.ConfigError):
        runconfig.resolve({"profile": "turbo"}, {}, None)        # not wide|home
    with pytest.raises(runconfig.ConfigError):
        runconfig.resolve({}, {}, ["oast"])                      # missing '='


def test_resolve_unset_knob_is_absent():
    out = _envmap(runconfig.resolve({}, {}, None))
    assert out == {}                                             # nothing set → nothing resolved


def test_load_config_missing_and_malformed(tmp_path):
    assert runconfig.load_config(None) == {}
    with pytest.raises(runconfig.ConfigError):
        runconfig.load_config(str(tmp_path / "nope.toml"))
    bad = tmp_path / "bad.toml"
    bad.write_text("profile = \n")                                # malformed
    with pytest.raises(runconfig.ConfigError):
        runconfig.load_config(str(bad))


def test_load_resolve_roundtrip_from_file(tmp_path):
    f = tmp_path / "c.toml"
    f.write_text('profile = "home"\noast = true\n[tools]\nsqlmap = "/opt/sqlmap-dev/sqlmap.py"\n')
    out = _envmap(runconfig.resolve(runconfig.load_config(str(f)), {}, None))
    assert out["PIPT_PROFILE"] == "home"
    assert out["PIPT_OAST"] == "on"
    assert out["PIPT_SQLMAP"] == "/opt/sqlmap-dev/sqlmap.py"


def test_snapshot_redacts_secrets_and_is_refeedable(tmp_path):
    resolved = runconfig.resolve(
        {"profile": "home", "http_header": ["Cookie: secret=abc"], "interactsh": {"token": "T0PSECRET"}},
        {}, None)
    out = runconfig.snapshot(tmp_path, resolved)
    assert out is not None
    text = out.read_text()
    assert "T0PSECRET" not in text                               # token redacted
    assert "secret=abc" not in text                              # http_header redacted
    assert "<redacted>" in text
    assert 'profile = "home"' in text
    # re-feed the snapshot: non-secret values round-trip
    out2 = _envmap(runconfig.resolve(runconfig.load_config(str(out)), {}, None))
    assert out2["PIPT_PROFILE"] == "home"


def test_snapshot_none_when_empty(tmp_path):
    assert runconfig.snapshot(tmp_path, []) is None
