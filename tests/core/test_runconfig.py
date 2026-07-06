# tests/core/test_runconfig.py
import pytest

from ptflow.core import runconfig


def _envmap(resolved):
    return {r.env: r.value for r in resolved}


def test_resolve_precedence_set_over_env_over_config():
    config = {"profile": "wide", "oast": False, "net_limit": 5}
    env = {"PTFLOW_PROFILE": "home"}                       # env beats config
    out = _envmap(runconfig.resolve(config, env, ["oast=on"]))  # --set beats env+config
    assert out["PTFLOW_PROFILE"] == "home"                 # env wins over config
    assert out["PTFLOW_OAST"] == "on"                      # --set wins (bool coerced)
    assert out["PTFLOW_NET_LIMIT"] == "5"                  # from config (int → str)


def test_resolve_coerces_bool_list_and_path():
    config = {"oast": True, "http_header": ["Cookie: a", "X: b"], "tools": {"sqlmap": "~/x/sqlmap.py"}}
    out = _envmap(runconfig.resolve(config, {}, None))
    assert out["PTFLOW_OAST"] == "on"
    assert out["PTFLOW_HTTP_HEADER"] == "Cookie: a;;X: b"  # list → ;;-joined
    assert out["PTFLOW_SQLMAP"].endswith("/x/sqlmap.py")   # path expanduser
    assert "~" not in out["PTFLOW_SQLMAP"]


def test_resolve_dynamic_wordlist_roles():
    config = {"wordlists": {"roles": {"content": "olfa.txt", "params": "p.txt"}}}
    out = _envmap(runconfig.resolve(config, {}, ["wordlists.roles.php=php.txt"]))
    assert out["PTFLOW_WL_CONTENT"].endswith("olfa.txt")
    assert out["PTFLOW_WL_PARAMS"].endswith("p.txt")
    assert out["PTFLOW_WL_PHP"].endswith("php.txt")        # added via --set


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
    assert out["PTFLOW_PROFILE"] == "home"
    assert out["PTFLOW_OAST"] == "on"
    assert out["PTFLOW_SQLMAP"] == "/opt/sqlmap-dev/sqlmap.py"


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
    assert out2["PTFLOW_PROFILE"] == "home"


def test_snapshot_none_when_empty(tmp_path):
    assert runconfig.snapshot(tmp_path, []) is None


def test_ai_flag_resolves_to_env():
    resolved = runconfig.resolve({}, {}, ["ai=on", "ai.model=claude-opus-4-8"])
    envs = {r.env: r.value for r in resolved}
    assert envs["PTFLOW_AI"] == "on"
    assert envs["PTFLOW_AI_MODEL"] == "claude-opus-4-8"


def test_resolve_disabled_steps_sparse_and_precedence():
    config = {"steps": {"external": {"dast": False, "cve_lookup": True}}}
    names = {"dast", "cve_lookup", "httpx"}
    # config: dast off, cve_lookup on; --set turns httpx off and flips cve_lookup off (--set wins)
    out = runconfig.resolve_disabled_steps(
        config, ["steps.external.httpx=off", "steps.external.cve_lookup=off"], "external", names)
    assert out == frozenset({"dast", "httpx", "cve_lookup"})


def test_resolve_disabled_steps_unlisted_stay_enabled():
    assert runconfig.resolve_disabled_steps({}, None, "external", {"dast", "httpx"}) == frozenset()


def test_resolve_disabled_steps_unknown_name_raises():
    with pytest.raises(runconfig.ConfigError):
        runconfig.resolve_disabled_steps(
            {"steps": {"external": {"nope": False}}}, None, "external", {"dast"})


def test_resolve_disabled_steps_scopes_to_pipeline():
    config = {"steps": {"internal": {"smb_checks": False}}}  # a DIFFERENT pipeline's table
    assert runconfig.resolve_disabled_steps(config, None, "external", {"dast"}) == frozenset()


def test_resolve_does_not_warn_steps_prefix(caplog):
    import logging
    caplog.set_level(logging.WARNING, logger="ptflow")
    runconfig.resolve({"steps": {"external": {"dast": False}}}, {}, None)
    assert "steps.external.dast" not in caplog.text  # recognized prefix, not a "unknown key" typo warning


def test_resolve_warns_malformed_steps_key_missing_pipeline(caplog):
    import logging
    caplog.set_level(logging.WARNING, logger="ptflow")
    runconfig.resolve({}, {}, ["steps.dast=off"])   # missing pipeline segment
    assert "steps.dast" in caplog.text               # warned as an unknown/typo key


def test_resolve_does_not_warn_wellformed_steps_key(caplog):
    import logging
    caplog.set_level(logging.WARNING, logger="ptflow")
    runconfig.resolve({"steps": {"external": {"dast": False}}}, {}, None)
    assert "steps.external.dast" not in caplog.text   # steps.<pipeline>.<step> is recognized


def test_snapshot_records_disabled_steps(tmp_path):
    resolved = runconfig.resolve({"profile": "home"}, {}, None)
    out = runconfig.snapshot(tmp_path, resolved, disabled_keys=["steps.external.dast"])
    text = out.read_text()
    assert 'profile = "home"' in text
    assert 'steps.external.dast = "off"' in text


def test_snapshot_disabled_only_still_writes(tmp_path):
    out = runconfig.snapshot(tmp_path, [], disabled_keys=["steps.external.dast"])
    assert out is not None
    assert 'steps.external.dast = "off"' in out.read_text()


def test_snapshot_nothing_set_returns_none(tmp_path):
    assert runconfig.snapshot(tmp_path, [], disabled_keys=[]) is None


def test_ai_provider_enum_accepts_new_values():
    from ptflow.core import runconfig
    for prov in ("claude-code", "openai"):
        resolved = runconfig.resolve({"ai": {"provider": prov}}, {})
        assert any(r.env == "PTFLOW_AI_PROVIDER" and r.value == prov for r in resolved)


def test_ai_provider_enum_rejects_unknown():
    import pytest

    from ptflow.core import runconfig
    with pytest.raises(runconfig.ConfigError):
        runconfig.resolve({"ai": {"provider": "anthropic"}}, {})
