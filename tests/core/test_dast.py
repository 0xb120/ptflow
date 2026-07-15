import json

import pytest

from ptflow.core import dast


def _template(path, template_id):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        f"id: {template_id}\n\ninfo:\n  name: Test\n  author: test\n  severity: info\n",
        encoding="utf-8",
    )
    return path


def test_settings_defaults_select_all_with_high_aggression():
    settings = dast.settings_from_env({})
    assert [pack.name for pack in settings.packs] == ["official", "ptflow-stable"]
    assert settings.aggression == "high"
    assert settings.fuzz_param_frequency == 10_000


def test_settings_parse_structured_packs_and_global_execution(tmp_path):
    packs = [{"name": "engagement", "path": str(tmp_path), "revision": "abc123"}]
    settings = dast.settings_from_env({
        "PTFLOW_DAST_PACKS": json.dumps(packs),
        "PTFLOW_DAST_AGGRESSION": "medium",
        "PTFLOW_DAST_FUZZ_PARAM_FREQUENCY": "25",
    })
    assert settings.packs[0].path == tmp_path
    assert settings.packs[0].revision == "abc123"
    assert settings.aggression == "medium"
    assert settings.fuzz_param_frequency == 25


def test_settings_reject_invalid_pack_and_execution_settings(tmp_path):
    with pytest.raises(dast.DastConfigError, match="invalid name"):
        dast.settings_from_env({
            "PTFLOW_DAST_PACKS": json.dumps([{"name": "bad name", "path": str(tmp_path)}]),
        })
    with pytest.raises(dast.DastConfigError, match="positive integer"):
        dast.settings_from_env({
            "PTFLOW_DAST_FUZZ_PARAM_FREQUENCY": "0",
        })
    with pytest.raises(dast.DastConfigError, match="aggression"):
        dast.settings_from_env({"PTFLOW_DAST_AGGRESSION": "maximum"})


def test_catalog_rejects_duplicate_template_ids(tmp_path):
    first = tmp_path / "first"
    second = tmp_path / "second"
    _template(first / "one.yaml", "duplicate-id")
    _template(second / "two.yaml", "duplicate-id")
    packs = (dast.Pack("first", first), dast.Pack("second", second))
    with pytest.raises(dast.DastConfigError, match="duplicate nuclei template id"):
        dast.catalog(packs)


def test_list_selection_maps_nuclei_output_to_pack(tmp_path):
    template = _template(tmp_path / "pack" / "rule.yaml", "custom-rule")
    settings = dast.Settings(
        packs=(dast.Pack("engagement", template.parent, revision="abc"),),
        aggression="high",
        fuzz_param_frequency=10_000,
    )
    calls = []

    def fake_run(command):
        calls.append(tuple(command))
        return f"{template}\n"

    selection = dast.list_selection(
        settings, run=fake_run,
    )
    assert [(item.template_id, item.pack) for item in selection.templates] == [
        ("custom-rule", "engagement"),
    ]
    assert ("-t", str(template.parent)) == calls[0][6:8]
    assert not {"-tags", "-etags", "-id", "-eid", "-ni"}.intersection(calls[0])


def test_list_selection_keeps_configured_templates_omitted_by_engine_preview(tmp_path):
    template = _template(tmp_path / "pack" / "rule.yaml", "engine-omitted-rule")
    settings = dast.Settings(packs=(dast.Pack("custom", template.parent),))
    selection = dast.list_selection(settings, run=lambda _command: "")

    assert [item.template_id for item in selection.templates] == ["engine-omitted-rule"]
    assert [item.template_id for item in selection.engine_omitted] == ["engine-omitted-rule"]
    assert selection.manifest()["engine_preview"]["listed_count"] == 0


def test_stamp_findings_adds_all_selection_and_revision(tmp_path):
    template = _template(tmp_path / "rule.yaml", "custom-rule")
    selection = dast.Selection(
        packs=({"name": "custom", "effective_revision": "sha256:123"},),
        templates=(dast.TemplateRef("custom-rule", template, "custom"),),
        template_args=("-t", str(tmp_path)),
        aggression="high",
        fuzz_param_frequency=10_000,
    )
    result = dast.stamp_findings([{"template-id": "custom-rule"}], selection)[0]
    assert result["ptflow_dast"] == {
        "selection": "all",
        "pack": "custom",
        "pack_revision": "sha256:123",
    }
