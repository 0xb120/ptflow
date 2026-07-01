# tests/test_cli_doctor.py
from ptflow.cli import main


def test_doctor_external_prints_report_and_returns_valid_code(capsys):
    code = main(["doctor", "external"])
    out = capsys.readouterr().out
    assert "ptflow doctor — external" in out
    assert code in (0, 1)   # 0 = all core present · 1 = a core tool missing (environment-dependent)


def test_doctor_defaults_to_external(capsys):
    main(["doctor"])                       # no pipeline arg → external
    assert "external" in capsys.readouterr().out


def test_doctor_pipeline_without_requirements_hook_passes(capsys):
    code = main(["doctor", "example"])     # example declares no requirements() hook → graceful pass
    out = capsys.readouterr().out
    assert code == 0
    assert "example" in out


def test_doctor_internal_and_webscan_declare_requirements(capsys):
    for name in ("internal", "webscan"):
        code = main(["doctor", name])
        out = capsys.readouterr().out
        assert name in out
        assert "declares no requirements" not in out   # both now wire the requirements() hook
        assert code in (0, 1)
