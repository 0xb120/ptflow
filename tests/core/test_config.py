from pipt.core.config import CONFIG, Config


def test_defaults():
    assert CONFIG.fanout.max_workers == 3
    assert CONFIG.fanout.net_limit == 10
    assert CONFIG.retries.tool_retries == 2
    assert CONFIG.db.busy_timeout_ms == 5000


def test_frozen():
    import dataclasses
    import pytest

    with pytest.raises(dataclasses.FrozenInstanceError):
        CONFIG.fanout.max_workers = 99  # type: ignore[misc]


def test_overridable_for_tests():
    cfg = Config()
    assert cfg.fanout.max_workers == 3
