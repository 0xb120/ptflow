import logging

from pipt.core import log


def test_setup_logging_sets_level_and_handler():
    lg = log.get_logger()
    log.setup_logging(verbose=False)
    assert lg.level == logging.INFO
    assert lg.handlers

    log.setup_logging(verbose=True)
    assert lg.level == logging.DEBUG
