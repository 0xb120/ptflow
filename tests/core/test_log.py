import logging

from ptflow.core import log


def _console(lg):
    return next(h for h in lg.handlers
                if isinstance(h, logging.StreamHandler) and not isinstance(h, logging.FileHandler))


def test_logger_always_debug_console_level_by_verbose():
    lg = log.get_logger()
    log.setup_logging(verbose=False)
    assert lg.level == logging.DEBUG            # logger always passes DEBUG (so the file can capture)
    assert _console(lg).level == logging.INFO   # console quiet without --verbose
    assert log.is_verbose() is False

    log.setup_logging(verbose=True)
    assert _console(lg).level == logging.DEBUG
    assert log.is_verbose() is True


def test_add_file_handler_persists_commands_even_when_console_quiet(tmp_path):
    lg = log.get_logger()
    log.setup_logging(verbose=False)            # console at INFO
    logfile = tmp_path / "logs" / "run.log"
    log.add_file_handler(logfile)

    lg.debug("$ some-tool --flag")              # DEBUG: console drops it, the file keeps it
    for h in lg.handlers:
        h.flush()
    assert logfile.exists()
    assert "some-tool --flag" in logfile.read_text(encoding="utf-8")

    # replaces, never accumulates
    log.add_file_handler(tmp_path / "logs" / "run2.log")
    assert sum(isinstance(h, logging.FileHandler) for h in lg.handlers) == 1

    # don't leak the file handler onto the global logger for later tests
    for h in list(lg.handlers):
        if isinstance(h, logging.FileHandler):
            h.close()
            lg.removeHandler(h)
