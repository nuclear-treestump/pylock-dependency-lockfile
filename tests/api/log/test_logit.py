import logging
import io
import json
import re
import pytest
from pydepguardnext.api.log.logit import logit, configure_logging, JSONFormatter, ColoredFormatter

@pytest.fixture
def log_buffer():
    buffer = io.StringIO()
    yield buffer
    buffer.close()

@pytest.fixture
def clear_logger():
    logger = logging.getLogger("pydepguard")
    logger.handlers.clear()
    logger.setLevel(logging.DEBUG)
    yield logger
    logger.handlers.clear()

def test_colored_text_log_output(log_buffer, clear_logger):
    handler = logging.StreamHandler(log_buffer) 
    handler.setFormatter(ColoredFormatter("[%(levelname)s] %(message)s"))
    clear_logger.addHandler(handler)
    clear_logger.setLevel(logging.INFO)

    logit("Color test message", level="i", log_enable=True)

    output = log_buffer.getvalue()
    assert "Color test message" in output
    assert "\033[" in output  


def test_json_log_output(log_buffer, clear_logger):
    handler = logging.StreamHandler(log_buffer)
    handler.setFormatter(JSONFormatter())
    clear_logger.addHandler(handler)

    # Normally, configure_logging would be called to init
    # But for sake of testing actual formatting, it is omitted here
    # You would not normally need log_enable=True
    # but it is set to ensure the logit function processes the message

    clear_logger.setLevel(logging.INFO)
    logit("JSON test message", level="i", log_enable=True)

    output = log_buffer.getvalue().strip()
    assert output, "Expected log output, got nothing"

    data = json.loads(output)

    assert data["message"] == "JSON test message"
    assert data["level"] == "INFO"
    assert "timestamp" in data
    assert data["name"] == "pydepguard"


def test_log_disabled_skips_output(log_buffer, clear_logger):
    handler = logging.StreamHandler(log_buffer)
    handler.setFormatter(logging.Formatter("[%(levelname)s] %(message)s"))
    clear_logger.addHandler(handler)

    configure_logging(level="i", fmt="text")
    logit("Should not appear", level="i", log_enable=False)

    output = log_buffer.getvalue().strip()
    assert output == ""

def test_redaction(log_buffer, clear_logger):
    from pydepguardnext.api.auth.guard import SECRETS_LIST
    SECRETS_LIST.append("SECRET123")

    handler = logging.StreamHandler(log_buffer)
    handler.setFormatter(logging.Formatter("[%(levelname)s] %(message)s"))
    clear_logger.addHandler(handler)

    logit("This contains SECRET123 and should be redacted", level="i", log_enable=True)

    output = log_buffer.getvalue()
    assert "SECRET123" not in output
    assert "[REDACTED]" in output
