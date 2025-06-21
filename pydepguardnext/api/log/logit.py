import logging
import re
import json
import sys
import hashlib
from typing import Any, Optional
from pydepguardnext.api.auth.guard import SECRETS_LIST
from datetime import datetime, timezone

_last_hash = None


class JSONFormatter(logging.Formatter):
    def format(self, record):
        log_data = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "message": record.getMessage(),
            "name": record.name,
        }
        return json.dumps(log_data)
    

COLOR_MAP = {
    "DEBUG": "\033[90m",
    "INFO": "\033[94m",
    "WARNING": "\033[93m",
    "ERROR": "\033[91m",
    "CRITICAL": "\033[95m",
    "FATAL": "\033[95m",
}
RESET_COLOR = "\033[0m"

class ColoredFormatter(logging.Formatter):
    def format(self, record):
        level_color = COLOR_MAP.get(record.levelname, "")
        formatted = super().format(record)
        return f"{level_color}{formatted}{RESET_COLOR}"
    
_LOGGING_STATE = {
    "enabled": False,
    "format": "text"
}

LOG_LEVELS = {
    "d": logging.DEBUG,
    "i": logging.INFO,
    "w": logging.WARNING,
    "e": logging.ERROR,
    "c": logging.CRITICAL,
    "f": logging.FATAL,
    "0": logging.FATAL,
    "1": logging.CRITICAL,
    "2": logging.ERROR,
    "3": logging.WARNING,
    "4": logging.INFO,
    "5": logging.DEBUG,
}

REDACT_PATTERNS = [re.compile(re.escape(s)) for s in SECRETS_LIST if s]

def _update_redact_patterns():
    global _last_hash, REDACT_PATTERNS
    secret_hash = hash(tuple(SECRETS_LIST))
    if secret_hash != _last_hash:
        _last_hash = secret_hash
        REDACT_PATTERNS = [re.compile(re.escape(s)) for s in SECRETS_LIST if s]

def redact(text: str) -> str:
    _update_redact_patterns()
    for pat in REDACT_PATTERNS:
        text = pat.sub("[REDACTED]", text)
    return text



def logit(
    message: str,
    level: Optional[str] = "d",
    trace: bool = False,
    stacktrace: Optional[Any] = None,
    log_enable: Optional[bool] = None,
    log_file: Optional[str] = None,
    stacklevel: int = 2,
    fmt: Optional[str] = None,
    source: Optional[str] = None,
    **kwargs: Any,
) -> None:
    active = log_enable if log_enable is not None else _LOGGING_STATE["enabled"]
    if not active:
        return

    logger = logging.getLogger("pydepguard")
    lvl = LOG_LEVELS.get(str(level).lower()[0], logging.INFO)

    if not logger.handlers:
        handler = logging.FileHandler(log_file) if log_file else logging.StreamHandler(sys.stdout)

        formatter_fmt = fmt if fmt is not None else _LOGGING_STATE["format"]
        if formatter_fmt == "json":
            handler.setFormatter(JSONFormatter())
        else:
            handler.setFormatter(ColoredFormatter("[%(levelname)s] %(message)s"))

        logger.addHandler(handler)
        logger.setLevel(lvl)

    message = redact(message)
    if stacktrace:
        stacktrace = redact(stacktrace)

    if trace and stacktrace:
        logger.exception(stacktrace, stacklevel=stacklevel)

    message = f"[{source}] {message}" if source else message

    logger.log(lvl, message, stacklevel=stacklevel, **kwargs)


def configure_logging(level="INFO", fmt="text", to_file=None):
    logger = logging.getLogger("pydepguard")
    logger.handlers.clear()

    handler = logging.FileHandler(to_file) if to_file else logging.StreamHandler()

    if fmt == "json":
        handler.setFormatter(JSONFormatter())
    else:
        handler.setFormatter(ColoredFormatter("[%(levelname)s] %(message)s"))

    logger.addHandler(handler)
    logger.setLevel(LOG_LEVELS.get(level[0].lower(), logging.INFO))

    _LOGGING_STATE["enabled"] = True
    _LOGGING_STATE["format"] = fmt





