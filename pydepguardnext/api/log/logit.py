import logging
import re
import json
import sys
import hashlib
from typing import Any, Optional
from pydepguardnext.api.auth.guard import SECRETS_LIST
from pydepguardnext.api.runtime.integrity import INTEGRITY_CHECK
from datetime import datetime, timezone
from pydepguardnext import get_gtime, _total_global_time
import inspect

def resolve_source(source="auto", max_depth=5):
    if source != "auto":
        return source

    stack = inspect.stack()
    parts = []

    for frame_info in stack[2:2+max_depth]:
        func = frame_info.function
        module = inspect.getmodule(frame_info.frame)
        if module and module.__name__ != "__main__":
            parts.append(f"{module.__name__}.{func}")
        else:
            parts.append(f"__main__.{func}")

    return '.'.join(reversed(parts))


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
    print_enabled: bool = True,
    **kwargs: Any,
) -> None:
    active = log_enable if log_enable is not None else _LOGGING_STATE["enabled"]
    if not active:
        return
    
    if source is None:
        source = "NOTHEREFILLTHISIN"
    if source == "auto":
        source = resolve_source("auto")
    if source != "auto" and source != "NOTHEREFILLTHISIN":
        source = source

    

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

    if source == "internal.init":
        message = message # No change to pre-configured logs from __init__.py
        lvl = logging.INFO

    elif source:
        message = f"[{get_gtime()}] [{source}] [{INTEGRITY_CHECK['global_.jit_check_uuid']}] {message}"
    else:
        message = f"[{get_gtime()}] [SOURCE MISSING] [{INTEGRITY_CHECK['global_.jit_check_uuid']}] {message}"

    logger.log(lvl, message, stacklevel=stacklevel, **kwargs)


def configure_logging(level="INFO", fmt="text", to_file=None, print_enabled=True, initial_logs: list[str] = []):
    logger = logging.getLogger("pydepguard")
    logger.handlers.clear()

    if print_enabled:
        cmd_handler = logging.StreamHandler(sys.stdout)
        if fmt != "json":
            cmd_handler.setFormatter(logging.Formatter("[%(levelname)s] %(message)s"))
        else:
            cmd_handler.setFormatter(ColoredFormatter("[%(levelname)s] %(message)s"))
        logger.addHandler(cmd_handler)
    
    if to_file:
        file_handler = logging.FileHandler(to_file)
        if fmt == "json":
            file_handler.setFormatter(JSONFormatter())
        else:
            file_handler.setFormatter(logging.Formatter("[%(levelname)s] %(message)s"))
        logger.addHandler(file_handler)

    logger.setLevel(LOG_LEVELS.get(level[0].lower(), logging.INFO))

    _LOGGING_STATE["enabled"] = True
    _LOGGING_STATE["format"] = fmt

    for log in initial_logs:
        logit(log, level=level, trace=False, log_enable=True, stacklevel=2, source="internal.init")