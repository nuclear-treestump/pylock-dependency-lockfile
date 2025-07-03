import logging
import re
import json
import sys
import hashlib
from typing import Any, Optional
from pydepguardnext.api.auth.guard import SECRETS_LIST
from pydepguardnext.api.runtime.integrity import INTEGRITY_CHECK
from datetime import datetime, timezone
from pydepguardnext.bootstrap import clock

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


class IntegrityUUIDFilter(logging.Filter):
    def __init__(self, uuid):
        super().__init__()
        self.uuid = uuid

    def filter(self, record):
        return "[INTEGRITY]" in record.msg and f"{self.uuid}" in record.msg
    
class StartEndFilter(logging.Filter):
    def __init__(self):
        super().__init__()
        self.start_str = "prerun"
        self.end_str = "postrun"
        self.uuid = GLOBAL_INTEGRITY_CHECK.get("global_.jit_check_uuid","NO UUID")

    def filter(self, record):
        if self.start_str in record.msg and self.uuid in record.msg:
            return True
        elif self.end_str in record.msg and self.uuid in record.msg:
            return True
        return False

class JSONFormatter(logging.Formatter):
    def format(self, record):
        log_data = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "message": record.getMessage(),
            "name": record.name,
        }
        return json.dumps(log_data)
    

def _maybe_parse_startend_json_block(message):
    if isinstance(message, dict) and message.get("obj_type") in {"prerun", "postrun"} and f"[{GLOBAL_INTEGRITY_CHECK.get('global_.jit_check_uuid', 'NO UUID')}]" in message:
        return json.dumps(message)
    try:
        parsed = json.loads(message)
        if isinstance(parsed, dict) and parsed.get("obj_type") in {"prerun", "postrun"} and f"[{GLOBAL_INTEGRITY_CHECK.get('global_.jit_check_uuid', 'NO UUID')}]" in parsed.get("message", ""):
            return json.dumps(parsed)
    except Exception:
        pass
    return None
    

COLOR_MAP = {
    "DEBUG": "\033[90m",
    "INFO": "\033[94m",
    "WARNING": "\033[93m",
    "ERROR": "\033[91m",
    "CRITICAL": "\033[95m",
    "FATAL": "\033[95m",
    "USER SCRIPT": "\033[94m",
}
RESET_COLOR = "\033[0m"

class ColoredFormatter(logging.Formatter):
    def format(self, record):
        original_level = record.levelname
        level_color = COLOR_MAP.get(record.levelname, "")
        record.levelname = f"{level_color}{record.levelname}{RESET_COLOR}"
        formatted = super().format(record)
        record.levelname = original_level
        return formatted
    
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
    "u": 21,
    "m": 25,
    "v": 69,
    "x": 70, # Integrity logs
    "z": 71, # INIT logs
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
    redir_file: Optional[str] = None,
    **kwargs: Any,
) -> None:
    active = log_enable if log_enable is not None else _LOGGING_STATE["enabled"]
    if not active:
        return
    
    if source is None:
        source = "NOTHEREFILLTHISIN"
    elif source == "auto":
        source = resolve_source("auto")
    else:
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

    elif source != "USER_SCRIPT":
        message = f"[{clock.timestamp()}] [{source if source else 'SOURCE MISSING'}] [{GLOBAL_INTEGRITY_CHECK.get('global_.jit_check_uuid', 'NO UUID')}] {message}"
    if level in {"u", "x"}:
        if redir_file:
            # Temporary handler for user_scripts or redirection
            from os import environ
            uuid = GLOBAL_INTEGRITY_CHECK.get("global_.jit_check_uuid", "NO UUID")
            runtime_handler = logging.FileHandler(environ.get("PYDEP_RUNTIME_LOG", "pydepguard.runtime.log"))
            integrity_handler = logging.FileHandler(environ.get("PYDEP_INTEGRITY_LOG", "pydepguard.integrity.log"))
            fmt = fmt if fmt is not None else _LOGGING_STATE["format"]
            integrity_handler.setFormatter(JSONFormatter() if fmt == "json" else ColoredFormatter("[%(levelname)s] %(message)s"))
            runtime_handler.setFormatter(JSONFormatter() if fmt == "json" else ColoredFormatter("[%(levelname)s] %(message)s"))
            logger.propagate = False
            logger.addHandler(runtime_handler)
            logger.addHandler(integrity_handler)
            integrity_handler.addFilter(IntegrityUUIDFilter(uuid))
            integrity_handler.addFilter(StartEndFilter())
            message_list = message.splitlines()
            for line in message_list:
                line_json = _maybe_parse_startend_json_block(line)
                if line_json:
                    logger.log(lvl, line_json, stacklevel=stacklevel, **kwargs)
                else:
                    logger.log(lvl, line, stacklevel=stacklevel, **kwargs)
            logger.removeHandler(integrity_handler)
            logger.removeHandler(runtime_handler)
            integrity_handler.close()
            runtime_handler.close()
            return
    else:
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
    logging.addLevelName(21, "USER SCRIPT")
    logging.addLevelName(25, "METRIC")
    logging.addLevelName(69, "IMPROVEMENT")
    logging.addLevelName(70, "INTEGRITY")
    logging.addLevelName(71, "INIT")
    logger.setLevel(LOG_LEVELS.get(level[0].lower(), logging.INFO))

    _LOGGING_STATE["enabled"] = True
    _LOGGING_STATE["format"] = fmt

    for log in initial_logs:
        logit(log, level=level, trace=False, log_enable=True, stacklevel=2, source="internal.init")