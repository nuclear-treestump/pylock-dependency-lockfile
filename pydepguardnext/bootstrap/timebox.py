import inspect
from functools import wraps
from pathlib import Path
import time

from pydepguardnext.bootstrap import clock

_PYDEP_LAST_CALL = clock._GLOBAL_CLOCK["T0"]  # Can use internal key or `clock.now()` directly

# Initial thresholds
TIMEBOX_MIN_THRESHOLD = 0.045
TIMEBOX_MAX_WINDOW = 30

class PyDepDocBrownError(Exception):
    pass

def timebox_guard(func, timebox=TIMEBOX_MIN_THRESHOLD, timebox_max=TIMEBOX_MAX_WINDOW):
    @wraps(func)
    def wrapper(*args, **kwargs):
        global _PYDEP_LAST_CALL
        now = clock.now()
        delta_start = now - _PYDEP_LAST_CALL
        since_boot = clock.since_boot()

        if since_boot < timebox:
            raise PyDepDocBrownError(
                f"[TooEarly] {func.__name__} called at {since_boot:.6f}s (<{timebox}s)"
            )
        if delta_start > timebox_max:
            raise PyDepDocBrownError(
                f"[TooLate] {func.__name__} called after {delta_start:.6f}s since last call (> {timebox_max}s)"
            )

        _PYDEP_LAST_CALL = now
        return func(*args, **kwargs)

    setattr(wrapper, "__pydepguard_verified__", True)
    setattr(wrapper, "__pydepguard_sha256__", func)
    return wrapper


def apply_global_timebox_and_tag():
    base_path = Path(__file__).parent
    for py_file in base_path.rglob("*.py"):
        if py_file.name == "__init__.py":
            continue
        rel_path = py_file.relative_to(base_path).with_suffix("")
        dotted_path = ".".join(["pydepguardnext"] + list(rel_path.parts))
        try:
            mod = __import__(dotted_path, fromlist=["*"])
        except Exception:
            continue

        for name, obj in inspect.getmembers(mod, inspect.isfunction):
            if obj.__module__ != dotted_path:
                continue
            try:
                unwrapped = inspect.unwrap(obj)
                if getattr(unwrapped, "__pydepguard_verified__", False):
                    continue
                composite = f"{dotted_path}.{name}"
                long_runners = {
                    "pydepguardnext.api.runtime.airjail.patch_environment_to_venv",
                    "pydepguardnext.api.pydep_lambda.create_lambda_venv",
                    "pydepguardnext.api.log.logit.logit",
                }
                if composite in long_runners:
                    wrapped = timebox_guard(unwrapped, timebox_max=60)
                else:
                    wrapped = timebox_guard(unwrapped)
                setattr(mod, name, wrapped)
            except Exception:
                continue

# Set min threshold *just before* wrapping
TIMEBOX_MIN_THRESHOLD = clock.since_boot() + 0.003
