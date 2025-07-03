import time
from datetime import datetime, timezone
from types import MappingProxyType
from typing import Literal

_T0 = time.perf_counter()
_GLOBAL_CLOCK = MappingProxyType({"T0": _T0})

def now() -> float:
    """Return current perf_counter time."""
    return time.perf_counter()

def since_boot() -> float:
    """Seconds since boot (float)."""
    return time.perf_counter() - _GLOBAL_CLOCK["T0"]

def timestamp(format: Literal["perf", "iso_utc", "iso_local"] = "perf") -> str:
    """
    Return a formatted timestamp.

    - "perf" -> float seconds since boot, as string
    - "iso_utc" -> UTC ISO8601 timestamp
    - "iso_local" -> local timezone ISO8601 timestamp
    """
    match format:
        case "perf":
            return f"{since_boot():.6f}"
        case "iso_utc":
            return datetime.now(timezone.utc).isoformat()
        case "iso_local":
            return datetime.now().astimezone().isoformat()
        case _:
            raise ValueError(f"Unknown timestamp format: {format}")