from os import getenv
from .modes import BootMode, RuntimeConfig, RUNTIME_MODE
import json

def detect_flags_and_mode():
    global RUNTIME_MODE

    parent_uuid = getenv("PYDEP_PARENT_UUID", None)
    no_capture = getenv("PYDEP_NO_CAPTURE", "0") == "1"
    hardened = getenv("PYDEP_HARDENED", "0") == "1"
    is_child = getenv("PYDEP_CHILD", "0") == "1"
    is_standalone = getenv("PYDEP_STANDALONE_NOSEC", "0") == "1"

    if is_child:
        mode = BootMode.CHILD
    elif is_standalone:
        mode = BootMode.STANDALONE
    else:
        mode = BootMode.SECURE

    flags = json.loads(getenv("PYDEP_FLAGS", "{}"))

    RUNTIME_MODE = RuntimeConfig(
        mode=mode,
        hardened=hardened,
        parent_uuid=parent_uuid,
        no_capture=no_capture,
        flags=flags
    )

    print(f"[BOOT] Runtime mode: {RUNTIME_MODE}")
    return RUNTIME_MODE
