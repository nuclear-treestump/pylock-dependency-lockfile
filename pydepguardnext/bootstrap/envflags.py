from os import getenv
from .modes import BootMode, RuntimeConfig, RUNTIME_MODE
import json

def detect_flags_and_mode(override=False, override_key="") -> RuntimeConfig:
    global RUNTIME_MODE

    parent_uuid = getenv("PYDEP_PARENT_UUID", None)
    no_capture = getenv("PYDEP_NO_CAPTURE", "0") == "1"
    hardened = getenv("PYDEP_HARDENED", "0") == "1"
    is_child = getenv("PYDEP_CHILD", "0") == "1"
    is_standalone = getenv("PYDEP_STANDALONE_NOSEC") == "1"
    is_quiet = getenv("PYDEP_QUIET", "0") == "1" # No boot messages
    has_manifest = getenv("PYDEP_MANIFEST", None) is not None

    print(f"[BOOT] Detected flags: parent_uuid={parent_uuid}, no_capture={no_capture}, "
          f"hardened={hardened}, is_child={is_child}, is_standalone={is_standalone}, is_quiet={is_quiet}, has_manifest={has_manifest}"   )

    if is_child or has_manifest:
        mode = BootMode.CHILD
    elif is_standalone:
        mode = BootMode.STANDALONE
    else:
        mode = BootMode.SECURE

    if override:
        match override_key:
            case "standalone":
                mode = BootMode.STANDALONE
            case "light":
                mode = BootMode.LIGHT
            case "secure":
                mode = BootMode.SECURE
            case "child":
                mode = BootMode.CHILD
            case _:
                raise ValueError(f"Unknown boot mode: {override_key}")

    flags = json.loads(getenv("PYDEP_FLAGS", "{}"))

    RUNTIME_MODE = RuntimeConfig(
        mode=mode,
        hardened=hardened,
        parent_uuid=parent_uuid,
        no_capture=no_capture,
        flags=flags,
        quiet=is_quiet,
    )

    print(f"[BOOT] Runtime mode: {RUNTIME_MODE}")
    return RUNTIME_MODE
