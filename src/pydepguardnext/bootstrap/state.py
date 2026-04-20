from types import MappingProxyType

_BOOT_HAS_RUN = False

PACKAGE_INFO = MappingProxyType({"package_name": "pydepguardnext","version": "2.0.8"})

INTEGRITY_CHECK = {}
INTEGRITY_UUID = {}
INTEGRITY_WATCHDOG = True
INTEGRITY_CHECK_DIGEST = {} # No longer used, kept for compatibility
INTEGRITY_CHECK_FROZEN = False # No longer used, kept for compatibility
INTEGRITY_UUID_FROZEN = False # No longer used, kept for compatibility
INTEGRITY_WATCHDOG_STARTED = False # No longer used, kept for compatibility
SYSLOCK_TIMING = 0.0 # No longer used, kept for compatibility
RUNTIME_DETAILS = {} # Will be frozen after boot completes
RUNTIME_IDS = {} # Will be frozen after boot completes. Replaces GLOBAL_JIT_CHECK
WATCHDOG_DETAILS = {} # Will be frozen after boot completes. Replaces GLOBAL_WATCHDOG_CHECK
FUNC_ID_BUNDLE = {}

def freeze_dict(d: dict) -> MappingProxyType:
    return MappingProxyType(dict(d))



def mark_boot_complete():
    from pydepguardnext.bootstrap.modes import RUNTIME_MODE
    global _BOOT_HAS_RUN
    if RUNTIME_MODE.mode == "standalone":
        print("[BOOT] Running in standalone mode. Skipping secure boot.")
        _BOOT_HAS_RUN = False
    _BOOT_HAS_RUN = True

def has_boot_run():
    return _BOOT_HAS_RUN

from inspect import unwrap
from hashlib import sha256
from json import dumps
class IntegrityFingerprint:
    def __init__(self):
        self.unwrapped_ids = {
            key: id(unwrap(func)) for key, func in FUNC_ID_BUNDLE.items()
        }
        self.digest = sha256(
            dumps(self.unwrapped_ids, sort_keys=True).encode("utf-8")
        ).hexdigest()

    def matches(self, target: object, label: str) -> bool:
        from inspect import unwrap
        try:
            return id(unwrap(target)) == self.unwrapped_ids[label]
        except Exception:
            return False

    def get_digest(self):
        return self.digest

    def get_ids(self):
        return self.unwrapped_ids