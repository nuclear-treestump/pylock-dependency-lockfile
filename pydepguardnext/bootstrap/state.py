from types import MappingProxyType

_BOOT_HAS_RUN = False

PACKAGE = "pydepguardnext"
VERSION = "2.0.6"

INTEGRITY_CHECK = {}
INTEGRITY_UUID = {}
INTEGRITY_WATCHDOG = True
INTEGRITY_CHECK_DIGEST = {}
INTEGRITY_CHECK_FROZEN = False
INTEGRITY_UUID_FROZEN = False
INTEGRITY_WATCHDOG_STARTED = False
SYSLOCK_TIMING = 0.0

def freeze_dict(d: dict) -> MappingProxyType:
    return MappingProxyType(dict(d))



def mark_boot_complete():
    global _BOOT_HAS_RUN
    _BOOT_HAS_RUN = True

def has_boot_run():
    return _BOOT_HAS_RUN