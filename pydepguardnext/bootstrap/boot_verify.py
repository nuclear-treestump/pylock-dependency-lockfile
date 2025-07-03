from json import dumps
from hashlib import sha256
from os import getenv
from time import time, sleep
from sys import exit
from types import MappingProxyType

from pydepguardnext.bootstrap.function_registry import IntegrityFingerprint

INTEGRITY_WATCHDOG = True
INTEGRITY_WATCHDOG_STARTED = False
SYSLOCK_TIMING = float()

class WatchdogViolationError(Exception):
    pass

def run_integrity_check():
    from pydepguardnext.api.errors import PyDepIntegrityError
    from pydepguardnext.bootstrap import clock

    fingerprint = IntegrityFingerprint()
    mismatches = []

    for label, _ in fingerprint.get_ids().items():
        if label == "id_sha256_digest" or label == "sealed_on":
            continue
        module_path = label.split(".")
        try:
            mod = __import__(".".join(module_path[:-1]), fromlist=[module_path[-1]])
            target = getattr(mod, module_path[-1])
            if not fingerprint.matches(target, label):
                mismatches.append(label)
        except Exception:
            mismatches.append(label)

    if mismatches:
        current_digest = fingerprint.get_digest()
        expected_digest = fingerprint.get_ids().get("id_sha256_digest", "missing")

        if getenv("PYDEP_HARDENED", "0") == "1":
            raise PyDepIntegrityError("Failed integrity check. Expected digest does not match current state.") from None
        elif getenv("PYDEP_DISABLE_INTEGRITY_CHECK", "0") != "1":
            for label in mismatches:
                print(f"[{clock.timestamp()}] [INTEGRITY] [BROKEN] Function {label} does not match frozen fingerprint.")
            print(f"[{clock.timestamp()}] [INTEGRITY] Digest mismatch. Expected: {expected_digest}, Found: {current_digest}")
            print(f"[{clock.timestamp()}] [INTEGRITY] This is not a hardened environment. Continuing anyway.")
    else:
        return time() - clock._GLOBAL_CLOCK["T0"]