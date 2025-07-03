from json import dumps
from hashlib import sha256
from os import getenv
from time import time, sleep
from sys import exit
from types import MappingProxyType
from datetime import datetime, timezone
from threading import Thread
import random

from pydepguardnext.bootstrap import clock
from pydepguardnext.bootstrap.function_registry import IntegrityFingerprint

INTEGRITY_WATCHDOG = True
INTEGRITY_WATCHDOG_STARTED = False

class WatchdogViolationError(Exception):
    pass

def get_prng_check():
    randints = [random.getrandbits(128) for _ in range(10)]
    if len(set(randints)) != 10:
        raise WatchdogViolationError("Random integer check failed! Integers are not unique.")

def _background_prng_check():
    while True:
        if getenv("PYDEP_DISABLE_INTEGRITY_CHECK", "0") == "1" and getenv("PYDEP_HARDENED", "0") != "1":
            print("[INTEGRITY] [PRNG] Skipped due to env override.")
            return
        sleep(random.randint(10, 30))
        try:
            get_prng_check()
            print(f"[{clock.timestamp()}] [INTEGRITY] [PRNG] Dice rolled clean.")
        except Exception as e:
            raise WatchdogViolationError(f"Random integrity check failed: {e}") from None

def _background_integrity_patrol():
    while True:
        if getenv("PYDEP_DISABLE_INTEGRITY_CHECK", "0") == "1" and getenv("PYDEP_HARDENED", "0") != "1":
            print(f"[{clock.timestamp()}] [INTEGRITY] [PATROL] Integrity checks are disabled.")
            return
        sleep(random.uniform(10, 30))
        try:
            phrases = [
                "Papers please...",
                "ID! Now!",
                "Show me papers!",
                "Your papers, please!",
                "Validating we are still a snake and not coffee...",
            ]
            message = random.choice(phrases)
            run_integrity_check()
            print(f"[{clock.timestamp()}] [INTEGRITY] [PATROL] {message}")
        except Exception as e:
            raise WatchdogViolationError(f"Background check error: {e}") from None

def start_patrol():
    global INTEGRITY_WATCHDOG_STARTED, INTEGRITY_WATCHDOG
    threads = [
        Thread(target=_background_integrity_patrol, daemon=True, name=f"IntegrityPatrolThread{i}")
        for i in range(4)
    ] + [
        Thread(target=_background_prng_check, daemon=True, name="RandomCheckThread")
    ]
    for t in threads:
        t.start()

    INTEGRITY_WATCHDOG_STARTED = True
    INTEGRITY_WATCHDOG = MappingProxyType({
        "started": True,
        "thread_names": [t.name for t in threads],
        "started_at_timestamp": datetime.now(timezone.utc).isoformat(),
        "watchdog_modules": ["_background_integrity_patrol", "_background_prng_check"]
    })
    print(f"[{clock.timestamp()}] [INTEGRITY] Watchdog threads launched: {INTEGRITY_WATCHDOG['thread_names']}")

def run_integrity_check():
    from pydepguardnext import PyDepBullshitDetectionError

    fingerprint = IntegrityFingerprint()
    mismatches = []

    for label, _ in fingerprint.get_ids().items():
        if label in {"id_sha256_digest", "sealed_on"}:
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
            raise PyDepBullshitDetectionError(
                expected=expected_digest,
                found=current_digest
            ) from None
        elif getenv("PYDEP_DISABLE_INTEGRITY_CHECK", "0") != "1":
            for label in mismatches:
                print(f"[{clock.timestamp()}] [INTEGRITY] [BROKEN] Function {label} does not match frozen fingerprint.")
            print(f"[{clock.timestamp()}] [INTEGRITY] Digest mismatch. Expected: {expected_digest}, Found: {current_digest}")
            print(f"[{clock.timestamp()}] [INTEGRITY] Continuing in non-hardened mode.")
    else:
        return time() - clock._GLOBAL_CLOCK["T0"]
