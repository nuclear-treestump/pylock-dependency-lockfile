from json import dumps
from hashlib import sha256
from os import getenv
from time import time, sleep
from sys import exit
from types import MappingProxyType

INTEGRITY_CHECK = {}
INTEGRITY_UUID = {}
INTEGRITY_WATCHDOG = True
INTEGRITY_CHECK_DIGEST = {}
INTEGRITY_CHECK_FROZEN = False
INTEGRITY_UUID_FROZEN = False
INTEGRITY_WATCHDOG_STARTED = False
SYSLOCK_TIMING = float()



class WatchdogViolationError(Exception):
    pass

def jit_check(check_uuid=None):
    # Here's where the bullshit begins...
    from pydepguardnext import _total_global_time, get_gtime
    from time import time
    _syslock = time() - _total_global_time
    """
    Perform JIT function ID capture and freeze the INTEGRITY_CHECK.
    """
    from pydepguardnext.api.runtime.importer import _patched_import, _patched_importlib_import_module, AutoInstallFinder
    from pydepguardnext.api.log.logit import logit
    from pydepguardnext.api.runtime.airjail import maximum_security, disable_socket_access, disable_file_write, disable_network_access, disable_urllib_requests, block_ctypes, enable_sandbox_open, patch_environment_to_venv, prepare_fakeroot
    # Most people have never even heard of MappingProxyType, let alone its dark secrets.
    # This is a type that creates a read-only view of a dictionary, allowing us to "freeze" the integrity check.
    # This ensure that once my JIT function IDs are captured, they cannot be tampered with.
    # This creates an immutable snapshot of the current state of the integrity check.
    # Then, I hash that digest and store it in INTEGRITY_CHECK_DIGEST.
    # This blocks monkeypatching for these functions and classes, ensuring that any changes to them will be detected.
    # If in HARDENED mode, this will raise a PyDepBullshitDetectionError if the integrity check fails.
    global INTEGRITY_CHECK, INTEGRITY_CHECK_DIGEST, INTEGRITY_CHECK_FROZEN, INTEGRITY_UUID, INTEGRITY_UUID_FROZEN, SYSLOCK_TIMING
    INTEGRITY_UUID.update({"global_.uuid": str(check_uuid)})
    INTEGRITY_CHECK.update({
        "importer._patched_import": id(_patched_import),
        "importer._patched_importlib_import_module": id(_patched_importlib_import_module),
        "importer.AutoInstallFinder": id(AutoInstallFinder),
        "logit.logit": id(logit),
        "airjail.maximum_security": id(maximum_security),
        "airjail.disable_socket_access": id(disable_socket_access),
        "airjail.disable_file_write": id(disable_file_write),
        "airjail.disable_network_access": id(disable_network_access),
        "airjail.disable_urllib_requests": id(disable_urllib_requests),
        "airjail.block_ctypes": id(block_ctypes),
        "airjail.enable_sandbox_open": id(enable_sandbox_open),
        "airjail.patch_environment_to_venv": id(patch_environment_to_venv),
        "airjail.prepare_fakeroot": id(prepare_fakeroot),
        "api.runtime.integrity.run_integrity_check": id(run_integrity_check),
        "api.runtime.integrity.jit_check": id(jit_check),
        "api.runtime.integrity.get_rpng_check": id(get_rpng_check),
        "api.runtime.integrity._background_integrity_patrol": id(_background_integrity_patrol),
        "api.runtime.integrity._background_rpng_check": id(_background_rpng_check),
        "api.runtime.integrity.start_patrol": id(start_patrol),
        "global_.jit_check_uuid": INTEGRITY_UUID.get("global_.uuid", None),
    })

    digest = sha256(dumps(INTEGRITY_CHECK, sort_keys=True).encode("utf-8")).hexdigest()
    INTEGRITY_CHECK_DIGEST = {"sha256digest": digest}
    INTEGRITY_CHECK_DIGEST = MappingProxyType(INTEGRITY_CHECK_DIGEST)
    INTEGRITY_CHECK = MappingProxyType(INTEGRITY_CHECK)
    INTEGRITY_UUID = MappingProxyType(INTEGRITY_UUID)
    SYSLOCK_TIMING = time() - _total_global_time
    print(f"[{get_gtime()}] [INTEGRITY] [api.runtime.integrity] [{INTEGRITY_CHECK['global_.jit_check_uuid']}] Absolute last moment of system not sealed at global time:  {time() - _total_global_time:.4f} seconds.")
    print(f"[{get_gtime()}] [INTEGRITY] [api.runtime.integrity] [{INTEGRITY_CHECK['global_.jit_check_uuid']}] Runtime sealed in {SYSLOCK_TIMING - _syslock:.6f} seconds.")
    # And this is the point where tampering with PyDepGuardNext's integrity check becomes impossible.
    # Once this is called, the integrity check is frozen and cannot be modified.
    # This happens in 0.001 seconds from invocation to completion. 
    # If you're going to try to beat the speedrun, be aware that this is 150x faster than the average human reaction time.
    # So good luck with that.
    INTEGRITY_CHECK_FROZEN = True
    INTEGRITY_UUID_FROZEN = True

    return INTEGRITY_CHECK


   


def get_rpng_check():
    import random
    from pydepguardnext import _total_global_time, get_gtime
    random_bytes_check = list()
    count = 10
    while count > 0:
        random_bytes = random.getrandbits(128).to_bytes(16, 'big')
        random_bytes_check.append(random_bytes)
        count -= 1
    bytes_check_set = set(random_bytes_check)
    if len(bytes_check_set) != len(random_bytes_check):
        print(f"[{get_gtime()}] [INTEGRITY] [api.runtime.integrity]  [{INTEGRITY_CHECK['global_.jit_check_uuid']}] Random integer check failed! Integers are not unique.")
        print(f"[{get_gtime()}] [INTEGRITY] [api.runtime.integrity]  [{INTEGRITY_CHECK['global_.jit_check_uuid']}] RUNTIME COMPROMISED!")
        raise WatchdogViolationError("Random integer check failed! Integers are not unique.") from None


def _background_rpng_check():
    import random
    from pydepguardnext import _total_global_time, get_gtime
    while True:
        interval = random.randint(10, 30)
        sleep(interval)
        try:
            if getenv("PYDEP_DISABLE_INTEGRITY_CHECK", "0") == "1" and getenv("PYDEP_HARDENED", "0") != "1": # Once again, two separate checks required.
                # If integrity checks are disabled, we do not run the integrity check. This shortcircuits the patrol.
                print("[INTEGRITY] [api.runtime.integrity] Integrity checks are disabled by environment variable.")
                return
            else:
                get_rpng_check()
                print(f"[{get_gtime()}] [INTEGRITY] [api.runtime.integrity] [{INTEGRITY_CHECK['global_.jit_check_uuid']}] Rolling some dice...")
        except Exception as e:
            raise WatchdogViolationError(f"Random integrity check failed: {e}") from None # This is a serious error, we should not continue if this happens.



def _background_integrity_patrol():
    # Let loose the dogs of war.
    from random import uniform
    from pydepguardnext import _total_global_time, get_gtime
    while True:
        interval = uniform(10, 30)
        sleep(interval)
        try:
            response = ""
            if getenv("PYDEP_DISABLE_INTEGRITY_CHECK", "0") == "1" and getenv("PYDEP_HARDENED", "0") != "1": # Once again, two separate checks required.
                # If integrity checks are disabled, we do not run the integrity check. This shortcircuits the patrol.
                print(f"[{get_gtime()}] [INTEGRITY] [api.runtime.integrity] [{INTEGRITY_CHECK['global_.jit_check_uuid']}] Integrity checks are disabled by environment variable.")
                return
            if getenv("PYDEP_I_HATE_FUN", "0") == "1": # If the user hates fun, we run the integrity check with no fun messages.
                response = "Validating runtime integrity check..."
                run_integrity_check()
                print(f"[{get_gtime()}] [INTEGRITY] [api.runtime.integrity] [{INTEGRITY_CHECK['global_.jit_check_uuid']}] {response}")
            else:
                resp = uniform(1,5)
                resp_list = [
                    "Papers please...",
                    "ID! Now!",
                    "Show me papers!",
                    "Your papers, please!",
                    "Validating we are still a snake and not coffee...",
                ]
                response = resp_list[int(resp)]
                run_integrity_check()
                print(f"[{get_gtime()}] [INTEGRITY] [api.runtime.integrity] [{INTEGRITY_CHECK['global_.jit_check_uuid']}] {(response)}")
                # This was a planned feature but I can't currently ... test it. PyDepGuardNext's BSD goes off.
                #if gettrace() is not None:
                #    print("[INTEGRITY] [pydepguard] Active trace detected! This may indicate a debugger or runtime hook.")
                #    from os import getenv
                #    from sys import exit
                #    if getenv("PYDEP_FORBID_TRACE", "0") == "1":
                #        print("[INTEGRITY] [pydepguard] Tracing is forbidden in this environment. Terminating...")
                #        exit(98)
        except Exception as e:
            raise WatchdogViolationError(f"Background check error: {e}") from None

def start_patrol():
    # This actually starts the background integrity patrol.
    # It runs in a separate thread and checks the integrity of the runtime every 10-30 seconds.
    from pydepguardnext import _total_global_time, get_gtime
    from threading import Thread
    from datetime import datetime, timezone
    import random
    integrity_thread1 = Thread(target=_background_integrity_patrol, daemon=True)
    integrity_thread1.name = ("IntegrityPatrolThread" + random.randbytes(16).hex())
    integrity_thread2 = Thread(target=_background_integrity_patrol, daemon=True)
    integrity_thread2.name = ("IntegrityPatrolThread" + random.randbytes(16).hex())
    integrity_thread3 = Thread(target=_background_integrity_patrol, daemon=True)
    integrity_thread3.name = ("IntegrityPatrolThread" + random.randbytes(16).hex())
    integrity_thread4 = Thread(target=_background_integrity_patrol, daemon=True)
    integrity_thread4.name = ("IntegrityPatrolThread" + random.randbytes(16).hex())
    random_check_thread = Thread(target=_background_rpng_check, daemon=True)
    random_check_thread.name = ("RandomCheckThread" + random.randbytes(16).hex())
    integrity_thread1.start()
    integrity_thread2.start()
    integrity_thread3.start()
    integrity_thread4.start()
    random_check_thread.start()
    global INTEGRITY_WATCHDOG_STARTED, INTEGRITY_WATCHDOG
    INTEGRITY_WATCHDOG_STARTED = True
    # Hey look, another MappingProxyType. Yet another thing you can't break.
    INTEGRITY_WATCHDOG = MappingProxyType({
        "started": INTEGRITY_WATCHDOG_STARTED,
        "thread": [integrity_thread1, integrity_thread2, integrity_thread3, integrity_thread4],
        "uuid": INTEGRITY_UUID.get("global_.uuid", None),
        "started_at_timestamp": datetime.now(timezone.utc).isoformat(),
        "rpng_check_thread": random_check_thread,
        "rpng_check_started_at_timestamp": datetime.now(timezone.utc).isoformat(),
        "watchdog_modules": {_background_rpng_check.__name__, _background_integrity_patrol.__name__}
    })
    watchdogtime = time() - _total_global_time
    print(f"[{get_gtime()}] [INTEGRITY] [api.runtime.integrity] [{INTEGRITY_WATCHDOG['uuid']}] Background integrity patrol started at {INTEGRITY_WATCHDOG['started_at_timestamp']} (Global time: {watchdogtime:.4f} seconds). Timedelta from JIT lock to watchdog activation: {watchdogtime - SYSLOCK_TIMING:.6f} seconds.")
    print(f"[{get_gtime()}] [INTEGRITY] [api.runtime.integrity] [{INTEGRITY_WATCHDOG['uuid']}] WATCHDOG PROVISIONED: {INTEGRITY_WATCHDOG['watchdog_modules']}")
    print(f"[{get_gtime()}] [INTEGRITY] [api.runtime.integrity] [{INTEGRITY_WATCHDOG['uuid']}] WATCHDOG THREADS: {INTEGRITY_WATCHDOG['thread']}")


def run_integrity_check():
    # Now we check our work.

    """
    Recalculate and compare ID hash to detect tampering.
    Raises PyDepBullshitDetectionError if modified.
    """
    from pydepguardnext.api.runtime.importer import _patched_import, _patched_importlib_import_module, AutoInstallFinder
    from pydepguardnext.api.log.logit import logit
    from pydepguardnext.api.runtime.airjail import maximum_security, disable_socket_access, disable_file_write, disable_network_access, disable_urllib_requests, block_ctypes, enable_sandbox_open, patch_environment_to_venv, prepare_fakeroot
    from pydepguardnext import PyDepBullshitDetectionError, _total_global_time, get_gtime
    # Snapshot of current state of the integrity check.
    # This gets hashed and compared to the original integrity check.
    # If they differ, we raise a PyDepBullshitDetectionError.
    current_snapshot = {
        "importer._patched_import": id(_patched_import),
        "importer._patched_importlib_import_module": id(_patched_importlib_import_module),
        "importer.AutoInstallFinder": id(AutoInstallFinder),
        "logit.logit": id(logit),
        "airjail.maximum_security": id(maximum_security),
        "airjail.disable_socket_access": id(disable_socket_access),
        "airjail.disable_file_write": id(disable_file_write),
        "airjail.disable_network_access": id(disable_network_access),
        "airjail.disable_urllib_requests": id(disable_urllib_requests),
        "airjail.block_ctypes": id(block_ctypes),
        "airjail.enable_sandbox_open": id(enable_sandbox_open),
        "airjail.patch_environment_to_venv": id(patch_environment_to_venv),
        "airjail.prepare_fakeroot": id(prepare_fakeroot),
        "api.runtime.integrity.run_integrity_check": id(run_integrity_check),
        "api.runtime.integrity.jit_check": id(jit_check),
        "api.runtime.integrity.get_rpng_check": id(get_rpng_check),
        "api.runtime.integrity._background_integrity_patrol": id(_background_integrity_patrol),
        "api.runtime.integrity._background_rpng_check": id(_background_rpng_check),
        "api.runtime.integrity.start_patrol": id(start_patrol),
        "global_.jit_check_uuid": INTEGRITY_UUID.get("global_.uuid", None),
    }

    current_digest = sha256(
        dumps(current_snapshot, sort_keys=True).encode("utf-8")
    ).hexdigest()

    if current_digest != INTEGRITY_CHECK_DIGEST["sha256digest"] and getenv("PYDEP_HARDENED", "0") == "1":
        raise PyDepBullshitDetectionError(
            expected=INTEGRITY_CHECK_DIGEST["sha256digest"],
            found=current_digest
        ) from None # No trace for you
    elif current_digest != INTEGRITY_CHECK_DIGEST["sha256digest"] and getenv("PYDEP_HARDENED", "0") != "1" and getenv("PYDEP_DISABLE_INTEGRITY_CHECK", "0") != "1": # Two separate checks required. This is an 'and', not an 'or'.
        # If we are not in hardened mode, we log the integrity check failure but do not raise an error.
        # This allows the program to continue running, but we log the integrity check failure.
        broken_values = []
        for key, value in current_snapshot.items():
            if key in INTEGRITY_CHECK:
                if value != INTEGRITY_CHECK[key]:
                    broken_values.append((key, value))
        for key, value in broken_values:
            print(f"[{get_gtime()}] [INTEGRITY] [api.runtime.integrity] [{current_snapshot['global_.jit_check_uuid']}] [BROKEN INTEGRITY] {key}: {value}")
        print(f"[{get_gtime()}] [INTEGRITY] [api.runtime.integrity] [{current_snapshot['global_.jit_check_uuid']}] [BROKEN INTEGRITY] ⚠ Integrity hash check failed! Expected: {INTEGRITY_CHECK_DIGEST}, Found: {current_digest}")
        print(f"[{get_gtime()}] [INTEGRITY] [api.runtime.integrity] [{current_snapshot['global_.jit_check_uuid']}] [BROKEN INTEGRITY] ⚠ This is not a hardened environment, continuing without raising an error.")
    else:
        return time() - _total_global_time  # Return the time it took to run the integrity check