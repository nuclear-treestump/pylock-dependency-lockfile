from threading import gettrace


INTEGRITY_CHECK = {}
INTEGRITY_UUID = {}
INTEGRITY_WATCHDOG = True
INTEGRITY_CHECK_DIGEST = ""
INTEGRITY_CHECK_FROZEN = False
INTEGRITY_UUID_FROZEN = False
INTEGRITY_WATCHDOG_STARTED = False

def jit_check(check_uuid=None):
    """
    Perform JIT function ID capture and freeze the INTEGRITY_CHECK.
    """
    from pydepguardnext.api.runtime.importer import _patched_import, _patched_importlib_import_module, AutoInstallFinder
    from pydepguardnext.api.log.logit import logit
    from pydepguardnext.api.runtime.airjail import maximum_security, disable_socket_access, disable_file_write, disable_network_access, disable_urllib_requests, block_ctypes, enable_sandbox_open, patch_environment_to_venv, prepare_fakeroot
    from json import dumps
    from hashlib import sha256
    from types import MappingProxyType
    global INTEGRITY_CHECK, INTEGRITY_CHECK_DIGEST, INTEGRITY_CHECK_FROZEN, INTEGRITY_UUID, INTEGRITY_UUID_FROZEN
    INTEGRITY_UUID.update({"global_.uuid": str(check_uuid)})
    INTEGRITY_CHECK.update({
        "importer._patched_import": id(_patched_import),
        "importer._patched_importlib_import_module": id(_patched_importlib_import_module),
        "importer.AutoInstallFinder": id(AutoInstallFinder),
        "airjail.maximum_security": id(maximum_security),
        "airjail.disable_socket_access": id(disable_socket_access),
        "airjail.disable_file_write": id(disable_file_write),
        "airjail.disable_network_access": id(disable_network_access),
        "airjail.disable_urllib_requests": id(disable_urllib_requests),
        "airjail.block_ctypes": id(block_ctypes),
        "airjail.enable_sandbox_open": id(enable_sandbox_open),
        "airjail.patch_environment_to_venv": id(patch_environment_to_venv),
        "airjail.prepare_fakeroot": id(prepare_fakeroot),
        "logit.logit": id(logit),
        "global_.jit_check_uuid": INTEGRITY_UUID["global_.uuid"],
    })

    digest = sha256(
        dumps(INTEGRITY_CHECK, sort_keys=True).encode("utf-8")
    ).hexdigest()
    INTEGRITY_CHECK_DIGEST = digest
    INTEGRITY_CHECK = MappingProxyType(INTEGRITY_CHECK)
    INTEGRITY_UUID = MappingProxyType(INTEGRITY_UUID)
    INTEGRITY_CHECK_FROZEN = True
    INTEGRITY_UUID_FROZEN = True

    return INTEGRITY_CHECK


def run_integrity_check():
    """
    Recalculate and compare ID hash to detect tampering.
    Raises PyDepBullshitDetectionError if modified.
    """
    from pydepguardnext.api.runtime.importer import _patched_import, _patched_importlib_import_module, AutoInstallFinder
    from pydepguardnext.api.log.logit import logit
    from pydepguardnext.api.runtime.airjail import maximum_security, disable_socket_access, disable_file_write, disable_network_access, disable_urllib_requests, block_ctypes, enable_sandbox_open, patch_environment_to_venv, prepare_fakeroot
    from pydepguardnext import PyDepBullshitDetectionError
    from os import getenv
    from json import dumps
    from hashlib import sha256
    from types import MappingProxyType

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
        "global_.jit_check_uuid": INTEGRITY_UUID.get("global_.uuid", None),

    }

    current_digest = sha256(
        dumps(current_snapshot, sort_keys=True).encode("utf-8")
    ).hexdigest()

    if current_digest != INTEGRITY_CHECK_DIGEST and getenv("PYDEP_HARDENED", "0") == "1":
        raise PyDepBullshitDetectionError(
            expected=INTEGRITY_CHECK_DIGEST,
            found=current_digest
        )
    elif current_digest != INTEGRITY_CHECK_DIGEST and getenv("PYDEP_HARDENED", "0") != "1" and getenv("PYDEP_DISABLE_INTEGRITY_CHECK", "0") != "1":
        broken_values = []
        for key, value in current_snapshot.items():
            if key in INTEGRITY_CHECK:
                if value != INTEGRITY_CHECK[key]:
                    broken_values.append((key, value))
        for key, value in broken_values:
            print(f"[INTEGRITY] [api.runtime.integrity] [{current_snapshot['global_.jit_check_uuid']}] [BROKEN INTEGRITY] {key}: {value}")
        print(f"[INTEGRITY] [api.runtime.integrity] [{current_snapshot['global_.jit_check_uuid']}] [BROKEN INTEGRITY] ⚠ Integrity hash check failed! Expected: {INTEGRITY_CHECK_DIGEST}, Found: {current_digest}")
        print(f"[INTEGRITY] [api.runtime.integrity] [{current_snapshot['global_.jit_check_uuid']}] [BROKEN INTEGRITY] ⚠ This is not a hardened environment, continuing without raising an error.")        



def _background_integrity_patrol():
    from random import uniform
    from time import sleep
    from sys import exit
    from os import getenv
    while True:
        interval = uniform(10, 30)
        sleep(interval)
        try:
            response = ""
            if getenv("PYDEP_DISABLE_INTEGRITY_CHECK", "0") == "1" and getenv("PYDEP_HARDENED", "0") != "1":
                print("[INTEGRITY] [api.runtime.integrity] Integrity checks are disabled by environment variable.")
                return
            if getenv("PYDEP_I_HATE_FUN", "0") == "1":
                response = "Validating runtime integrity check..."
                run_integrity_check()
                print(f"[INTEGRITY] [api.runtime.integrity] {(response)}")
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
                print(f"[INTEGRITY] [api.runtime.integrity] {(response)}")
                #if gettrace() is not None:
                #    print("[INTEGRITY] [pydepguard] Active trace detected! This may indicate a debugger or runtime hook.")
                #    from os import getenv
                #    from sys import exit
                #    if getenv("PYDEP_FORBID_TRACE", "0") == "1":
                #        print("[INTEGRITY] [pydepguard] Tracing is forbidden in this environment. Terminating...")
                #        exit(98)
        except Exception as e:
            print(f"[INTEGRITY] [api.runtime.integrity] ⚠ Background check error: {e}")
            exit(99)

def start_patrol():
    from threading import Thread
    from types import MappingProxyType
    from datetime import datetime, timezone
    t = Thread(target=_background_integrity_patrol, daemon=True)
    t.start()
    global INTEGRITY_WATCHDOG_STARTED, INTEGRITY_WATCHDOG
    INTEGRITY_WATCHDOG_STARTED = True
    INTEGRITY_WATCHDOG = MappingProxyType({
        "started": INTEGRITY_WATCHDOG_STARTED,
        "thread": t,
        "uuid": INTEGRITY_UUID.get("global_.uuid", None),
        "started_at_timestamp": datetime.now(timezone.utc).isoformat(),
    })
    print(f"[INTEGRITY] [api.runtime.integrity] [{INTEGRITY_WATCHDOG['uuid']}] Background integrity patrol started at {INTEGRITY_WATCHDOG['started_at_timestamp']}")