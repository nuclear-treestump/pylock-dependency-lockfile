# pydepguardnext/bootstrap/boot.py
from pydepguardnext.bootstrap.modes import RUNTIME_MODE, RuntimeConfig, BootMode
from .envflags import detect_flags_and_mode
from .timebox import apply_global_timebox_and_tag
from .clock import now, timestamp, since_boot
from .get_uuid import get_uuid
from .function_registry import seal_runtime_ids
from .verify_signature import verify_signature
from .fingerprint import generate_system_fingerprint
from .bootwall import render_boot_wall
from .api_gate import enforce_api_gate
from .state import freeze_dict
from .self import validate_self
from hashlib import sha256
from .state import mark_boot_complete, has_boot_run, PACKAGE, VERSION, RUNTIME_DETAILS, RUNTIME_IDS, WATCHDOG_DETAILS, FUNC_ID_BUNDLE
from .boot_patrol import start_patrol
from json import dumps
import sys
from io import StringIO

_capture_buffer = StringIO()
_capture_enabled = False

def _start_capture():
    global _capture_enabled
    _capture_enabled = True
    sys.stdout = _capture_buffer

def _stop_capture():
    global _capture_enabled
    sys.stdout = sys.__stdout__
    _capture_enabled = False

def _get_capture():
    return _capture_buffer.getvalue().splitlines()

JIT_DATA_BUNDLE = {
    "boot_mode": None,
    "jit_check_uuid": None,
    "global_time": None,
    "since_boot": None,
    "timestamp": None,
    "sealed_time": None,
    "id_sha256_digest": None,
    "id_composite_digest": None,
    "sys_fingerprint": None,
    "sys_fingerprint_digest": None,
    "signature_total": 0,
    "signature_signed": 0,
}

JIT_ID_BUNDLE = {}

JIT_SIGNATURE_BUNDLE = {}

def run_boot(bootmode="secure"):
    if bootmode == "standalone":
        from os import environ
        environ["PYDEP_STANDALONE_NOSEC"] = "1"
        mode = detect_flags_and_mode(override=True, override_key="standalone")
        return
    if has_boot_run():
        print("[BOOT] Boot already completed. Skipping.")
        return
    mark_boot_complete()
    _start_capture()
    mode = detect_flags_and_mode()
    jit_uuid = get_uuid()
    global JIT_DATA_BUNDLE, JIT_ID_BUNDLE, JIT_SIGNATURE_BUNDLE, RUNTIME_DETAILS, RUNTIME_IDS, WATCHDOG_DETAILS, FUNC_ID_BUNDLE
    JIT_DATA_BUNDLE = {
        "boot_mode": mode.mode,
        "jit_check_uuid": jit_uuid,
        "global_time": now(),
        "since_boot": since_boot(),
        "timestamp": timestamp(),
    }

    if mode.mode == BootMode.LIGHT or mode.mode == BootMode.STANDALONE:
        print("[BOOT] Light mode requested. Skipping full seal.")
        return

    if mode.mode == BootMode.SECURE or mode.mode == BootMode.CHILD:
        print(f"[BOOT] Secure mode detected: {mode.mode}.")
        pass

    # MANIFEST_DATA = 
    ID_DATA = seal_runtime_ids()
    FUNC_ID_BUNDLE = ID_DATA  # Copy IDs for later use
    data = ID_DATA.copy()  # Copy IDs for later use
    composite_id = sha256(dumps(data, sort_keys=True).encode("utf-8")).hexdigest() # Freeze IDs post-wrap
    apply_global_timebox_and_tag() # Wrap early
    signature_data, total_signed, total_failed = verify_signature(jit_uuid)# SIGSTORE check
    signed = total_signed - total_failed
    JIT_DATA_BUNDLE["signature_total"] = total_signed
    JIT_DATA_BUNDLE["signature_signed"] = signed
    status, local_hash, expected_hash = validate_self(JIT_DATA_BUNDLE) # Validate self integrity
    JIT_ID_BUNDLE = ID_DATA  # Freeze IDs post-wrap
    RUNTIME_IDS = freeze_dict(data)
    JIT_SIGNATURE_BUNDLE = freeze_dict(signature_data)
    enforce_api_gate()  # Gate API exposure based on mode
    fingerprint, fingerprinthash = generate_system_fingerprint() # Generate system fingerprint
    JIT_DATA_BUNDLE["sys_fingerprint"] = fingerprint
    JIT_DATA_BUNDLE["sys_fingerprint_digest"] = fingerprinthash
    JIT_DATA_BUNDLE["id_sha256_digest"] = ID_DATA["id_sha256_digest"]
    JIT_DATA_BUNDLE["id_composite_digest"] = composite_id
    JIT_DATA_BUNDLE["sealed_time"] = now()
    from copy import deepcopy
    RUNTIME_DETAILS = deepcopy(JIT_DATA_BUNDLE)  # Store runtime details for later use outside boot.py
    RUNTIME_DETAILS = freeze_dict(RUNTIME_DETAILS)  # Freeze runtime details for immutability  
    JIT_DATA_BUNDLE = freeze_dict(JIT_DATA_BUNDLE) 

    FUNC_ID_BUNDLE = freeze_dict(ID_DATA)  # Freeze function IDs for immutability
    watchdog_data = start_patrol()  # Start integrity patrol threads
    WATCHDOG_DETAILS = watchdog_data  # Freeze watchdog details for immutability
    boot_wall = render_boot_wall(fingerprint, fingerprinthash, JIT_DATA_BUNDLE, JIT_SIGNATURE_BUNDLE, status, PACKAGE, VERSION, local_hash, expected_hash, watchdog_data=watchdog_data) 
    print(boot_wall) # Render boot wall
    _stop_capture()
    captured_output = _get_capture()
    print("\n".join(captured_output))
