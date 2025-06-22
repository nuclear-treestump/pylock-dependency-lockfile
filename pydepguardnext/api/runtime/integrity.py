import json
import hashlib
from types import MappingProxyType

INTEGRITY_CHECK = {}
INTEGRITY_UUID = {}
INTEGRITY_CHECK_DIGEST = ""
INTEGRITY_CHECK_FROZEN = False
INTEGRITY_UUID_FROZEN = False

def jit_check(check_uuid=None):
    """
    Perform JIT function ID capture and freeze the INTEGRITY_CHECK.
    """
    import importlib
    from . import importer
    global INTEGRITY_CHECK, INTEGRITY_CHECK_DIGEST, INTEGRITY_CHECK_FROZEN, INTEGRITY_UUID, INTEGRITY_UUID_FROZEN
    INTEGRITY_UUID.update({"global_.uuid": str(check_uuid)})
    INTEGRITY_CHECK.update({
        "importer._patched_import": id(importer._patched_import),
        "importer._patched_importlib_import_module": id(importer._patched_importlib_import_module),
        "importer.AutoInstallFinder": id(importer.AutoInstallFinder),
        "global_.jit_check_uuid": INTEGRITY_UUID["global_.uuid"],
    })

    digest = hashlib.sha256(
        json.dumps(INTEGRITY_CHECK, sort_keys=True).encode("utf-8")
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
    from . import importer
    from pydepguardnext import PyDepBullshitDetectionError

    current_snapshot = {
        "importer._patched_import": id(importer._patched_import),
        "importer._patched_importlib_import_module": id(importer._patched_importlib_import_module),
        "importer.AutoInstallFinder": id(importer.AutoInstallFinder),
        "global_.jit_check_uuid": INTEGRITY_UUID.get("global_.uuid", None),

    }

    current_digest = hashlib.sha256(
        json.dumps(current_snapshot, sort_keys=True).encode("utf-8")
    ).hexdigest()

    if current_digest != INTEGRITY_CHECK_DIGEST:
        raise PyDepBullshitDetectionError(
            expected=INTEGRITY_CHECK_DIGEST,
            found=current_digest
        )

import threading
import random
import time
import sys

def _background_integrity_patrol():
    while True:
        interval = random.uniform(10, 30)
        time.sleep(interval)
        try:
            print("[pydepguard] Papers please...")
            run_integrity_check()
        except Exception as e:
            print(f"[pydepguard] ⚠ Background check error: {e}")
            sys.exit(99)

def start_patrol():
    t = threading.Thread(target=_background_integrity_patrol, daemon=True)
    t.start()