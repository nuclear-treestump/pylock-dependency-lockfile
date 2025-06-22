import sys
import json
import uuid
import platform
import time
from datetime import datetime, timezone

_validate_self_has_fired = False
PACKAGE = "pydepguardnext"
VERSION = "1.0.0"
_written_incidents = set()
_total_global_time = time.time()


def log_incident(incident_id, expected, found, context="validate_self"):
    if incident_id in _written_incidents:
        return
    _written_incidents.add(incident_id)

    log_entry = {
        "timestamp": datetime.now(timezone.utc).isoformat()+"Z",
        "incident": incident_id,
        "event": "tamper_detected",
        "package": "pydepguardnext",
        "expected_hash": expected,
        "found_hash": found,
        "python": platform.python_version(),
        "executable": sys.executable,
        "script": sys.argv[0],
    }
    try:
        with open("pydepguard_audit.log", "a", encoding="utf-8") as f:
            f.write(json.dumps(log_entry) + "\n")
    except Exception as e:
        print(f"[pydepguard] ⚠ Audit log write failed: {e}")

class PyDepBullshitDetectionError(Exception):
    def __init__(self, expected, found):
        self.expected = expected
        self.found = found
        self.incident_id = str(uuid.uuid4())
        super().__init__(self.__str__())

    def __str__(self):
        log_incident(self.incident_id, self.expected, self.found)
        return (
            "\n💀 PyDepBullshitDetectionError: Self-integrity check failed.\n"
            f"Expected: {self.expected}\n"
            f"Found: {self.found}\n"
            f"Incident ID: {self.incident_id}\n"
            "Linked traceback omitted intentionally."
        )
print(f"[pydepguard] Bullshit Detection System Initialized\n"
      f"Package: {PACKAGE}, Version: {VERSION}\n"
      f"Python: {platform.python_version()}, Executable: {sys.executable}\n")
jit_check_uuid = uuid.uuid4()
print(f"[pydepguard] Integrity Check UUID: {jit_check_uuid}\n")
from .api.runtime.integrity import jit_check, start_patrol

JIT_INTEGRITY_CHECK = jit_check(jit_check_uuid)
print(f"[pydepguard] [{JIT_INTEGRITY_CHECK['global_.jit_check_uuid']}] JIT Integrity Check Snapshot: {JIT_INTEGRITY_CHECK}\n")
print(JIT_INTEGRITY_CHECK)

start_patrol()

from .api.log.logit import configure_logging, logit


if not sys.stdin.isatty():
    configure_logging(
            level=("debug"),
            to_file=("pydepguard.log"),
            fmt=("text"),
            print_enabled=True
        )

from pathlib import Path

import hashlib
import urllib.request
import importlib.util
import os


def abort_with_skull(expected_hash, local_hash):
    msg = (
        "Abort, Retry, 💀\n"
        f"Self-integrity check failed.\nExpected: {expected_hash}, Found: {local_hash}\n"
        "Linked traceback has been omitted for security reasons."
    )
    print(msg, file=sys.stderr)
    sys.exit(99)


def get_module_root():
    spec = importlib.util.find_spec(PACKAGE)
    if spec is None or not spec.origin:
        return None
    path = Path(spec.origin).resolve()
    if path.name == "__init__.py":
        return path.parent
    return path

def sha256sum_dir(directory: Path):
    h = hashlib.sha256()
    for file in sorted(directory.rglob("*.py")):
        with open(file, "rb") as f:
            while True:
                block = f.read(8192)
                if not block:
                    break
                h.update(block)
    return h.hexdigest()


def fetch_pypi_sha256(package, version):
    url = f"https://pypi.org/pypi/{package}/json"
    with urllib.request.urlopen(url) as response:
        data = json.load(response)
        for file_info in data["releases"].get(version, []):
            if file_info["filename"].endswith(".tar.gz"):
                return file_info["digests"]["sha256"]
    return None


def validate_self():
    global _validate_self_has_fired
    if _validate_self_has_fired:
        return
    _validate_self_has_fired = True
    expected_hash = fetch_pypi_sha256(PACKAGE, VERSION)
    env_hash = os.getenv("PYDEP_TRUSTED_HASH")

    local_hash = sha256sum_dir(get_module_root())

    if expected_hash and local_hash == expected_hash:
        return

    # Stage 3: Final fallback (warn-only unless hardened)
    if os.getenv("PYDEP_HARDENED") == "1":
        if expected_hash and local_hash != expected_hash:
            raise PyDepBullshitDetectionError(expected_hash, local_hash) from None
    if env_hash and local_hash == env_hash:
        print(f"[pydepguard] [{INTEGRITY_CHECK['global_.jit_check_uuid']}] ⚠ Using override hash: {env_hash[:10]}... (dev mode only)")

    else:
        print(f"[pydepguard] [{INTEGRITY_CHECK['global_.jit_check_uuid']}] ⚠ Hash mismatch detected, but not hardened. Proceeding with warning.")



from .api import *
from .api.install import *
from .api.install.parser import *
from .api.jit import *
from .api.log import *
from .api.errors import *
from .api.runtime import * 



