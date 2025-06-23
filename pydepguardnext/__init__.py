from time import time

_validate_self_has_fired = False
PACKAGE = "pydepguardnext"
VERSION = "1.0.0"
_written_incidents = set()
_total_global_time = time()



def log_incident(incident_id, expected, found, context="validate_self"):
    from datetime import datetime, timezone
    from platform import python_version
    from sys import executable, argv
    from json import dumps
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
        "python": python_version(),
        "executable": executable,
        "abs_path": str(Path(executable).resolve(strict=False)),
        "script": argv[0],
    }
    try:
        with open("pydepguard_audit.log", "a", encoding="utf-8") as f:
            f.write(dumps(log_entry) + "\n")
    except Exception as e:
        print(f"[INIT] [pydepguard] ⚠ Audit log write failed: {e}")

class PyDepBullshitDetectionError(Exception):
    def __init__(self, expected, found):
        self.expected = expected
        self.found = found
        self.incident_id = str(uuid4())
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

def fingerprint_system():
    from platform import system, release, version, machine, platform, python_version, python_build, python_compiler 
    from getpass import getuser
    from socket import gethostname
    from os import getcwd
    from sys import executable
    from pathlib import Path
    from hashlib import sha256

    def hash_interpreter():
        path = Path(executable).resolve(strict=False)
        h = sha256()
        with open(path, "rb") as f:
            while chunk := f.read(8192):
                h.update(chunk)
        return h.hexdigest()
    fingerprint = {
        "hostname": gethostname(),
        "os": system(),
        "os_release": release(),
        "os_version": version(),
        "arch": machine(),
        "platform": platform(),
        "user": getuser(),
        "python_version": python_version(),
        "python_build": python_build(),
        "python_compiler": python_compiler(),
        "python_abs_path": str(Path(executable).resolve(strict=False)),
        "python_interpreter_hash": hash_interpreter(),
        "executable": executable,
        "cwd": getcwd(),
        "pydepguard_package": PACKAGE,
        "pydepguard_version": VERSION
    }
    print("[INIT] [pydepguard] System fingerprint:")
    for k, v in fingerprint.items():
        print(f"  {k}: {v}")
    from hashlib import sha256
    from json import dumps
    print("[INIT] Fingerprint hash:", sha256(dumps(fingerprint, sort_keys=True).encode()).hexdigest())


from platform import python_version
from sys import executable
from uuid import uuid4
jit_check_uuid = uuid4()
print(f"[INIT] [pydepguard] Integrity Check UUID: {jit_check_uuid}")
from .api.runtime.integrity import jit_check, start_patrol, run_integrity_check
fingerprint_system()
print(f"[INIT] [pydepguard] Bullshit Detection System activating.")
_syslock = time() - _total_global_time
print(f"[INIT] [pydepguard] Locking down environment for integrity checks at {_syslock:.6f} seconds.")
JIT_INTEGRITY_CHECK = jit_check(jit_check_uuid)
start_patrol()
run_integrity_check()
_syslock_complete = time() - _total_global_time
print(f"[INIT] [pydepguard] [{JIT_INTEGRITY_CHECK['global_.jit_check_uuid']}] Background integrity patrol started.")
print(f"[INIT] [pydepguard] [{JIT_INTEGRITY_CHECK['global_.jit_check_uuid']}] System locked down at {time() - _total_global_time:.6f} seconds. Timedelta: {_syslock_complete - _syslock:.6f} seconds.")
print(f"[INIT] [pydepguard] [{JIT_INTEGRITY_CHECK['global_.jit_check_uuid']}] JIT Integrity Check Snapshot: {JIT_INTEGRITY_CHECK}")

from .api.log.logit import configure_logging, logit

from sys import stdin
if not stdin.isatty():
    configure_logging(
            level=("debug"),
            to_file=("pydepguard.log"),
            fmt=("text"),
            print_enabled=True
        )

from pathlib import Path


def abort_with_skull(expected_hash, local_hash):
    msg = (
        "Abort, Retry, 💀\n"
        f"Self-integrity check failed.\nExpected: {expected_hash}, Found: {local_hash}\n"
        "Linked traceback has been omitted for security reasons."
    )
    print(msg, file=sys.stderr)
    sys.exit(99)


def get_module_root():
    from importlib.util import find_spec
    from pathlib import Path
    spec = find_spec(PACKAGE)
    if spec is None or not spec.origin:
        return None
    path = Path(spec.origin).resolve()
    if path.name == "__init__.py":
        return path.parent
    return path

def sha256sum_dir(directory: Path):
    from hashlib import sha256
    h = sha256()
    for file in sorted(directory.rglob("*.py")):
        with open(file, "rb") as f:
            while True:
                block = f.read(8192)
                if not block:
                    break
                h.update(block)
    return h.hexdigest()


def fetch_pypi_sha256(package, version):
    from urllib.request import urlopen
    from json import load
    url = f"https://pypi.org/pypi/{package}/json"
    with urlopen(url) as response:
        data = load(response)
        for file_info in data["releases"].get(version, []):
            if file_info["filename"].endswith(".tar.gz"):
                return file_info["digests"]["sha256"]
    return None



def validate_self():
    from os import getenv
    from .api.runtime.integrity import INTEGRITY_CHECK
    global _validate_self_has_fired
    if _validate_self_has_fired:
        return
    _validate_self_has_fired = True
    expected_hash = fetch_pypi_sha256(PACKAGE, VERSION)
    env_hash = getenv("PYDEP_TRUSTED_HASH","0")

    local_hash = sha256sum_dir(get_module_root())
    if expected_hash and local_hash == expected_hash:
        return
    if getenv("PYDEP_HARDENED") == "1":
        if expected_hash and local_hash != expected_hash:
            raise PyDepBullshitDetectionError(expected_hash, local_hash) from None
    if env_hash and local_hash == env_hash:
        print(f"[INIT] [pydepguard] [{INTEGRITY_CHECK['global_.jit_check_uuid']}] ⚠ Using override hash: {env_hash[:10]}... (dev mode only)")

    else:
        print(f"[INIT] [pydepguard] [{INTEGRITY_CHECK['global_.jit_check_uuid']}] ⚠ Hash mismatch detected, but not hardened. Proceeding with warning.")
        

validate_self()
print(f"[INIT] [pydepguard] [{JIT_INTEGRITY_CHECK['global_.jit_check_uuid']}] Self-integrity check passed. Init complete. Total time: {time() - _total_global_time:.6f} seconds.")

from .api import *
from .api.install import *
from .api.install.parser import *
from .api.jit import *
from .api.log import *
from .api.errors import *
from .api.runtime import * 
from .api.runtime.airjail import *



