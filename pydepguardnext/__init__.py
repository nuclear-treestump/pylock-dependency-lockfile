import time
# This is a self-integrity check for the PyDepGuardNext package.
# It ensures that the package has not been tampered with and is running in a secure environment
# I am aware of how much this looks like malware, but I assure you, it is not.
# This is a security feature to protect the package and its users.
# It does this by reading the hash of itself and the files, comparing it to the expected hash from PyPI.
# If the hashes do not match, it raises an error and logs the incident.
# Then it gets the id() of critical functions and modules to ensure they have not been tampered with.
# This is then saved in a MappingProxyType to prevent modification.
# From there, this makes using any of the critical functions or modules impossible if the integrity check fails.
# This entire process has the environmment locked down by 0.035 seconds total, with the earliest monkeypatch opportunity being right before the JIT integrity check.
# This window is 0.001 seconds. You are not going to outrun physics.
# If you are reading this, you are probably a security researcher or a curious user.
# If you don't believe me, you can check the source code on GitHub:
# https://github.com/nuclear-treestump/pylock-dependency-lockfile
# If you find any issues, please report them there.
# Thank you for your understanding and for using PyDepGuardNext!

from types import MappingProxyType
SIGSTORE_PUBKEY = MappingProxyType({
    "n": int("0x9bf8b66bdc4cf01fb6c7b69a52bdfba451da6337932ada7ba3df605c064eaf9d02b6ac891d6b334b266cb43b83678a057ef057a3a2adaf5adbec6df3ca7dc10f50e615ca99e5c1ca35a33b44e52457f165a63ca2b05b78ebd31307aa80776eed9d89aec4cff11d41a88c900a3f48c0236b524912904fda2ca47fd229ff9c19f90a1132cba3226156b42146e44eee697d763505f636b7bbb6c276731318f4d532efbcd5360ec0ca115d4d4cabcb6e824506640cfe59c8bd5a48feb0d6cf2bd297805dcffb3738d6caaad27b9ea500a59c2f891e29e6312ba695132bcd95c346a1542b15f6a64b099da0e86bb5cec2a3fd1fbf221c50126cc7159972884fe4034d", 16),
    "e": 65537
})

_validate_self_has_fired = False
PACKAGE = "pydepguardnext"
VERSION = "2.0.1"
_written_incidents = set()
_total_global_time = time.time()

import sys
import io

PRINT_CAPTURE = io.StringIO()

def start_capture():
    sys.stdout = PRINT_CAPTURE

def stop_capture():
    sys.stdout = sys.__stdout__

def get_capture_log():
    return PRINT_CAPTURE.getvalue().splitlines()

def get_gtime():
    gtime_calc = time.time() - _total_global_time
    return gtime_calc # This is the global time since the start of the package.

start_capture() 
# Start capturing print output to a StringIO object. This is because logit cannot be started before the integrity check is done, and we need to capture the output for logging later.
# Otherwise circular import hell.

def log_incident(incident_id, expected, found, context="validate_self"):
    # This function logs an incident of tampering detected in the package.
    # It writes a JSON entry to a log file with details about the incident.
    # This is used to track tampering attempts and provide information for debugging.
    # This does not have an HTTP loader, but if that's a feature you want, please open an issue on GitHub.
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
        # TODO: Add ENV control for audit log location
        with open("pydepguard_audit.log", "a", encoding="utf-8") as f:
            f.write(dumps(log_entry) + "\n")
    except Exception as e:
        print(f"[{get_gtime()}] [INIT] [pydepguard] ⚠ Audit log write failed: {e}")

class PyDepBullshitDetectionError(Exception):
    # This exception is raised when the self-integrity check fails.
    # It logs the incident and raises an error with details.
    # The incident ID is generated to track the issue.
    # This intentionally omits the traceback to prevent leaking sensitive information.
    # This only comes into play if the environment is hardened.
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

# This function fingerprints the system and logs the details, gathering as much information as possible
# The more items in the json, the more tripwires we have to detect tampering.
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
    print(f"[{get_gtime()}] [INIT] [pydepguard] System fingerprint:")
    for k, v in fingerprint.items():
        print(f"  {k}: {v}")
    from hashlib import sha256
    from json import dumps
    print(f"[{get_gtime()}] [INIT] Fingerprint hash:", sha256(dumps(fingerprint, sort_keys=True).encode()).hexdigest()) # I will be using this hash to verify the integrity of the environment later on.
    # TODO: Add more fingerprinting data, like installed packages, environment variables, etc. to INTEGRITY_CHECK


from platform import python_version
from sys import executable
from uuid import uuid4
jit_check_uuid = uuid4()
print(f"[{get_gtime()}] [INIT] [pydepguard] Integrity Check UUID: {jit_check_uuid}")
from .api.runtime.integrity import jit_check, start_patrol, run_integrity_check
fingerprint_system()
print(f"[{get_gtime()}] [INIT] [pydepguard] Bullshit Detection System activating.")
JIT_INTEGRITY_CHECK = jit_check(jit_check_uuid)
start_patrol()
print(f"[{get_gtime()}] [INIT] [pydepguard] [{JIT_INTEGRITY_CHECK['global_.jit_check_uuid']}] Background integrity patrol started.")
 # This is the time it took to run the first integrity check, which is the JIT integrity check.
print(f"[{get_gtime()}] [INIT] [pydepguard] [{JIT_INTEGRITY_CHECK['global_.jit_check_uuid']}] First check: {run_integrity_check():.6f} seconds. JIT Integrity Check Snapshot: {JIT_INTEGRITY_CHECK}")
print(f"[{get_gtime()}] [INIT] [pydepguard] [{JIT_INTEGRITY_CHECK['global_.jit_check_uuid']}] JIT Integrity Check complete. Starting SIGVERIFY Stage 2.")

from pydepguardnext.api.runtime.sigverify import validate_all_functions
import json

from pathlib import Path
from os import getenv
sigstore_path = Path(__file__).parent / ".sigstore"
if not sigstore_path.exists() and getenv("PYDEP_SKIP_SIGVER", "0") != "1":
    print(f"[{get_gtime()}] [INIT] [pydepguard] [{JIT_INTEGRITY_CHECK['global_.jit_check_uuid']}] WARNING: .sigstore not found at {sigstore_path}. Skipping signature validation.")
elif getenv("PYDEP_SKIP_SIGVER", "0") == "1":
    raise PyDepBullshitDetectionError(
        expected=".sigstore file missing",
        found="N/A"
    )
_sigtime = time.time()
res = validate_all_functions(sigstore_path=sigstore_path)
from pydepguardnext.api.runtime.sigverify import SIGVERIFIED
start_capture() # Start capturing print output again, now that the integrity check is done.
_fail_count = 0
_total_count = len(SIGVERIFIED)
for fqname, result in SIGVERIFIED.items():
    if not result["valid"]:
        print(f"[{get_gtime()}] [INIT] [pydepguard] [{JIT_INTEGRITY_CHECK['global_.jit_check_uuid']}] ERROR: Function {fqname} failed validation: {result.get('error', 'Unknown error')}")
        log_incident(fqname, result.get("expected", "N/A"), result.get("computed", "N/A"), context="validate_self")
        _fail_count += 1

print(f"[{get_gtime()}] [INIT] [pydepguard] [{JIT_INTEGRITY_CHECK['global_.jit_check_uuid']}] SIGVERIFY Stage 2 complete. {len(SIGVERIFIED)} of {_total_count - _fail_count} functions verified.")
_sigfrozen = time.time()
print(f"[{get_gtime()}] [INIT] [pydepguard] [{JIT_INTEGRITY_CHECK['global_.jit_check_uuid']}] SIGVERIFY frozen in {_sigfrozen - _sigtime:.6f} seconds.")


from .api.log.logit import configure_logging

# I delayed logging configuration to avoid circular imports and ensure the integrity check runs first.
# The time between moving from execution on __init__ to running the integrity check is sub <0.001 seconds, so this is not a performance issue.
# If you're an attacker, you'll have a bad time trying to outrun physics.

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
    # This was the first iteration of PyDepBullshitDetectionError
    msg = (
        "Abort, Retry, 💀\n"
        f"Self-integrity check failed.\nExpected: {expected_hash}, Found: {local_hash}\n"
        "Linked traceback has been omitted for security reasons."
    )
    print(msg, file=sys.stderr)
    sys.exit(99)


def get_module_root():
    # This function returns the root directory of the current package.
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
    # Hash all the things
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
    # Fetch the SHA256 hash of the package version from PyPI
    from urllib.request import urlopen
    from json import load
    url = f"https://pypi.org/pypi/{package}/json"
    with urlopen(url) as response:
        data = load(response)
        # TODO: Add try/except for network errors
        for file_info in data["releases"].get(version, []):
            if file_info["filename"].endswith(".tar.gz"):
                return file_info["digests"]["sha256"]
    return None



def validate_self():
    # This is where the self-integrity check is performed.
    from os import getenv
    from .api.runtime.integrity import INTEGRITY_CHECK
    global _validate_self_has_fired
    if _validate_self_has_fired:
        return
    _validate_self_has_fired = True
    expected_hash = fetch_pypi_sha256(PACKAGE, VERSION)
    env_hash = getenv("PYDEP_TRUSTED_HASH")

    local_hash = sha256sum_dir(get_module_root())
    if expected_hash and local_hash == expected_hash:
        return
    if getenv("PYDEP_HARDENED") == "1": # Hardened mode
        if expected_hash and local_hash != expected_hash:
            raise PyDepBullshitDetectionError(expected_hash, local_hash) from None # No trace for you
    if env_hash and local_hash == env_hash: # Dev mode override PYDEP_TRUSTED_HASH
        # This is a development mode override, allowing the user to run the package without a valid PyPI hash.
        # This is useful for development and testing, but should not be used in production.
        # Even if the hash matches, if you call this in hardened mode, it will still crash to BSD (Bullshit Detection Error).
        print(f"[{get_gtime()}] [INIT] [pydepguard] [{INTEGRITY_CHECK['global_.jit_check_uuid']}] ⚠ Using override hash: last 10: {env_hash[:10]}... (dev mode only)")

    else:
        print(f"[{get_gtime()}] [INIT] [pydepguard] [{INTEGRITY_CHECK['global_.jit_check_uuid']}] ⚠ Hash mismatch detected, but not hardened. Proceeding with warning.")


validate_self()
print(f"[{get_gtime()}] [INIT] [pydepguard] [{JIT_INTEGRITY_CHECK['global_.jit_check_uuid']}] Self-integrity check passed. Init complete. Total time: {time.time() - _total_global_time:.6f} seconds.") # Annnnnd TIME!

# Oh yeah, should probably import the API modules now that the integrity check is done.
# This is intended, if self-integrity check fails, the API modules will not be imported.
# You get nothing, you lose, good day sir! Or ma'am, idk

stop_capture() # Done with boot, now getting log output

_log = get_capture_log() # Get the captured log output

from .api import *
from .api.install import *
from .api.install.parser import *
from .api.jit import *
from .api.log import *
from .api.errors import *
from .api.runtime import * 
from .api.runtime.airjail import *



