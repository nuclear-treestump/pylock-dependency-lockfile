from urllib.request import urlopen
from json import load
import socket
from os import getenv
from .fingerprint import get_module_root, sha256sum_dir
from pydepguardnext.bootstrap import clock
from pydepguardnext.bootstrap.state import PACKAGE, VERSION

_validate_self_has_fired = False

def fetch_pypi_sha256(package: str, version: str):
    try:
        socket.gethostbyname("pypi.org")
    except Exception as e:
        print(f"[INIT] [{clock.timestamp()}] [INSECURE] Network check failed: {e}")
        return "not_reachable", ""
    try:
        url = f"https://pypi.org/pypi/{package}/json"
        with urlopen(url) as response:
            data = load(response)
            for file_info in data["releases"].get(version, []):
                if file_info["filename"].endswith(".tar.gz"):
                    return "ok", file_info["digests"]["sha256"]
    except Exception as e:
        print(f"[INIT] [{clock.timestamp()}] [INSECURE] Fetch error: {e}")
        return "fetch_error", ""

def validate_self(jit_data: dict):
    global _validate_self_has_fired
    jit_check_uuid = jit_data.get("jit_check_uuid", "unknown")
    if _validate_self_has_fired:
        return
    _validate_self_has_fired = True

    code, expected_hash = fetch_pypi_sha256(PACKAGE, VERSION)
    offline = code in ("not_reachable", "fetch_error")

    local_hash = sha256sum_dir(get_module_root())
    env_hash = getenv("PYDEP_TRUSTED_HASH")

    if code == "ok":
        print(f"[INIT] [{clock.timestamp()}] [SECURE] [{jit_check_uuid}] Fetched expected hash from PyPI: {expected_hash[:10]}...")
    elif offline:
        print(f"[INIT] [{clock.timestamp()}] [INSECURE] [{jit_check_uuid}] PyPI unreachable. Skipping hash validation.")

    if expected_hash and local_hash == expected_hash:
        return
    if getenv("PYDEP_HARDENED") == "1" and expected_hash and local_hash != expected_hash:
        raise Exception("Hash mismatch")
    if env_hash and local_hash == env_hash:
        print(f"[INIT] [{clock.timestamp()}] [SECURE] [{jit_check_uuid}] Using override hash: {env_hash[:10]}... (dev mode only)")
    else:
        print(f"[INIT] [{clock.timestamp()}] [SECURE] [{jit_check_uuid}] Hash mismatch (non-hardened). Proceeding with warning.")