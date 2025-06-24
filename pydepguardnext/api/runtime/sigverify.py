import ast
import importlib
import inspect
import hashlib
import json
import types
from pathlib import Path
from pydepguardnext import SIGSTORE_PUBKEY, start_capture, stop_capture, PRINT_CAPTURE
from types import MappingProxyType

SIGVERIFY = {}
SIGVERIFIED = {}

def emsa_pkcs1_v1_5_encode(digest_bytes: bytes, n_bytes: int) -> bytes:
    sha256_prefix = bytes.fromhex("3031300d060960864801650304020105000420")
    t = sha256_prefix + digest_bytes
    padding_len = n_bytes - len(t) - 3
    if padding_len < 8:
        raise ValueError("Encoding error: insufficient padding space.")
    return b"\x00\x01" + b"\xff" * padding_len + b"\x00" + t


def validate_signature(digest_bytes: bytes, sig_int: int) -> bool:
    pubkey = SIGSTORE_PUBKEY
    n_bytes = (pubkey["n"].bit_length() + 7) // 8
    decrypted_bytes = pow(sig_int, pubkey["e"], pubkey["n"]).to_bytes(n_bytes, "big")
    expected_bytes = emsa_pkcs1_v1_5_encode(digest_bytes, n_bytes)
    return decrypted_bytes == expected_bytes


def compute_digest(func: types.FunctionType) -> bytes:
    """
    Compute the SHA256 digest of a function's bytecode and constants.
    """
    from marshal import dumps as marshal_dumps
    import inspect
    source = inspect.getsource(func)
    return hashlib.sha256(source.encode()).digest()



def validate_all_functions(sigstore_path: Path = None, _log: list = None) -> dict:
    global SIGVERIFY
    start_capture()
    """
    Validates all functions in the pydepguardnext package using .sigstore.
    Returns a dict of results for introspection or reporting.
    """
    import pydepguardnext

    results = {}
    base_path = Path(pydepguardnext.__file__).parent
    sigstore_path = sigstore_path or (base_path / ".sigstore")

    if not sigstore_path.exists():
        return {"error": "No .sigstore file found at the expected location."}

    with open(sigstore_path, "r", encoding="utf-8") as f:
        sig_data = json.load(f)

    def scan_module(module_name):
        try:
            module = importlib.import_module(module_name)
            if not hasattr(module, "__file__"):
                return
            for name, obj in inspect.getmembers(module, inspect.isfunction):
                fqname = f"{module_name}.{name}"
                entry = sig_data.get(fqname, {})
                if obj.__module__ != module_name:
                    continue
                if entry:
                    computed = compute_digest(obj)
                    computed_hex = computed.hex()
                    digest_bytes = computed
                    expected_hex = entry["sha256"]
                    sig_int = int(entry["sig"], 16)

                    sig_ok = validate_signature(digest_bytes, sig_int)
                    match = (computed_hex == expected_hex)
                    valid = match and sig_ok
                    if not valid:
                        print(f"[SIGVERIFY FAIL] {fqname} → match={match} sig_ok={sig_ok}")
                    result_mpt = {
                        "valid": valid,
                        "computed": computed_hex,
                        "expected": expected_hex,
                        "signature": sig_int,
                        "match": match,
                        "sig_ok": sig_ok
                    }
                    SIGVERIFY[fqname] = MappingProxyType(result_mpt)
                else:
                    results[fqname] = {"valid": False, "error": "No sigstore entry"}
        except Exception as e:
            results[module_name] = {"valid": False, "error": str(e)}

    # Recursively gather all modules under pydepguardnext
    for py in base_path.rglob("*.py"):
        if py.name == "__init__.py":
            continue
        rel = py.relative_to(base_path)
        mod = ".".join(["pydepguardnext"] + list(rel.with_suffix("").parts))
        scan_module(mod)
    global SIGVERIFIED
    SIGVERIFIED = MappingProxyType(SIGVERIFY)
    stop_capture()
    return results