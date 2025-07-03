import ast
import importlib
import inspect
import hashlib
import json
import types
from pathlib import Path
from pydepguardnext import SIGSTORE_PUBKEY
from types import MappingProxyType
from concurrent.futures import ThreadPoolExecutor, as_completed

SIGMAP = {}
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
    try:
        func = inspect.unwrap(func)
        source = inspect.getsource(func)
    except Exception:
        raise RuntimeError(f"Cannot unwrap or fetch source for {func}")
    return hashlib.sha256(source.encode()).digest()

def scan_module_preloaded(modname: str, module, sig_data: dict) -> dict:
    local_sigverify = {}
    local_results = {}

    for name, obj in inspect.getmembers(module, inspect.isfunction):
        fqname = f"{modname}.{name}"
        if fqname.startswith("pydepguardnext.standalone."):
            continue
        entry = sig_data.get(fqname, {})
        if obj.__module__ != modname:
            continue
        if entry:
            try:
                computed = compute_digest(obj)
                digest_bytes = computed  # locked bytes
                sig_ok = validate_signature(digest_bytes, int(entry["sig"], 16))
                match = (computed.hex() == entry["sha256"])
                valid = match and sig_ok

                result = MappingProxyType({  # wrap immediately
                    "valid": valid,
                    "computed": computed.hex(),
                    "expected": entry["sha256"],
                    "signature": entry["sig"],
                    "match": match,
                    "sig_ok": sig_ok,
                    "obj_id": id(obj),
                    "obj_name": name,
                    "module": modname,
                    "fqname": fqname,
                    "compound_hash": hashlib.sha256(f"{id(obj)}-{computed.hex()}".encode()).hexdigest()
                })

                local_sigverify[fqname] = result

            except Exception as inner:
                local_results[fqname] = MappingProxyType({
                    "valid": False,
                    "error": str(inner),
                    "fqname": fqname
                })
        else:
            local_results[fqname] = MappingProxyType({
                "valid": False,
                "error": "No sigstore entry",
                "fqname": fqname
            })

    return {
        "sigverify": MappingProxyType(local_sigverify),
        "results": MappingProxyType(local_results)
    }

def validate_all_functions(sigstore_path: Path = None, _log: list = None) -> dict:
    global SIGMAP, SIGVERIFIED
    print("[SIGVERIFY] Starting validation of all functions...")
    print("[SIGVERIFY] Loading sigstore data...")
    print(f"[SIGVERIFY] Expected sigstore path: {sigstore_path}")
    import pydepguardnext
    results = {}
    base_path = Path(pydepguardnext.__file__).parent
    sigstore_path = sigstore_path or (base_path / ".sigstore")

    if not sigstore_path.exists():
        return {"error": "No .sigstore file found at the expected location."}

    with open(sigstore_path, "r", encoding="utf-8") as f:
        sig_data = json.load(f)
        SIGMAP = MappingProxyType(sig_data)

    # Phase 1: Discover module names
    module_names = []
    for py in base_path.rglob("*.py"):
        if py.name == "__init__.py":
            continue
        rel = py.relative_to(base_path)
        modname = ".".join(["pydepguardnext"] + list(rel.with_suffix("").parts))
        module_names.append(modname)

    # Phase 2: Serial import in main thread
    modules = {}
    for mod in module_names:
        try:
            modules[mod] = importlib.import_module(mod)
        except Exception as e:
            results[mod] = {"valid": False, "error": f"Import failed: {e}"}

    # Phase 3: Parallel validation of functions
    with ThreadPoolExecutor(max_workers=8) as executor:
        futures = {
            executor.submit(scan_module_preloaded, mod, importlib.import_module(mod), sig_data): mod
            for mod in modules
        }

        for future in as_completed(futures):
            mod = futures[future]
            try:
                result = future.result()
                SIGVERIFY.update(result["sigverify"])
                results.update(result["results"])
            except Exception as e:
                print(f"[SIGVERIFY ERROR] Module {mod} raised an exception: {e}")
                import traceback
                traceback.print_exc()
                results[mod] = {"valid": False, "error": str(e)}

    SIGVERIFIED = MappingProxyType(SIGVERIFY)
    return results
