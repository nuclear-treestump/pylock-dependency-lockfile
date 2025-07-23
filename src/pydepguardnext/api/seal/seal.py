import hmac
import hashlib
import json
import secrets
import time
import sys
import os
from typing import Tuple, Any
from types import MappingProxyType
from base64 import b64encode, b64decode
from pydepguardnext.bootstrap.modes import RUNTIME_MODE
from pydepguardnext.bootstrap.boot import JIT_DATA_BUNDLE
from pydepguardnext.api.errors import RuntimeInterdictionError


data_uuid = ""
    
def shred_locals_by_ref(namespace: dict, exclude: Tuple[str, ...] = ()):
    for k in list(namespace.keys()):
        if k in exclude or k.startswith("__"):
            continue
        try:
            namespace[k] = os.urandom(len(namespace[k]))
            namespace[k] = None
        except Exception:
            pass
        finally:
            import gc
            gc.collect()
    

def constant_time_fail(reason="Tampering suspected. Request denied."):
    time.sleep(0.4 + secrets.randbelow(200) / 1000 + secrets.randbits(1) * 0.5)
    sys.tracebacklimit = 0
    raise RuntimeInterdictionError(reason)


PDGHEADER_MAGIC = b'\x50\x44\x47\x4d\x41\x4e\x49\x46\x45\x53\x54'  # "PDGMANIFEST"

DIFFICULTY_SLIDER = MappingProxyType({
    "test": 1_000,
    "easy": 10_000,
    "medium": 100_000,
    "hard": 1_000_000,
})

if RUNTIME_MODE.mode.CHILD:
    data_uuid = RUNTIME_MODE.parent_uuid
else:
    data_uuid = JIT_DATA_BUNDLE.get("jit_check_uuid", None)

def generate_key():
    return secrets.token_bytes(64)

def derive_nonce():
    return secrets.token_bytes(32)

def xor_stream(data: bytes, key: bytes, nonce: bytes, difficulty: int) -> bytes:
    chunk_size = 64
    out = bytearray()
    for i in range(0, len(data), chunk_size):
        chunk = data[i:i + chunk_size]
        salt = nonce + i.to_bytes(4, 'big')
        stream = hashlib.pbkdf2_hmac('sha256', salt, key, difficulty, dklen=len(chunk))
        out.extend(a ^ b for a, b in zip(chunk, stream))
    return bytes(out)

def seal_manifest(data: dict, key: bytes, nonce: bytes, context: str, difficulty: str) -> Tuple[dict, bytes]:
    from uuid import uuid4
    data['timestamp'] = time.time()
    data['context'] = context
    data['parent_uuid'] = data.get('parent_uuid', None)
    data['manifest_uuid'] = str(uuid4()) 
    data['expiry'] = str(time.time() + 60)
    if data["manifest_uuid"] == data["parent_uuid"]:
        shred_locals_by_ref(locals())
        constant_time_fail("Manifest corruption error. Request denied.")
    raw = PDGHEADER_MAGIC + json.dumps(data, sort_keys=True, separators=(',', ':')).encode()
    if difficulty not in DIFFICULTY_SLIDER:
        shred_locals_by_ref(locals())
        constant_time_fail("Manifest corruption error. Request denied.")
    encrypted = xor_stream(raw, key, nonce, DIFFICULTY_SLIDER[difficulty])
    hmac_key = secrets.token_bytes(64)
    tag = hmac.new(hmac_key, encrypted + nonce + data['manifest_uuid'].encode(), hashlib.sha256).hexdigest()
    data_blob = {"nonce": b64encode(nonce).decode(), "blob": b64encode(encrypted).decode(), "tag": tag, "manifest_uuid": data['manifest_uuid'], "difficulty": difficulty}
    shred_locals_by_ref(locals(), exclude=("data_blob", "hmac_key"))
    return data_blob, hmac_key

def unseal_manifest(sealed: dict, key: bytes, hmac_key: bytes) -> dict:
    nonce = b64decode(sealed["nonce"])
    blob = b64decode(sealed["blob"])
    expected_tag = sealed["tag"]
    difficulty = sealed["difficulty"]

    calc_tag = hmac.new(hmac_key, blob + nonce + sealed['manifest_uuid'].encode(), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(calc_tag, expected_tag):
        shred_locals_by_ref(locals())
        constant_time_fail("Manifest corruption error. Request denied.")
    decrypted = xor_stream(blob, key, nonce, DIFFICULTY_SLIDER[difficulty])
    if not decrypted.startswith(b'\x50\x44\x47\x4d\x41\x4e\x49\x46\x45\x53\x54'):  # Check for PDGMANIFEST
        shred_locals_by_ref(locals())
        constant_time_fail("Manifest corruption error. Request denied.")
    manifest = json.loads(decrypted[len(PDGHEADER_MAGIC):].decode())
    if not hmac.compare_digest(manifest.get("manifest_uuid", ""), sealed.get("manifest_uuid", "")):
        shred_locals_by_ref(locals())
        constant_time_fail("Manifest corruption error. Request denied.")
    expiry = manifest.get("expiry", 0)
    if expiry and (time.time() > expiry or time.time() < manifest['timestamp'] - 120):
        shred_locals_by_ref(locals())
        constant_time_fail("Manifest corruption error. Request denied.")
    shred_locals_by_ref(locals(), exclude=("manifest",))
    return manifest

def get_manifest_data(get_from_env: bool = False, sealed_manifest: str = '', manifest_key: str = '', manifest_hmac_key: str = ''):
    if get_from_env:
        from os import getenv
        sealed_manifest = getenv("PYDEP_MANIFEST", "")
        manifest_key = getenv("PYDEP_MANIFEST_KEY", "")
        manifest_hmac_key = getenv("PYDEP_MANIFEST_HMAC_KEY", "")
    if get_from_env and (not sealed_manifest or not manifest_key or not manifest_hmac_key):
        from os import environ
        for k in ("PYDEP_MANIFEST", "PYDEP_MANIFEST_KEY", "PYDEP_MANIFEST_HMAC_KEY"):
            if k in environ:
                environ[k] = "\x00" * 128
                del environ[k]
        shred_locals_by_ref(locals())
        constant_time_fail("Manifest corruption error. Request denied.")
    try:
        from os import urandom
        internal_manifest_data = json.loads(sealed_manifest)
        internal_manifest_key = b64decode(manifest_key)
        internal_manifest_hmac_key = b64decode(manifest_hmac_key)
        manifest = unseal_manifest(internal_manifest_data, internal_manifest_key, internal_manifest_hmac_key)
        internal_manifest_data = urandom(32)
        internal_manifest_key = urandom(32)
        internal_manifest_hmac_key = urandom(32)
        shred_locals_by_ref(locals(), exclude=("manifest",))
        return manifest
    except json.JSONDecodeError:
        shred_locals_by_ref(locals())
        constant_time_fail("Manifest corruption error. Request denied.")
    finally:
        from os import environ
        for k in ("PYDEP_MANIFEST", "PYDEP_MANIFEST_KEY", "PYDEP_MANIFEST_HMAC_KEY"):
            if k in environ:
                environ[k] = "\x00" * 128
                del environ[k]
        shred_locals_by_ref(locals())

def make_manifest_data(data: dict, use_env: bool, context: str = "default", difficulty: str = "medium") -> Tuple[dict, bytes, bytes]:
    key = generate_key()
    nonce = derive_nonce()
    sealed_data, hmac_key = seal_manifest(data, key, nonce, context, difficulty)

    # Store in environment variables for child retrieval
    if use_env:
        import json
        from base64 import b64encode
        from os import environ
        environ["PYDEP_MANIFEST"] = json.dumps(sealed_data)
        environ["PYDEP_MANIFEST_KEY"] = b64encode(key).decode()
        environ["PYDEP_MANIFEST_HMAC_KEY"] = b64encode(hmac_key).decode()
    for k in locals().keys():
        if k not in ("sealed_data", "key", "hmac_key"):
            locals()[k] = os.urandom(32)
            del locals()[k]
    shred_locals_by_ref(locals(), exclude=("sealed_data", "key", "hmac_key"))
    return sealed_data, key, hmac_key