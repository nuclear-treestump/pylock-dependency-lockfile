import hmac
import hashlib
import json
import secrets
import time
from typing import Tuple
from base64 import b64encode, b64decode
from pydepguardnext.bootstrap.modes import RUNTIME_MODE
from pydepguardnext.bootstrap.boot import JIT_DATA_BUNDLE

data_uuid = ""

if RUNTIME_MODE.mode.CHILD:
    data_uuid = RUNTIME_MODE.parent_uuid
else:
    data_uuid = JIT_DATA_BUNDLE.get("jit_check_uuid", None)

def generate_key():
    return secrets.token_bytes(64)

def derive_nonce():
    return secrets.token_bytes(32)

def xor_stream(data: bytes, key: bytes, nonce: bytes) -> bytes:
    chunk_size = 64
    out = bytearray()
    for i in range(0, len(data), chunk_size):
        chunk = data[i:i + chunk_size]
        salt = nonce + i.to_bytes(4, 'big')
        stream = hashlib.pbkdf2_hmac('sha256', salt, key, 100_000, dklen=len(chunk))
        out.extend(a ^ b for a, b in zip(chunk, stream))
    return bytes(out)

def seal_manifest(data: dict, key: bytes, nonce: bytes, context: str) -> Tuple[dict, bytes]:
    data['timestamp'] = time.time()
    data['context'] = context
    data['parent_uuid'] = data.get('parent_uuid', None)
    raw = json.dumps(data, separators=(',', ':')).encode()
    encrypted = xor_stream(raw, key, nonce)
    hmac_key = secrets.token_bytes(64)
    tag = hmac.new(hmac_key, encrypted + nonce, hashlib.sha256).hexdigest()
    data_blob = {"nonce": b64encode(nonce).decode(), "blob": b64encode(encrypted).decode(), "tag": tag}
    return data_blob, hmac_key

def unseal_manifest(sealed: dict, key: bytes, hmac_key: bytes) -> dict:
    nonce = b64decode(sealed["nonce"])
    blob = b64decode(sealed["blob"])
    expected_tag = sealed["tag"]

    calc_tag = hmac.new(hmac_key, blob + nonce, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(calc_tag, expected_tag):
        from pydepguardnext.api.errors import RuntimeInterdictionError
        raise RuntimeInterdictionError("HMAC tag mismatch. Refusing to unseal.")

    decrypted = xor_stream(blob, key, nonce)
    return json.loads(decrypted.decode())
